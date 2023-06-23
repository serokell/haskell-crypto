-- SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE ConstraintKinds, TypeFamilies, ExistentialQuantification, RankNTypes #-}

-- | The sensitive data type internals.
module Data.SensitiveBytes.Internal
  ( withSecureMemory
  , WithSecureMemory
  , SecureMemoryInitException

  , SensitiveBytes (..)
  , allocate
  , free
  , unsafePtr
  , resized

  , withSensitiveBytes
  , SensitiveBytesAllocException
  ) where

import Control.Exception.Safe (Exception, MonadMask, bracket, throwIO)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.ByteArray (ByteArrayAccess (length, withByteArray))
import Data.Kind (Constraint)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Libsodium (sodium_free, sodium_init, sodium_malloc, sodium_memzero)
import Unsafe.Coerce (unsafeCoerce)

-- | A constraint for functions that require access to secure memory.
-- The only way to satisfy it is to call 'withSecureMemory'.
type family WithSecureMemory :: Constraint where


-- | This function performs the initialisation steps
-- required for allocating data in secure memory regions.
--
-- The basic usage is to call this function and provide to it
-- a block of code that will be allocating memory for sensitive
-- data. The type of 'withSensitiveBytes' is such that it can
-- only be called withing such a code block.
--
-- Ideally, you should call 'withSecureMemory' only once and deal
-- with all your sensitive data within this single code block,
-- however it is not a requirement – you can call it as many
-- times as you wish and the only downside to doing so is that
-- it will incur a tiny performance penalty.
--
-- In some rare circumstances this function secure memory initialisation
-- may fail, in which case this function will throw
-- 'SecureMemoryInitException'.
withSecureMemory
  :: forall m r. MonadIO m
  => (WithSecureMemory => m r)  -- ^ Action to perform.
  -> m r
withSecureMemory act = do
  liftIO $ sodium_init >>= \case
    0 ->
      -- Ok
      pure ()
    1 ->
      -- Already initialised, ok
      pure ()
    _ ->
      -- sodium_init failed, not good
      throwIO SodiumInitFailed
  case unsafeCoerce (Dict @()) :: Dict WithSecureMemory of
    Dict -> act

-- | Exception thrown by 'withSecureMemory'.
data SecureMemoryInitException
  = SodiumInitFailed  -- ^ libsodium failed to initialise.

instance Show SecureMemoryInitException where
  show SodiumInitFailed =
    "Failed to initialise a secure memory region"

instance Exception SecureMemoryInitException


-- | Bytes that will be allocated in a secure memory location
-- such that they will never be moved by the garbage collector
-- and, hopefully, never swapped out to the disk (if the
-- operating system supports this kind of protection).
data SensitiveBytes s = SensitiveBytes
  { allocSize :: Int  -- ^ Size of the allocated buffer.
  , dataSize :: Int  -- ^ Size of the actual data stored.
  , bufPtr :: Ptr ()  -- ^ Buffer pointer.
  }

instance ByteArrayAccess (SensitiveBytes s) where
  length SensitiveBytes{ dataSize } = dataSize
  withByteArray SensitiveBytes{ bufPtr } act = act (castPtr bufPtr)

-- | Get the underlying data pointer.
--
-- This function is unsafe, because it discards the second-order context
-- and thus can allow the pointer to escape its scope and be used after free.
unsafePtr :: SensitiveBytes s -> Ptr ()
unsafePtr = bufPtr


-- | Allocate bytes in a protected memory region.
--
-- Just as regular @malloc@, this function can fail, for example,
-- if there is not enough memory. In this case, it will throw
-- 'SensitiveBytesAllocException'.
allocate
  :: forall s m. (MonadIO m, WithSecureMemory)
  => Int  -- ^ Size of the array (in bytes).
  -> m (SensitiveBytes s)
allocate size = requiringSecureMemory $ liftIO $ do
  res <- sodium_malloc (fromIntegral size)
  if res == nullPtr
    then throwIO SodiumMallocFailed
    else pure $ SensitiveBytes size size res

-- | Free bytes previously allocated in a protected memory region.
free
  :: forall s m. (MonadIO m, WithSecureMemory)
  => SensitiveBytes s
  -> m ()
free SensitiveBytes{ bufPtr } = requiringSecureMemory $
  liftIO $ sodium_free bufPtr

-- | Zero-out memory.
memzero
  :: forall s m. (MonadIO m)
  => SensitiveBytes s
  -> m ()
memzero SensitiveBytes{ allocSize, bufPtr } =
  liftIO $ sodium_memzero bufPtr (fromIntegral allocSize)

-- | Rewrite the recorded size of the data.
--
-- This is a very dangerous internal-only function. It is essentially
-- a hack that allows other functions exported from this library to
-- efficiently read data of unknown size by first allocating a large buffer
-- and then tweaking the 'ByteArrayAccess' instance to return the size that
-- is smaller than what was actually allocated.
resized
  :: forall s. ()
  => Int  -- ^ New data size.
  -> SensitiveBytes s  -- ^ What to resize.
  -> SensitiveBytes s
resized newSize sb@SensitiveBytes{ allocSize }
  | newSize <= allocSize = sb{ dataSize = newSize }
  | otherwise = error "SensitiveBytes.Internal.resized: the new size is too large"


-- | Allocate a byte array in a secure memory region.
--
-- This function guarantees that:
--
-- 1. The garbage collector will not touch the allocated memory and
--    will not try to copy the sensitive data.
-- 2. The memory will be zeroed-out and freed as soon as the computation
--    finishes.
--
-- Additionally, it will try its best (subject to the support from
-- the operating system) to do the following:
--
-- 1. Allocate the buffer at the end of a page and make sure that the
--    following page is not mapped, so trying to access past the end of
--    the buffer will crash the program.
-- 2. Place a canary immediately before the buffer, check that it was not
--    modified before deallocating the memory, and crash the program otherwise.
-- 3. @mlock@ the memory to make sure it will not be paged to the disk.
-- 4. Ask the operating system not to include this memory in core dumps.
--
-- Just as with regular @malloc@, allocation can fail, for example,
-- if there is not enough memory. In this case, the function will throw
-- 'SensitiveBytesAllocException'.
withSensitiveBytes
  :: forall s m r. (MonadIO m, MonadMask m, WithSecureMemory)
  => Int  -- ^ Size of the array (in bytes).
  -> (SensitiveBytes s -> m r)  -- ^ Action to perform with memory allocated.
  -> m r
-- TODO: libsodium docs also say something about the allocated size being
-- a multiple of the required alignment, but it is not clear what the
-- implications are (I added a test, just in case).
withSensitiveBytes size = bracket (allocate size) finalise
  where
    -- OK, this is weird, but libsodium has a whole bunch of ifdefs that
    -- control the logic of @sodium_free@ and, for some reason, if it does
    -- not @HAVE_ALIGNED_MALLOC@, it will not zero-out the memory.
    -- Cool story, but this makes no sense, so we zero-out it ourselves
    -- in case we are on such a system.
    finalise sb = memzero sb *> free sb

-- | Exception thrown by 'withSensitiveBytes'.
data SensitiveBytesAllocException
  = SodiumMallocFailed  -- ^ @sodium_malloc@ returned NULL.

instance Show SensitiveBytesAllocException where
  show SodiumMallocFailed =
    "Failed to allocate secure memory"

instance Exception SensitiveBytesAllocException



-- | An internal helper that fakes needing "WithSecureMemory".
--
-- It is a complete no-op and exists only to silence the unused constraint
-- warning. Hopefully, it will get optimised away every time.
requiringSecureMemory :: WithSecureMemory => r -> r
requiringSecureMemory act = act
  where _ = Dict @WithSecureMemory
{-# INLINE requiringSecureMemory #-}

-- | We don't need to depend on @constraints@ for a single trivial type.
data Dict c = c => Dict

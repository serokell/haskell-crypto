-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Scalar multiplication in a group.
--
-- This is @crypto_scalarmult_*@ from NaCl.
--
-- Note that this primitive is designed to only make the /Computational Diffie–Hellman/
-- problem hard. It makes no promises about other assumptions, therefore it is
-- the user’s responsibility to hash the output if required for the security
-- of the specific application.
module NaCl.Scalarmult
  ( Point (..)
  , toPoint
  , Scalar (..)
  , toScalar

  , mult
  , multBase
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess, withByteArray)
import Data.ByteArray.Sized (ByteArrayN, SizedByteArray, allocRet, sizedByteArray)
import Data.Proxy (Proxy (Proxy))
import System.IO.Unsafe (unsafePerformIO)

import qualified Libsodium as Na


-- | Point in the group.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
newtype Point a = Point (SizedByteArray Na.CRYPTO_SCALARMULT_BYTES a)
  deriving
    ( ByteArrayAccess, ByteArrayN Na.CRYPTO_SCALARMULT_BYTES
    , Eq, Ord, Show
    )

-- | Convert bytes to a group point.
toPoint :: ByteArrayAccess bytes => bytes -> Maybe (Point bytes)
toPoint = fmap Point . sizedByteArray

-- | Scalar that can be used for group multiplication.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
newtype Scalar a = Scalar (SizedByteArray Na.CRYPTO_SCALARMULT_SCALARBYTES a)
  deriving
    ( ByteArrayAccess, ByteArrayN Na.CRYPTO_SCALARMULT_SCALARBYTES
    , Eq, Ord, Show
    )

-- | Convert bytes to a scalar.
toScalar :: ByteArrayAccess bytes => bytes -> Maybe (Scalar bytes)
toScalar = fmap Scalar . sizedByteArray

-- | Multiply a group point by an integer.
--
-- Note that this function is slightly different from the corresponding function
-- in NaCl. Namely, unlike @crypto_scalarmult@ in NaCl, this one will return
-- @Nothing@ if:
--
-- * either the group point has a small order (1, 2, 4, or 8)
-- * or the result of the multiplication is the identity point.
--
-- This is how it is implemented in libsodium.
mult
  :: forall outBytes pointBytes scalarBytes.
     ( ByteArrayAccess pointBytes
     , ByteArrayAccess scalarBytes
     , ByteArray outBytes
     )
  => Point pointBytes  -- ^ Group point.
  -> Scalar scalarBytes  -- ^ Scalar.
  -> Maybe (Point outBytes)
mult point scalar = unsafePerformIO $ do
    (ret, out) <-
      allocRet (Proxy @Na.CRYPTO_SCALARMULT_BYTES) $ \outPtr ->
      withByteArray point $ \pointPtr ->
      withByteArray scalar $ \scalarPtr ->
        Na.crypto_scalarmult outPtr scalarPtr pointPtr
    if ret == 0
    then pure $ Just out
    else pure Nothing

-- | Multiply the standard group point by an integer.
multBase
  :: forall outBytes scalarBytes.
     ( ByteArrayAccess scalarBytes
     , ByteArray outBytes
     )
  => Scalar scalarBytes  -- ^ Scalar.
  -> Point outBytes
multBase scalar = unsafePerformIO $ do
    (_ret, out) <-
      allocRet (Proxy @Na.CRYPTO_SCALARMULT_BYTES) $ \outPtr ->
      withByteArray scalar $ \scalarPtr ->
        Na.crypto_scalarmult_base outPtr scalarPtr
    -- _ret can be only 0, so we don’t check it
    pure out

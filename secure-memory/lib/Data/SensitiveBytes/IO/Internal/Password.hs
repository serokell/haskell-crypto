-- SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE CPP #-}
{-# LANGUAGE InterruptibleFFI #-}

-- | Internal utilities for reading passwords.
module Data.SensitiveBytes.IO.Internal.Password
  ( readPassword
  ) where

import Control.Exception.Safe (MonadMask, bracket)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Text (Text)
import qualified Data.Text.IO as T
import Foreign.C.Error (eILSEQ, getErrno)
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr)
import System.IO (Handle, hFlush)

#if defined(mingw32_HOST_OS)
#else
import Data.Coerce (coerce)
import System.Posix.IO (handleToFd)
import System.Posix.Types (Fd (Fd))
import qualified System.Posix.Terminal as Term
#endif


foreign import ccall interruptible "readline_max"
  c_readLineMax :: CInt -> Ptr () -> CInt -> IO CInt

-- | A quick wrapper around the C function that turns the Haskell IO
-- 'Handle' into a system-dependent handle/fd.
readLineMax :: Handle -> Ptr () -> CInt -> IO CInt
#if defined(mingw32_HOST_OS)
readLineMax _ bufPtr maxLength = do
  c_readLineMax 0 bufPtr maxLength
#else
readLineMax hIn bufPtr maxLength = do
  fdIn <- handleToFd hIn
  c_readLineMax (coerce fdIn) bufPtr maxLength
#endif


-- | Flush stdout, disable echo, and read user input from stdin.
readPassword
  :: Handle  -- ^ Input file handle.
  -> Handle  -- ^ Output file handle.
  -> Text  -- ^ Prompt.
  -> Ptr ()  -- ^ Target buffer.
  -> Int  -- ^ Target buffer size.
  -> IO Int
readPassword hIn hOut prompt bufPtr allocSize = do
  T.hPutStr hOut prompt
  withEchoDisabled hIn $ do
    hFlush hOut  -- need to flush _after_ echo is disabled
    -- TODO: Do we also want to install signal handlers?
    res <- readLineMax hIn bufPtr (fromIntegral allocSize)
    if res >= 0
    then do
      T.hPutStrLn hOut ""
      pure $ fromIntegral res
    else do
      errno <- getErrno
      -- TODO: Maybe return a Maybe or throw a proper exception?
      case res of
        -1 -> do
          if errno == eILSEQ
          then error "readPassword: locale/terminal misconfiguration"
          else error "readPassword: read error"
        _ -> error $ "readPassword: impossible error happened: " <> show res

-- | Run an action with terminal echo off (and then restore it).
withEchoDisabled :: (MonadIO m, MonadMask m) => Handle -> m r -> m r
#if defined(mingw32_HOST_OS)
withEchoDisabled _ = id  -- on Windows our @c_readLineMax@ does not echo anyway
#else
withEchoDisabled hIn act = do
  fin <- liftIO $ handleToFd hIn
  liftIO (Term.queryTerminal fin) >>= \case
    False -> act
    True -> do
      attrs <- liftIO $ Term.getTerminalAttributes fin
      let attrsNoEcho = Term.withoutMode attrs Term.EnableEcho
      bracket
        (liftIO $ Term.setTerminalAttributes fin attrsNoEcho Term.WhenFlushed)
        (\_ -> liftIO $ Term.setTerminalAttributes fin attrs Term.Immediately)
        (\_ -> act)
#endif

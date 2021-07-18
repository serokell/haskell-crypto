-- SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE CPP #-}

-- | Internal utilities for reading passwords.
module Data.SensitiveBytes.IO.Internal.Password
  ( readPassword
  ) where

import Control.Exception.Safe (MonadMask, bracket)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Text (Text)
import qualified Data.Text.IO as T
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr)
import System.IO (hFlush, stdout)

#if defined(mingw32_HOST_OS)
#else
import System.Posix.IO (stdInput)
import qualified System.Posix.Terminal as Term
#endif

import Data.SensitiveBytes.Internal (SensitiveBytes (..))


foreign import ccall unsafe "readline_max"
  c_readLineMax :: CInt -> Ptr () -> IO CInt


-- | Flush stdout, disable echo, and read user input from stdin.
readPassword
  :: forall s. ()
  => Text  -- ^ Prompt.
  -> SensitiveBytes s  -- ^ Target buffer.
  -> IO Int
readPassword prompt SensitiveBytes{ allocSize, bufPtr } = do
  T.hPutStr stdout prompt
  withEchoDisabled $ do
    hFlush stdout  -- need to flush _after_ echo is disabled
    -- TODO: Do we also want to install signal handlers?
    res <- c_readLineMax (fromIntegral allocSize) bufPtr
    if res < 0
    then
      -- TODO: Maybe return a Maybe or throw a proper exception?
      error "Unexpected error reading the password"
    else do
      T.hPutStrLn stdout ""
      pure $ fromIntegral res

-- | Run an action with terminal echo off (and then restore it).
withEchoDisabled :: (MonadIO m, MonadMask m) => m r -> m r
#if defined(mingw32_HOST_OS)
withEchoDisable = id  -- on Windows our @c_readLineMax@ does not echo anyway
#else
withEchoDisabled act = liftIO (Term.queryTerminal fin) >>= \case
    False -> act
    True -> do
      attrs <- liftIO $ Term.getTerminalAttributes fin
      let attrsNoEcho = Term.withoutMode attrs Term.EnableEcho
      bracket
        (liftIO $ Term.setTerminalAttributes fin attrsNoEcho Term.WhenFlushed)
        (\_ -> liftIO $ Term.setTerminalAttributes fin attrs Term.Immediately)
        (\_ -> act)
  where
    fin = stdInput
#endif

-- SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE CPP #-}

-- | Tests for reading passwords.
module Test.Data.SensitiveBytes.IO.Password where

import Control.Concurrent.Async (waitBoth, withAsync)
import Control.Monad.IO.Class (liftIO)
import Data.ByteArray (allocRet)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import System.IO (Handle, hClose)

#if !defined(mingw32_HOST_OS)
import System.Posix.IO (createPipe, fdToHandle)
#endif

import Hedgehog (MonadGen, Property, (===), forAll, property)
import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R
import Test.Tasty.HUnit ((@?=))

import Data.SensitiveBytes.IO.Internal.Password (readPassword)


-- | Read a user-provided password into a 'ByteString'.
-- This is a terrible, terrible idea, since it copies
-- the password from the secure memory into the regular
-- GC-managed heap. Never ever do this (except for tests).
unsafeReadPassword :: Handle -> Handle -> Int -> IO ByteString
unsafeReadPassword hIn hOut maxLength = do
  (size, bs) <- allocRet maxLength $ \ba ->
    readPassword hIn hOut "Password: " ba maxLength
  pure $ BS.take size bs

#if !defined(mingw32_HOST_OS)
-- | Read a password from the 'ByteString' provided.
--
-- Make sure the input bytes can be read using current locale.
-- Unfortunately, this function only works on Unix, since I don’t know
-- any easy way to create a pipe on Windows.
--
-- This requires a threaded runtime due to the use of async.
unsafeReadPasswordFrom :: ByteString -> Int -> IO (ByteString, ByteString)
unsafeReadPasswordFrom input maxLength = do
    -- Create two pipes: one for stdin, one for stdout.
    (hInRead, hInWrite) <- createPipeHandles
    (hOutRead, hOutWrite) <- createPipeHandles

    -- This thread will capture the stdout.
    withAsync (readHandle hOutRead) $ \aStdoutReader -> do
      -- This thread will read the password.
      withAsync (readPassword' hInRead hOutWrite) $ \aPasswordReader -> do
        -- Feed password to stdin.
        BS.hPutStr hInWrite (input <> "\n")
        hClose hInWrite
        -- Now we wait for everyone else to finish.
        waitBoth aStdoutReader aPasswordReader
  where
    createPipeHandles = do
      (fdRead, fdWrite) <- createPipe
      hRead <- fdToHandle fdRead
      hWrite <- fdToHandle fdWrite
      pure (hRead, hWrite)

    readHandle = BS.hGetContents

    readPassword' hIn hOut =
      unsafeReadPassword hIn hOut maxLength <* hClose hOut

-----------------------------------------

-- | A generator for a printable ASCII character.
asciiPrintable :: MonadGen m => m Char
asciiPrintable = G.element ['\32' .. '\126']

-----------------------------------------

unit_test_unsafe_read :: IO ()
unit_test_unsafe_read = do
  (stdoutBs, pass) <- unsafeReadPasswordFrom "hello" 16
  stdoutBs @?= "Password: \n"
  pass @?= "hello"

hprop_ascii :: Property
hprop_ascii = property $ do
  input <- forAll $ G.utf8 (R.linear 0 100) asciiPrintable
  (_, pass) <- liftIO $ unsafeReadPasswordFrom input 100
  pass === input

hprop_ascii_longer :: Property
hprop_ascii_longer = property $ do
  size <- forAll $ G.integral (R.linear 0 100)
  extra <- forAll $ G.integral (R.linear 1 100)
  -- input is longer than the allocated buffer by `extra`
  input <- forAll $ G.utf8 (R.singleton $ size + extra) asciiPrintable
  (_, pass) <- liftIO $ unsafeReadPasswordFrom input size
  pass === BS.take size input


#endif

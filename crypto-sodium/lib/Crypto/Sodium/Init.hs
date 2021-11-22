-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Libsodium initialisation.

-- = Thread-safety #threadSafety#
--
-- Some of the Sodium (and NaCl) functions (those that generate random data)
-- are not thread-safe. All these functions are explicitly marked as such
-- in their Haddock documentation.
--
-- Calling 'sodiumInit' before they are used makes them thread-safe.
--
-- = Performance
--
-- Sodium contains multiple implementations of the primitives it provides.
-- There are generic implementations, that are used by default, and
-- multiple alternatives optimised for various platforms.
--
-- 'sodiumInit' will quickly benchmark all available implementations and choose
-- the best ones for each primitive.
module Crypto.Sodium.Init
  ( sodiumInit
  , SodiumInitException (..)
  ) where

import Control.Exception (Exception, throwIO)
import Libsodium (sodium_init)


-- | Initialise libsodium.
--
-- This is just @sodium_init()@ from libsodium. Calling it before using
-- any Sodium functions is optional, but strongly recommended.
--
-- This function does the following:
--
-- 1. Open @\/dev\/urandom@ (on Unix) to make it accessible even after @chroot()@.
--
-- 2. Make all libsodium functions thread-safe.
--
-- 3. Benchmark different implementations of cryptographic primitives provided
-- and choose the best ones.
--
-- This function itself is thread-safe (since libsodium-1.0.11).
sodiumInit :: IO ()
sodiumInit = sodium_init >>= \case
  0 ->
    -- Success!
    pure ()
  1 ->
    -- Already initialised, that’s ok.
    pure ()
  _ ->
    -- If initialisation fails, using libsodium is unsafe, and there is
    -- really nothing that can be done at this point and there is no way
    -- to recover.
    -- It would be nice to provide some helpful diagnostic here, but,
    -- unfortunately, libsodium gives no information on the failure reason.
    throwIO SodiumInitFailed


-- | Exception thrown by 'sodiumInit'.
data SodiumInitException
  = SodiumInitFailed  -- ^ libsodium failed to initialise.

instance Show SodiumInitException where
  show SodiumInitFailed =
    "libsodium failed to initialise and is not safe to use"

instance Exception SodiumInitException

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}

-- ! This module merely re-exports definitions from the corresponding
-- ! module in NaCl and alters the Haddock to make it more specific
-- ! to crypto-sodium. So, the docs should be kept more-or-less in sync.

-- | Public-key signatures.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Sodium.Sign as Sign
--
-- signed = Sign.'create' sk message
-- verified = Sign.'open' pk signed
-- @
--
-- Functions in this modules work with /combined/ signatures.
-- This means that when you sign a message, it will be copied as is
-- and then a signature will be prepended. So you should treat the
-- resulting value as a transparent (because it is not encrypted)
-- package with a signature attached on top.
--
-- Instead of accessing the message directly, you should use
-- 'open', which will verify the signature and return a copy of the
-- original message only if the signature was valid.
module Crypto.Sodium.Sign
  (
  -- * Keys
    PublicKey
  , toPublicKey
  , SecretKey
  , toSecretKey
  , keypair

  , Seed
  , keypairFromSeed
  , unsafeKeypairFromSeed

  -- * Signing/verifying
  , create
  , open
  ) where

import Data.ByteArray (ByteArrayAccess, ScrubbedBytes, withByteArray)
import Data.ByteString (ByteString)
import Data.ByteArray.Sized (SizedByteArray, alloc, allocRet)
import Data.Functor (void)
import Data.Proxy (Proxy(..))
import System.IO.Unsafe (unsafePerformIO)

import qualified Libsodium as Na

import NaCl.Sign
  (PublicKey, SecretKey, create, keypair, open, toPublicKey, toSecretKey)

-- | Seed for deterministically generating a keypair.
--
-- In accordance with Libsodium's documentation, the seed must be of size
-- @Na.CRYPTO_SIGN_SEEDBYTES@.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type Seed a = SizedByteArray Na.CRYPTO_SIGN_SEEDBYTES a


-- | Generate a new 'SecretKey' together with its 'PublicKey' from a given seed.
keypairFromSeed
  :: ByteArrayAccess seed
  => Seed seed
  -> IO (PublicKey ByteString, SecretKey ScrubbedBytes)
keypairFromSeed seed = do
  allocRet Proxy $ \skPtr ->
    alloc $ \pkPtr ->
    withByteArray seed $ \sdPtr ->
    -- always returns 0, so we don’t check it
    void $ Na.crypto_sign_seed_keypair pkPtr skPtr sdPtr

-- | Generate a new 'SecretKey' together with its 'PublicKey' from a given seed,
-- in a pure context.
unsafeKeypairFromSeed
  :: ByteArrayAccess seed
  => Seed seed
  -> (PublicKey ByteString, SecretKey ScrubbedBytes)
unsafeKeypairFromSeed = unsafePerformIO . keypairFromSeed

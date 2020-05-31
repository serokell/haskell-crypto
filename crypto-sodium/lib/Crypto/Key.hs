{-# OPTIONS_GHC -Wno-redundant-constraints #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Utilities for working with secret keys.
module Crypto.Key
  ( fromPassword
  , Params (..)
  , type (!>=!)

  , generate
  ) where

import Data.ByteArray (ByteArrayAccess, ScrubbedBytes)
import Data.ByteArray.Sized (ByteArrayN, SizedByteArray)
import Data.Kind (Constraint)
import GHC.TypeLits (type (<=), KnownNat)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Crypto.Pwhash.Internal (Algorithm (Argon2id_1_3), Params (..), Salt, pwhash)

import qualified Libsodium as Na

import qualified Crypto.Random


-- | “At least as secure as”.
--
-- @a !>=! b@ means that the storage behind a is not less secure than b.
-- This is a little bit of an ad-hoc safety hack, which ensures that if
-- @b@ is stored in a securely allocated memory, then @a@ is stored in
-- memory allocated as securely, or more securely.
--
-- Here are our very ad-hoc rules:
--
-- * This relation is reflexive (@a@ is as secure as @a@ for any @a@).
-- * 'ScrubbedBytes' is more secure than anything.
-- * Everything else is equally (in)secure.
--
-- So, for example, if the original password is stored in @ScrubbedBytes@,
-- you will not be able to put the derived from it key into a @ByteString@,
-- because that would be less secure.
type family a !>=! b :: Constraint where
  a !>=! a = ()  -- reflexivity
  a !>=! ScrubbedBytes = LessSecureStorage a ScrubbedBytes
  a !>=! b = ()
class LessSecureStorage a b

-- | Derive an encryption key from a password using a secure KDF.
--
-- The purpose of the nonce is to protect against the user using a weak
-- password and the attacker being able to precompute the derived secret key.
-- For this reason, the recommended strategy is to generate a new random
-- nonce when deriving the encryption key for the first time and then store
-- the nonce for deriving the key in the future (e.g. for decryption).
-- The nonce is not secret and can be stored as plaintext.
--
-- See @libsodium@ documentation for how to determine 'Params'.
fromPassword
  ::  ( ByteArrayAccess passwd, ByteArrayAccess nonceBytes
      , ByteArrayN n hash, hash !>=! passwd
      , Na.CRYPTO_PWHASH_BYTES_MIN <= n, n <= Na.CRYPTO_PWHASH_BYTES_MAX
      )
  => Params -- ^ Hashing parameters.
  -> passwd  -- ^ Password to hash.
  -> Salt nonceBytes  -- ^ Nonce used for deriving the key from the password.
  -> Maybe hash
fromPassword params passwd salt =
  unsafeDupablePerformIO $ pwhash Argon2id_1_3 params passwd salt
  -- This IO is safe, because it is pure.


-- | Generate a new secret key using a cryptographically-secure generator.
--
-- This is just a specialisation of @Crypto.Random.'generate'@ that stores
-- it in a secure memory location.
generate :: KnownNat n => IO (SizedByteArray n ScrubbedBytes)
generate = Crypto.Random.generate

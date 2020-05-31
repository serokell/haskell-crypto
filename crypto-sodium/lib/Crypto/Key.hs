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
  ) where

import Data.ByteArray (ByteArrayAccess)
import Data.ByteArray.Sized (ByteArrayN)
import GHC.TypeLits (type (<=))
import System.IO.Unsafe (unsafeDupablePerformIO)

import Crypto.Pwhash.Internal (Algorithm (Argon2id_1_3), Params (..), Salt, pwhash)

import qualified Libsodium as Na


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
      , ByteArrayN n hash
      , Na.CRYPTO_PWHASH_BYTES_MIN <= n, n <= Na.CRYPTO_PWHASH_BYTES_MAX
      )
  => Params -- ^ Hashing parameters.
  -> passwd  -- ^ Password to hash.
  -> Salt nonceBytes  -- ^ Nonce used for deriving the key from the password.
  -> Maybe hash
fromPassword params passwd salt =
  unsafeDupablePerformIO $ pwhash Argon2id_1_3 params passwd salt
  -- This IO is safe, because it is pure.

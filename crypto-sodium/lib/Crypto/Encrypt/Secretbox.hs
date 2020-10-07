-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}

-- ! This module merely re-exports definitions from the corresponding
-- ! module in NaCl and alters the Haddock to make it more specific
-- ! to crypto-sodium. So, the docs should be kept more-or-less in sync.

-- | Symmetric authenticated encryption.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Encrypt.Secretbox as Secretbox
--
-- encrypted = Secretbox.'create' key nonce message
-- decrypted = Secretbox.'open' key nonce encrypted
-- @
--
-- A secretbox is an abstraction from NaCl. One way to think about it
-- is to imagine that you are putting data into a box protected by a
-- secret key. You 'create' such a box first, store it somewhere
-- (it is just a sequence of bytes), and when you need it in the
-- future, you 'open' it using the same secret key.
module Crypto.Encrypt.Secretbox
  (
  -- * Keys
    Key
  , toKey

  -- * Nonce
  , Nonce
  , toNonce

  -- * Encryption/decryption
  , create
  , open
  ) where

import NaCl.Secretbox (Key, Nonce, open, toKey, toNonce)
import Data.ByteArray (ByteArray, ByteArrayAccess)

import qualified NaCl.Secretbox as NaCl.Secretbox


-- | Encrypt a message.
--
-- @
-- encrypted = Secretbox.create key nonce message
-- @
--
-- *   @key@ is the secret key used for encryption. See "Crypto.Key" for how
--     to get one.
--
-- *   @nonce@ is an extra noise that ensures that is required for security.
--     See "Crypto.Nonce" for how to work with it.
--
-- *   @message@ is the data you are encrypting.
--
-- This function adds authentication data, so if anyone modifies the cyphertext,
-- 'open' will refuse to decrypt it.
create
  ::  ( ByteArrayAccess keyBytes, ByteArrayAccess nonceBytes
      , ByteArrayAccess ptBytes, ByteArray ctBytes
      )
  => Key keyBytes  -- ^ Secret key
  -> Nonce nonceBytes  -- ^ Nonce
  -> ptBytes -- ^ Plaintext message
  -> ctBytes
create = NaCl.Secretbox.create

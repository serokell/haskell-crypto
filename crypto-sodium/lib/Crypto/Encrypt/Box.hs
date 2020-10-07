-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}

-- ! This module merely re-exports definitions from the corresponding
-- ! module in NaCl and alters the Haddock to make it more specific
-- ! to crypto-sodium. So, the docs should be kept more-or-less in sync.

-- | Public-key authenticated encryption.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Encrypt.Box as Box
--
-- encrypted = Box.'create' pk sk nonce message
-- decrypted = Box.'open' pk sk nonce encrypted
-- @
--
-- A box is an abstraction from NaCl. One way to think about it
-- is to imagine that you are putting data into a box protected by
-- the receiver’s public key and signed by your private key. The
-- receive will then be able to 'open' it using their private key
-- and your public key.
--
-- Note that this means that you need to exchange your public keys
-- in advance. It might seem strange at first that the receiver
-- needs to know your public key too, but this is actually very important
-- as otherwise the receiver would not be able to have any guarantees
-- regarding the source or the integrity of the data.
module Crypto.Encrypt.Box
  (
  -- * Keys
    PublicKey
  , toPublicKey
  , SecretKey
  , toSecretKey
  , keypair

  -- * Nonce
  , Nonce
  , toNonce

  -- * Encryption/decryption
  , create
  , open
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import NaCl.Box (Nonce, PublicKey, SecretKey, keypair, open, toNonce, toPublicKey, toSecretKey)

import qualified NaCl.Box as NaCl.Box


-- | Encrypt a message.
--
-- @
-- encrypted = Box.create pk sk nonce message
-- @
--
-- *   @pk@ is the receiver’s public key, used for encryption.
--     @sk@ is the sender’s secret key, used for authentication.
--
--     These are generated using 'keypair' and are supposed to be exchanged
--     in advance. Both parties need to know their own secret key and the other’s
--     public key.
--
-- *   @nonce@ is an extra noise that ensures that is required for security.
--     See "Crypto.Nonce" for how to work with it.
--
-- *   @message@ is the data you are encrypting.
--
-- This function adds authentication data, so if anyone modifies the cyphertext,
-- 'open' will refuse to decrypt it.
create
  ::  ( ByteArrayAccess pkBytes, ByteArrayAccess skBytes
      , ByteArrayAccess nonceBytes
      , ByteArrayAccess ptBytes, ByteArray ctBytes
      )
  => PublicKey pkBytes  -- ^ Receiver’s public key
  -> SecretKey skBytes  -- ^ Sender’s secret key
  -> Nonce nonceBytes  -- ^ Nonce
  -> ptBytes -- ^ Plaintext message
  -> ctBytes
create = NaCl.Box.create

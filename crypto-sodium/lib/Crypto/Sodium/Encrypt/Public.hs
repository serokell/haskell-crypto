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
-- import qualified Crypto.Sodium.Encrypt.Public as Public
--
-- encrypted = Public.'encrypt' pk sk nonce message
-- decrypted = Public.'decrypt' pk sk nonce encrypted
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
module Crypto.Sodium.Encrypt.Public
  (
  -- * Keys
    PublicKey
  , toPublicKey
  , SecretKey
  , toSecretKey
  , keypair
  , keypairFromSeed
  , unsafeKeypairFromSeed

  -- * Nonce
  , Nonce
  , toNonce

  -- * Encryption/decryption
  , encrypt
  , decrypt
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess, ScrubbedBytes, withByteArray)
import Data.ByteArray.Sized as Sized (SizedByteArray, alloc, allocRet)
import Data.ByteString (ByteString)
import Data.Functor (void)
import Data.Proxy (Proxy(..))
import System.IO.Unsafe (unsafePerformIO)

import qualified Libsodium as Na

import NaCl.Box
  (Nonce, PublicKey, SecretKey, keypair, toNonce, toPublicKey, toSecretKey)
import qualified NaCl.Box as NaCl.Box


-- | Encrypt a message.
--
-- @
-- encrypted = Public.encrypt pk sk nonce message
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
--     See "Crypto.Sodium.Nonce" for how to work with it.
--
-- *   @message@ is the data you are encrypting.
--
-- This function adds authentication data, so if anyone modifies the cyphertext,
-- 'decrypt' will refuse to decrypt it.
encrypt
  ::  ( ByteArrayAccess pkBytes, ByteArrayAccess skBytes
      , ByteArrayAccess nonceBytes
      , ByteArrayAccess ptBytes, ByteArray ctBytes
      )
  => PublicKey pkBytes  -- ^ Receiver’s public key
  -> SecretKey skBytes  -- ^ Sender’s secret key
  -> Nonce nonceBytes  -- ^ Nonce
  -> ptBytes -- ^ Plaintext message
  -> ctBytes
encrypt = NaCl.Box.create


-- | Decrypt a message.
--
-- @
-- decrypted = Public.decrypt sk pk nonce encrypted
-- @
--
-- * @sk@ is the receiver’s secret key, used for decription.
-- * @pk@ is the sender’s public key, used for authentication.
-- * @nonce@ is the same that was used for encryption.
-- * @encrypted@ is the output of 'encrypt'.
--
-- This function will return @Nothing@ if the encrypted message was tampered
-- with after it was encrypted.
decrypt
  ::  ( ByteArrayAccess skBytes, ByteArrayAccess pkBytes
      , ByteArrayAccess nonceBytes
      , ByteArray ptBytes, ByteArrayAccess ctBytes
      )
  => SecretKey skBytes  -- ^ Receiver’s secret key
  -> PublicKey pkBytes  -- ^ Sender’s public key
  -> Nonce nonceBytes  -- ^ Nonce
  -> ctBytes -- ^ Encrypted message (cyphertext)
  -> Maybe ptBytes
decrypt = NaCl.Box.open


-- | Seed for deterministically generating a keypair.
--
-- In accordance with Libsodium's documentation, the seed must be of size
-- @Na.CRYPTO_BOX_SEEDBYTES@.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type Seed a = SizedByteArray Na.CRYPTO_BOX_SEEDBYTES a


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
    void $ Na.crypto_box_seed_keypair pkPtr skPtr sdPtr

-- | Generate a new 'SecretKey' together with its 'PublicKey' from a given seed,
-- in a pure context.
unsafeKeypairFromSeed
  :: ByteArrayAccess seed
  => Seed seed
  -> (PublicKey ByteString, SecretKey ScrubbedBytes)
unsafeKeypairFromSeed = unsafePerformIO . keypairFromSeed

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Public-key authenticated encryption.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified NaCl.Box as Box
--
-- encrypted = Box.'create' pk sk nonce message
-- decrypted = Box.'open' pk sk nonce encrypted
-- @
--
-- This is @crypto_box_*@ from NaCl.
module NaCl.Box
  ( PublicKey
  , toPublicKey
  , SecretKey
  , toSecretKey
  , keypair

  , Nonce
  , toNonce

  , create
  , open
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import System.IO.Unsafe (unsafeDupablePerformIO)

import NaCl.Box.Internal (Nonce, PublicKey, SecretKey, keypair, toNonce, toPublicKey, toSecretKey)

import qualified NaCl.Box.Internal as I


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
-- *   @nonce@ is an extra noise that ensures that if you encrypt the same
--     message with the same key multiple times, you will get different ciphertexts,
--     which is required for
--     <https://en.wikipedia.org/wiki/Semantic_security semantic security>.
--     There are two standard ways of getting it:
--
--     1. /Use a counter/. In this case you keep a counter of encrypted messages,
--     which means that the nonce will be new for each new message.
--
--     2. /Random/. You generate a random nonce every time you encrypt a message.
--     Since the nonce is large enough, the chances of you using the same
--     nonce twice are negligible. For useful helpers, see @Crypto.Random@,
--     in <https://hackage.haskell.org/package/crypto-sodium crypto-sodium>.
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
create pk sk nonce msg =
  -- This IO is safe, because it is pure.
  unsafeDupablePerformIO $ I.create pk sk nonce msg


-- | Decrypt a message.
--
-- @
-- decrypted = Box.open sk pk nonce encrypted
-- @
--
-- * @sk@ is the receiver’s secret key, used for description.
-- * @pk@ is the sender’s public key, used for authentication.
-- * @nonce@ is the same that was used for encryption.
-- * @encrypted@ is the output of 'create'.
--
-- This function will return @Nothing@ if the encrypted message was tampered
-- with after it was encrypted.
open
  ::  ( ByteArrayAccess skBytes, ByteArrayAccess pkBytes
      , ByteArrayAccess nonceBytes
      , ByteArray ptBytes, ByteArrayAccess ctBytes
      )
  => SecretKey skBytes  -- ^ Receiver’s secret key
  -> PublicKey pkBytes  -- ^ Sender’s public key
  -> Nonce nonceBytes  -- ^ Nonce
  -> ctBytes -- ^ Encrypted message (cyphertext)
  -> Maybe ptBytes
open sk pk nonce ct =
  -- This IO is safe, because it is pure.
  unsafeDupablePerformIO $ I.open sk pk nonce ct

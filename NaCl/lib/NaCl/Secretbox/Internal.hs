-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internals of @crypto_secretbox@.
module NaCl.Secretbox.Internal
  ( Key
  , toKey

  , Nonce
  , toNonce

  , create
  , open
  ) where

import Prelude hiding (length)

import Data.ByteArray (ByteArray, ByteArrayAccess, allocRet, length, withByteArray)
import Data.ByteArray.Sized (SizedByteArray, sizedByteArray)

import qualified Libsodium as Na


-- | Encryption key that can be used for Secretbox.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@, but, since this
-- is a secret key, it is better to use @ScrubbedBytes@.
type Key a = SizedByteArray Na.CRYPTO_SECRETBOX_KEYBYTES a

-- | Make a 'Key' from an arbitrary byte array.
--
-- This function returns @Just@ if and only if the byte array has
-- the right length to be used as a key with a Secretbox.
toKey :: ByteArrayAccess ba => ba -> Maybe (Key ba)
toKey = sizedByteArray


-- | Nonce that can be used for Secretbox.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type Nonce a = SizedByteArray Na.CRYPTO_SECRETBOX_NONCEBYTES a

-- | Make a 'Nonce' from an arbitrary byte array.
--
-- This function returns @Just@ if and only if the byte array has
-- the right length to be used as a nonce with a Secretbox.
toNonce :: ByteArrayAccess ba => ba -> Maybe (Nonce ba)
toNonce = sizedByteArray


-- | Encrypt a message.
create
  ::  ( ByteArrayAccess key, ByteArrayAccess nonce
      , ByteArrayAccess pt, ByteArray ct
      )
  => Key key  -- ^ Secret key
  -> Nonce nonce  -- ^ Nonce
  -> pt -- ^ Plaintext message
  -> IO ct
create key nonce msg = do
    (_ret, ct) <-
      allocRet clen $ \ctPtr ->
      withByteArray key $ \keyPtr ->
      withByteArray nonce $ \noncePtr ->
      withByteArray msg $ \msgPtr -> do
        -- TODO: Maybe, reimplement this without _easy, to stay closer
        -- to the original NaCl.
        Na.crypto_secretbox_easy ctPtr
          msgPtr (fromIntegral $ length msg)
          noncePtr
          keyPtr
    -- _ret can be only 0, so we don’t check it
    pure ct
  where
    clen :: Int
    clen = fromIntegral Na.crypto_secretbox_macbytes + length msg


-- | Decrypt a message.
open
  ::  ( ByteArrayAccess key, ByteArrayAccess nonce
      , ByteArray pt, ByteArrayAccess ct
      )
  => Key key  -- ^ Secret key
  -> Nonce nonce  -- ^ Nonce
  -> ct -- ^ Cyphertext
  -> IO (Maybe pt)
open key nonce ct = do
    (ret, msg) <-
      allocRet mlen $ \msgPtr ->
      withByteArray key $ \keyPtr ->
      withByteArray nonce $ \noncePtr ->
      withByteArray ct $ \ctPtr -> do
        -- TODO: Maybe, reimplement this without _easy, to stay closer
        -- to the original NaCl.
        Na.crypto_secretbox_open_easy msgPtr
          ctPtr (fromIntegral $ length ct)
          noncePtr
          keyPtr
    if ret == 0 then
      pure $ Just msg
    else
      pure Nothing
  where
    mlen :: Int
    mlen = length ct - fromIntegral Na.crypto_secretbox_macbytes

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internals of @crypto_box@.
module NaCl.Box.Internal
  ( SecretKey
  , toSecretKey
  , PublicKey
  , toPublicKey
  , keypair

  , Nonce
  , toNonce

  , create
  , open
  ) where

import Prelude hiding (length)

import Data.ByteArray (ByteArray, ByteArrayAccess, ScrubbedBytes, allocRet, length, withByteArray)
import Data.ByteArray.Sized (SizedByteArray, sizedByteArray)
import Data.ByteString (ByteString)
import Data.Functor (void)
import Data.Proxy (Proxy (Proxy))

import qualified Data.ByteArray.Sized as Sized (alloc, allocRet)
import qualified Libsodium as Na


-- | Secret key that can be used for Box.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@, but, since this
-- is a secret key, it is better to use @ScrubbedBytes@.
type SecretKey a = SizedByteArray Na.CRYPTO_BOX_SECRETKEYBYTES a

-- | Convert bytes to a secret key.
toSecretKey :: ByteArrayAccess bytes => bytes -> Maybe (SecretKey bytes)
toSecretKey = sizedByteArray

-- | Public key that can be used for Box.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type PublicKey a = SizedByteArray Na.CRYPTO_BOX_PUBLICKEYBYTES a

-- | Convert bytes to a public key.
toPublicKey :: ByteArrayAccess bytes => bytes -> Maybe (PublicKey bytes)
toPublicKey = sizedByteArray

-- | Generate a new 'SecretKey' together with its 'PublicKey'.
--
-- Note: this function is not thread-safe (since the underlying
-- C function is not thread-safe both in Sodium and in NaCl)!
-- Either make sure there are no concurrent calls or see
-- @Crypto.Init@ in
-- <https://hackage.haskell.org/package/crypto-sodium crypto-sodium>
-- to learn how to make this function thread-safe.
keypair :: IO (PublicKey ByteString, SecretKey ScrubbedBytes)
keypair = do
  (pk, sk) <-
    Sized.allocRet Proxy $ \skPtr ->
    Sized.alloc $ \pkPtr ->
    -- always returns 0, so we don’t check it
    void $ Na.crypto_box_keypair pkPtr skPtr
  pure (pk, sk)


-- | Nonce that can be used for Box.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type Nonce a = SizedByteArray Na.CRYPTO_BOX_NONCEBYTES a

-- | Make a 'Nonce' from an arbitrary byte array.
--
-- This function returns @Just@ if and only if the byte array has
-- the right length to be used as a nonce with a Box.
toNonce :: ByteArrayAccess ba => ba -> Maybe (Nonce ba)
toNonce = sizedByteArray


-- | Encrypt a message.
create
  ::  ( ByteArrayAccess pkBytes, ByteArrayAccess skBytes
      , ByteArrayAccess nonce
      , ByteArrayAccess pt, ByteArray ct
      )
  => PublicKey pkBytes  -- ^ Receiver’s public key
  -> SecretKey skBytes  -- ^ Sender’s secret key
  -> Nonce nonce  -- ^ Nonce
  -> pt -- ^ Plaintext message
  -> IO ct
create pk sk nonce msg = do
    (_ret, ct) <-
      allocRet clen $ \ctPtr ->
      withByteArray pk $ \pkPtr ->
      withByteArray sk $ \skPtr ->
      withByteArray nonce $ \noncePtr ->
      withByteArray msg $ \msgPtr -> do
        -- TODO: Maybe, reimplement this without _easy, to stay closer
        -- to the original NaCl.
        Na.crypto_box_easy ctPtr
          msgPtr (fromIntegral $ length msg)
          noncePtr
          pkPtr skPtr
    -- _ret can be only 0, so we don’t check it
    -- TODO: Actually, it looks like this function can fail and return
    -- a -1, even though this is not documented :/.
    pure ct
  where
    clen :: Int
    clen = fromIntegral Na.crypto_box_macbytes + length msg


-- | Decrypt a message.
open
  ::  ( ByteArrayAccess skBytes, ByteArrayAccess pkBytes
      , ByteArrayAccess nonce
      , ByteArray pt, ByteArrayAccess ct
      )
  => SecretKey skBytes  -- ^ Receiver’s secret key
  -> PublicKey pkBytes  -- ^ Sender’s public key
  -> Nonce nonce  -- ^ Nonce
  -> ct -- ^ Cyphertext
  -> IO (Maybe pt)
open sk pk nonce ct = do
    (ret, msg) <-
      allocRet mlen $ \msgPtr ->
      withByteArray sk $ \skPtr ->
      withByteArray pk $ \pkPtr ->
      withByteArray nonce $ \noncePtr ->
      withByteArray ct $ \ctPtr -> do
        -- TODO: Maybe, reimplement this without _easy, to stay closer
        -- to the original NaCl.
        Na.crypto_box_open_easy msgPtr
          ctPtr (fromIntegral $ length ct)
          noncePtr
          pkPtr skPtr
    if ret == 0 then
      pure $ Just msg
    else
      pure Nothing
  where
    mlen :: Int
    mlen = length ct - fromIntegral Na.crypto_box_macbytes

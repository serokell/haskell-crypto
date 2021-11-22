-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internals of @crypto_sign@.
module NaCl.Sign.Internal
  ( SecretKey
  , toSecretKey
  , PublicKey
  , toPublicKey
  , keypair

  , create
  , open
  ) where

import Prelude hiding (length)

import Data.ByteArray (ByteArray, ByteArrayAccess, ScrubbedBytes, allocRet, length, withByteArray)
import Data.ByteArray.Sized (SizedByteArray, sizedByteArray)
import Data.ByteString (ByteString)
import Data.Functor (void)
import Data.Proxy (Proxy (Proxy))
import Foreign.Ptr (nullPtr)

import qualified Data.ByteArray.Sized as Sized (alloc, allocRet)
import qualified Libsodium as Na


-- | Secret key that can be used for creating a signature.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@, but, since this
-- is a secret key, it is better to use @ScrubbedBytes@.
type SecretKey a = SizedByteArray Na.CRYPTO_SIGN_SECRETKEYBYTES a

-- | Convert bytes to a secret key.
toSecretKey :: ByteArrayAccess bytes => bytes -> Maybe (SecretKey bytes)
toSecretKey = sizedByteArray

-- | Public key that can be used for verifyiing a signature.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type PublicKey a = SizedByteArray Na.CRYPTO_SIGN_PUBLICKEYBYTES a

-- | Convert bytes to a public key.
toPublicKey :: ByteArrayAccess bytes => bytes -> Maybe (PublicKey bytes)
toPublicKey = sizedByteArray

-- | Generate a new 'SecretKey' together with its 'PublicKey'.
--
-- Note: this function is not thread-safe (since the underlying
-- C function is not thread-safe both in Sodium and in NaCl)!
-- Either make sure there are no concurrent calls or see
-- @Crypto.Sodium.Init@ in
-- <https://hackage.haskell.org/package/crypto-sodium crypto-sodium>
-- to learn how to make this function thread-safe.
keypair :: IO (PublicKey ByteString, SecretKey ScrubbedBytes)
keypair = do
  (pk, sk) <-
    Sized.allocRet Proxy $ \skPtr ->
    Sized.alloc $ \pkPtr ->
    -- always returns 0, so we don’t check it
    void $ Na.crypto_sign_keypair pkPtr skPtr
  pure (pk, sk)


-- | Sign a message.
create
  ::  ( ByteArrayAccess skBytes
      , ByteArrayAccess pt, ByteArray ct
      )
  => SecretKey skBytes  -- ^ Signer’s secret key
  -> pt  -- ^ Message to sign
  -> IO ct
create sk msg = do
    (_ret, ct) <-
      allocRet clen $ \ctPtr ->
      withByteArray sk $ \skPtr ->
      withByteArray msg $ \msgPtr -> do
        Na.crypto_sign ctPtr nullPtr
          msgPtr (fromIntegral $ length msg)
          skPtr
    -- _ret can be only 0, so we don’t check it
    -- TODO: Actually, it looks like this function can fail and return
    -- a -1, even though this is not documented :/.
    pure ct
  where
    clen :: Int
    clen = fromIntegral Na.crypto_sign_bytes + length msg


-- | Verify the signature of a signed message.
open
  ::  ( ByteArrayAccess pkBytes
      , ByteArray pt, ByteArrayAccess ct
      )
  => PublicKey pkBytes  -- ^ Signer’s public key
  -> ct  -- ^ Signed message
  -> IO (Maybe pt)
open pk ct = do
    (ret, msg) <-
      allocRet mlen $ \msgPtr ->
      withByteArray pk $ \pkPtr ->
      withByteArray ct $ \ctPtr -> do
        Na.crypto_sign_open msgPtr nullPtr
          ctPtr (fromIntegral $ length ct)
          pkPtr
    if ret == 0 then
      pure $ Just msg
    else
      pure Nothing
  where
    mlen :: Int
    mlen = length ct - fromIntegral Na.crypto_sign_bytes

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internals of @crypto_hash@.
module NaCl.Hash.Internal
  ( HashSha256
  , sha256

  , HashSha512
  , sha512
  ) where

import Prelude hiding (length)

import Data.ByteArray (ByteArray, ByteArrayAccess, length, withByteArray)
import Data.ByteArray.Sized (SizedByteArray, allocRet)
import Data.Proxy (Proxy (Proxy))

import qualified Libsodium as Na


-- | Hash returned by 'sha256'.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type HashSha256 a = SizedByteArray Na.CRYPTO_HASH_SHA256_BYTES a

-- | Hash a message using SHA-256.
sha256
  ::  ( ByteArrayAccess pt
      , ByteArray hashBytes
      )
  => pt  -- ^ Message to hash
  -> IO (HashSha256 hashBytes)
sha256 msg = do
    (_ret, ct) <-
      allocRet (Proxy :: Proxy Na.CRYPTO_HASH_SHA256_BYTES) $ \hashPtr ->
      withByteArray msg $ \msgPtr -> do
        Na.crypto_hash_sha256 hashPtr
          msgPtr (fromIntegral $ length msg)
    -- _ret can be only 0, so we don’t check it
    pure ct


-- | Hash returned by 'sha512'.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type HashSha512 a = SizedByteArray Na.CRYPTO_HASH_SHA512_BYTES a

-- | Hash a message using SHA-512.
sha512
  ::  ( ByteArrayAccess pt
      , ByteArray hashBytes
      )
  => pt  -- ^ Message to hash
  -> IO (HashSha512 hashBytes)
sha512 msg = do
    (_ret, ct) <-
      allocRet (Proxy :: Proxy Na.CRYPTO_HASH_SHA512_BYTES) $ \hashPtr ->
      withByteArray msg $ \msgPtr -> do
        Na.crypto_hash_sha512 hashPtr
          msgPtr (fromIntegral $ length msg)
    -- _ret can be only 0, so we don’t check it
    pure ct

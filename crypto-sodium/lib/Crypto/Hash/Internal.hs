-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE ExplicitNamespaces, TypeOperators, TypeFamilies #-}
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- | Internals of @crypto_generichash@.
module Crypto.Hash.Internal
  ( HashBlake2b
  , blake2b
  ) where

import Prelude hiding (length)

import Data.ByteArray (ByteArray, ByteArrayAccess, length, withByteArray)
import Data.ByteArray.Sized (SizedByteArray, allocRet)
import Data.Proxy (Proxy (Proxy))
import Foreign.Ptr (nullPtr)
import GHC.TypeNats (KnownNat, natVal, type (<=))

import qualified Libsodium as Na

-- | Hash returned by 'blake2b'.
--
-- This type is parametrised by hash size in bytes and the actual data type
-- that contains bytes. This can be, for example, a @ByteString@.
--
-- Length must be between 16 and 64 bytes.
type HashBlake2b len a = SizedByteArray len a

-- | Hash a message using BLAKE2b.
blake2b
  ::  forall pt key hashBytes len.
      ( ByteArrayAccess pt
      , ByteArrayAccess key
      , ByteArray hashBytes
      , KnownNat len
      , Na.CRYPTO_GENERICHASH_BYTES_MIN <= len
      , len <= Na.CRYPTO_GENERICHASH_BYTES_MAX
      )
  => Maybe key -- ^ Hash key
  -> pt  -- ^ Message to hash
  -> IO (HashBlake2b len hashBytes)
blake2b key msg = do
  (_ret, hash) <-
    allocRet @len Proxy $ \hashPtr ->
    withByteArray msg $ \msgPtr ->
    withKey $ \keyPtr ->
      Na.crypto_generichash_blake2b hashPtr (fromIntegral $ natVal @len Proxy)
        msgPtr (fromIntegral $ length msg)
        keyPtr keyLen
  -- _ret can be only 0, so we don’t check it
  pure hash
  where
    (withKey, keyLen)
      | Just key' <- key = (withByteArray key', fromIntegral $ length key')
      | otherwise = (($ nullPtr), 0)

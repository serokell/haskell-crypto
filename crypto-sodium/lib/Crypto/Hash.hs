-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE ExplicitNamespaces, TypeOperators, TypeFamilies #-}

-- | Hashing.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Hash as Hash
--
-- hash_blake2b256_keyed = Hash.'blake2b' @32 message (Just key)
-- hash_blake2b256 = Hash.'blake2b' @32 message Nothing
-- hash_blake2b512 = Hash.'blake2b' @64 message Nothing
-- @
--
-- This is @crypto_generichash_*@ from NaCl.
module Crypto.Hash
  ( I.HashBlake2b
  , blake2b
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import GHC.TypeNats (KnownNat, type (<=))
import System.IO.Unsafe (unsafePerformIO)

import qualified Crypto.Hash.Internal as I
import qualified Libsodium as Na

-- | Hash a message using BLAKE2b.
--
-- @
-- hash128 = Hash.'blake2b' @16 Nothing message
-- hash256 = Hash.'blake2b' @32 Nothing message
-- hash512 = Hash.'blake2b' @64 Nothing message
-- hash128_keyed = Hash.'blake2b' @16 (Just key) message
-- hash256_keyed = Hash.'blake2b' @32 (Just key) message
-- hash512_keyed = Hash.'blake2b' @64 (Just key) message
-- @
--
-- *   @key@ is the optional BLAKE2b key.
-- *   @message@ is the data you are hashing.
blake2b
  ::  forall len hashBytes pt key.
      ( ByteArrayAccess pt
      , ByteArrayAccess key
      , ByteArray hashBytes
      , KnownNat len
      , Na.CRYPTO_GENERICHASH_BYTES_MIN <= len
      , len <= Na.CRYPTO_GENERICHASH_BYTES_MAX
      )
  => Maybe key -- ^ Hash key
  -> pt  -- ^ Message to hash
  -> I.HashBlake2b len hashBytes
blake2b mbkey msg = unsafePerformIO $ I.blake2b mbkey msg

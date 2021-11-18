-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE ExplicitNamespaces, TypeOperators, TypeFamilies #-}

-- | Hashing
module Crypto.Hash
  ( I.HashBlake2b
  , blake2b
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import GHC.TypeNats (KnownNat, type (<=))
import System.IO.Unsafe (unsafePerformIO)

import qualified Crypto.Hash.Internal as I
import qualified Libsodium as Na

-- | Hash a message using BLAKE2b
blake2b
  ::  forall pt key hashBytes len.
      ( ByteArrayAccess pt
      , ByteArrayAccess key
      , ByteArray hashBytes
      , KnownNat len
      , Na.CRYPTO_GENERICHASH_BYTES_MIN <= len
      , len <= Na.CRYPTO_GENERICHASH_BYTES_MAX
      )
  => pt  -- ^ Message to hash
  -> Maybe key -- ^ Hash key
  -> Maybe (I.HashBlake2b len hashBytes)
blake2b msg mbkey = unsafePerformIO $ I.blake2b msg mbkey

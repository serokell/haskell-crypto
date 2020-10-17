-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Hashing.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified NaCl.Hash as Hash
--
-- hash_sha256 = Hash.'sha256' message
-- hash_sha512 = Hash.'sha512' signed
-- @
--
-- This is @crypto_hash_*@ from NaCl.
module NaCl.Hash
  ( HashSha256
  , sha256

  , HashSha512
  , sha512
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import System.IO.Unsafe (unsafePerformIO)

import NaCl.Hash.Internal (HashSha256, HashSha512)

import qualified NaCl.Hash.Internal as I


-- | Hash a message using SHA-256.
--
-- @
-- hash = Hash.'sha256' message
-- @
--
-- *   @message@ is the data you are hashing.
sha256
  ::  ( ByteArrayAccess pt
      , ByteArray hashBytes
      )
  => pt  -- ^ Message to hash
  -> HashSha256 hashBytes
sha256 msg =
  -- This IO is safe, because it is pure.
  unsafePerformIO $ I.sha256 msg

-- | Hash a message using SHA-512.
--
-- @
-- hash = Hash.'sha512' message
-- @
--
-- *   @message@ is the data you are hashing.
sha512
  ::  ( ByteArrayAccess pt
      , ByteArray hashBytes
      )
  => pt  -- ^ Message to hash
  -> HashSha512 hashBytes
sha512 msg =
  -- This IO is safe, because it is pure.
  unsafePerformIO $ I.sha512 msg

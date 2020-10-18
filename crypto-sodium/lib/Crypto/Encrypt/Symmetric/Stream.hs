-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}

-- | Symmetric authenticated encryption for streams.
--
-- This module provides generic types for Sodium-based streaming
-- encryption. It does not provide any functionality itself.
--
-- There are separate packages that actually implement this functionality
-- for specific streaming libraries:
--
-- * @crypto-sodium-streamly@ for @streamly@ streams.
module Crypto.Encrypt.Symmetric.Stream
  (
  -- * Keys
    Key
  , toKey
  ) where

import Data.ByteArray (ByteArrayAccess)
import Data.ByteArray.Sized (SizedByteArray, sizedByteArray)

import qualified Libsodium as Na


-- | Encryption key that can be used for streaming symmetric encryption.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@, but, since this
-- is a secret key, it is better to use @ScrubbedBytes@.
type Key a = SizedByteArray Na.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES a

-- | Make a 'Key' from an arbitrary byte array.
--
-- This function returns @Just@ if and only if the byte array has
-- the right length to be used as a key with a streaming symmetric encryption.
toKey :: ByteArrayAccess ba => ba -> Maybe (Key ba)
toKey = sizedByteArray

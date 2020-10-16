{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- ! This module intentionally does not contain extensive documentation
-- ! as a measure for discouraging its use.

-- | Unauthenticated streaming encryption.
--
-- __Note:__ Unauthenticated encryption is __insecure__ in general.
-- Only use the functions from this modules if you know exactly what you are doing.
-- We only provide this module for compatibility with NaCl.
-- @
--
-- This is @crypto_box_*@ from NaCl.
module NaCl.Stream
  ( Key
  , toKey

  , Nonce
  , toNonce

  , MaxStreamSize
  , generate

  , xor
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import Data.ByteArray.Sized (ByteArrayN)
import GHC.TypeLits (type (<=))
import System.IO.Unsafe (unsafeDupablePerformIO)

import NaCl.Stream.Internal (Nonce, Key, MaxStreamSize, toNonce, toKey)

import qualified NaCl.Stream.Internal as I


-- | Generate a stream of pseudo-random bytes.
generate
  ::  forall key nonce n ct.
      ( ByteArrayAccess key, ByteArrayAccess nonce
      , ByteArrayN n ct
      , n <= MaxStreamSize
      )
  => Key key  -- ^ Secret key
  -> Nonce nonce  -- ^ Nonce
  -> ct
generate key nonce =
  -- This IO is safe, because it is pure.
  unsafeDupablePerformIO $ I.generate key nonce


-- | Encrypt/decrypt a message.
xor
  ::  ( ByteArrayAccess key, ByteArrayAccess nonce
      , ByteArrayAccess pt, ByteArray ct
      )
  => Key key  -- ^ Secret key
  -> Nonce nonce  -- ^ Nonce
  -> pt -- ^ Input (plain/cipher) text
  -> ct
xor key nonce msg =
  -- This IO is safe, because it is pure.
  unsafeDupablePerformIO $ I.xor key nonce msg

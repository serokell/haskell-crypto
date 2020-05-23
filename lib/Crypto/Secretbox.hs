-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

module Crypto.Secretbox
  ( Key
  , toKey

  , Nonce
  , toNonce

  , create
  , open
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Crypto.Secretbox.Internal (Key, Nonce, toKey, toNonce)

import qualified Crypto.Secretbox.Internal as I


-- | Encrypt a message.
--
-- Note: This function is similar to the C++ API of NaCl.
-- That is, unlike @crypto_secretbox@ from the C API of NaCl,
-- it does not require any special padding.
create
  ::  ( ByteArrayAccess key, ByteArrayAccess nonce
      , ByteArrayAccess pt, ByteArray ct
      )
  => Key key  -- ^ Secret key
  -> Nonce nonce  -- ^ Nonce
  -> pt -- ^ Plaintext message
  -> ct
create key nonce msg = unsafeDupablePerformIO $ I.create key nonce msg


-- | Decrypt a message.
--
-- Note: This function is similar to the C++ API of NaCl.
-- That is, unlike @crypto_secretbox_open@ from the C API of NaCl,
-- it does not require any special padding.
open
  ::  ( ByteArrayAccess key, ByteArrayAccess nonce
      , ByteArray pt, ByteArrayAccess ct
      )
  => Key key  -- ^ Secret key
  -> Nonce nonce  -- ^ Nonce
  -> ct -- ^ Cyphertext
  -> Maybe pt
open key nonce ct = unsafeDupablePerformIO $ I.open key nonce ct
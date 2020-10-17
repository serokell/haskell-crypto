-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}

-- ! This module has the same API as the corresponding strict module.
-- ! So, the docs should be kept more-or-less in sync.

-- | Message authentication codes for lazy @ByteString@.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Mac.Lazy as Mac
--
-- authenticator = Mac.'create' key message
-- if Secretbox.'verify' key message authenticator
-- then {- Ok! -}
-- else {- Fail! -}
-- @
--
-- A message authenticator is like a signature, except that the key is
-- secret. It can be used when it is not necessary to encrypt the data,
-- but its integrity needs to be guaranteed.
--
-- Functions in this module are similar to the ones in "Crypto.Mac",
-- but work with /lazy/ @ByteString@s, so they are suitable for stream-like
-- processing of data, as they consume the byte string in chunks.
module Crypto.Mac.Lazy
  (
  -- * Keys
    Key
  , toKey

  -- * Authenticator tags
  , Authenticator
  , toAuthenticator

  -- * Authentication
  , create
  , verify
  ) where

import Control.Monad (forM_)
import Data.ByteArray (ByteArray, ByteArrayAccess)
import Data.ByteString.Lazy (ByteString)
import NaCl.Auth (Authenticator, Key, toAuthenticator, toKey)
import System.IO.Unsafe (unsafePerformIO)

import qualified Data.ByteString.Lazy as BSL

import Crypto.Mac.Stream (createStreaming, verifyStreaming)


-- | Create an authenticator for a message.
--
-- @
-- authenticator = Mac.create key message
-- @
--
-- *   @key@ is the secret key used for authentication. See "Crypto.Key" for how
--     to get one.
--
-- *   @message@ is the data you are authenticating.
--
-- This function produces authentication data, so if anyone modifies the message,
-- @verify@ will return @False@.
create
  ::  ( ByteArray authBytes
      , ByteArrayAccess keyBytes
      )
  => Key keyBytes  -- ^ Secret key.
  -> ByteString  -- ^ Message to authenticate.
  -> Authenticator authBytes
create key msg = unsafePerformIO $
  -- Our “stream” is actually a pure list, so the computation is pure
  createStreaming key (forM_ $ BSL.toChunks msg)


-- | Verify an authenticator for a message.
--
-- @
-- isValid = Auth.verify key message authenticator
-- @
--
-- * @key@ and @message@ are the same as when creating the authenticator.
-- * @authenticator@ is the output of 'create'.
--
-- This function will return @False@ if the message is not exactly the same
-- as it was when the authenticator was created.
verify
  ::  ( ByteArrayAccess authBytes
      , ByteArrayAccess keyBytes
      )
  => Key keyBytes  -- ^ Secret key.
  -> ByteString  -- ^ Authenticated message.
  -> Authenticator authBytes  -- ^ Authenticator tag.
  -> Bool
verify key msg auth = unsafePerformIO $
  -- Our “stream” is actually a pure list, so the computation is pure
  verifyStreaming key (forM_ $ BSL.toChunks msg) auth

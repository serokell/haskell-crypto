-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}

-- ! This module merely re-exports definitions from the corresponding
-- ! module in NaCl and alters the Haddock to make it more specific
-- ! to crypto-sodium. So, the docs should be kept more-or-less in sync.

-- | Message authentication codes.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Mac as Mac
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
module Crypto.Mac
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

import NaCl.Auth (Authenticator, Key, toAuthenticator, toKey, verify)
import Data.ByteArray (ByteArray, ByteArrayAccess)

import qualified NaCl.Auth as NaCl.Auth


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
      , ByteArrayAccess msg
      )
  => Key keyBytes  -- ^ Secret key.
  -> msg  -- ^ Message to authenticate.
  -> Authenticator authBytes
create = NaCl.Auth.create

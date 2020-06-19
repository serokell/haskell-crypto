-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}
{-# LANGUAGE TypeFamilies #-}

-- ! This module has the same API as the corresponding strict module.
-- ! So, the docs should be kept more-or-less in sync.

-- | Message authentication codes for @streamly@ streams.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Mac.Streamly as Mac
--
-- authenticator = Mac.'create' key messageStream
-- if Secretbox.'verify' key messageStream authenticator
-- then {- Ok! -}
-- else {- Fail! -}
-- @
--
-- A message authenticator is like a signature, except that the key is
-- secret. It can be used when it is not necessary to encrypt the data,
-- but its integrity needs to be guaranteed.
--
-- Functions in this module are similar to the ones in "Crypto.Mac",
-- but work with @streamly@ streams. See @streamly@ documentation for
-- how to convert other streams to @streamly@ streams or use
-- "Crypto.Mac.Stream" from @crypto-sodium@ to easily implement first-class
-- support for your favourite streaming library.
module Crypto.Mac.Streamly
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

import Control.Monad.IO.Class (MonadIO)
import Data.ByteArray (ByteArray, ByteArrayAccess)
import Crypto.Mac.Stream (Authenticator, Key, createStreaming, toAuthenticator, toKey, verifyStreaming)
import Streamly (SerialT)

import qualified Streamly.Prelude as S


-- | Create an authenticator for a message.
--
-- @
-- authenticator = Mac.create key message
-- @
--
-- *   @key@ is the secret key used for authentication. See "Crypto.Key" for how
--     to get one.
--
-- *   @messageStream@ is the data you are authenticating.
--
-- This function produces authentication data, so if anyone modifies the message,
-- @verify@ will return @False@.
create
  ::  ( ByteArray authBytes
      , ByteArrayAccess keyBytes
      , ByteArrayAccess msg
      , MonadIO m, m ~ IO
      )
  => Key keyBytes  -- ^ Secret key.
  -> SerialT m msg  -- ^ Message to authenticate.
  -> m (Authenticator authBytes)
create key stream = createStreaming key (flip S.mapM_ stream)

-- | Verify an authenticator for a message.
--
-- @
-- isValid = Auth.verify key message authenticator
-- @
--
-- * @key@ and @messageStream@ are the same as when creating the authenticator.
-- * @authenticator@ is the output of 'create'.
--
-- This function will return @False@ if the message is not exactly the same
-- as it was when the authenticator was created.
verify
  ::  ( ByteArrayAccess authBytes
      , ByteArrayAccess keyBytes
      , ByteArrayAccess msg
      , MonadIO m, m ~ IO
      )
  => Key keyBytes  -- ^ Secret key.
  -> SerialT m msg  -- ^ Authenticated message.
  -> Authenticator authBytes  -- ^ Authenticator tag.
  -> m Bool
verify key stream = verifyStreaming key (flip S.mapM_ stream)

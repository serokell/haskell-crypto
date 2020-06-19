-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}
{-# LANGUAGE TypeFamilies #-}

-- | Message authentication codes for streams.
--
-- This module provides ready-to-use functions that will help you to
-- work with streams efficiently, regardless of which specific streaming
-- library you are using. The only requirement is that it provides a
-- @mapM_@ for its stream type.
--
-- The @crypto-sodium-streamly@ package uses functions in this module
-- to provide support for working with @streamly@ streams.
module Crypto.Mac.Stream
  (
  -- * Keys
    Key
  , toKey

  -- * Authenticator tags
  , Authenticator
  , toAuthenticator

  -- * Authentication
  , createStreaming
  , verifyStreaming
  ) where

import Prelude hiding (length)

import Control.Monad.IO.Class (MonadIO)
import Data.ByteArray (ByteArray, ByteArrayAccess, Bytes, length, withByteArray)
import Data.ByteArray.Sized (alloc)
import Data.Functor (void)
import Foreign (alloca)
import NaCl.Auth (Authenticator, Key, toAuthenticator, toKey)

import qualified Libsodium as Na

import Crypto.Internal.Verify (verifyBytes32)


-- | Create an authenticator for a message.
--
-- @
-- authenticator = Mac.create key message
-- @
--
-- *   @key@ is the secret key used for authentication. See "Crypto.Key" for how
--     to get one.
--
-- *   @sForM_@ is the @forM_@ (equivalently, @flip mapM_@) function from the
--     streaming library, pre-applied to the stream.
--
-- This function produces authentication data, so if anyone modifies the message,
-- @verify@ will return @False@.
createStreaming
  ::  ( ByteArray authBytes
      , ByteArrayAccess keyBytes
      , ByteArrayAccess msg
      , MonadIO m, m ~ IO  -- TODO: unlift withByteArray
      )
  => Key keyBytes  -- ^ Secret key.
  -> ((msg -> m ()) -> m ())  -- ^ @mapM_@ pre-applied to the data stream
  -> m (Authenticator authBytes)
createStreaming key sForM_ = do
    auth <-
      alloc $ \authPtr ->
      withByteArray key $ \keyPtr ->
      alloca $ \statePtr -> do
        void $ Na.crypto_auth_hmacsha512256_init statePtr
          keyPtr (fromIntegral Na.crypto_auth_keybytes)
        sForM_ $ \chunk -> do
          withByteArray chunk $ \chunkPtr ->
            void $ Na.crypto_auth_hmacsha512256_update statePtr
              chunkPtr (fromIntegral $ length chunk)
        void $ Na.crypto_auth_hmacsha512256_final statePtr authPtr
    pure auth


-- | Verify an authenticator for a message.
--
-- @
-- isValid = Auth.verify key message authenticator
-- @
--
-- * @key@ and @sForM_@ are the same as when creating the authenticator.
--
-- * @authenticator@ is the output of 'create'.
--
-- This function will return @False@ if the message is not exactly the same
-- as it was when the authenticator was created.
verifyStreaming
  ::  ( ByteArrayAccess authBytes
      , ByteArrayAccess keyBytes
      , ByteArrayAccess msg
      , MonadIO m, m ~ IO  -- TODO: unlift withByteArray
      )
  => Key keyBytes  -- ^ Secret key.
  -> ((msg -> m ()) -> m ())  -- ^ @mapM_@ pre-applied to the data stream
  -> Authenticator authBytes  -- ^ Authenticator tag.
  -> m Bool
verifyStreaming key sForM_ auth =
    createStreaming @Bytes key sForM_ >>= verifyBytes32 auth

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internals of @crypto_auth@.
module NaCl.Auth.Internal
  ( Key
  , toKey

  , Authenticator
  , toAuthenticator

  , create
  , verify
  ) where

import Prelude hiding (length)

import Data.ByteArray (ByteArray, ByteArrayAccess, length, withByteArray)
import Data.ByteArray.Sized (SizedByteArray, allocRet, sizedByteArray)
import Data.Proxy (Proxy (Proxy))

import qualified Libsodium as Na


-- | Secret key that can be used for Sea authentication.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@, but, since this
-- is a secret key, it is better to use @ScrubbedBytes@.
type Key a = SizedByteArray Na.CRYPTO_AUTH_KEYBYTES a

-- | Make a 'Key' from an arbitrary byte array.
--
-- This function returns @Just@ if and only if the byte array has
-- the right length to be used as a key for authentication.
toKey :: ByteArrayAccess ba => ba -> Maybe (Key ba)
toKey = sizedByteArray


-- | A tag that confirms the authenticity of somde data.
type Authenticator a = SizedByteArray Na.CRYPTO_AUTH_BYTES a

-- | Convert raw bytes into an 'Authenticator'.
--
-- This function returns @Just@ if and only if the byte array has
-- the right length to be used as an authenticator.
toAuthenticator :: ByteArrayAccess ba => ba -> Maybe (Authenticator ba)
toAuthenticator = sizedByteArray


-- | Create an authenticator.
create
  ::  ( ByteArrayAccess keyBytes
      , ByteArrayAccess msg
      , ByteArray authBytes
      )
  => Key keyBytes  -- ^ Secret key.
  -> msg  -- ^ Message to authenticate.
  -> IO (Authenticator authBytes)
create key msg = do
    (_ret, auth) <-
      allocRet (Proxy @Na.CRYPTO_AUTH_BYTES) $ \authPtr ->
      withByteArray key $ \keyPtr ->
      withByteArray msg $ \msgPtr -> do
        Na.crypto_auth authPtr
          msgPtr (fromIntegral $ length msg)
          keyPtr
    -- _ret can be only 0, so we don’t check it
    pure auth


-- | Verify an authenticator.
verify
  ::  ( ByteArrayAccess keyBytes
      , ByteArrayAccess msg
      , ByteArrayAccess authBytes
      )
  => Key keyBytes  -- ^ Secret key.
  -> msg  -- ^ Authenticated message.
  -> Authenticator authBytes  -- ^ Authenticator tag.
  -> IO Bool
verify key msg auth = do
    ret <-
      withByteArray key $ \keyPtr ->
      withByteArray msg $ \msgPtr ->
      withByteArray auth $ \authPtr ->
        Na.crypto_auth_verify authPtr
          msgPtr (fromIntegral $ length msg)
          keyPtr
    pure $ ret == 0

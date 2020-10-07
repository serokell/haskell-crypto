-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Public-key signatures.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified NaCl.Sign as Sign
--
-- signed = Sign.'create' sk message
-- verified = Sign.'open' pk signed
-- @
--
-- This is @crypto_sign_*@ from NaCl.
module NaCl.Sign
  ( PublicKey
  , toPublicKey
  , SecretKey
  , toSecretKey
  , keypair

  , create
  , open
  ) where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import System.IO.Unsafe (unsafeDupablePerformIO)

import NaCl.Sign.Internal (PublicKey, SecretKey, keypair, toPublicKey, toSecretKey)

import qualified NaCl.Sign.Internal as I


-- | Sign a message.
--
-- @
-- signed = Sign.create sk message
-- @
--
-- *   @sk@ is the signer’s secret key, used for authentication.
--
--     This is generated using 'keypair' and the public part of the key
--     needs to be given to the verifying party in advance.
--
-- *   @message@ is the data you are signing.
--
-- This function will copy the message to a new location
-- and add a signature, so that 'open' will refuce to verify it.
create
  ::  ( ByteArrayAccess skBytes
      , ByteArrayAccess ptBytes, ByteArray ctBytes
      )
  => SecretKey skBytes  -- ^ Signer’s secret key
  -> ptBytes  -- ^ Message to sign
  -> ctBytes
create sk msg =
  -- This IO is safe, because it is pure.
  unsafeDupablePerformIO $ I.create sk msg


-- | Verify a signature.
--
-- @
-- verified = Sign.open pk signed
-- @
--
-- * @pk@ is the signer’s public key.
-- * @signed@ is the output of 'create'.
--
-- This function will return @Nothing@ if the signature on the message
-- is invalid.
open
  ::  ( ByteArrayAccess pkBytes
      , ByteArray ptBytes, ByteArrayAccess ctBytes
      )
  => PublicKey pkBytes  -- ^ Signer’s public key
  -> ctBytes -- ^ Signed message
  -> Maybe ptBytes
open pk ct =
  -- This IO is safe, because it is pure.
  unsafeDupablePerformIO $ I.open pk ct

{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Key derivation/generation internals.
module Crypto.Key.Internal
  ( Params (..)
  , DerivationSlip
  , derive
  , rederive

  , DerivationSlipData (..)
  , derivationSlipEncode
  , derivationSlipDecode
  ) where

import Control.Monad (when)
import Data.ByteArray (ByteArrayAccess)
import Data.ByteArray.Sized (ByteArrayN, sizedByteArray, unSizedByteArray)
import Data.ByteString (ByteString)
import Data.Serialize (Serialize (put, get), decode, encode)
import Data.Word (Word8)
import GHC.TypeLits (type (<=))

import qualified Libsodium as Na

import Crypto.Nonce (generate)
import Crypto.Pwhash.Internal (Algorithm (Argon2id_1_3), Params (..), Salt, pwhash)


-- | Opaque bytes that contain the salt and pwhash params.
type DerivationSlip = ByteString

-- | Data contained in a derivation slip.
--
-- This data type is used only internally within this module for
-- convenience. It is exported only for testing purposes.
--
-- Currently only one KDF is supported, so it is assumed implicitly,
-- however the actual binary encoding contains an identifier of the KDF
-- used (for forward-compatibility).
data DerivationSlipData = DerivationSlipData
  { params :: !Params
  , salt :: !(Salt ByteString)
  }
  deriving (Eq, Show)

instance Serialize DerivationSlipData where
  put (DerivationSlipData Params{opsLimit, memLimit} salt) = do
    put (1 :: Word8)  -- algorithm marker for forward-compatibility
    put opsLimit >> put memLimit
    put (unSizedByteArray salt)
  get = do
    tag <- get @Word8
    when (tag /= 1) $ fail "Wrong algorithm parameters encoding tag"
    params <- Params <$> get <*> get
    msalt <- sizedByteArray <$> get @ByteString
    case msalt of
      Nothing -> fail "Unexpected salt size"
      Just salt -> pure $ DerivationSlipData params salt


-- | Encode derivation slip data into bytes.
derivationSlipEncode :: DerivationSlipData -> DerivationSlip
derivationSlipEncode = encode

-- | Decode derivation slip data from bytes.
derivationSlipDecode :: DerivationSlip -> Maybe DerivationSlipData
derivationSlipDecode bytes = case decode bytes of
  Right slip -> Just slip
  Left _ -> Nothing


-- | Derive a key for the first time.
derive
  ::  ( ByteArrayAccess passwd
      , ByteArrayN n key
      , Na.CRYPTO_PWHASH_BYTES_MIN <= n, n <= Na.CRYPTO_PWHASH_BYTES_MAX
      )
  => Params
  -> passwd
  -> IO (Maybe (key, DerivationSlip))
derive params passwd = do
  salt <- generate
  mkey <- pwhash Argon2id_1_3 params passwd salt
  let slip = DerivationSlipData params salt
  pure $ fmap (, derivationSlipEncode slip) mkey

-- | Derive the same key form the same password again.
rederive
  ::  ( ByteArrayAccess passwd
      , ByteArrayN n key
      , Na.CRYPTO_PWHASH_BYTES_MIN <= n, n <= Na.CRYPTO_PWHASH_BYTES_MAX
      )
  => DerivationSlip
  -> passwd
  -> IO (Maybe key)
rederive slip passwd =
  case derivationSlipDecode slip of
    Nothing -> pure Nothing
    Just (DerivationSlipData{params, salt}) ->
      pwhash Argon2id_1_3 params passwd salt

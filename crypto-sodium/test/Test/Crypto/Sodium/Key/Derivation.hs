-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Tests for our cool slip-based KDF
module Test.Crypto.Sodium.Key.Derivation where

import Hedgehog (Gen, Property, (===), evalIO, forAll, property, tripping)

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import Data.ByteString (ByteString)
import Data.ByteArray.Sized (SizedByteArray)

import qualified Libsodium as Na

import qualified Test.Crypto.Sodium.Gen as G

import Crypto.Sodium.Key (Params (Params), derive, rederive)

import qualified Crypto.Sodium.Key.Internal as KI


genParams :: Gen Params
genParams = Params
  <$> G.integral
    (R.linear (fromIntegral Na.crypto_pwhash_opslimit_min) 10)
  <*> G.integral
    (R.linear (fromIntegral Na.crypto_pwhash_memlimit_min) (2 * 1024 * 1024))

genSlipData :: Gen KI.DerivationSlipData
genSlipData = KI.DerivationSlipData
  <$> genParams
  <*> G.nonce


hprop_slip_encode_decode :: Property
hprop_slip_encode_decode = property $ do
    slipData <- forAll $ genSlipData
    tripping slipData KI.derivationSlipEncode KI.derivationSlipDecode

hprop_derive_rederive :: Property
hprop_derive_rederive = property $ do
    params <- forAll $ genParams
    passwd <- forAll $ G.bytes (R.linear 0 100)
    Just (key, slip) <- evalIO $
      derive @(SizedByteArray 64 ByteString) params passwd
    rederive slip passwd === Just key

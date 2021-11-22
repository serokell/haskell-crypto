-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | “Integration” tests: using Sign with our helpers.
module Test.Crypto.Sodium.Sign where

import Hedgehog (Property, evalMaybe, forAll, property, tripping)
import Hedgehog.Internal.Property (forAllT)

import Control.Monad.IO.Class (liftIO)
import Data.ByteArray.Sized (sizedByteArray)
import Data.ByteString (ByteString)

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import qualified Libsodium as Na

import qualified Crypto.Sodium.Sign as Sign


seedSize :: R.Range Int
seedSize = R.singleton $ fromIntegral Na.crypto_sign_seedbytes


hprop_encode_decode_seed :: Property
hprop_encode_decode_seed = property $ do
    seed <- evalMaybe . sizedByteArray =<< forAll (G.bytes seedSize)
    (pk, sk) <- forAllT . liftIO $ Sign.keypairFromSeed seed
    msg <- forAll $ G.bytes (R.linear 0 1_000)
    tripping msg (encodeBs sk) (decodeBs pk)
  where
    -- We need to specify the type of the signed msg as it is polymorphic
    encodeBs sk msg = Sign.create sk msg :: ByteString
    decodeBs pk ct = Sign.open pk ct :: Maybe ByteString

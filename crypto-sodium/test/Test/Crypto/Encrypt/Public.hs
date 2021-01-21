-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | “Integration” tests: using Public with our helpers.
module Test.Crypto.Encrypt.Public where

import Hedgehog (Property, forAll, property, tripping)
import Hedgehog.Internal.Property (forAllT)

import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)

import qualified Libsodium as Na

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import qualified Crypto.Encrypt.Public as Public


nonceSize :: R.Range Int
nonceSize = R.singleton $ fromIntegral Na.crypto_box_noncebytes

seedSize :: R.Range Int
seedSize = R.singleton $ fromIntegral Na.crypto_box_seedbytes


hprop_encode_decode_seed :: Property
hprop_encode_decode_seed = property $ do
    seed1 <- forAll $ G.bytes seedSize
    seed2 <- forAll $ G.bytes seedSize
    (pkS, skS) <- forAllT . liftIO $ Public.keypairFromSeed seed1
    (pkR, skR) <- forAllT . liftIO $ Public.keypairFromSeed seed2
    nonceBytes <- forAll $ G.bytes nonceSize
    let Just nonce = Public.toNonce nonceBytes
    msg <- forAll $ G.bytes (R.linear 0 1_000)
    tripping msg (encodeBs pkR skS nonce) (decodeBs skR pkS nonce)
  where
    -- We need to specify the type of the cyphertext as it is polymorphic
    encodeBs pkR skS nonce msg = Public.encrypt pkR skS nonce msg :: ByteString
    decodeBs skR pkS nonce ct = Public.decrypt skR pkS nonce ct :: Maybe ByteString

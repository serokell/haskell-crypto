-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | “Integration” tests: using Symmetric with our helpers.
module Test.Crypto.Encrypt.Symmetric where

import Hedgehog (Property, forAll, property, tripping)
import Hedgehog.Internal.Property (forAllT)

import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import qualified Crypto.Key as Key (generate)
import qualified Crypto.Random (generate)

import qualified Crypto.Encrypt.Symmetric as Symmetric


hprop_encode_decode :: Property
hprop_encode_decode = property $ do
    key <- forAllT $ liftIO Key.generate
    nonce <- forAllT $ liftIO $ Crypto.Random.generate @ByteString
    msg <- forAll $ G.bytes (R.linear 0 1_000)
    tripping msg (encodeBs key nonce) (decodeBs key nonce)
  where
    -- We need to specify the type of the cyphertext as it is polymorphic
    encodeBs key nonce msg = Symmetric.encrypt key nonce msg :: ByteString
    decodeBs key nonce ct = Symmetric.decrypt key nonce ct :: Maybe ByteString

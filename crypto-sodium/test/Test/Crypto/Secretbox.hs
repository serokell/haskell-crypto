-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | “Integration” tests: using Secretbox with our helpers.
module Test.Crypto.Secretbox where

import Hedgehog (Property, forAll, property, tripping)

import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import qualified Crypto.Key as Key (generate)
import qualified Crypto.Random (generate)

import qualified Crypto.Secretbox as Secretbox


hprop_encode_decode :: Property
hprop_encode_decode = property $ do
    key <- liftIO $ Key.generate
    nonce <- liftIO $ Crypto.Random.generate @ByteString
    msg <- forAll $ G.bytes (R.linear 0 1_000)
    tripping msg (encodeBs key nonce) (decodeBs key nonce)
  where
    -- We need to specify the type of the cyphertext as it is polymorphic
    encodeBs key nonce msg = Secretbox.create key nonce msg :: ByteString
    decodeBs key nonce ct = Secretbox.open key nonce ct :: Maybe ByteString
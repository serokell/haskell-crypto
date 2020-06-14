-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.Crypto.Mac.Lazy where

import Hedgehog (Property, (===), assert, forAll, property)

import Data.ByteString (ByteString)

import qualified Data.ByteString.Lazy as BSL
import qualified Libsodium as Na

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import qualified Crypto.Mac as MacStrict
import qualified Crypto.Mac.Lazy as Mac


keySize :: R.Range Int
keySize = R.singleton $ fromIntegral Na.crypto_auth_keybytes


hprop_verify_of_create :: Property
hprop_verify_of_create = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Mac.toKey keyBytes
    chunks <- forAll $ G.list (R.linear 0 10) (G.bytes (R.linear 0 100))
    let msg = BSL.fromChunks chunks
    assert $ Mac.verify key msg (Mac.create @ByteString key msg)


hprop_agrees_with_strict_on_one_chunk :: Property
hprop_agrees_with_strict_on_one_chunk = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Mac.toKey keyBytes
    chunk <- forAll $ G.bytes (R.linear 0 100)
    let lazy = Mac.create @ByteString key (BSL.fromChunks [chunk])
    let strict = MacStrict.create @ByteString key chunk
    lazy === strict


hprop_agrees_with_strict_on_many_chunks :: Property
hprop_agrees_with_strict_on_many_chunks = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Mac.toKey keyBytes
    chunks <- forAll $ G.list (R.linear 0 10) (G.bytes (R.linear 0 100))
    let lazy = Mac.create @ByteString key (BSL.fromChunks chunks)
    let strict = MacStrict.create @ByteString key (mconcat chunks)
    lazy === strict

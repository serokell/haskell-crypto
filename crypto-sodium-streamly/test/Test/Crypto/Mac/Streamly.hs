-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.Crypto.Mac.Streamly where

import Hedgehog (Property, (===), assert, evalIO, forAll, property)

import Data.ByteString (ByteString)

import qualified Libsodium as Na
import qualified Streamly.Prelude as S

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import qualified Crypto.Mac as MacStrict
import qualified Crypto.Mac.Streamly as Mac


keySize :: R.Range Int
keySize = R.singleton $ fromIntegral Na.crypto_auth_keybytes


hprop_verify_of_create :: Property
hprop_verify_of_create = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Mac.toKey keyBytes
    chunks <- forAll $ G.list (R.linear 0 10) (G.bytes (R.linear 0 100))
    let msg = S.fromFoldable chunks
    mac <- evalIO $ Mac.create @ByteString key msg
    res <- evalIO $ Mac.verify key msg mac
    assert res


hprop_agrees_with_strict_on_one_chunk :: Property
hprop_agrees_with_strict_on_one_chunk = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Mac.toKey keyBytes
    chunk <- forAll $ G.bytes (R.linear 0 100)
    lazy <- evalIO $ Mac.create @ByteString key (S.yield chunk)
    let strict = MacStrict.create @ByteString key chunk
    lazy === strict


hprop_agrees_with_strict_on_many_chunks :: Property
hprop_agrees_with_strict_on_many_chunks = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Mac.toKey keyBytes
    chunks <- forAll $ G.list (R.linear 0 10) (G.bytes (R.linear 0 100))
    lazy <- evalIO $ Mac.create @ByteString key (S.fromFoldable chunks)
    let strict = MacStrict.create @ByteString key (mconcat chunks)
    lazy === strict

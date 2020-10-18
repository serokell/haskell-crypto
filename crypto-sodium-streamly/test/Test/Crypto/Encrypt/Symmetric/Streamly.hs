-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.Crypto.Encrypt.Symmetric.Streamly where

import Hedgehog (Property, (===), evalEither, evalIO, forAll, property)
import Test.HUnit ((@?=), Assertion, assert)

import Control.Exception.Safe (try)
import Data.ByteString (ByteString)

import qualified Data.ByteString as BS
import qualified Data.ByteArray.Sized as Sized
import qualified Libsodium as Na
import qualified Streamly.Prelude as S

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import qualified Crypto.Encrypt.Symmetric.Streamly as Symmetric


keySize :: R.Range Int
keySize = R.singleton $ fromIntegral Na.crypto_secretstream_xchacha20poly1305_keybytes


unit_empty_on_empty :: Assertion
unit_empty_on_empty = do
    let key = Sized.zero :: Symmetric.Key ByteString
    let encrypted = Symmetric.encrypt @ByteString @ByteString key S.nil
    assert (S.null encrypted)
    let decrypted = Symmetric.decrypt @ByteString key encrypted
    assert (S.null decrypted)
    output <- S.toList decrypted
    assert (null output)

unit_empty_chunk :: Assertion
unit_empty_chunk = do
    let key = Sized.zero :: Symmetric.Key ByteString
    let input = [""] :: [ByteString]
    let encrypted = Symmetric.encrypt @ByteString key (S.fromFoldable input)
    assert (not <$> S.null encrypted)
    let decrypted = Symmetric.decrypt @ByteString key encrypted
    assert (not <$> S.null decrypted)
    output <- S.toList decrypted
    output @?= input

unit_two_empty :: Assertion
unit_two_empty = do
    let key = Sized.zero :: Symmetric.Key ByteString
    let input = ["", ""] :: [ByteString]
    let encrypted = Symmetric.encrypt key (S.fromFoldable input)
    encrypted' <- S.toList encrypted
    map BS.length encrypted' @?= [24, 17, 17]
    let decrypted = Symmetric.decrypt key (S.fromFoldable encrypted')
    decrypted' <- S.toList decrypted
    decrypted' @?= input

unit_two_chunks_streamed :: Assertion
unit_two_chunks_streamed = do
    let key = Sized.zero :: Symmetric.Key ByteString
    let input = ["123", "456"] :: [ByteString]
    let encrypted = Symmetric.encrypt @ByteString key $ S.fromFoldable input
    let decrypted = Symmetric.decrypt @ByteString key encrypted
    decrypted' <- S.toList decrypted
    decrypted' @?= input

hprop_encode_decode :: Property
hprop_encode_decode = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Symmetric.toKey keyBytes
    chunks <- forAll $ G.list (R.linear 0 10) (G.bytes (R.linear 0 100))
    let encrypted = Symmetric.encrypt @ByteString key $ S.fromFoldable chunks
    decrypted <- evalIO . S.toList $ Symmetric.decrypt key encrypted
    decrypted === chunks

hprop_subseq :: Property
hprop_subseq = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Symmetric.toKey keyBytes
    chunks <- forAll $ G.list (R.linear 1 10) (G.bytes (R.linear 0 100))
    let encrypted = Symmetric.encrypt @ByteString key $ S.fromFoldable chunks
    (header : body) <- evalIO $ S.toList encrypted

    -- Always preserve the header
    body_subseq <- forAll $ G.subsequence body
    let subseq = header : body_subseq
    decrypted <- evalIO . try . S.toList . Symmetric.decrypt key . S.fromFoldable $ subseq

    if length body_subseq == length body
    then do
      decrypted' <- evalEither decrypted
      decrypted' === chunks
    else do
      err <- evalEither (either Right Left decrypted)
      if length subseq == 1 then
        err === Symmetric.EmptyCyphertext
      else
        err === Symmetric.InvalidCyphertext

hprop_shuffle :: Property
hprop_shuffle = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Symmetric.toKey keyBytes
    chunks <- forAll $ G.list (R.linear 1 10) (G.bytes (R.linear 0 100))
    let encrypted = Symmetric.encrypt @ByteString key $ S.fromFoldable chunks
    (header : body) <- evalIO $ S.toList encrypted

    -- Always preserve the header
    body_shuffle <- forAll $ G.shuffle body
    let shuffle = header : body_shuffle
    decrypted <- evalIO . try . S.toList . Symmetric.decrypt key . S.fromFoldable $ shuffle

    if body_shuffle == body
    then do
      decrypted' <- evalEither decrypted
      decrypted' === chunks
    else do
      err <- evalEither (either Right Left decrypted)
      err === Symmetric.InvalidCyphertext

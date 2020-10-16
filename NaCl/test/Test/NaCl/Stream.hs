-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.NaCl.Stream where

import Hedgehog (Property, forAll, property, tripping)
import Test.HUnit ((@?=), Assertion)

import Data.ByteString (ByteString)

import qualified Data.ByteString as BS
import qualified Libsodium as Na

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import qualified NaCl.Stream as Stream


keySize :: R.Range Int
keySize = R.singleton $ fromIntegral Na.crypto_stream_keybytes

nonceSize :: R.Range Int
nonceSize = R.singleton $ fromIntegral Na.crypto_stream_noncebytes


hprop_xor_twice :: Property
hprop_xor_twice = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Stream.toKey keyBytes
    nonceBytes <- forAll $ G.bytes nonceSize
    let Just nonce = Stream.toNonce nonceBytes
    msg <- forAll $ G.bytes (R.linear 0 1_000)
    tripping msg (encodeBs key nonce) (decodeBs key nonce)
  where
    -- We need to specify the type of the cyphertext as it is polymorphic
    encodeBs key nonce msg = Stream.xor key nonce msg :: ByteString
    decodeBs key nonce ct = Just $ Stream.xor key nonce ct :: Maybe ByteString


-- Test vector from
-- https://github.com/jedisct1/libsodium/blob/f911b56650b680ecfc5d32b11b090849fc2b5f92/test/default/stream.c

-- exampleKey :: ByteString
-- exampleKey = BS.pack $
--   [ 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85
--   , 0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a
--   , 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac
--   , 0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08
--   , 0x44, 0xf6, 0x83, 0x89
--   ]
--
-- exampleNonce :: ByteString
-- exampleNonce = BS.pack $
--   [ 0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6
--   , 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8
--   , 0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19
--   , 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
--   ]
--
-- exampleStreamSha256 :: ByteString
-- exampleStreamSha256 = BS.pack $
--   [ 0x66 0x2b 0x9d 0x0e 0x34 0x63 0x02 0x91
--   , 0x56 0x06 0x9b 0x12 0xf9 0x18 0x69 0x1a
--   , 0x98 0xf7 0xdf 0xb2 0xca 0x03 0x93 0xc9
--   , 0x6b 0xbf 0xc6 0xb1 0xfb 0xd6 0x30 0xa2
--   ]
--
-- unit_example_generate :: Assertion
-- unit_example_generate = do
--   let Just key = Stream.toKey exampleKey
--   let Just nonce = Stream.toNonce exampleNonce
--   Stream.generate key nonce @?= exampleStream

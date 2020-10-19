-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.NaCl.Scalarmult where

import Hedgehog ((===), Property, discard, failure, forAll, property, success)
import Test.HUnit ((@?=), Assertion)

import Data.ByteString (ByteString)
import Data.ByteString.Base16 (decode)

import qualified Data.ByteString as BS

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import NaCl.Scalarmult (Scalar, Point, mult, multBase, toScalar, toPoint)


pointSize :: R.Range Int
pointSize = R.singleton 32

scalarSize :: R.Range Int
scalarSize = R.singleton 32


-- Test vectors from
-- https://github.com/jedisct1/libsodium/blob/f911b56650b680ecfc5d32b11b090849fc2b5f92/test/default/scalarmult.c

aliceSk :: Scalar ByteString
Just aliceSk = toScalar . BS.pack $
  [ 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
    0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
    0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
  ]
alicePk :: Point ByteString
alicePk = multBase aliceSk


bobSk :: Scalar ByteString
Just bobSk = toScalar . BS.pack $
  [ 0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
    0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
    0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
  ]
bobPk :: Point ByteString
bobPk = multBase bobSk

smallOrderP :: Point ByteString
Just smallOrderP = toPoint . BS.pack $
  [ 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
    0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
    0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00
  ]


unit_alice_pk :: Assertion
unit_alice_pk = do
  let Just expected = toPoint . fst . decode $ "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  alicePk @?= expected

unit_bob_pk :: Assertion
unit_bob_pk = do
  let Just expected = toPoint . fst . decode $ "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
  bobPk @?= expected

unit_shared_example :: Assertion
unit_shared_example = do
  let Just aliceShared = bobPk `mult` aliceSk
  let Just bobShared = alicePk `mult` bobSk
  let Just expected = toPoint . fst . decode $ "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  aliceShared @?= expected
  bobShared @?= expected

hprop_small_order :: Property
hprop_small_order = property $ do
  Just sk <- forAll $ toScalar <$> G.bytes scalarSize
  case mult @ByteString smallOrderP sk of
    Nothing -> success
    Just _ -> failure

hprop_shared :: Property
hprop_shared = property $ do
  Just sk1 <- forAll $ toScalar <$> G.bytes scalarSize
  let pk1 = multBase @ByteString sk1
  Just sk2 <- forAll $ toScalar <$> G.bytes scalarSize
  let pk2 = multBase @ByteString sk2

  let mshared1 = mult @ByteString pk2 sk1
  let mshared2 = mult @ByteString pk1 sk2
  case (mshared1, mshared2) of
    (Just shared1, Just shared2) -> shared1 === shared2
    _ -> discard

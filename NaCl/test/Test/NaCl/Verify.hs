-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE AllowAmbiguousTypes #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.NaCl.Verify where

import Hedgehog (assert, forAll, property)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.Hedgehog (testProperty)

import Data.ByteArray.Sized (sizedByteArray)
import Data.Proxy (Proxy (Proxy))
import GHC.TypeLits (natVal)

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import NaCl.Verify (eq, NaClComparable)


crypto_verify_test :: forall n. NaClComparable n => TestTree
crypto_verify_test =
    testGroup ("crypto_verify_" <> show n) $
      [ testProperty "self random" $ property $ do
          xBytes <- forAll $ G.bytes (R.singleton n)
          let Just x = sizedByteArray @n xBytes
          assert $ x `eq` x
      , testProperty "two random" $ property $ do
          xBytes <- forAll $ G.bytes (R.singleton n)
          let Just x = sizedByteArray @n xBytes
          yBytes <- forAll $ G.bytes (R.singleton n)
          let Just y = sizedByteArray @n yBytes
          assert $ (x `eq` y) == (x == y)
      , testProperty "checks last" $ property $ do
          prefix <- forAll $ G.bytes (R.singleton $ n - 1)
          xLast <- forAll $ G.bytes (R.singleton 1)
          let Just x = sizedByteArray @n (prefix <> xLast)
          yLast <- forAll $ G.bytes (R.singleton 1)
          let Just y = sizedByteArray @n (prefix <> yLast)
          assert $ (x `eq` y) == (xLast == yLast)
      ]
  where
    n = fromIntegral $ natVal (Proxy @n)


test_16 :: TestTree
test_16 = crypto_verify_test @16

test_32 :: TestTree
test_32 = crypto_verify_test @32

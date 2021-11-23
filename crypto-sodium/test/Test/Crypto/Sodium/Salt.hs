-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

module Test.Crypto.Sodium.Salt where

import Data.ByteArray.Sized (SizedByteArray, unSizedByteArray)
import Data.ByteString (ByteString)

import Test.HUnit ((@?=), Assertion, assertFailure)

import Crypto.Sodium.Salt (utf8Lit)


unit_literal :: Assertion
unit_literal = do
    -- see if it type-checks
    case utf8Lit @"hello" @5 :: Maybe (SizedByteArray 5 ByteString) of
      Just lit -> unSizedByteArray lit @?= "hello"
      Nothing -> assertFailure "Size mismatch"

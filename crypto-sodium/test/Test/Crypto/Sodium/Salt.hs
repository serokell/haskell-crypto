-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE QuasiQuotes #-}

module Test.Crypto.Sodium.Salt where

import Data.ByteArray.Sized (SizedByteArray, unSizedByteArray)
import Data.ByteString (ByteString)

import Test.HUnit ((@?=), Assertion)

import Crypto.Sodium.Salt (utf8)


unit_ascii_literal :: Assertion
unit_ascii_literal = do
    let lit = [utf8|hello|] :: SizedByteArray 5 ByteString
    unSizedByteArray lit @?= "hello"

unit_nonascii_literal :: Assertion
unit_nonascii_literal = do
    let lit = [utf8|привет|] :: SizedByteArray 12 ByteString
    unSizedByteArray lit @?= "\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82"

unit_space_literal :: Assertion
unit_space_literal = do
    let lit = [utf8|hello world|] :: SizedByteArray 11 ByteString
    unSizedByteArray lit @?= "hello world"

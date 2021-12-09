-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE QuasiQuotes #-}

module Test.Crypto.Sodium.Salt where

import Data.ByteArray.Sized (SizedByteArray, unSizedByteArray)
import Data.ByteString (ByteString)

import Test.HUnit ((@?=), Assertion)

import Crypto.Sodium.Salt (utf8, bytes)


unit_utf8_ascii_literal :: Assertion
unit_utf8_ascii_literal = do
    let lit = [utf8|hello|] :: SizedByteArray 5 ByteString
    unSizedByteArray lit @?= "hello"

unit_utf8_nonascii_literal :: Assertion
unit_utf8_nonascii_literal = do
    let lit = [utf8|привет|] :: SizedByteArray 12 ByteString
    unSizedByteArray lit @?= "\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82"

unit_utf8_space_literal :: Assertion
unit_utf8_space_literal = do
    let lit = [utf8|hello world|] :: SizedByteArray 11 ByteString
    unSizedByteArray lit @?= "hello world"

unit_utf8_escapes :: Assertion
unit_utf8_escapes = do
    let lit = [utf8|ĝis\x0021\r\n|] :: SizedByteArray 7 ByteString
    unSizedByteArray lit @?= "\xc4\x9dis!\r\n"


unit_bytes_literal :: Assertion
unit_bytes_literal = do
    let lit = [bytes|hi\n\x00|] :: SizedByteArray 4 ByteString
    unSizedByteArray lit @?= "hi\n\x00"

unit_bytes_literal_2 :: Assertion
unit_bytes_literal_2 = do
    let lit = [bytes|z\x00\xff\SOH\1\&2|] :: SizedByteArray 6 ByteString
    unSizedByteArray lit @?= "z\x00\xff\SOH\1\&2"

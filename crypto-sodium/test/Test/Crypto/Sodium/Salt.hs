-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE QuasiQuotes #-}

module Test.Crypto.Sodium.Salt where

import Data.ByteArray.Sized (SizedByteArray, unSizedByteArray)
import Data.ByteString (ByteString)

import Hedgehog (Property, (===), evalMaybe, failure, forAll, property)
import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R
import Test.HUnit ((@?=), Assertion)

import Crypto.Sodium.Salt (utf8, bytes)
import Crypto.Sodium.Salt.Internal (parseEscapes)


hprop_parseEscapes_latin1 :: Property
hprop_parseEscapes_latin1 = property $ do
    str <- forAll $ G.string (R.linear 0 100) notBackslash
    result <- evalMaybe $ parseEscapes str
    result === str
  where
    -- latin1 (including non-printable garbage) but not backslash
    notBackslash = G.filter (/= '\\') G.latin1

hprop_parseEscapes_shown_ascii :: Property
hprop_parseEscapes_shown_ascii = property $ do
    str <- forAll $ G.string (R.linear 0 100) G.ascii
    -- show and drop the quotation marks around the result
    result <- evalMaybe $ parseEscapes (init . tail . show $ str)
    result === str

hprop_parseEscapes_shown_bytes :: Property
hprop_parseEscapes_shown_bytes = property $ do
    bs <- forAll $ G.bytes (R.linear 0 100)
    -- show and drop the quotation marks around the result
    result <- evalMaybe $ parseEscapes (init . tail . show $ bs)
    show result === show bs

hprop_parseEscapes_bad_escape_fail :: Property
hprop_parseEscapes_bad_escape_fail = property $ do
    str1 <- forAll $ G.string (R.linear 0 10) G.alphaNum
    str2 <- forAll $ G.string (R.linear 0 10) G.alphaNum
    case parseEscapes (str1 ++ "\\z" ++ str2) of
      Just _ -> failure
      Nothing -> pure ()


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

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.NaCl.Auth where

import Hedgehog (Property, assert, forAll, property)
import Test.HUnit ((@?), (@?=), Assertion)

import Data.ByteArray.Sized (unSizedByteArray)
import Data.ByteString (ByteString)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Libsodium as Na

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R

import qualified NaCl.Auth as Auth


keySize :: R.Range Int
keySize = R.singleton $ fromIntegral Na.crypto_auth_keybytes


hprop_verify_of_create :: Property
hprop_verify_of_create = property $ do
    keyBytes <- forAll $ G.bytes keySize
    let Just key = Auth.toKey keyBytes
    msg <- forAll $ G.bytes (R.linear 0 1_000)
    assert $ Auth.verify key msg (Auth.create @ByteString key msg)


-- Test vector from
-- https://github.com/jedisct1/libsodium/blob/f911b56650b680ecfc5d32b11b090849fc2b5f92/test/default/auth.c

exampleKey :: ByteString
exampleKey = C8.pack $ "Jefe" ++ replicate (32 - 4) '\NUL'

exampleMsg :: ByteString
exampleMsg = C8.pack "what do ya want for nothing?"

exampleAuth :: ByteString
exampleAuth = BS.pack $
  [ 0x16,0x4b,0x7a,0x7b,0xfc,0xf8,0x19,0xe2
  , 0xe3,0x95,0xfb,0xe7,0x3b,0x56,0xe0,0xa3
  , 0x87,0xbd,0x64,0x22,0x2e,0x83,0x1f,0xd6
  , 0x10,0x27,0x0c,0xd7,0xea,0x25,0x05,0x54
  ]

unit_example_create :: Assertion
unit_example_create = do
  let Just key = Auth.toKey exampleKey
  unSizedByteArray (Auth.create key exampleMsg) @?= exampleAuth

unit_example_verify :: Assertion
unit_example_verify = do
  let Just key = Auth.toKey exampleKey
  let Just auth = Auth.toAuthenticator exampleAuth
  Auth.verify key exampleMsg auth @? "Verify ok"

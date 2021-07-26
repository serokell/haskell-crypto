-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.NaCl.Hash where

import Test.HUnit ((@?=), Assertion)

import Data.ByteArray.Sized (sizedByteArray)
import Data.ByteString (ByteString)
import Data.ByteString.Base16 (decodeBase16)
import Data.Either (fromRight)

import qualified NaCl.Hash as Hash


-- Test vectors from
-- https://github.com/jedisct1/libsodium/blob/f911b56650b680ecfc5d32b11b090849fc2b5f92/test/default/hash.c

unit_sha512_test1 :: Assertion
unit_sha512_test1 = do
    let
      msg = "testing\n" :: ByteString
      Just hash = sizedByteArray . fromRight (error "impossible") . decodeBase16 $
        "24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28"
    Hash.sha512 msg @?= hash

unit_sha512_test2 :: Assertion
unit_sha512_test2 = do
    let
      msg = mconcat @ByteString
        [ "The Conscience of a Hacker is a small essay written January 8, 1986 by a "
        , "computer security hacker who went by the handle of The Mentor, who "
        , "belonged to the 2nd generation of Legion of Doom."
        ]
      Just hash = sizedByteArray . fromRight (error "impossible") . decodeBase16 $
        "a77abe1ccf8f5497e228fbc0acd73a521ededb21b89726684a6ebbc3baa32361aca5a244daa84f24bf19c68baf78e6907625a659b15479eb7bd426fc62aafa73"
    Hash.sha512 msg @?= hash

unit_sha256_test1 :: Assertion
unit_sha256_test1 = do
    let
      msg = "testing\n" :: ByteString
      Just hash = sizedByteArray . fromRight (error "impossible") . decodeBase16 $
        "12a61f4e173fb3a11c05d6471f74728f76231b4a5fcd9667cef3af87a3ae4dc2"
    Hash.sha256 msg @?= hash

unit_sha256_test2 :: Assertion
unit_sha256_test2 = do
    let
      msg = mconcat @ByteString
        [ "The Conscience of a Hacker is a small essay written January 8, 1986 by a "
        , "computer security hacker who went by the handle of The Mentor, who "
        , "belonged to the 2nd generation of Legion of Doom."
        ]
      Just hash = sizedByteArray . fromRight (error "impossible") . decodeBase16 $
        "71cc8123fef8c236e451d3c3ddf1adae9aa6cd9521e7041769d737024900a03a"
    Hash.sha256 msg @?= hash

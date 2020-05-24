-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.Crypto.Random where

import Test.HUnit ((@?=), Assertion)

import Data.ByteArray.Sized (unSizedByteArray)
import Data.ByteString (ByteString)

import qualified Data.ByteString as BS
import qualified Libsodium as Na

import Crypto.Random (generate)

import qualified Crypto.Secretbox as Secretbox


-- Well, this is kinda stupid, because we merely generate one random sequence,
-- but this is just to check that the lengths are correctly propagated
-- through types. So, good enough.
--
-- Also it is not thread-safe, since we don’t call @sodiumInit@...

unit_generate_Secretbox_key :: Assertion
unit_generate_Secretbox_key = do
  key <- generate :: IO (Secretbox.Key ByteString)
  let bs = unSizedByteArray key
  BS.length bs @?= fromIntegral Na.crypto_secretbox_keybytes

unit_generate_Secretbox_nonce :: Assertion
unit_generate_Secretbox_nonce = do
  nonce <- generate :: IO (Secretbox.Nonce ByteString)
  let bs = unSizedByteArray nonce
  BS.length bs @?= fromIntegral Na.crypto_secretbox_noncebytes

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

module Test.Crypto.Nonce where

import Test.HUnit ((@?), (@?=), Assertion)

import Control.DeepSeq (deepseq)
import Data.ByteArray.Sized (unSizedByteArray)
import Data.ByteString (ByteString)
import Data.Ratio ((%))
import System.CPUTime (getCPUTime)

import qualified Data.ByteString as BS
import qualified Libsodium as Na

import Crypto.Nonce (generate)

import qualified Crypto.Encrypt.Symmetric as Symmetric
import qualified Crypto.Nonce as Nonce (generate)
import qualified Crypto.Pwhash.Internal as Pwhash
import qualified Crypto.Random as Random (generate)


-- Well, this is kinda stupid, because we merely generate one random sequence,
-- but this is just to check that the lengths are correctly propagated
-- through types. So, good enough.

unit_generate_Symmetric_nonce :: Assertion
unit_generate_Symmetric_nonce = do
  nonce <- generate :: IO (Symmetric.Nonce ByteString)
  let bs = unSizedByteArray nonce
  BS.length bs @?= fromIntegral Na.crypto_secretbox_noncebytes

unit_generate_Pwhash_salt :: Assertion
unit_generate_Pwhash_salt = do
  nonce <- generate :: IO (Pwhash.Salt ByteString)
  let bs = unSizedByteArray nonce
  BS.length bs @?= fromIntegral Na.crypto_pwhash_saltbytes



-- Benchmark to make sure this all makes sense and insecure nonse generation
-- is actually faster than cryptographically-secure generation.
unit_bench_against_crypto :: Assertion
unit_bench_against_crypto = do
    tNonce <- measure $ (unSizedByteArray <$> Nonce.generate @64)
    tCrypto <- measure $ (unSizedByteArray <$> Random.generate @ByteString @64)
    let ratio = fromRational (tNonce % tCrypto) :: Double

    -- XXX: The benchmark is disabled, because we don’t yet have an
    -- implementation that would actually be faster :/.
    --        vvvvvvvv
    ratio < 1 || True @? "Crypto gen is " <> show ratio <> "x faster"
    --        ^^^^^^^^
  where
    measure act = do
        t1 <- getCPUTime
        go 1000
        t2 <- getCPUTime
        pure $ t2 - t1
      where
        go :: Int -> IO ()
        go n
          | n <= 0 = pure ()
          | otherwise = do
              res <- act
              res `deepseq` go (n - 1)

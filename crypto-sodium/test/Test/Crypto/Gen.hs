-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Hedgehog generators of test data
module Test.Crypto.Gen where

import Hedgehog (Gen)

import Data.ByteString (ByteString)
import Data.ByteArray (ByteArray, ScrubbedBytes, convert)
import Data.ByteArray.Sized (SizedByteArray, sizedByteArray)
import Data.Maybe (fromJust)
import Data.Proxy (Proxy (Proxy))
import GHC.TypeLits (KnownNat, natVal)

import qualified Hedgehog.Gen as G
import qualified Hedgehog.Range as R


-- | Generate a random sized byte array
sizedBytes
  :: forall n ba. (ByteArray ba, KnownNat n)
  => Gen (SizedByteArray n ba)
sizedBytes = fromJust . sizedByteArray . convert <$>
  G.bytes (R.singleton $ fromIntegral $ natVal (Proxy @n))

-- | Generate a random nonce of the right size.
nonce :: forall n. KnownNat n => Gen (SizedByteArray n ByteString)
nonce = sizedBytes

-- | Generate a random key of the right size.
--
-- THIS FUNCTION IS NOT SECURE AND IS ONLY SUITABLE FOR TESTS.
key :: forall n. KnownNat n => Gen (SizedByteArray n ScrubbedBytes)
key = sizedBytes

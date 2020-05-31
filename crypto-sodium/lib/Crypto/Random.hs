-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Generate cryptographically-secure random data.
module Crypto.Random
  ( generate
  ) where

import Data.ByteArray (ByteArray)
import Data.ByteArray.Sized (SizedByteArray, alloc)
import Data.Proxy (Proxy (Proxy))
import GHC.TypeLits (KnownNat, natVal)

import qualified Libsodium as Na


-- | Generate a sequence of cryptographically-secure renadom bytes.
--
-- The output of this function is suitable to generate secret keys.
--
-- Note: This function is not thread-safe until Sodium is initialised.
-- See "Crypto.Init" for details.
generate
  :: forall ba n. (ByteArray ba, KnownNat n)
  => IO (SizedByteArray n ba)
generate = alloc $ \bytesPtr ->
    Na.randombytes_buf bytesPtr len
  where
    len = fromIntegral $ natVal (Proxy :: Proxy n)

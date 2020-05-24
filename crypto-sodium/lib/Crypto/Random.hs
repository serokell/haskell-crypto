-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Generate cryptographically-secure random data.
module Crypto.Random
  ( generate
  ) where

import Data.ByteArray (ByteArray)
import Data.ByteArray.Sized.Internal (OfLength, alloc)
import Data.Proxy (Proxy (Proxy))
import GHC.TypeLits (KnownNat, natVal)

import qualified Libsodium as Na


-- | Generate a sequence of cryptographically-secure renadom bytes.
--
-- The output of this function is suitable to generate secret keys.
generate
  :: forall ba n. (ByteArray ba, KnownNat n)
  => IO (OfLength n ba)
generate = alloc $ \bytesPtr ->
    Na.randombytes_buf bytesPtr len
  where
    len = fromIntegral $ natVal (Proxy :: Proxy n)

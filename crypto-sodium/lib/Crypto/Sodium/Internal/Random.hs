-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Generate simple insecure random data.
module Crypto.Sodium.Internal.Random
  ( generateInsecure
  ) where

import Data.ByteArray.Sized (SizedByteArray)
import Data.ByteString (ByteString)
import GHC.TypeLits (KnownNat)

import Crypto.Sodium.Random (generate)


-- | Generate a sequence of random bytes.
--
-- The output of this function is NOT suitable for secret keys.
generateInsecure
  :: forall n. (KnownNat n)
  => IO (SizedByteArray n ByteString)
generateInsecure
{-
  = unsafeSizedByteArray . BS.pack . take len . randoms <$> newStdGen
  where
    len = fromIntegral $ natVal (Proxy :: Proxy n)
-}
  -- Haddock above is actually a lie. We use the same random generator
  -- as for keys, because, after benchmarking, it happens to be faster :/.
  = generate

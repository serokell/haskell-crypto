-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | @crypto_verify_*@
module Crypto.Sodium.Internal.Verify
  ( verifyBytes32
  ) where

import Data.ByteArray (ByteArrayAccess, withByteArray)
import Data.ByteArray.Sized (SizedByteArray)

import qualified Libsodium as Na


-- | Compare two byte arrays of length 32.
verifyBytes32
  :: ( ByteArrayAccess ba1
     , ByteArrayAccess ba2
     )
  => SizedByteArray 32 ba1  -- ^ First byte array
  -> SizedByteArray 32 ba2  -- ^ Second byte array
  -> IO Bool
verifyBytes32 bytes1 bytes2 =
  withByteArray bytes1 $ \ptr1 ->
  withByteArray bytes2 $ \ptr2 -> do
    -- TODO: I have no idea what I am doing
    --
    -- - Sodium also checks that pointers are different?
    -- - This kind of double comparison was added in
    --   c5a9d46386f917aa0ff1bfb711450f9af1d79a17
    --   (why?)
    res1 <- Na.crypto_verify_32 ptr1 ptr2
    res2 <- Na.sodium_memcmp ptr2 ptr1 32
    pure $ res1 == 0 && res2 == 0

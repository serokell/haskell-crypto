-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE TypeFamilies #-}

-- | String comparison.
--
-- This is @crypto_verify_*@ from NaCl.
--
-- Unlike NaCl, which provides multiple functions, this module exports only
-- one function – 'eq'. The function will automatically pick the correct
-- implementation based on type-level sizes of its inputs.
module NaCl.Verify
  ( eq
  , NaClComparable
  ) where

import Data.ByteArray (ByteArrayAccess, withByteArray)
import Data.ByteArray.Sized (SizedByteArray)
import Data.Proxy (Proxy (Proxy))
import Foreign.C.Types (CInt, CUChar)
import Foreign.Ptr (Ptr)
import GHC.TypeLits (KnownNat, Nat)
import System.IO.Unsafe (unsafeDupablePerformIO)

import qualified Libsodium as Na


-- | Class of bytestring lengths that can be verified by NaCl.
--
-- This is a private class, we do not export it so that it is closed.
-- External users can use the @NaClComparable@ constraint on their functions,
-- but they can’t add instances.
class KnownNat n => CryptoVerify (n :: Nat) where
  crypto_verify_n :: Proxy n -> Ptr CUChar -> Ptr CUChar -> IO CInt

-- | Class of bytestring lengths that can be compared in constant-time
-- by NaCl.
class CryptoVerify n => NaClComparable n where

instance CryptoVerify 16 where
  crypto_verify_n _proxy = Na.crypto_verify_16
instance NaClComparable 16 where

instance CryptoVerify 32 where
  crypto_verify_n _proxy = Na.crypto_verify_32
instance NaClComparable 32 where


-- | Constant-time comparison of sequences of bytes.
--
-- Unlike regular comparison, this function will always read both
-- sequences until the end rather than exit as soon as it finds
-- differing bytes. This makes it suitable for comparing secret data.
--
-- It only works with inputs of size 16 or 32.
eq
  :: forall n xBytes yBytes.
     ( NaClComparable n
     , ByteArrayAccess xBytes, ByteArrayAccess yBytes
     )
  => SizedByteArray n xBytes -> SizedByteArray n yBytes -> Bool
eq x y = unsafeDupablePerformIO $ do
  ret <-
    withByteArray x $ \xPtr ->
    withByteArray y $ \yPtr ->
      crypto_verify_n (Proxy :: Proxy n) xPtr yPtr
  pure $ ret == 0

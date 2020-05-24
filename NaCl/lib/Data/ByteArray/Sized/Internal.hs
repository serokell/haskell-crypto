-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internals of sized byte arrays.
--
-- This module exports the 'OfLength' constructor, which allows you
-- to “postulate” that byte arrays you create have the right length.
-- Use with care.
module Data.ByteArray.Sized.Internal
  ( OfLength (..)
  , hasRightLength

  , allocRet
  , alloc
  ) where

import Prelude hiding (length)

import Data.Bifunctor (second)
import Data.Proxy (Proxy (Proxy))
import Data.The (The)
import Foreign.Ptr (Ptr)
import GHC.TypeLits (KnownNat, Nat, natVal)

import Data.ByteArray (ByteArray, ByteArrayAccess, length)

import qualified Data.ByteArray


-- | Type of byte arrays that have length @l@.
newtype OfLength (l :: Nat) ba = OfLength ba
  deriving (ByteArrayAccess, Eq, Ord)

instance The (OfLength l ba) ba


-- | Check that the byte array has the given length.
hasRightLength
  :: forall ba n. (ByteArrayAccess ba, KnownNat n)
  => ba
  -> Maybe (OfLength n ba)
hasRightLength ba
  | fromIntegral (length ba) == natVal (Proxy :: Proxy n) = Just $ OfLength ba
  | otherwise = Nothing

-- | Allocate a new byte array of the given length, and perform the given operation.
--
-- This is the same as 'Data.ByteArray.allocRet'.
allocRet
  :: forall ba n p a. (ByteArray ba, KnownNat n)
  => (Ptr p -> IO a)
  -> IO (a, OfLength n ba)
allocRet
  = fmap (second OfLength)
  . Data.ByteArray.allocRet (fromIntegral $ natVal (Proxy :: Proxy n))

-- | Allocate a new byte array of the given length, and run the initialiser.
--
-- This is the same as 'Data.ByteArray.alloc'.
alloc
  :: forall ba n p. (ByteArray ba, KnownNat n)
  => (Ptr p -> IO ())
  -> IO (OfLength n ba)
alloc
  = fmap OfLength
  . Data.ByteArray.alloc (fromIntegral $ natVal (Proxy :: Proxy n))

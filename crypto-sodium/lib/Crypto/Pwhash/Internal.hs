{-# OPTIONS_GHC -Wno-redundant-constraints #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Tools for hashing passwords.
module Crypto.Pwhash.Internal
  ( Algorithm (..)
  , Params (..)
  , Salt

  , pwhash
  ) where

import Prelude hiding (length)

import Data.ByteArray (ByteArrayAccess, length, withByteArray)
import Data.ByteArray.Sized (ByteArrayN, SizedByteArray, allocRet)
import Data.Proxy (Proxy (Proxy))
import Data.Word (Word64)
import GHC.TypeLits (type (<=), natVal)
import Foreign.C.Types (CInt, CSize (CSize), CULLong (CULLong))

import qualified Libsodium as Na


-- | Secure hashing algorithm.
data Algorithm
  = Argon2i_1_3 -- ^ Argon2i version 1.3
  | Argon2id_1_3 -- ^ Argon2id version 1.3
  deriving (Eq, Ord, Show)

algorithmToInt :: Algorithm -> CInt
algorithmToInt Argon2i_1_3 = Na.crypto_pwhash_alg_argon2i13
algorithmToInt Argon2id_1_3 = Na.crypto_pwhash_alg_argon2id13


-- | Secure-hashing parameters.
data Params = Params
  { opsLimit :: !Word64  -- ^ Maximum amount of computation to perform.
  , memLimit :: !Word64  -- ^ Maximum amount of RAM (bytes) to use.
  }
  deriving (Eq, Ord, Show)


-- | Salt used for password hashing.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type Salt a = SizedByteArray Na.CRYPTO_PWHASH_SALTBYTES a


-- | Securely hash a password.
--
-- This is @crypto_pwhash@, it can be used for key derivation.
pwhash
  ::  forall passwd salt n hash.
      ( ByteArrayAccess passwd, ByteArrayAccess salt
      , ByteArrayN n hash
      , Na.CRYPTO_PWHASH_BYTES_MIN <= n, n <= Na.CRYPTO_PWHASH_BYTES_MAX
      )
  => Algorithm  -- ^ Hashing algorithm.
  -> Params  -- ^ Hashing parameters.
  -> passwd  -- ^ Password to hash.
  -> Salt salt  -- ^ Hashing salt.
  -> IO (Maybe hash)
pwhash alg Params{opsLimit, memLimit} passwd salt = do
  (ret, hash) <-
    allocRet (Proxy :: Proxy n) $ \hashPtr ->
    withByteArray passwd $ \passwdPtr ->
    withByteArray salt $ \saltPtr -> do
      Na.crypto_pwhash hashPtr (fromIntegral $ natVal (Proxy :: Proxy n))
        passwdPtr (fromIntegral $ length passwd)
        saltPtr
        (CULLong opsLimit) (CSize memLimit) (algorithmToInt alg)
  if ret == 0 then
    pure $ Just hash
  else
    pure $ Nothing

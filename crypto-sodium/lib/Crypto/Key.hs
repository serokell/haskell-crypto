{-# OPTIONS_GHC -Wno-redundant-constraints #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | This module gives different ways of obtaining secret keys.
--
-- = Key derivation (from a password)
--
-- Sometimes, instead of generating fresh random transient encryption keys,
-- you want an encryption key to be persistent and you don’t want to
-- store it anywhere – instead you ask the user to provide it.
-- Such a secret value known and entered by the user is usually called
-- a “password”.
--
-- However, passwords make terrible encryption keys because encryption keys:
--
-- 1. often need to have a specific exact length and
-- 2. need to be hard to guess (or brute-force).
--
-- Item 1 above can be easily ticked off by deriving the encryption key from
-- the password by applying a hash-function to it, however in order to
-- achieve 2 we need our “hash-function” to:
--
-- * be slow to compute (to make brute-forcing less feasible) and
-- * mix extra “noise” into the derivation process to make it harder
--   to pre-compute derived values in advance.
--
-- A construction that satisfies both requirements is called a /key derivation
-- function (KDF)/. This module provides a convenient interface for deriving
-- secure keys from passwords by the way of one such KDF.
--
-- == Use
--
-- This module provides two functions: 'derive' and 'rederive'.
-- You can think of the entire process similar to how you set the password
-- on your account at some website once, and then use this password to log in.
--
-- When you derive a key for the first time (e.g. you ask the user to enter their
-- password twice, and then encrypt something), you use the 'derive' function,
-- which gives you the derived key and a /derivation slip/. The slip is not
-- secret, you can store it in plain text and, in fact, you /have to/ store it
-- in plaintext somewhere next to the encrypted data.
--
-- When you need to derive the key in the future (e.g. to decrypt some previously
-- encrypted data), you will need the user’s password (ask them) /and/ you
-- will need the original derivation slip, which you should have stored.
-- You pass these to 'rederive' and it will give you the same key.
--
-- @
-- import qualified Crypto.Key as Key
--
-- encrypt = do
--   password <- {- ask the user to enter their password -}
--   password2 <- {- ask the user to confirm their password -}
--   when (password /= password2 then) $ throwIO {- passwords do not match -}
--
--   let params = {- choose key derivation parameters -}
--   (key, slip) <- Key.derive params password
--
--   {- store slip (it is not secret) -}
--   {- encrypt data with key -}
--
-- decrypt = do
--   password <- {- ask the user to enter their password -}
--   slip <- {- get the stored slip -}
--
--   key <- Key.rederive slip password
--
--   {- decrypt data with key -}
-- @
--
-- = Random key generation
--
-- The 'random' function is great at generating new secure secret keys.
module Crypto.Key
  ( type (!>=!)

  -- * Key derivation
  , Params (..)
  , DerivationSlip
  , derive
  , rederive

  -- * Random key generation
  , generate
  ) where

import Data.ByteArray (ByteArrayAccess, ScrubbedBytes)
import Data.ByteArray.Sized (ByteArrayN, SizedByteArray)
import Data.Kind (Constraint)
import GHC.TypeLits (type (<=), KnownNat)
import System.IO.Unsafe (unsafeDupablePerformIO)

import qualified Libsodium as Na

import Crypto.Key.Internal (DerivationSlip, Params (..))

import qualified Crypto.Key.Internal as I
import qualified Crypto.Random


-- | “At least as secure as”.
--
-- @a !>=! b@ means that the storage behind a is not less secure than b.
-- This is a little bit of an ad-hoc safety hack, which ensures that if
-- @b@ is stored in a securely allocated memory, then @a@ is stored in
-- memory allocated as securely, or more securely.
--
-- Here are our very ad-hoc rules:
--
-- * This relation is reflexive (@a@ is as secure as @a@ for any @a@).
-- * 'ScrubbedBytes' is more secure than anything.
-- * Everything else is equally (in)secure.
--
-- So, for example, if the original password is stored in @ScrubbedBytes@,
-- you will not be able to put the derived from it key into a @ByteString@,
-- because that would be less secure.
type family a !>=! b :: Constraint where
  a !>=! a = ()  -- reflexivity
  a !>=! ScrubbedBytes = LessSecureStorage a ScrubbedBytes
  a !>=! b = ()
class LessSecureStorage a b


-- | Derive a key from a password using a secure KDF for the first time.
--
-- This function takes two arguments:
--
-- 1. key derivation parameters, which specify how slow the derivation process
-- will be (the slower you can afford the better for security),
--
-- 2. the user’s password to derive the key from.
--
-- See @libsodium@ documentation for how to determine 'Params'.
--
-- It returns the derived key and a /slip/ that you need to save in order to be
-- able to derive the same key from the same password in the future. The slip
-- is not secret, so you can store it in plaintext; just make sure you can
-- access it in the future, as you will need to provide it to 'rederive'.
--
-- It can derive a key of almost any length and the output length is encoded
-- in the type. There is an additional type-level restriction which forces
-- you to store the derived key in memory at least as securely as you
-- stored the password.
--
-- Note: This function is not thread-safe until Sodium is initialised.
-- See "Crypto.Init" for details.
derive
  ::  forall key n passwd.
      ( ByteArrayAccess passwd
      , ByteArrayN n key, key !>=! passwd
      , Na.CRYPTO_PWHASH_BYTES_MIN <= n, n <= Na.CRYPTO_PWHASH_BYTES_MAX
      )
  => I.Params -- ^ Derivation parameters.
  -> passwd  -- ^ Password to derive from.
  -> IO (Maybe (key, I.DerivationSlip))
derive = I.derive

-- | Reerive a key from a password using a secure KDF.
--
-- This function takes two arguments:
--
-- 1. A derivation slip previously returned by 'derive'.
--
-- 2. The user’s password.
--
-- This function is guaranteed to derive the same key from the same password
-- as long as the same derivation slip was provided.
--
-- See 'derive' for additional details.
rederive
  ::  forall key n passwd.
      ( ByteArrayAccess passwd
      , ByteArrayN n key, key !>=! passwd
      , Na.CRYPTO_PWHASH_BYTES_MIN <= n, n <= Na.CRYPTO_PWHASH_BYTES_MAX
      )
  => I.DerivationSlip -- ^ Original derivation slip.
  -> passwd  -- ^ Password to rederive from.
  -> Maybe key
rederive slip passwd =
  unsafeDupablePerformIO $ I.rederive slip passwd
  -- This IO is safe, because it is pure.


-- | Generate a new secret key using a cryptographically-secure generator.
--
-- This is just a specialisation of @Crypto.Random.'generate'@ that stores
-- it in a secure memory location.
--
-- Note: This function is not thread-safe until Sodium is initialised.
-- See "Crypto.Init" for details.
generate :: KnownNat n => IO (SizedByteArray n ScrubbedBytes)
generate = Crypto.Random.generate

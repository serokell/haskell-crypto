{-# LANGUAGE AllowAmbiguousTypes #-}

-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | This module gives different ways of obtaining salts.
--
-- A “salt” is additional input provided to certain functions.
-- Unlike a nonce, salt is used for “namespacing”, so there is not
-- requirement that it is used only once, instead you use different
-- salts to deisgnate different applications of an algorithm.
--
-- This is a subtle and pure semantical difference, so, for convenience,
-- we also re-export some functions from "Crypto.Sodium.Nonce".
module Crypto.Sodium.Salt
  (
  -- * Literals
    utf8Lit

  -- * Random salt generation
  , Crypto.Sodium.Nonce.generate
  ) where

import Data.ByteArray.Sized (SizedByteArray, sizedByteArray)
import Data.ByteString (ByteString)
import Data.Proxy (Proxy (Proxy))
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import GHC.TypeLits (KnownNat, KnownSymbol, symbolVal)

import qualified Crypto.Sodium.Nonce


-- | Make a /sized/ 'ByteString' from a type-level string literal.
--
-- @
-- case utf8Lit \@"hello" \@5 of
--   Just bytes -> {- ... -}  -- bytes :: 'SizedByteArray' 5 ByteString
--   Nothing -> {- the size did not match the expected one -}
-- @
--
-- Unfortunately, it is impossible to know the length of a UTF8-encoded
-- string at type-level, so you have to explicitly provide the right length
-- and the function will return 'Nothing' if you fail to do so.
--
-- You have to provide the string as a type-level symbol rather than a
-- value-level string to make sure it is harder to pass here something
-- that is not really a literal.
utf8Lit
  :: forall s n.
     (KnownSymbol s, KnownNat n)
  => Maybe (SizedByteArray n ByteString)
utf8Lit = sizedByteArray $ T.encodeUtf8 (T.pack str)
  where
    str :: String
    str = symbolVal (Proxy :: Proxy s)

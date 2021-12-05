-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE MagicHash #-}
{-# LANGUAGE TemplateHaskell #-}

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
    utf8

  -- * Random salt generation
  , Crypto.Sodium.Nonce.generate
  ) where

import Data.ByteArray.Sized (SizedByteArray, unsafeSizedByteArray)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import GHC.Exts (Addr#)
import Language.Haskell.TH (Exp, Q, TExp, Type)
import qualified Language.Haskell.TH.Lib as TH
import Language.Haskell.TH.Quote (QuasiQuoter (..))
import qualified Language.Haskell.TH.Syntax as TH
import System.IO.Unsafe (unsafeDupablePerformIO)

import qualified Crypto.Sodium.Nonce


-- | Quasi-quoter to construct a /sized/ 'ByteString' literal.
--
-- @
-- {-# LANGUAGE QuasiQuotes #-}
--
-- {- ... -}
--
-- let salt = [utf8|hello world|] :: 'SizedByteArray' 11 ByteString
-- @
--
-- This uses Template Haskell to compute the length of the UTF-8 encoding
-- of the string you provide. Note that the string will be taken as is,
-- with all whitespace preserved, for example @[utf8| x |]@ will have length 3.
utf8 :: QuasiQuoter
utf8 = QuasiQuoter { quoteExp, quotePat, quoteType, quoteDec }
  where
    quoteExp :: String -> Q Exp
    quoteExp str = [e|unsafeSizedByteArray $(TH.unType <$> bsExpr) :: $tSized|]
      where
        bs :: ByteString
        bs = T.encodeUtf8 $ T.pack str

        len :: Int
        len = BS.length bs

        cstrExpr :: Q (TExp Addr#)
        cstrExpr = TH.unsafeTExpCoerce . TH.litE . TH.stringPrimL . BS.unpack $ bs

        bsExpr :: Q (TExp ByteString)
        bsExpr = [e||unsafeDupablePerformIO $ BS.unsafePackAddressLen len $$cstrExpr||]

        tSized :: Q Type
        tSized = [t|SizedByteArray $(TH.litT . TH.numTyLit . fromIntegral $ len) ByteString|]

    err :: String -> Q a
    err _ = fail "A `utf8` quasi-quotation can only be used as an expression"
    quotePat = err
    quoteType = err
    quoteDec = err

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
  , bytes

  -- * Random salt generation
  , Crypto.Sodium.Nonce.generate
  ) where

import Control.Monad ((<=<))
import Data.Bits (toIntegralSized)
import Data.ByteArray.Sized (SizedByteArray, unsafeSizedByteArray)
import Data.ByteString (ByteString, pack)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Maybe (listToMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import GHC.Exts (Addr#)
import Language.Haskell.TH (Exp, Q, Type)
import qualified Language.Haskell.TH.Lib as TH
import Language.Haskell.TH.Quote (QuasiQuoter (..))
import Language.Haskell.TH.Syntax.Compat (SpliceQ)
import qualified Language.Haskell.TH.Syntax.Compat as TH
import System.IO.Unsafe (unsafeDupablePerformIO)
import Text.ParserCombinators.ReadP (eof, readP_to_S, many)
import Text.Read.Lex (lexChar)

import qualified Crypto.Sodium.Nonce


-- | Quasi-quoter to construct a /sized/ 'ByteString' from string literal
-- encoded using UTF-8.
--
-- @
-- {-# LANGUAGE QuasiQuotes #-}
--
-- {- ... -}
--
-- let salt1 = [utf8|hello world|] :: 'SizedByteArray' 11 ByteString
-- let salt2 = [utf8|ĝis\x0021\r\n|] :: 'SizedByteArray' 7 ByteString
-- @
--
-- This uses Template Haskell to compute the length of the UTF-8 encoding
-- of the string you provide.
--
-- The string literal is treated similar to how a Haskell compiler treats
-- string literals in source code – this means you can use escape sequences
-- as in the example above.
--
-- Note that the string will be taken as is, with all whitespace preserved,
-- for example @[utf8| x |]@ will have length 3.
utf8 :: QuasiQuoter
utf8 = mkQuoter "utf8" (pure . T.encodeUtf8 . T.pack <=< parseEscapes)

-- | Quasi-quoter to construct a /sized/ 'ByteString' from literal bytes.
--
-- @
-- {-# LANGUAGE QuasiQuotes #-}
--
-- {- ... -}
--
-- let salt = [bytes|hi\n\x00|] :: 'SizedByteArray' 4 ByteString
-- @
--
-- This uses Template Haskell to compute the length of the raw byte
-- string you provide.
--
-- The bytes literal is treated similar to how a Haskell compiler treats
-- string literals in source code – this means you can use escape sequences
-- as in example above. Characters that do not fit into one byte will cause
-- a compilation error – use 'utf8' instead.
--
-- Note that the bytes will be taken as is, with all whitespace preserved,
-- for example @[bytes| x |]@ will have length 3.
bytes :: QuasiQuoter
bytes = mkQuoter "bytes" (toBytes <=< parseEscapes)
  where
    toBytes = fmap pack . traverse charToByte
    charToByte c =
      let msg = "Character does not fit into a byte: '" <> [c] <> "' (" <> show c <> ")"
      in maybe (fail msg) pure $ toIntegralSized (fromEnum c)

-- | A helper function to construct a quasi-quoter making a sized byte array
-- given a conversion from 'String' to 'ByteString'.
mkQuoter :: String -> (String -> Q ByteString) -> QuasiQuoter
mkQuoter name convert = QuasiQuoter { quoteExp, quotePat, quoteType, quoteDec }
  where
    quoteExp :: String -> Q Exp
    quoteExp str = do
      bs <- convert str
      let len = BS.length bs
          tSized = mkTSized len
          bsSplice = mkBsSplice len bs
      [e|unsafeSizedByteArray $(TH.unTypeSplice bsSplice) :: $tSized|]

    mkBsSplice :: Int -> ByteString -> SpliceQ ByteString
    mkBsSplice len bs =
      let cstrSplice :: SpliceQ Addr#
          cstrSplice = TH.unsafeSpliceCoerce . TH.litE . TH.stringPrimL . BS.unpack $ bs
      in [e||unsafeDupablePerformIO $ BS.unsafePackAddressLen len $$cstrSplice||]

    mkTSized :: Int -> Q Type
    mkTSized len = [t|SizedByteArray $(TH.litT . TH.numTyLit . fromIntegral $ len) ByteString|]

    err :: String -> Q a
    err _ = fail $ "A `" <> name <> "` quasi-quotation can only be used as an expression"

    quotePat = err
    quoteType = err
    quoteDec = err

-- | Parse a Haskell string literal with escapes.
--
-- Given a string similar to what a Haskell compiler can see between double quotes,
-- process escape sequences according to the Haskell standard and return
-- the resulting string.
--
-- This function can fail if there are invalid escape sequences.
parseEscapes :: MonadFail m => String -> m String
parseEscapes str = case listToMaybe (readP_to_S (many lexChar <* eof) str) of
  Just (result, "") -> pure result
  _ -> fail $ "Failed to parse raw bytes (no parse): " <> str

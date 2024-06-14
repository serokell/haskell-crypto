-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internal utilities for "Crypto.Sodium.Salt".
module Crypto.Sodium.Salt.Internal
  ( parseEscapes
  ) where

import Control.Monad (liftM2)
import Data.Char (isSpace)
import Data.Maybe (listToMaybe)
import Text.ParserCombinators.ReadP (ReadP, readP_to_S, (<++))
import Text.Read.Lex (lexChar)

-- | Parse a Haskell string literal with escapes.
--
-- Given a string similar to what a Haskell compiler can see between double quotes,
-- process escape sequences according to the Haskell standard and return
-- the resulting string.
--
-- This function can fail if there are invalid escape sequences.
parseEscapes :: MonadFail m => String -> m String
parseEscapes str = case listToMaybe (readP_to_S (many' lexChar) str) of
  Just (result, "") -> pure result
  Just (_, rest) -> fail $ case rest of
      '\\':rest' -> "Failed to parse character escape '\\"
        <> takeWhile (\c -> not (isSpace c) && c /= '\\') rest' <> "'"
      -- the next case shouldn't happen since 'lexChar' can only fail on escapes
      _ -> "Failed to parse string with escapes"
    <> " at input position " <> show (length str - length rest)
  -- the last case shouldn't happen since parser will happily parse zero characters
  _ -> fail $ "Failed to parse string with escapes: " <> str

many' :: ReadP a -> ReadP [a]
many' p = liftM2 (:) p (many' p) <++ pure []

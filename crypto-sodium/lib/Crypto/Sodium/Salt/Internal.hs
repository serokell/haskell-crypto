-- SPDX-FileCopyrightText: 2021 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internal utilities for "Crypto.Sodium.Salt".
module Crypto.Sodium.Salt.Internal
  ( parseEscapes
  ) where

import Data.Maybe (listToMaybe)
import Text.ParserCombinators.ReadP (eof, readP_to_S, many)
import Text.Read.Lex (lexChar)

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

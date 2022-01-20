-- SPDX-FileCopyrightText: 2022 Serokell
--
-- SPDX-License-Identifier: MPL-2.0
{-# LANGUAGE DerivingStrategies #-}

module Test.Crypto.Sodium.Salt.Internal where

import Test.HUnit ((@?=), Assertion)

import Crypto.Sodium.Salt.Internal (parseEscapes)

newtype ErrM a = ErrM (Either String a)
  deriving stock (Show, Eq)
  deriving newtype (Functor, Applicative, Monad)

instance MonadFail ErrM where
  fail = ErrM . Left

ok :: a -> ErrM a
ok = ErrM . Right

err :: String -> ErrM a
err = ErrM . Left

unit_parseEscapes_noEscapes, unit_parseEscapes_goodEscapes, unit_parseEscapes_emptyString,
  unit_parseEscapes_badEscape, unit_parseEscapes_badEscapeMidLine,
  unit_parseEscapes_emptyEscape :: Assertion
unit_parseEscapes_noEscapes =
  parseEscapes "no escapes" @?= ok "no escapes"
unit_parseEscapes_goodEscapes =
  parseEscapes "\\123\\456" @?= ok "\123\456"
unit_parseEscapes_emptyString =
  parseEscapes "" @?= ok ""
unit_parseEscapes_badEscape =
  parseEscapes "\\err" @?= err "Failed to parse character escape '\\err' at input position 0"
unit_parseEscapes_badEscapeMidLine =
  parseEscapes "some text \\somearbitrarystring other text"
    @?= err "Failed to parse character escape '\\somearbitrarystring' at input position 10"
unit_parseEscapes_emptyEscape =
  parseEscapes "\\" @?= err "Failed to parse character escape '\\' at input position 0"

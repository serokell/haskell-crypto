-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | 'ByteArray' with length known at compile time.
module Data.ByteArray.Sized
  ( module M
  ) where

import Data.ByteArray.Sized.Internal as M (OfLength, hasRightLength)

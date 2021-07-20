-- SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
--
-- SPDX-License-Identifier: MPL-2.0

module Test.Data.SensitiveBytes where

import qualified Data.SensitiveBytes as SB


unit_nop :: IO ()
unit_nop = SB.withSecureMemory $ SB.withSensitiveBytes 128 (\_ptr -> pure ())

unit_unaligned :: IO ()
unit_unaligned = SB.withSecureMemory $ SB.withSensitiveBytes 126 (\_ptr -> pure ())

unit_withSecureMemory_twice :: IO ()
unit_withSecureMemory_twice
  = SB.withSecureMemory
  $ SB.withSecureMemory  -- this has to be fine
  $ SB.withSensitiveBytes 128 (\_ptr -> pure ())

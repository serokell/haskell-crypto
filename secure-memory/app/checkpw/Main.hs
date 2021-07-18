-- SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
--
-- SPDX-License-Identifier: MPL-2.0

module Main (main) where

import Data.ByteArray (constEq)
import Data.SensitiveBytes (withSecureMemory)
import Data.SensitiveBytes.IO (withUserPassword)


main :: IO ()
main = withSecureMemory $ do
  withUserPassword 128 (Just "Password: ") $ \pw1 ->
    withUserPassword 128 (Just "Repeat password: ") $ \pw2 ->
      if pw1 `constEq` pw2
      then putStrLn "You are super!"
      else putStrLn "Passwords do not match."

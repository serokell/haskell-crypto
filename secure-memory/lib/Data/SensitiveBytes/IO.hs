-- SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
--
-- SPDX-License-Identifier: MPL-2.0

-- | Reading and writing sensitive data.
module Data.SensitiveBytes.IO
  ( withUserPassword
  ) where

import Prelude hiding (length)

import Control.Exception.Safe (MonadMask)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import System.IO (stdin, stdout)

import Data.SensitiveBytes (WithSecureMemory)
import Data.SensitiveBytes.Internal (SensitiveBytes (..), resized, withSensitiveBytes)
import Data.SensitiveBytes.IO.Internal.Password (readPassword)

-- | Ask the user to enter their password and read it securely.
--
-- “Securely” means “following all the best pracrices”, such as:
--
-- * Disable echoing the entered characters back to the terminal.
-- * Enable some sort of secure input mode, if the OS supports it.
-- * Store it in a secure region of memory.
--
-- Since this function reads the data into securely allocated memory,
-- which is very expensive to allocate, it needs to know the maximum
-- possible length of the password to be read.
-- If the user enters something longer, it will be silently discarded
-- (similar to @readpassphrase@ on BSD).
-- In the future it is possible that this limitation will be removed
-- at the cost of performing multiple expensive allocations.
--
-- This function always writes prompt to @stdout@ and then reads from @stdin@.
--
-- Example:
--
-- @
-- 'Data.SensitiveBytes.withSecureMemory' $
--   'withUserPassword' 128 (Just "Enter your password: ") $ \pw -> do
--     {- hash the @pw@ or do something else with it -}
-- @
withUserPassword
  :: forall m s r. (MonadIO m, MonadMask m, WithSecureMemory)
  => Int  -- ^ Maximum possible length of the password to read (in bytes).
  -> Maybe Text  -- ^ Prompt (defaults to "Password: ").
  -> (SensitiveBytes s -> m r)  -- ^ Action to perform with the password.
  -> m r
withUserPassword maxLength mprompt act =
    withSensitiveBytes allocSize $ \sb@SensitiveBytes{ bufPtr } -> do
      size <- liftIO $ readPassword stdin stdout prompt bufPtr allocSize
      act (resized size sb)
  where
    defaultPrompt = "Password: "
    prompt = fromMaybe defaultPrompt mprompt
    allocSize = maxLength  -- the C function does not null-terminate the string

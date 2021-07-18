-- SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
--
-- SPDX-License-Identifier: MPL-2.0

-- | The sensitive data type.
--
-- A typical usage looks something like this:
--
-- @
-- import Data.SensitiveBytes (SensitiveBytes, withSecureMemory, withSensitiveBytes)
--
-- your_function = 'withSecureMemory' $ do
--  {- some optional initialisation -}
--  'withSensitiveBytes' 128 $ \sb -> do
--    {- work with sb using its 'Data.ByteArray.ByteArrayAccess' instance -}
-- @
--
-- Note that 'withSensitiveBytes' can only be called withing a code block
-- passed to 'withSecureMemory' and its type will prevent your from doing
-- otherwise.
--
-- You will typically read sensitive data into 'SensitiveBytes' using functions
-- in "Data.SensitiveBytes.IO" and then pass to some other function that
-- will work with it using the 'Data.ByteArray.ByteArrayAccess' instance. Just make sure
-- the function you pass it to does not copy the data and does not convert
-- it to some other insecure byte-array-like type.
module Data.SensitiveBytes
  ( -- * Library initialisation
    withSecureMemory
  , WithSecureMemory
  , SecureMemoryInitException

    -- * Allocation
  , SensitiveBytes
  , withSensitiveBytes
  , SensitiveBytesAllocException
  ) where

import Data.SensitiveBytes.Internal

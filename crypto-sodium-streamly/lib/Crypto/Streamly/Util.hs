-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Utilities for working with @streamly@.
module Crypto.Streamly.Util
  ( mapLastSpecialM
  ) where

-- import Control.Monad.Trans.Class (lift)
import Streamly.Prelude (MonadAsync, SerialT)

import qualified Streamly.Internal.Data.SVar as SD
import qualified Streamly.Internal.Data.Stream.StreamD as SD
-- import qualified Streamly.Prelude as S


-- | Like @mapM@ but applies a different function to the last item.
mapLastSpecialM
  :: forall m a b. MonadAsync m
  => m ()  -- ^ What to do if the stream is empty.
  -> (Bool -> a -> m b)  -- ^ Function to map over items. @True@ means last.
  -> SerialT m a -> SerialT m b
{-
 - This doesn’t work: https://github.com/composewell/streamly/issues/720
 -
mapLastSpecialM empty f = go
  where
    go :: SerialT m a -> SerialT m b
    go stream = lift (S.uncons stream) >>= \case
      Nothing -> lift empty
      Just (x, rest) -> lift (S.null rest) >>= \case
        False -> S.yieldM (f False x) <> go rest
        True -> S.yieldM (f True x)
-}
mapLastSpecialM empty f
  = SD.fromStreamD . mapLastSpecialMD empty f . SD.toStreamD

data MapLastSpecialState a s
  = Empty s
  | Stashed a s
  | Done

mapLastSpecialMD
  :: forall m a b. MonadAsync m
  => m ()  -- ^ What to do if the stream is empty.
  -> (Bool -> a -> m b)  -- ^ Function to map over items. @True@ means last.
  -> SD.Stream m a -> SD.Stream m b
mapLastSpecialMD empty f (SD.Stream step state) = SD.Stream step' (Empty state)
  where
    {-# INLINE[0] step' #-}
    step' _ Done = pure SD.Stop
    step' gst (Empty s) = do
      r <- step (SD.adaptState gst) s
      case r of
        SD.Stop -> empty *> pure SD.Stop
        SD.Skip s' -> pure $ SD.Skip (Empty s')
        SD.Yield a s' -> pure $ SD.Skip (Stashed a s')
    step' gst (Stashed a s) = do
      r <- step (SD.adaptState gst) s
      case r of
        SD.Stop -> SD.Yield <$> f True a <*> pure Done
        SD.Skip s' -> pure $ SD.Skip (Stashed a s')
        SD.Yield a' s' -> SD.Yield <$> f False a <*> pure (Stashed a' s')

{-|
  Module      : Auth.Biscuit.Timer
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
  Maintainer  : clement@delafargue.name
  Helper function making sure an IO action runs in an alloted time
-}
module Auth.Biscuit.Timer
  ( timerIO
  ) where

import           Control.Concurrent       (threadDelay)
import           Control.Concurrent.Async (race)
import           Control.Exception        (evaluate)

-- | Given a maximum execution time, run the provide action, and
-- fail (by returning `Nothing`) if it takes too much time.
-- Else, the action result is returned in a `Just`
timerIO :: Int
        -> a
        -> IO (Maybe a)
timerIO timeout job = do
  let watchDog = threadDelay timeout
  result <- race watchDog $ evaluate job
  pure $ case result of
    Left _  -> Nothing
    Right a -> Just a


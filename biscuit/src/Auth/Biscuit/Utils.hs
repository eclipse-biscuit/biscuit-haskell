{-# LANGUAGE CPP #-}

-- |
--  Module      : Auth.Biscuit.Utils
--  Copyright   : © Clément Delafargue, 2021
--  License     : BSD-3-Clause
--  Maintainer  : clement@delafargue.name
module Auth.Biscuit.Utils
  ( maybeToRight,
    rightToMaybe,
    encodeHex,
    encodeHex',
    decodeHex,
    anyM,
    allM,
    setFilterM,
    foldMapM,
    mapMaybeM,
  )
where

#if MIN_VERSION_base16(1,0,0)
import qualified Data.Base16.Types      as Hex
#endif
import           Data.Bool              (bool)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString.Base16 as Hex
import           Data.Maybe             (maybeToList)
import           Data.Monoid            (All (..), Any (..))
import           Data.Set               (Set)
import qualified Data.Set               as Set
import           Data.Text              (Text)

encodeHex :: ByteString -> Text
#if MIN_VERSION_base16(1,0,0)
encodeHex = Hex.extractBase16 . Hex.encodeBase16
#else
encodeHex = Hex.encodeBase16
#endif

encodeHex' :: ByteString -> ByteString
#if MIN_VERSION_base16(1,0,0)
encodeHex' = Hex.extractBase16 . Hex.encodeBase16'
#else
encodeHex' = Hex.encodeBase16'
#endif

decodeHex :: ByteString -> Either Text ByteString
#if MIN_VERSION_base16(1,0,0)
decodeHex = Hex.decodeBase16Untyped
#else
decodeHex = Hex.decodeBase16
#endif

-- | Exactly like `maybeToRight` from the `either` package,
-- but without the dependency footprint
maybeToRight :: b -> Maybe a -> Either b a
maybeToRight b = maybe (Left b) Right

-- | Exactly like `rightToMaybe` from the `either` package,
-- but without the dependency footprint
rightToMaybe :: Either b a -> Maybe a
rightToMaybe = either (const Nothing) Just

anyM :: (Foldable t, Monad m) => (a -> m Bool) -> t a -> m Bool
anyM f = fmap getAny . foldMapM (fmap Any . f)

allM :: (Foldable t, Monad m) => (a -> m Bool) -> t a -> m Bool
allM f = fmap getAll . foldMapM (fmap All . f)

setFilterM :: (Ord a, Monad m) => (a -> m Bool) -> Set a -> m (Set a)
setFilterM p = foldMapM (\a -> bool mempty (Set.singleton a) <$> p a)

-- from Relude
foldMapM :: (Monoid b, Monad m, Foldable f) => (a -> m b) -> f a -> m b
foldMapM f xs = foldr step return xs mempty
  where
    step x r z = f x >>= \y -> r $! z `mappend` y
{-# INLINE foldMapM #-}

mapMaybeM :: (Monad m) => (a -> m (Maybe b)) -> [a] -> m [b]
mapMaybeM f = foldMapM (fmap maybeToList . f)

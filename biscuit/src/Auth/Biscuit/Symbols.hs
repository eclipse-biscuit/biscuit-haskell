{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedLists            #-}
{-# LANGUAGE OverloadedStrings          #-}
{-|
  Module      : Auth.Biscuit.Symbols
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
  Maintainer  : clement@delafargue.name
  Symbol management logic for biscuit serialization
-}
module Auth.Biscuit.Symbols
  ( Symbols
  , BlockSymbols
  , ReverseSymbols
  , SymbolRef (..)
  , PublicKeyRef (..)
  , getSymbol
  , getPublicKey'
  , addSymbols
  , addFromBlock
  , registerNewSymbols
  , registerNewPublicKeys
  , reverseSymbols
  , getSymbolList
  , getPkList
  , getPkTable
  , getSymbolCode
  , getPublicKeyCode
  , newSymbolTable
  ) where

import           Auth.Biscuit.Crypto (PublicKey)
import           Data.Int            (Int64)
import           Data.List           ((\\))
import           Data.Map            (Map, elems, (!?))
import qualified Data.Map            as Map
import           Data.Set            (Set, difference, union)
import qualified Data.Set            as Set
import           Data.Text           (Text)

import           Auth.Biscuit.Utils  (maybeToRight)

newtype SymbolRef = SymbolRef { getSymbolRef :: Int64 }
  deriving stock (Eq, Ord)
  deriving newtype (Enum)

instance Show SymbolRef where
  show = ("#" <>) . show . getSymbolRef

newtype PublicKeyRef = PublicKeyRef { getPublicKeyRef :: Int64 }
  deriving stock (Eq, Ord)
  deriving newtype (Enum)

instance Show PublicKeyRef where
  show = ("#" <>) . show . getPublicKeyRef

data Symbols = Symbols
  { symbols    :: Map SymbolRef Text
  , publicKeys :: Map PublicKeyRef PublicKey
  } deriving stock (Eq, Show)

data BlockSymbols = BlockSymbols
  { blockSymbols    :: Map SymbolRef Text
  , blockPublicKeys :: Map PublicKeyRef PublicKey
  } deriving stock (Eq, Show)

instance Semigroup BlockSymbols where
  b <> b' = BlockSymbols
              { blockSymbols = blockSymbols b <> blockSymbols b'
              , blockPublicKeys = blockPublicKeys b <> blockPublicKeys b'
              }

data ReverseSymbols = ReverseSymbols
  { reverseSymbolMap    :: Map Text SymbolRef
  , reversePublicKeyMap :: Map PublicKey PublicKeyRef
  }
  deriving stock (Eq, Show)

instance Semigroup ReverseSymbols where
  b <> b' = ReverseSymbols
              { reverseSymbolMap = reverseSymbolMap b <> reverseSymbolMap b'
              , reversePublicKeyMap = reversePublicKeyMap b <> reversePublicKeyMap b'
              }

getNextOffset :: Symbols -> SymbolRef
getNextOffset (Symbols m _) =
  SymbolRef $ fromIntegral $ 1024 + (Map.size m - Map.size commonSymbols)

getNextPublicKeyOffset :: Symbols -> PublicKeyRef
getNextPublicKeyOffset (Symbols _ m) =
  PublicKeyRef $ fromIntegral $ Map.size m

getSymbol :: Symbols -> SymbolRef -> Either String Text
getSymbol (Symbols m _) i =
  maybeToRight ("Missing symbol at id " <> show i) $ m !? i

getPublicKey' :: Symbols -> PublicKeyRef -> Either String PublicKey
getPublicKey' (Symbols _ m) i =
  maybeToRight ("Missing symbol at id " <> show i) $ m !? i

-- | Given already existing symbols and a set of symbols used in a block,
-- compute the symbol table carried by this specific block
addSymbols :: Symbols -> Set Text -> Set PublicKey -> BlockSymbols
addSymbols s@(Symbols sm pkm) bSymbols pks =
  let existingSymbols = Set.fromList (elems commonSymbols) `union` Set.fromList (elems sm)
      newSymbols = Set.toList $ bSymbols `difference` existingSymbols
      starting = getNextOffset s
      existingPks = Set.fromList (elems pkm)
      newPks = Set.toList $ pks `difference` existingPks
      startingPk = getNextPublicKeyOffset s
   in BlockSymbols
        { blockSymbols = Map.fromList (zip [starting..] newSymbols)
        , blockPublicKeys = Map.fromList (zip [startingPk..] newPks)
        }

getSymbolList :: BlockSymbols -> [Text]
getSymbolList (BlockSymbols m _) = Map.elems m

getPkList :: BlockSymbols -> [PublicKey]
getPkList (BlockSymbols _ m) = Map.elems m

getPkTable :: Symbols -> [PublicKey]
getPkTable (Symbols _ m) = Map.elems m

newSymbolTable :: Symbols
newSymbolTable = Symbols commonSymbols Map.empty

-- | Given the symbol table of a protobuf block, update the provided symbol table
addFromBlock :: Symbols -> BlockSymbols -> Symbols
addFromBlock (Symbols sm pkm) (BlockSymbols bsm bpkm) =
   Symbols
     { symbols = sm <> bsm
     , publicKeys = pkm <> bpkm
     }

registerNewSymbols :: [Text] -> Symbols -> Symbols
registerNewSymbols newSymbols s@Symbols{symbols} =
  let newSymbolsMap = Map.fromList $ zip [getNextOffset s..] newSymbols
   in s { symbols = symbols <> newSymbolsMap }

registerNewPublicKeys :: [PublicKey] -> Symbols -> Symbols
registerNewPublicKeys newPks s@Symbols{publicKeys} =
  let newPkMap = Map.fromList $ zip [getNextPublicKeyOffset s..] (newPks \\ elems publicKeys)
   in s { publicKeys = publicKeys <> newPkMap }

-- | Reverse a symbol table
reverseSymbols :: Symbols -> ReverseSymbols
reverseSymbols (Symbols sm pkm) =
  let swap (a,b) = (b,a)
      reverseMap :: (Ord a, Ord b) => Map a b -> Map b a
      reverseMap = Map.fromList . fmap swap . Map.toList
   in ReverseSymbols
       { reverseSymbolMap = reverseMap sm
       , reversePublicKeyMap = reverseMap pkm
       }

-- | Given a reverse symbol table (symbol refs indexed by their textual
-- representation), turn textual representations into symbol refs.
-- This function is partial, the reverse table is guaranteed to
-- contain the expected textual symbols.
getSymbolCode :: ReverseSymbols -> Text -> SymbolRef
getSymbolCode (ReverseSymbols rm _) t = rm Map.! t

getPublicKeyCode :: ReverseSymbols -> PublicKey -> Int64
getPublicKeyCode (ReverseSymbols _ rm) t = getPublicKeyRef $ rm Map.! t

-- | The common symbols defined in the biscuit spec
commonSymbols :: Map SymbolRef Text
commonSymbols = Map.fromList $ zip [SymbolRef 0..]
  [ "read"
  , "write"
  , "resource"
  , "operation"
  , "right"
  , "time"
  , "role"
  , "owner"
  , "tenant"
  , "namespace"
  , "user"
  , "team"
  , "service"
  , "admin"
  , "email"
  , "group"
  , "member"
  , "ip_address"
  , "client"
  , "client_ip"
  , "domain"
  , "path"
  , "version"
  , "cluster"
  , "node"
  , "hostname"
  , "nonce"
  , "query"
  ]

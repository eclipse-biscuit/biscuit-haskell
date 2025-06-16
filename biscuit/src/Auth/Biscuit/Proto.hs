{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-|
  Module      : Auth.Biscuit.Proto
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
  Maintainer  : clement@delafargue.name
  Haskell data structures mapping the biscuit protobuf definitions
-}

module Auth.Biscuit.Proto
  ( Biscuit (..)
  , SignedBlock (..)
  , PublicKey (..)
  , Algorithm (..)
  , ExternalSig (..)
  , Proof (..)
  , Block (..)
  , Scope (..)
  , ScopeType (..)
  , FactV2 (..)
  , RuleV2 (..)
  , CheckKind (..)
  , CheckV2 (..)
  , PredicateV2 (..)
  , TermV2 (..)
  , ExpressionV2 (..)
  , TermSet (..)
  , TermArray (..)
  , TermMap (..)
  , MapKey (..)
  , MapEntry (..)
  , Empty (..)
  , Op (..)
  , OpUnary (..)
  , UnaryKind (..)
  , OpBinary (..)
  , BinaryKind (..)
  , OpClosure (..)
  , ThirdPartyBlockContents (..)
  , ThirdPartyBlockRequest (..)
  , getField
  , putField
  , decodeBlockList
  , decodeBlock
  , encodeBlockList
  , encodeBlock
  , decodeThirdPartyBlockRequest
  , decodeThirdPartyBlockContents
  , encodeThirdPartyBlockRequest
  , encodeThirdPartyBlockContents
  ) where

import           Data.ByteString      (ByteString)
import           Data.Int
import           Data.ProtocolBuffers
import           Data.Serialize
import           Data.Text
import           GHC.Generics         (Generic)

data Biscuit = Biscuit
  { rootKeyId :: Optional 1 (Value Int32)
  , authority :: Required 2 (Message SignedBlock)
  , blocks    :: Repeated 3 (Message SignedBlock)
  , proof     :: Required 4 (Message Proof)
  } deriving (Generic, Show)
    deriving anyclass (Decode, Encode)

data Proof =
    ProofSecret    (Required 1 (Value ByteString))
  | ProofSignature (Required 2 (Value ByteString))
  deriving (Generic, Show)
  deriving anyclass (Decode, Encode)

data ExternalSig = ExternalSig
  { signature :: Required 1 (Value ByteString)
  , publicKey :: Required 2 (Message PublicKey)
  }
  deriving (Generic, Show)
  deriving anyclass (Decode, Encode)

data SignedBlock = SignedBlock
  { block       :: Required 1 (Value ByteString)
  , nextKey     :: Required 2 (Message PublicKey)
  , signature   :: Required 3 (Value ByteString)
  , externalSig :: Optional 4 (Message ExternalSig)
  , version     :: Optional 5 (Value Int32)
  }
  deriving (Generic, Show)
  deriving anyclass (Decode, Encode)

data Algorithm = Ed25519
  deriving stock (Show, Enum, Bounded)

data PublicKey = PublicKey
  { algorithm :: Required 1 (Enumeration Algorithm)
  , key       :: Required 2 (Value ByteString)
  }
  deriving (Generic, Show)
  deriving anyclass (Decode, Encode)

data Block = Block {
    symbols   :: Repeated 1 (Value Text)
  , context   :: Optional 2 (Value Text)
  , version   :: Optional 3 (Value Int32)
  , facts_v2  :: Repeated 4 (Message FactV2)
  , rules_v2  :: Repeated 5 (Message RuleV2)
  , checks_v2 :: Repeated 6 (Message CheckV2)
  , scope     :: Repeated 7 (Message Scope)
  , pksTable  :: Repeated 8 (Message PublicKey)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data ScopeType =
    ScopeAuthority
  | ScopePrevious
  deriving stock (Show, Enum, Bounded)

data Scope =
    ScType  (Required 1 (Enumeration ScopeType))
  | ScBlock (Required 2 (Value Int64))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype FactV2 = FactV2
  { predicate :: Required 1 (Message PredicateV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data RuleV2 = RuleV2
  { head        :: Required 1 (Message PredicateV2)
  , body        :: Repeated 2 (Message PredicateV2)
  , expressions :: Repeated 3 (Message ExpressionV2)
  , scope       :: Repeated 4 (Message Scope)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data CheckKind =
    CheckOne
  | CheckAll
  | Reject
  deriving stock (Show, Enum, Bounded)

data CheckV2 = CheckV2
  { queries :: Repeated 1 (Message RuleV2)
  , kind    :: Optional 2 (Enumeration CheckKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data PredicateV2 = PredicateV2
  { name  :: Required 1 (Value Int64)
  , terms :: Repeated 2 (Message TermV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data TermV2 =
    TermVariable  (Required 1  (Value Int64))
  | TermInteger   (Required 2  (Value Int64))
  | TermString    (Required 3  (Value Int64))
  | TermDate      (Required 4  (Value Int64))
  | TermBytes     (Required 5  (Value ByteString))
  | TermBool      (Required 6  (Value Bool))
  | TermTermSet   (Required 7  (Message TermSet))
  | TermNull      (Required 8  (Message Empty))
  | TermTermArray (Required 9  (Message TermArray))
  | TermTermMap   (Required 10 (Message TermMap))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data Empty = Empty {}
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)


newtype TermSet = TermSet
  { set :: Repeated 1 (Message TermV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype TermArray = TermArray
  { array :: Repeated 1 (Message TermV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data MapKey =
    MapKeyInt    (Required 1 (Value Int64))
  | MapKeyString (Required 2 (Value Int64))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data MapEntry = MapEntry
  { key   ::   Required 1 (Message MapKey)
  , value :: Required 2 (Message TermV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype TermMap = TermMap
  { map :: Repeated 1 (Message MapEntry)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype ExpressionV2 = ExpressionV2
  { ops :: Repeated 1 (Message Op)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data Op =
    OpVValue  (Required 1 (Message TermV2))
  | OpVUnary  (Required 2 (Message OpUnary))
  | OpVBinary (Required 3 (Message OpBinary))
  | OpVClosure (Required 4 (Message OpClosure))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data UnaryKind = Negate | Parens | Length | TypeOf | UnaryFfi
  deriving stock (Show, Enum, Bounded)

data OpUnary = OpUnary
  { kind    :: Required 1 (Enumeration UnaryKind)
  , ffiName :: Optional 2 (Value Int64)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data BinaryKind =
    LessThan
  | GreaterThan
  | LessOrEqual
  | GreaterOrEqual
  | Equal
  | Contains
  | Prefix
  | Suffix
  | Regex
  | Add
  | Sub
  | Mul
  | Div
  | And
  | Or
  | Intersection
  | Union
  | BitwiseAnd
  | BitwiseOr
  | BitwiseXor
  | NotEqual
  | HeterogeneousEqual
  | HeterogeneousNotEqual
  | LazyAnd
  | LazyOr
  | All
  | Any
  | Get
  | BinaryFfi
  | Try
  deriving stock (Show, Enum, Bounded)

data OpBinary = OpBinary
  { kind    :: Required 1 (Enumeration BinaryKind)
  , ffiName :: Optional 2 (Value Int64)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data OpClosure = OpClosure
  { params :: Repeated 1 (Value Int64)
  , ops    :: Repeated 2 (Message Op)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

decodeBlockList :: ByteString
                -> Either String Biscuit
decodeBlockList = runGet decodeMessage

decodeBlock :: ByteString
            -> Either String Block
decodeBlock = runGet decodeMessage

encodeBlockList :: Biscuit -> ByteString
encodeBlockList = runPut . encodeMessage

encodeBlock :: Block -> ByteString
encodeBlock = runPut . encodeMessage

encodeThirdPartyBlockRequest :: ThirdPartyBlockRequest -> ByteString
encodeThirdPartyBlockRequest = runPut . encodeMessage

encodeThirdPartyBlockContents :: ThirdPartyBlockContents -> ByteString
encodeThirdPartyBlockContents = runPut . encodeMessage

decodeThirdPartyBlockRequest :: ByteString -> Either String ThirdPartyBlockRequest
decodeThirdPartyBlockRequest = runGet decodeMessage

decodeThirdPartyBlockContents :: ByteString -> Either String ThirdPartyBlockContents
decodeThirdPartyBlockContents = runGet decodeMessage

data ThirdPartyBlockRequest
  = ThirdPartyBlockRequest
  { legacyPk :: Optional 1 (Message PublicKey)
  , pkTable  :: Repeated 2 (Message PublicKey)
  , prevSig  :: Required 3 (Value ByteString)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data ThirdPartyBlockContents
  = ThirdPartyBlockContents
  { payload     :: Required 1 (Value ByteString)
  , externalSig :: Required 2 (Message ExternalSig)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

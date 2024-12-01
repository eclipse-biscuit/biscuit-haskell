{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeApplications  #-}
{-|
  Module      : Auth.Biscuit.Utils
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
  Maintainer  : clement@delafargue.name
  Conversion functions between biscuit components and protobuf-encoded components
-}
module Auth.Biscuit.ProtoBufAdapter
  ( Symbols
  , buildSymbolTable
  , pbToBlock
  , blockToPb
  , pbToSignedBlock
  , signedBlockToPb
  , pbToProof
  , pbToThirdPartyBlockRequest
  , thirdPartyBlockRequestToPb
  , pbToThirdPartyBlockContents
  , thirdPartyBlockContentsToPb
  ) where

import           Control.Monad            (unless, when)
import           Control.Monad.State      (StateT, get, lift, modify)
import           Data.ByteString          (ByteString)
import           Data.Int                 (Int64)
import qualified Data.List.NonEmpty       as NE
import           Data.Maybe               (isJust, isNothing)
import qualified Data.Set                 as Set
import qualified Data.Text                as T
import           Data.Time                (UTCTime)
import           Data.Time.Clock.POSIX    (posixSecondsToUTCTime,
                                           utcTimeToPOSIXSeconds)
import           Data.Void                (absurd)
import           GHC.Records              (getField)
import           Validation               (Validation (..))

import qualified Auth.Biscuit.Crypto      as Crypto
import           Auth.Biscuit.Datalog.AST
import qualified Auth.Biscuit.Proto       as PB
import           Auth.Biscuit.Symbols
import           Auth.Biscuit.Utils       (maybeToRight)

buildSymbolTable :: Symbols -> Block -> BlockSymbols
buildSymbolTable existingSymbols block =
  let allSymbols = listSymbolsInBlock block
      allKeys = listPublicKeysInBlock block
   in addSymbols existingSymbols allSymbols allKeys

pbToPublicKey :: PB.PublicKey -> Either String Crypto.PublicKey
pbToPublicKey PB.PublicKey{..} =
  let keyBytes = PB.getField key
      parseKey = Crypto.readEd25519PublicKey
   in case PB.getField algorithm of
        PB.Ed25519 -> maybeToRight "Invalid ed25519 public key" $ parseKey keyBytes

pbToOptionalSignature :: PB.ExternalSig -> Either String (Crypto.Signature, Crypto.PublicKey)
pbToOptionalSignature PB.ExternalSig{..} = do
  let sig = Crypto.signature $ PB.getField signature
  pk  <- pbToPublicKey $ PB.getField publicKey
  pure (sig, pk)

-- | Parse a protobuf signed block into a signed biscuit block
pbToSignedBlock :: PB.SignedBlock -> Either String Crypto.SignedBlock
pbToSignedBlock PB.SignedBlock{..} = do
  let sig = Crypto.signature $ PB.getField signature
  mSig <- traverse pbToOptionalSignature $ PB.getField externalSig
  pk  <- pbToPublicKey $ PB.getField nextKey
  let sigVersion = fromIntegral <$> PB.getField version
  pure ( PB.getField block
       , sig
       , pk
       , mSig
       , sigVersion
       )

publicKeyToPb :: Crypto.PublicKey -> PB.PublicKey
publicKeyToPb pk = PB.PublicKey
  { algorithm = PB.putField PB.Ed25519
  , key = PB.putField $ Crypto.pkBytes pk
  }

externalSigToPb :: (Crypto.Signature, Crypto.PublicKey) -> PB.ExternalSig
externalSigToPb (sig, pk) = PB.ExternalSig
  { signature = PB.putField $ Crypto.sigBytes sig
  , publicKey = PB.putField $ publicKeyToPb pk
  }

signedBlockToPb :: Crypto.SignedBlock -> PB.SignedBlock
signedBlockToPb (block, sig, pk, eSig, sigVersion) = PB.SignedBlock
  { block = PB.putField block
  , signature = PB.putField $ Crypto.sigBytes sig
  , nextKey = PB.putField $ publicKeyToPb pk
  , externalSig = PB.putField $ externalSigToPb <$> eSig
  , version = PB.putField $ fromIntegral <$> sigVersion
  }

pbToProof :: PB.Proof -> Either String (Either Crypto.Signature Crypto.SecretKey)
pbToProof (PB.ProofSignature rawSig) = Left  <$> Right (Crypto.signature $ PB.getField rawSig)
pbToProof (PB.ProofSecret    rawPk)  = Right <$> maybeToRight "Invalid public key proof" (Crypto.readEd25519SecretKey $ PB.getField rawPk)

pbToBlock :: Maybe Crypto.PublicKey -> PB.Block -> StateT Symbols (Either String) Block
pbToBlock ePk PB.Block{..} = do
  blockPks <- lift $ traverse pbToPublicKey $ PB.getField pksTable
  let blockSymbols = PB.getField symbols
  -- third party blocks use an isolated symbol table,
  -- but use the global public keys table:
  --   symbols defined in 3rd party blocks are not visible
  --   to following blocks, but public keys are
  when (isNothing ePk) $ do
    modify (registerNewSymbols blockSymbols)
    modify (registerNewPublicKeys blockPks)
  currentSymbols <- get

  let symbolsForCurrentBlock =
        -- third party blocks use an isolated symbol and public keys table,
        --   3rd party blocks don't see previously defined
        --   symbols or public keys
        if isNothing ePk then currentSymbols
                         else registerNewPublicKeys blockPks $ registerNewSymbols blockSymbols newSymbolTable
  let bContext = PB.getField context
      bVersion = PB.getField version
  lift $ do
    let s = symbolsForCurrentBlock
    bFacts <- traverse (pbToFact s) $ PB.getField facts_v2
    bRules <- traverse (pbToRule s) $ PB.getField rules_v2
    bChecks <- traverse (pbToCheck s) $ PB.getField checks_v2
    bScope <- Set.fromList <$> traverse (pbToScope s) (PB.getField scope)
    let v6Plus = any isReject bChecks
        v5Plus = isJust ePk
        v4Plus = not $ and
          [ Set.null bScope
          , all ruleHasNoScope bRules
          , all (queryHasNoScope . cQueries) bChecks
          , all isCheckOne bChecks
          , all ruleHasNoV4Operators bRules
          , all (queryHasNoV4Operators . cQueries) bChecks
          ]
    case (bVersion, v4Plus, v5Plus, v6Plus) of
      (Just 6, _, _, _) -> pure Block {..}
      (Just 5, _, _, True) ->
        Left "Biscuit v6 features are present, but the block version is 5."
      (Just 5, _, _, _) -> pure Block {..}
      (Just 4, _, False, False) -> pure Block {..}
      (Just 4, _, _, True) ->
        Left "Biscuit v6 features are present, but the block version is 4."
      (Just 4, _, True, False) ->
        Left "Biscuit v5 features are present, but the block version is 4."
      (Just 3, False, False, False) -> pure Block {..}
      (Just 3, True, False, False) ->
        Left "Biscuit v4 features are present, but the block version is 3."
      (Just 3, _, True, False) ->
        Left "Biscuit v5 features are present, but the block version is 3."
      (Just 3, _, _, True) ->
        Left "Biscuit v6 features are present, but the block version is 3."
      _ ->
        Left $ "Unsupported biscuit version: " <> maybe "0" show bVersion <> ". Only versions 3 to 6 are supported"

-- | Turn a biscuit block into a protobuf block, for serialization,
-- along with the newly defined symbols
blockToPb :: Bool -> Symbols -> Block -> ((BlockSymbols, Int), PB.Block)
blockToPb hasExternalPk existingSymbols b@Block{..} =
  let v4Plus = not $ and
        [Set.null bScope
        , all ruleHasNoScope bRules
        , all (queryHasNoScope . cQueries) bChecks
        , all isCheckOne bChecks
        , all ruleHasNoV4Operators bRules
        , all (queryHasNoV4Operators . cQueries) bChecks
        ]
      v5Plus = hasExternalPk
      bSymbols = buildSymbolTable existingSymbols b
      s = reverseSymbols $ addFromBlock existingSymbols bSymbols
      symbols   = PB.putField $ getSymbolList bSymbols
      context   = PB.putField bContext
      facts_v2  = PB.putField $ factToPb s <$> bFacts
      rules_v2  = PB.putField $ ruleToPb s <$> bRules
      checks_v2 = PB.putField $ checkToPb s <$> bChecks
      scope     = PB.putField $ scopeToPb s <$> Set.toList bScope
      pksTable   = PB.putField $ publicKeyToPb <$> getPkList bSymbols
      version   =  if | v5Plus    -> 5
                      | v4Plus    -> 4
                      | otherwise -> 3
   in ((bSymbols, version), PB.Block {version = PB.putField $ Just $ fromIntegral version, ..})

pbToFact :: Symbols -> PB.FactV2 -> Either String Fact
pbToFact s PB.FactV2{predicate} = do
  let pbName  = PB.getField $ PB.name  $ PB.getField predicate
      pbTerms = PB.getField $ PB.terms $ PB.getField predicate
  name <- getSymbol s $ SymbolRef pbName
  terms <- traverse (pbToValue s) pbTerms
  pure Predicate{..}

factToPb :: ReverseSymbols -> Fact -> PB.FactV2
factToPb s Predicate{..} =
  let
      predicate = PB.PredicateV2
        { name  = PB.putField $ getSymbolRef $ getSymbolCode s name
        , terms = PB.putField $ valueToPb s <$> terms
        }
   in PB.FactV2{predicate = PB.putField predicate}

pbToRule :: Symbols -> PB.RuleV2 -> Either String Rule
pbToRule s pbRule = do
  let pbHead = PB.getField $ PB.head pbRule
      pbBody = PB.getField $ PB.body pbRule
      pbExpressions = PB.getField $ PB.expressions pbRule
      pbScope = PB.getField $ getField @"scope" pbRule
  rhead       <- pbToPredicate s pbHead
  body        <- traverse (pbToPredicate s) pbBody
  expressions <- traverse (pbToExpression s) pbExpressions
  scope       <- Set.fromList <$> traverse (pbToScope s) pbScope
  case makeRule rhead body expressions scope of
    Failure vs -> Left $ "Unbound variables in rule: " <> T.unpack (T.intercalate ", " $ NE.toList vs)
    Success r  -> pure r

ruleToPb :: ReverseSymbols -> Rule -> PB.RuleV2
ruleToPb s Rule{..} =
  PB.RuleV2
    { head = PB.putField $ predicateToPb s rhead
    , body = PB.putField $ predicateToPb s <$> body
    , expressions = PB.putField $ expressionToPb s <$> expressions
    , scope = PB.putField $ scopeToPb s <$> Set.toList scope
    }

pbToCheck :: Symbols -> PB.CheckV2 -> Either String Check
pbToCheck s PB.CheckV2{queries,kind} = do
  let toCheck Rule{body,expressions,scope} = QueryItem{qBody = body, qExpressions = expressions, qScope = scope}
  rules <- traverse (pbToRule s) $ PB.getField queries
  let cQueries = toCheck <$> rules
  let cKind = case PB.getField kind of
        Just PB.All    -> All
        Just PB.One    -> One
        Just PB.Reject -> Reject
        Nothing        -> One
  pure Check{..}

checkToPb :: ReverseSymbols -> Check -> PB.CheckV2
checkToPb s Check{..} =
  let dummyHead = Predicate "query" []
      toQuery QueryItem{..} =
        ruleToPb s $ Rule { rhead = dummyHead
                          , body = qBody
                          , expressions = qExpressions
                          , scope = qScope
                          }
      pbKind = case cKind of
        One    -> Nothing
        All    -> Just PB.All
        Reject -> Just PB.Reject
   in PB.CheckV2 { queries = PB.putField $ toQuery <$> cQueries
                 , kind = PB.putField pbKind
                 }

pbToScope :: Symbols -> PB.Scope -> Either String RuleScope
pbToScope s = \case
  PB.ScType e       -> case PB.getField e of
    PB.ScopeAuthority -> Right OnlyAuthority
    PB.ScopePrevious  -> Right Previous
  PB.ScBlock pkRef ->
    BlockId <$> getPublicKey' s (PublicKeyRef $ PB.getField pkRef)

scopeToPb :: ReverseSymbols -> RuleScope -> PB.Scope
scopeToPb s = \case
  OnlyAuthority -> PB.ScType $ PB.putField PB.ScopeAuthority
  Previous      -> PB.ScType $ PB.putField PB.ScopePrevious
  BlockId pk    -> PB.ScBlock $ PB.putField $ getPublicKeyCode s pk

pbToPredicate :: Symbols -> PB.PredicateV2 -> Either String (Predicate' 'InPredicate 'Representation)
pbToPredicate s pbPredicate = do
  let pbName  = PB.getField $ PB.name  pbPredicate
      pbTerms = PB.getField $ PB.terms pbPredicate
  name <- getSymbol s $ SymbolRef pbName
  terms <- traverse (pbToTerm s) pbTerms
  pure Predicate{..}

predicateToPb :: ReverseSymbols -> Predicate -> PB.PredicateV2
predicateToPb s Predicate{..} =
  PB.PredicateV2
    { name  = PB.putField $ getSymbolRef $ getSymbolCode s name
    , terms = PB.putField $ termToPb s <$> terms
    }

pbTimeToUtcTime :: Int64 -> UTCTime
pbTimeToUtcTime = posixSecondsToUTCTime . fromIntegral

pbToTerm :: Symbols -> PB.TermV2 -> Either String Term
pbToTerm s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable f -> Variable <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

termToPb :: ReverseSymbols -> Term -> PB.TermV2
termToPb s = \case
  Variable n -> PB.TermVariable $ PB.putField $ getSymbolRef $ getSymbolCode s n
  LInteger v -> PB.TermInteger  $ PB.putField $ fromIntegral v
  LString  v -> PB.TermString   $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate    v -> PB.TermDate     $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.TermBytes    $ PB.putField v
  LBool    v -> PB.TermBool     $ PB.putField v
  TermSet vs -> PB.TermTermSet  $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs

  Antiquote v -> absurd v

pbToValue :: Symbols -> PB.TermV2 -> Either String Value
pbToValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable _ -> Left "Variables can't appear in facts"
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

valueToPb :: ReverseSymbols -> Value -> PB.TermV2
valueToPb s = \case
  LInteger v -> PB.TermInteger $ PB.putField $ fromIntegral v
  LString  v -> PB.TermString  $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate    v -> PB.TermDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.TermBytes   $ PB.putField v
  LBool    v -> PB.TermBool    $ PB.putField v
  TermSet vs -> PB.TermTermSet $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs

  Variable v  -> absurd v
  Antiquote v -> absurd v

pbToSetValue :: Symbols -> PB.TermV2 -> Either String (Term' 'WithinSet 'InFact 'Representation)
pbToSetValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString  <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable _ -> Left "Variables can't appear in facts or sets"
  PB.TermTermSet  _ -> Left "Sets can't be nested"

setValueToPb :: ReverseSymbols -> Term' 'WithinSet 'InFact 'Representation -> PB.TermV2
setValueToPb s = \case
  LInteger v  -> PB.TermInteger $ PB.putField $ fromIntegral v
  LString  v  -> PB.TermString  $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate    v  -> PB.TermDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v  -> PB.TermBytes   $ PB.putField v
  LBool    v  -> PB.TermBool    $ PB.putField v

  TermSet   v -> absurd v
  Variable  v -> absurd v
  Antiquote v -> absurd v

pbToExpression :: Symbols -> PB.ExpressionV2 -> Either String Expression
pbToExpression s PB.ExpressionV2{ops} = do
  parsedOps <- traverse (pbToOp s) $ PB.getField ops
  fromStack parsedOps

expressionToPb :: ReverseSymbols -> Expression -> PB.ExpressionV2
expressionToPb s e =
  let ops = opToPb s <$> toStack e
   in PB.ExpressionV2 { ops = PB.putField ops }

pbToOp :: Symbols -> PB.Op -> Either String Op
pbToOp s = \case
  PB.OpVValue v  -> VOp <$> pbToTerm s (PB.getField v)
  PB.OpVUnary v  -> pure . UOp . pbToUnary $ PB.getField v
  PB.OpVBinary v -> pure . BOp . pbToBinary $ PB.getField v

opToPb :: ReverseSymbols -> Op -> PB.Op
opToPb s = \case
  VOp t -> PB.OpVValue  $ PB.putField $ termToPb s t
  UOp o -> PB.OpVUnary  $ PB.putField $ unaryToPb o
  BOp o -> PB.OpVBinary $ PB.putField $ binaryToPb o

pbToUnary :: PB.OpUnary -> Unary
pbToUnary PB.OpUnary{kind} = case PB.getField kind of
  PB.Negate -> Negate
  PB.Parens -> Parens
  PB.Length -> Length

unaryToPb ::  Unary -> PB.OpUnary
unaryToPb = PB.OpUnary . PB.putField . \case
  Negate -> PB.Negate
  Parens -> PB.Parens
  Length -> PB.Length

pbToBinary :: PB.OpBinary -> Binary
pbToBinary PB.OpBinary{kind} = case PB.getField kind of
  PB.LessThan       -> LessThan
  PB.GreaterThan    -> GreaterThan
  PB.LessOrEqual    -> LessOrEqual
  PB.GreaterOrEqual -> GreaterOrEqual
  PB.Equal          -> Equal
  PB.Contains       -> Contains
  PB.Prefix         -> Prefix
  PB.Suffix         -> Suffix
  PB.Regex          -> Regex
  PB.Add            -> Add
  PB.Sub            -> Sub
  PB.Mul            -> Mul
  PB.Div            -> Div
  PB.And            -> And
  PB.Or             -> Or
  PB.Intersection   -> Intersection
  PB.Union          -> Union
  PB.BitwiseAnd     -> BitwiseAnd
  PB.BitwiseOr      -> BitwiseOr
  PB.BitwiseXor     -> BitwiseXor
  PB.NotEqual       -> NotEqual

binaryToPb :: Binary -> PB.OpBinary
binaryToPb = PB.OpBinary . PB.putField . \case
  LessThan       -> PB.LessThan
  GreaterThan    -> PB.GreaterThan
  LessOrEqual    -> PB.LessOrEqual
  GreaterOrEqual -> PB.GreaterOrEqual
  Equal          -> PB.Equal
  Contains       -> PB.Contains
  Prefix         -> PB.Prefix
  Suffix         -> PB.Suffix
  Regex          -> PB.Regex
  Add            -> PB.Add
  Sub            -> PB.Sub
  Mul            -> PB.Mul
  Div            -> PB.Div
  And            -> PB.And
  Or             -> PB.Or
  Intersection   -> PB.Intersection
  Union          -> PB.Union
  BitwiseAnd     -> PB.BitwiseAnd
  BitwiseOr      -> PB.BitwiseOr
  BitwiseXor     -> PB.BitwiseXor
  NotEqual       -> PB.NotEqual

pbToThirdPartyBlockRequest :: PB.ThirdPartyBlockRequest -> Either String Crypto.Signature
pbToThirdPartyBlockRequest PB.ThirdPartyBlockRequest{legacyPk, pkTable, prevSig} = do
  unless (isNothing $ PB.getField legacyPk) $ Left "Public key provided in third-party block request"
  unless (null $ PB.getField pkTable) $ Left "Public key table provided in third-party block request"
  pure . Crypto.signature $ PB.getField prevSig

thirdPartyBlockRequestToPb :: Crypto.Signature -> PB.ThirdPartyBlockRequest
thirdPartyBlockRequestToPb prevSig = PB.ThirdPartyBlockRequest
  { legacyPk = PB.putField Nothing
  , pkTable = PB.putField []
  , prevSig = PB.putField $ Crypto.sigBytes prevSig
  }

pbToThirdPartyBlockContents :: PB.ThirdPartyBlockContents -> Either String (ByteString, Crypto.Signature, Crypto.PublicKey)
pbToThirdPartyBlockContents PB.ThirdPartyBlockContents{payload,externalSig} = do
  (sig, pk) <- pbToOptionalSignature $ PB.getField externalSig
  pure ( PB.getField payload
       , sig
       , pk
       )

thirdPartyBlockContentsToPb :: (ByteString, Crypto.Signature, Crypto.PublicKey) -> PB.ThirdPartyBlockContents
thirdPartyBlockContentsToPb (payload, sig, pk) = PB.ThirdPartyBlockContents
  { PB.payload = PB.putField payload
  , PB.externalSig = PB.putField $ externalSigToPb (sig, pk)
  }


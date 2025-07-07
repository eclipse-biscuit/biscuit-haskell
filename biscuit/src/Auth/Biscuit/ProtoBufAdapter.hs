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
import           Data.Bitraversable       (bitraverse)
import           Data.ByteString          (ByteString)
import           Data.Int                 (Int64)
import qualified Data.List.NonEmpty       as NE
import qualified Data.Map                 as Map
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
    bFacts <- traverse (pbToFact s) $ PB.getField facts
    bRules <- traverse (pbToRule s) $ PB.getField rules
    bChecks <- traverse (pbToCheck s) $ PB.getField checks
    bScope <- Set.fromList <$> traverse (pbToScope s) (PB.getField scope)
    let v6Plus = or
          [ any isReject bChecks
          , not (all predicateHasNoV6Values bFacts)
          , not (all ruleHasNoV6Values bRules)
          , not (all checkHasNoV6Values bChecks)
          ]
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
      v6Plus = or
        [ any isReject bChecks
        , not (all predicateHasNoV6Values bFacts)
        , not (all ruleHasNoV6Values bRules)
        , not (all checkHasNoV6Values bChecks)
        ]
      bSymbols = buildSymbolTable existingSymbols b
      s = reverseSymbols $ addFromBlock existingSymbols bSymbols
      symbols  = PB.putField $ getSymbolList bSymbols
      context  = PB.putField bContext
      facts    = PB.putField $ factToPb s <$> bFacts
      rules    = PB.putField $ ruleToPb s <$> bRules
      checks   = PB.putField $ checkToPb s <$> bChecks
      scope    = PB.putField $ scopeToPb s <$> Set.toList bScope
      pksTable = PB.putField $ publicKeyToPb <$> getPkList bSymbols
      version  =  if | v6Plus    -> 6
                     | v5Plus    -> 5
                     | v4Plus    -> 4
                     | otherwise -> 3
   in ((bSymbols, version), PB.Block {version = PB.putField $ Just $ fromIntegral version, ..})

pbToFact :: Symbols -> PB.Fact -> Either String Fact
pbToFact s PB.Fact{predicate} = do
  let pbName  = PB.getField $ PB.name  $ PB.getField predicate
      pbTerms = PB.getField $ PB.terms $ PB.getField predicate
  name <- getSymbol s $ SymbolRef pbName
  terms <- traverse (pbToValue s) pbTerms
  pure Predicate{..}

factToPb :: ReverseSymbols -> Fact -> PB.Fact
factToPb s Predicate{..} =
  let
      predicate = PB.Predicate
        { name  = PB.putField $ getSymbolRef $ getSymbolCode s name
        , terms = PB.putField $ valueToPb s <$> terms
        }
   in PB.Fact{predicate = PB.putField predicate}

pbToRule :: Symbols -> PB.Rule -> Either String Rule
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

ruleToPb :: ReverseSymbols -> Rule -> PB.Rule
ruleToPb s Rule{..} =
  PB.Rule
    { head = PB.putField $ predicateToPb s rhead
    , body = PB.putField $ predicateToPb s <$> body
    , expressions = PB.putField $ expressionToPb s <$> expressions
    , scope = PB.putField $ scopeToPb s <$> Set.toList scope
    }

pbToCheck :: Symbols -> PB.Check -> Either String Check
pbToCheck s PB.Check{queries,kind} = do
  let toCheck Rule{body,expressions,scope} = QueryItem{qBody = body, qExpressions = expressions, qScope = scope}
  rules <- traverse (pbToRule s) $ PB.getField queries
  let cQueries = toCheck <$> rules
  let cKind = case PB.getField kind of
        Just PB.CheckAll -> CheckAll
        Just PB.CheckOne -> CheckOne
        Just PB.Reject   -> Reject
        Nothing          -> CheckOne
  pure Check{..}

checkToPb :: ReverseSymbols -> Check -> PB.Check
checkToPb s Check{..} =
  let dummyHead = Predicate "query" []
      toQuery QueryItem{..} =
        ruleToPb s $ Rule { rhead = dummyHead
                          , body = qBody
                          , expressions = qExpressions
                          , scope = qScope
                          }
      pbKind = case cKind of
        CheckOne -> Nothing
        CheckAll -> Just PB.CheckAll
        Reject   -> Just PB.Reject
   in PB.Check { queries = PB.putField $ toQuery <$> cQueries
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

pbToPredicate :: Symbols -> PB.Predicate -> Either String (Predicate' 'InPredicate 'Representation)
pbToPredicate s pbPredicate = do
  let pbName  = PB.getField $ PB.name  pbPredicate
      pbTerms = PB.getField $ PB.terms pbPredicate
  name <- getSymbol s $ SymbolRef pbName
  terms <- traverse (pbToTerm s) pbTerms
  pure Predicate{..}

predicateToPb :: ReverseSymbols -> Predicate -> PB.Predicate
predicateToPb s Predicate{..} =
  PB.Predicate
    { name  = PB.putField $ getSymbolRef $ getSymbolCode s name
    , terms = PB.putField $ termToPb s <$> terms
    }

pbTimeToUtcTime :: Int64 -> UTCTime
pbTimeToUtcTime = posixSecondsToUTCTime . fromIntegral

pbToTerm :: Symbols -> PB.Term -> Either String Term
pbToTerm s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable f -> Variable <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)
  PB.TermTermArray f -> TermArray <$> traverse (pbToValue s) (PB.getField . PB.array $ PB.getField f)
  PB.TermTermMap f -> TermMap . Map.fromList <$> traverse (pbToMapEntry s) (PB.getField . PB.map $ PB.getField f)
  PB.TermNull     _ -> pure LNull

termToPb :: ReverseSymbols -> Term -> PB.Term
termToPb s = \case
  Variable n -> PB.TermVariable $ PB.putField $ getSymbolRef $ getSymbolCode s n
  LInteger v -> PB.TermInteger  $ PB.putField $ fromIntegral v
  LString  v -> PB.TermString   $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate    v -> PB.TermDate     $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.TermBytes    $ PB.putField v
  LBool    v -> PB.TermBool     $ PB.putField v
  TermSet vs -> PB.TermTermSet  $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs
  TermArray vs -> PB.TermTermArray $ PB.putField $ PB.TermArray $ PB.putField $ valueToPb s <$> vs
  TermMap vs -> PB.TermTermMap $ PB.putField $ PB.TermMap $ PB.putField $ uncurry (mapEntryToPb s) <$> Map.toList vs
  LNull      -> PB.TermNull     $ PB.putField $ PB.Empty {}

  Antiquote v -> absurd v

mapEntryToPb :: ReverseSymbols -> MapKey -> Value -> PB.MapEntry
mapEntryToPb s k v = PB.MapEntry
  { key = PB.putField $ case k of
      IntKey i    -> PB.MapKeyInt . PB.putField $ fromIntegral i
      StringKey n -> PB.MapKeyString . PB.putField $ getSymbolRef $ getSymbolCode s n
  , value = PB.putField $ valueToPb s v
  }

pbToMapEntry :: Symbols -> PB.MapEntry -> Either String (MapKey, Value)
pbToMapEntry s PB.MapEntry{key,value} = do
  k <- case PB.getField key of
         PB.MapKeyInt i    -> pure . IntKey . fromIntegral $ PB.getField i
         PB.MapKeyString i -> StringKey <$> getSymbol s (SymbolRef $ PB.getField i)
  v <- pbToValue s $ PB.getField value
  pure (k, v)

pbToValue :: Symbols -> PB.Term -> Either String Value
pbToValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable _ -> Left "Variables can't appear in facts"
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)
  PB.TermTermArray f -> TermArray <$> traverse (pbToValue s) (PB.getField . PB.array $ PB.getField f)
  PB.TermTermMap f -> TermMap . Map.fromList <$> traverse (pbToMapEntry s) (PB.getField . PB.map $ PB.getField f)
  PB.TermNull     _ -> pure LNull

valueToPb :: ReverseSymbols -> Value -> PB.Term
valueToPb s = \case
  LInteger v -> PB.TermInteger $ PB.putField $ fromIntegral v
  LString  v -> PB.TermString  $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate    v -> PB.TermDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.TermBytes   $ PB.putField v
  LBool    v -> PB.TermBool    $ PB.putField v
  TermSet vs -> PB.TermTermSet $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs
  TermArray vs -> PB.TermTermArray $ PB.putField $ PB.TermArray $ PB.putField $ valueToPb s <$> vs
  TermMap vs -> PB.TermTermMap $ PB.putField $ PB.TermMap $ PB.putField $ uncurry (mapEntryToPb s) <$> Map.toList vs
  LNull      -> PB.TermNull $ PB.putField PB.Empty

  Variable v  -> absurd v
  Antiquote v -> absurd v

pbToSetValue :: Symbols -> PB.Term -> Either String (Term' 'WithinSet 'InFact 'Representation)
pbToSetValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString  <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermNull     _ -> pure LNull
  PB.TermVariable _ -> Left "Variables can't appear in facts or sets"
  PB.TermTermSet  _ -> Left "Sets can't be nested"
  PB.TermTermArray _ -> Left "Arrays can’t appear in sets"
  PB.TermTermMap _ -> Left "Maps can’t appear in sets"

setValueToPb :: ReverseSymbols -> Term' 'WithinSet 'InFact 'Representation -> PB.Term
setValueToPb s = \case
  LInteger v  -> PB.TermInteger $ PB.putField $ fromIntegral v
  LString  v  -> PB.TermString  $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate    v  -> PB.TermDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v  -> PB.TermBytes   $ PB.putField v
  LBool    v  -> PB.TermBool    $ PB.putField v
  LNull      -> PB.TermNull     $ PB.putField $ PB.Empty {}

  TermSet   v -> absurd v
  TermArray v -> absurd v
  TermMap   v -> absurd v
  Variable  v -> absurd v
  Antiquote v -> absurd v

pbToExpression :: Symbols -> PB.Expression -> Either String Expression
pbToExpression s PB.Expression{ops} = do
  parsedOps <- traverse (pbToOp s) $ PB.getField ops
  fromStack parsedOps

expressionToPb :: ReverseSymbols -> Expression -> PB.Expression
expressionToPb s e =
  let ops = opToPb s <$> toStack e
   in PB.Expression { ops = PB.putField ops }

pbToOp :: Symbols -> PB.Op -> Either String Op
pbToOp s = \case
  PB.OpVValue v  -> VOp <$> pbToTerm s (PB.getField v)
  PB.OpVUnary v  -> UOp <$> pbToUnary s (PB.getField v)
  PB.OpVBinary v -> BOp <$> pbToBinary s (PB.getField v)
  PB.OpVClosure v -> uncurry COp <$> pbToClosure s (PB.getField v)

opToPb :: ReverseSymbols -> Op -> PB.Op
opToPb s = \case
  VOp t -> PB.OpVValue  $ PB.putField $ termToPb s t
  UOp o -> PB.OpVUnary  $ PB.putField $ unaryToPb s o
  BOp o -> PB.OpVBinary $ PB.putField $ binaryToPb s o
  COp p os -> PB.OpVClosure $ PB.putField $ closureToPb s p os

pbToUnary :: Symbols -> PB.OpUnary -> Either String Unary
pbToUnary s PB.OpUnary{kind,ffiName} = case PB.getField kind of
  PB.Negate -> Right Negate
  PB.Parens -> Right Parens
  PB.Length -> Right Length
  PB.TypeOf -> Right TypeOf
  PB.UnaryFfi -> do
    nameIdx <- maybeToRight "Missing extern call name" $ PB.getField ffiName
    name' <- getSymbol s $ SymbolRef nameIdx
    pure $ UnaryFfi name'

unaryToPb :: ReverseSymbols -> Unary -> PB.OpUnary
unaryToPb s = \case
  Negate -> PB.OpUnary { kind = PB.putField PB.Negate, ffiName = PB.putField Nothing }
  Parens -> PB.OpUnary { kind = PB.putField PB.Parens, ffiName = PB.putField Nothing }
  Length -> PB.OpUnary { kind = PB.putField PB.Length, ffiName = PB.putField Nothing }
  TypeOf -> PB.OpUnary { kind = PB.putField PB.TypeOf, ffiName = PB.putField Nothing }
  UnaryFfi name ->
    PB.OpUnary {
      kind = PB.putField PB.UnaryFfi,
      ffiName = PB.putField . Just . getSymbolRef $ getSymbolCode s name
    }

pbToBinary :: Symbols -> PB.OpBinary -> Either String Binary
pbToBinary s PB.OpBinary{kind, ffiName} =
  case PB.getField kind of
        PB.LessThan              -> Right LessThan
        PB.GreaterThan           -> Right GreaterThan
        PB.LessOrEqual           -> Right LessOrEqual
        PB.GreaterOrEqual        -> Right GreaterOrEqual
        PB.Equal                 -> Right Equal
        PB.Contains              -> Right Contains
        PB.Prefix                -> Right Prefix
        PB.Suffix                -> Right Suffix
        PB.Regex                 -> Right Regex
        PB.Add                   -> Right Add
        PB.Sub                   -> Right Sub
        PB.Mul                   -> Right Mul
        PB.Div                   -> Right Div
        PB.And                   -> Right And
        PB.Or                    -> Right Or
        PB.Intersection          -> Right Intersection
        PB.Union                 -> Right Union
        PB.BitwiseAnd            -> Right BitwiseAnd
        PB.BitwiseOr             -> Right BitwiseOr
        PB.BitwiseXor            -> Right BitwiseXor
        PB.NotEqual              -> Right NotEqual
        PB.HeterogeneousEqual    -> Right HeterogeneousEqual
        PB.HeterogeneousNotEqual -> Right HeterogeneousNotEqual
        PB.LazyAnd               -> Right LazyAnd
        PB.LazyOr                -> Right LazyOr
        PB.All                   -> Right All
        PB.Any                   -> Right Any
        PB.Get                   -> Right Get
        PB.TryOr                 -> Right Try
        PB.BinaryFfi -> do
          nameIdx <- maybeToRight "Missing extern call name" $ PB.getField ffiName
          name' <- getSymbol s $ SymbolRef nameIdx
          pure $ BinaryFfi name'

pbToClosure :: Symbols -> PB.OpClosure -> Either String ([T.Text], [Op])
pbToClosure s PB.OpClosure{..} =
  let getParams = traverse (getSymbol s . SymbolRef) . PB.getField
      getOps = traverse (pbToOp s) . PB.getField
   in bitraverse getParams getOps (params, ops)

closureToPb :: ReverseSymbols -> [T.Text] -> [Op] -> PB.OpClosure
closureToPb s params' ops' =
  let params = PB.putField $ fmap (getSymbolRef . getSymbolCode s) params'
      ops = PB.putField $ fmap (opToPb s) ops'
   in PB.OpClosure{..}

binaryToPb :: ReverseSymbols -> Binary -> PB.OpBinary
binaryToPb s = \case
  LessThan       -> PB.OpBinary { kind = PB.putField PB.LessThan, ffiName = PB.putField Nothing }
  GreaterThan    -> PB.OpBinary { kind = PB.putField PB.GreaterThan, ffiName = PB.putField Nothing }
  LessOrEqual    -> PB.OpBinary { kind = PB.putField PB.LessOrEqual, ffiName = PB.putField Nothing }
  GreaterOrEqual -> PB.OpBinary { kind = PB.putField PB.GreaterOrEqual, ffiName = PB.putField Nothing }
  Equal          -> PB.OpBinary { kind = PB.putField PB.Equal, ffiName = PB.putField Nothing }
  Contains       -> PB.OpBinary { kind = PB.putField PB.Contains, ffiName = PB.putField Nothing }
  Prefix         -> PB.OpBinary { kind = PB.putField PB.Prefix, ffiName = PB.putField Nothing }
  Suffix         -> PB.OpBinary { kind = PB.putField PB.Suffix, ffiName = PB.putField Nothing }
  Regex          -> PB.OpBinary { kind = PB.putField PB.Regex, ffiName = PB.putField Nothing }
  Add            -> PB.OpBinary { kind = PB.putField PB.Add, ffiName = PB.putField Nothing }
  Sub            -> PB.OpBinary { kind = PB.putField PB.Sub, ffiName = PB.putField Nothing }
  Mul            -> PB.OpBinary { kind = PB.putField PB.Mul, ffiName = PB.putField Nothing }
  Div            -> PB.OpBinary { kind = PB.putField PB.Div, ffiName = PB.putField Nothing }
  And            -> PB.OpBinary { kind = PB.putField PB.And, ffiName = PB.putField Nothing }
  Or             -> PB.OpBinary { kind = PB.putField PB.Or, ffiName = PB.putField Nothing }
  Intersection   -> PB.OpBinary { kind = PB.putField PB.Intersection, ffiName = PB.putField Nothing }
  Union          -> PB.OpBinary { kind = PB.putField PB.Union, ffiName = PB.putField Nothing }
  BitwiseAnd     -> PB.OpBinary { kind = PB.putField PB.BitwiseAnd, ffiName = PB.putField Nothing }
  BitwiseOr      -> PB.OpBinary { kind = PB.putField PB.BitwiseOr, ffiName = PB.putField Nothing }
  BitwiseXor     -> PB.OpBinary { kind = PB.putField PB.BitwiseXor, ffiName = PB.putField Nothing }
  NotEqual       -> PB.OpBinary { kind = PB.putField PB.NotEqual, ffiName = PB.putField Nothing }
  HeterogeneousEqual -> PB.OpBinary { kind = PB.putField PB.HeterogeneousEqual, ffiName = PB.putField Nothing }
  HeterogeneousNotEqual -> PB.OpBinary { kind = PB.putField PB.HeterogeneousNotEqual, ffiName = PB.putField Nothing }
  LazyAnd ->PB.OpBinary { kind = PB.putField PB.LazyAnd, ffiName = PB.putField Nothing }
  LazyOr -> PB.OpBinary { kind = PB.putField PB.LazyOr, ffiName = PB.putField Nothing }
  Any -> PB.OpBinary { kind = PB.putField PB.Any, ffiName = PB.putField Nothing }
  All -> PB.OpBinary { kind = PB.putField PB.All, ffiName = PB.putField Nothing }
  Get -> PB.OpBinary { kind = PB.putField PB.Get, ffiName = PB.putField Nothing }
  Try -> PB.OpBinary { kind = PB.putField PB.TryOr, ffiName = PB.putField Nothing }
  BinaryFfi n -> PB.OpBinary
    { kind = PB.putField PB.BinaryFfi
    , ffiName = PB.putField . Just . getSymbolRef $ getSymbolCode s n
    }

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


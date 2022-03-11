{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE DuplicateRecordFields      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TupleSections              #-}
module Auth.Biscuit.Datalog.ScopedExecutor
  ( BlockWithRevocationId
  , runAuthorizer
  , runAuthorizerWithLimits
  , runAuthorizerNoTimeout
  , runFactGeneration
  , PureExecError (..)
  , AuthorizationSuccess (..)
  , getBindings
  , queryAuthorizerFacts
  , getVariableValues
  , getSingleVariableValue
  , FactGroup (..)
  ) where

import           Control.Monad                 (when)
import           Control.Monad.State           (StateT (..), evalStateT, get,
                                                gets, lift, put)
import           Data.Bifunctor                (first)
import           Data.ByteString               (ByteString)
import           Data.Foldable                 (fold, traverse_)
import           Data.List.NonEmpty            (NonEmpty)
import qualified Data.List.NonEmpty            as NE
import           Data.Map                      (Map)
import qualified Data.Map                      as Map
import           Data.Map.Strict               ((!?))
import           Data.Maybe                    (mapMaybe)
import           Data.Set                      (Set)
import qualified Data.Set                      as Set
import           Data.Text                     (Text, unpack)
import           Numeric.Natural               (Natural)
import           Validation                    (Validation (..))

import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Datalog.Executor (Bindings, ExecutionError (..),
                                                Limits (..), MatchedQuery (..),
                                                ResultError (..), Scoped,
                                                checkCheck, checkPolicy,
                                                defaultLimits,
                                                getBindingsForRuleBody,
                                                getFactsForRule)
import           Auth.Biscuit.Datalog.Parser   (fact)
import           Auth.Biscuit.Timer            (timer)

type BlockWithRevocationId = (Block, ByteString)

-- | A subset of 'ExecutionError' that can only happen during fact generation
data PureExecError = Facts | Iterations
  deriving (Eq, Show)

-- | Proof that a biscuit was authorized successfully. In addition to the matched
-- @allow query@, the generated facts are kept around for further querying.
-- Since only authority facts can be trusted, they are kept separate.
data AuthorizationSuccess
  = AuthorizationSuccess
  { matchedAllowQuery :: MatchedQuery
  -- ^ The allow query that matched
  , allFacts          :: FactGroup
  -- ^ All the facts that were generated by the biscuit, grouped by their origin
  , limits            :: Limits
  -- ^ Limits used when running datalog. It is kept around to allow further
  -- datalog computation when querying facts
  }
  deriving (Eq, Show)

-- | Get the matched variables from the @allow@ query used to authorize the biscuit.
-- This can be used in conjuction with 'getVariableValues' or 'getSingleVariableValue'
-- to extract the actual values
getBindings :: AuthorizationSuccess -> Set Bindings
getBindings AuthorizationSuccess{matchedAllowQuery=MatchedQuery{bindings}} = bindings


-- | Given a series of blocks and an authorizer, ensure that all
-- the checks and policies match
runAuthorizer :: BlockWithRevocationId
            -- ^ The authority block
            -> [BlockWithRevocationId]
            -- ^ The extra blocks
            -> Authorizer
            -- ^ A authorizer
            -> IO (Either ExecutionError AuthorizationSuccess)
runAuthorizer = runAuthorizerWithLimits defaultLimits

-- | Given a series of blocks and an authorizer, ensure that all
-- the checks and policies match, with provided execution
-- constraints
runAuthorizerWithLimits :: Limits
                      -- ^ custom limits
                      -> BlockWithRevocationId
                      -- ^ The authority block
                      -> [BlockWithRevocationId]
                      -- ^ The extra blocks
                      -> Authorizer
                      -- ^ A authorizer
                      -> IO (Either ExecutionError AuthorizationSuccess)
runAuthorizerWithLimits l@Limits{..} authority blocks v = do
  resultOrTimeout <- timer maxTime $ pure $ runAuthorizerNoTimeout l authority blocks v
  pure $ case resultOrTimeout of
    Nothing -> Left Timeout
    Just r  -> r


mkRevocationIdFacts :: BlockWithRevocationId -> [BlockWithRevocationId]
                    -> Set Fact
mkRevocationIdFacts authority blocks =
  let allIds :: [(Int, ByteString)]
      allIds = zip [0..] $ snd <$> authority : blocks
      mkFact (index, rid) = [fact|revocation_id(${index}, ${rid})|]
   in Set.fromList $ mkFact <$> allIds

data ComputeState
  = ComputeState
  { sLimits     :: Limits -- readonly
  , sRules      :: Map Natural (Set Rule) -- readonly
  -- state
  , sIterations :: Int -- elapsed iterations
  , sFacts      :: FactGroup -- facts generated so far
  }
  deriving (Eq, Show)

mkInitState :: Limits -> BlockWithRevocationId -> [BlockWithRevocationId] -> Authorizer -> ComputeState
mkInitState limits authority blocks authorizer =
  let revocationWorld = (mempty, FactGroup $ Map.singleton (Set.singleton 0) $ mkRevocationIdFacts authority blocks)
      firstBlock = fst authority <> vBlock authorizer
      otherBlocks = fst <$> blocks
      allBlocks = firstBlock : otherBlocks
      (sRules, sFacts) = revocationWorld <> fold (zipWith collectWorld [0..] allBlocks)
   in ComputeState
        { sLimits = limits
        , sRules
        , sFacts
        , sIterations = 0
        }

runAuthorizerNoTimeout :: Limits
                       -> BlockWithRevocationId
                       -> [BlockWithRevocationId]
                       -> Authorizer
                       -> Either ExecutionError AuthorizationSuccess
runAuthorizerNoTimeout limits authority blocks authorizer = do
  let initState = mkInitState limits authority blocks authorizer
      toExecutionError = \case
        Facts      -> TooManyFacts
        Iterations -> TooManyIterations
  allFacts <- first toExecutionError $ computeAllFacts initState
  let checks = zip [0..] $ bChecks <$> ((fst authority <> vBlock authorizer) : (fst <$> blocks))
      policies = vPolicies authorizer
      checkResults = checkChecks limits allFacts checks
      policyResults = checkPolicies limits allFacts policies
  case (checkResults, policyResults) of
    (Success (), Left Nothing)  -> Left $ ResultError $ NoPoliciesMatched []
    (Success (), Left (Just p)) -> Left $ ResultError $ DenyRuleMatched [] p
    (Failure cs, Left Nothing)  -> Left $ ResultError $ NoPoliciesMatched (NE.toList cs)
    (Failure cs, Left (Just p)) -> Left $ ResultError $ DenyRuleMatched (NE.toList cs) p
    (Failure cs, Right _)       -> Left $ ResultError $ FailedChecks cs
    (Success (), Right p)       -> Right $ AuthorizationSuccess { matchedAllowQuery = p
                                                                , allFacts
                                                                , limits
                                                                }

runStep :: StateT ComputeState (Either PureExecError) Int
runStep = do
  state@ComputeState{sLimits,sFacts,sRules, sIterations} <- get
  let Limits{maxFacts, maxIterations} = sLimits
      previousCount = countFacts sFacts
      newFacts = sFacts <> extend sLimits sRules sFacts
      newCount = countFacts newFacts
      -- counting the facts returned by `extend` is not equivalent to
      -- comparing complete counts, as `extend` may return facts that
      -- are already present in `sFacts`
      addedFactsCount = newCount - previousCount
  when (newCount >= maxFacts) $ lift $ Left Facts
  when (sIterations >= maxIterations) $ lift $ Left Iterations
  put $ state { sIterations = sIterations + 1
              , sFacts = newFacts
              }
  return addedFactsCount

-- | Repeatedly generate new facts until it converges (no new
-- facts are generated)
computeAllFacts :: ComputeState -> Either PureExecError FactGroup
computeAllFacts initState =
  let go = do
        newFacts <- runStep
        if newFacts > 0 then go else gets sFacts
   in evalStateT go initState

-- | Small helper used in tests to directly provide rules and facts without creating
-- a biscuit token
runFactGeneration :: Limits -> Map Natural (Set Rule) -> FactGroup -> Either PureExecError FactGroup
runFactGeneration sLimits sRules sFacts =
  let initState = ComputeState{sIterations = 0, ..}
   in computeAllFacts initState

checkChecks :: Limits -> FactGroup -> [(Natural, [Check])] -> Validation (NonEmpty Check) ()
checkChecks limits allFacts =
  traverse_ (uncurry $ checkChecksForGroup limits allFacts)

checkChecksForGroup :: Limits -> FactGroup -> Natural -> [Check] -> Validation (NonEmpty Check) ()
checkChecksForGroup limits allFacts checksBlockId checks =
  let facts = fold $ getFactGroup $ keepAuthorized allFacts (Set.fromList [0..checksBlockId])
   in traverse_ (checkCheck limits facts) checks

checkPolicies :: Limits -> FactGroup -> [Policy] -> Either (Maybe MatchedQuery) MatchedQuery
checkPolicies limits allFacts policies =
  let facts = fold $ getFactGroup $ keepAuthorized allFacts (Set.singleton 0)
      results = mapMaybe (checkPolicy limits facts) policies
   in case results of
        p : _ -> first Just p
        []    -> Left Nothing

newtype FactGroup = FactGroup { getFactGroup :: Map (Set Natural) (Set Fact) }
  deriving newtype (Eq)

instance Show FactGroup where
  show (FactGroup groups) =
    let showGroup (origin, facts) = unlines
          [ "For origin: " <> show (Set.toList origin)
          , "Facts: \n" <> unlines (unpack . renderFact <$> Set.toList facts)
          ]
     in unlines $ showGroup <$> Map.toList groups

instance Semigroup FactGroup where
  FactGroup f1 <> FactGroup f2 = FactGroup $ Map.unionWith (<>) f1 f2
instance Monoid FactGroup where
  mempty = FactGroup mempty

toScopedFacts :: FactGroup -> Set (Scoped Fact)
toScopedFacts (FactGroup factGroups) =
  let distributeScope scope facts = Set.map (scope,) facts
   in foldMap (uncurry distributeScope) $ Map.toList factGroups

fromScopedFacts :: Set (Scoped Fact) -> FactGroup
fromScopedFacts = FactGroup . Map.fromListWith (<>) . Set.toList . Set.map (fmap Set.singleton)

countFacts :: FactGroup -> Int
countFacts (FactGroup facts) = sum $ Set.size <$> Map.elems facts

keepAuthorized :: FactGroup -> Set Natural -> FactGroup
keepAuthorized (FactGroup facts) authorizedOrigins =
  let isAuthorized k _ = k `Set.isSubsetOf` authorizedOrigins
   in FactGroup $ Map.filterWithKey isAuthorized facts

-- | Generate new facts by applying rules on existing facts
extend :: Limits -> Map Natural (Set Rule) -> FactGroup -> FactGroup
extend l rules facts =
  let buildFacts :: Set Rule -> Set (Scoped Fact) -> Set (Scoped Fact)
      buildFacts ruleGroup factGroup = foldMap (getFactsForRule l factGroup) ruleGroup

      extendRuleGroup :: Natural -> Set Rule -> FactGroup
      extendRuleGroup ruleBlockId ruleGroup =
        let authorizedFacts = toScopedFacts $ keepAuthorized facts $ Set.fromList [0..ruleBlockId]
            addRuleOrigin = FactGroup . Map.mapKeysWith (<>) (Set.insert ruleBlockId) . getFactGroup
         in addRuleOrigin . fromScopedFacts $ buildFacts ruleGroup authorizedFacts

   in foldMap (uncurry extendRuleGroup) $ Map.toList rules


collectWorld :: Natural -> Block -> (Map Natural (Set Rule), FactGroup)
collectWorld blockId Block{..} =
  ( Map.singleton blockId $ Set.fromList bRules
  , FactGroup $ Map.singleton (Set.singleton blockId) $ Set.fromList bFacts
  )

-- | Query the facts generated by the authority and authorizer blocks
-- during authorization. This can be used in conjuction with 'getVariableValues'
-- and 'getSingleVariableValue' to retrieve actual values.
--
-- ⚠ Only the facts generated by the authority and authorizer blocks are queried.
-- Block facts are not queried (since they can't be trusted).
--
-- 💁 If the facts you want to query are part of an allow query in the authorizer,
-- you can directly get values from 'AuthorizationSuccess'.
queryAuthorizerFacts :: AuthorizationSuccess -> Query -> Set Bindings
queryAuthorizerFacts AuthorizationSuccess{allFacts, limits} q =
  let authorityFacts = fold (Map.lookup (Set.singleton 0) $ getFactGroup allFacts)
      -- we've already ensured that we've kept only authority facts, we don't
      -- need to track their origin further
      getBindingsForQueryItem QueryItem{qBody,qExpressions} = Set.map snd $
        getBindingsForRuleBody limits (Set.map (mempty,) authorityFacts) qBody qExpressions
   in foldMap getBindingsForQueryItem q

-- | Extract a set of values from a matched variable for a specific type.
-- Returning @Set Value@ allows to get all values, whatever their type.
getVariableValues :: (Ord t, FromValue t)
                  => Set Bindings
                  -> Text
                  -> Set t
getVariableValues bindings variableName =
  let mapMaybeS f = foldMap (foldMap Set.singleton . f)
      getVar vars = fromValue =<< vars !? variableName
   in mapMaybeS getVar bindings

-- | Extract exactly one value from a matched variable. If the variable has 0
-- matches or more than one match, 'Nothing' will be returned
getSingleVariableValue :: (Ord t, FromValue t)
                       => Set Bindings
                       -> Text
                       -> Maybe t
getSingleVariableValue bindings variableName =
  let values = getVariableValues bindings variableName
   in case Set.toList values of
        [v] -> Just v
        _   -> Nothing

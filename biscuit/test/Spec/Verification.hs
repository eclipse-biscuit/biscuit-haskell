{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}
{-
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
-}
module Spec.Verification
  ( specs
  ) where

import           Data.List.NonEmpty            (NonEmpty ((:|)))
import qualified Data.Set                      as Set
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Datalog.AST      (Block' (..), Check, Check' (..),
                                                CheckKind (..),
                                                Expression' (..),
                                                Predicate' (..), Query,
                                                QueryItem' (..), Rule' (..),
                                                Term' (..))
import           Auth.Biscuit.Datalog.Executor (MatchedQuery (..),
                                                ResultError (..))
import qualified Auth.Biscuit.Datalog.Executor as Executor
import           Auth.Biscuit.Datalog.Parser   (check, fact, query)

specs :: TestTree
specs = testGroup "Datalog checks"
  [ singleBlock
  , checkAll
  , errorAccumulation
  , unboundVarRule
  , symbolRestrictions
  ]

ifTrue :: MatchedQuery
ifTrue = MatchedQuery
  { matchedQuery = [query|true|]
  , bindings = Set.singleton mempty
  }

ifFalse :: MatchedQuery
ifFalse = MatchedQuery
  { matchedQuery = [query|false|]
  , bindings = Set.singleton mempty
  }

ifFalse' :: Check
ifFalse' = Check
  { cQueries = matchedQuery ifFalse
  , cKind = One
  }

checkAll' :: Check
checkAll' = [check|check all fact($value), $value|]

singleBlock :: TestTree
singleBlock = testCase "Single block" $ do
  secret <- newSecret
  biscuit <- mkBiscuit secret [block|right("file1", "read");|]
  res <- authorizeBiscuit biscuit [authorizer|check if right("file1", "read");allow if true;|]
  matchedAllowQuery . authorizationSuccess <$> res @?= Right ifTrue

checkAll :: TestTree
checkAll = testCase "Check all" $ do
  secret <- newSecret
  biscuit <- mkBiscuit secret [block|fact(true); fact(false);|]
  res <- authorizeBiscuit biscuit [authorizer|check all fact($value), $value;allow if true;|]
  res @?= Left (ResultError $ FailedChecks $ pure checkAll')

errorAccumulation :: TestTree
errorAccumulation = testGroup "Error accumulation"
  [ testCase "Only checks" $ do
      secret <- newSecret
      biscuit <- mkBiscuit secret[block|check if false; check if false;|]
      res <- authorizeBiscuit biscuit [authorizer|allow if true;|]
      res @?= Left (ResultError $ FailedChecks $ ifFalse' :| [ifFalse'])
  , testCase "Checks and deny policies" $ do
      secret <- newSecret
      biscuit <- mkBiscuit secret [block|check if false; check if false;|]
      res <- authorizeBiscuit biscuit [authorizer|deny if true;|]
      res @?= Left(ResultError $ DenyRuleMatched [ifFalse', ifFalse'] ifTrue)
  , testCase "Checks and no policies matched" $ do
      secret <- newSecret
      biscuit <- mkBiscuit secret [block|check if false; check if false;|]
      res <- authorizeBiscuit biscuit [authorizer|allow if false;|]
      res @?= Left (ResultError $ NoPoliciesMatched [ifFalse', ifFalse'])
  ]

unboundVarRule :: TestTree
unboundVarRule = testCase "Rule with unbound variable" $ do
  secret <- newSecret
  b1 <- mkBiscuit secret [block|check if operation("read");|]
  -- rules with unbound variables don't parse, so we have
  -- to manually construct a broken rule
  let brokenRuleBlock = Block {
        bRules = [Rule{
          rhead = Predicate{
            name = "operation",
            terms = [Variable"unbound", LString "read"]
          },
          body = [Predicate{
            name = "operation",
            terms = Variable <$> ["any1", "any2"]
          }],
          expressions = mempty,
          scope = mempty
        }],
        bFacts = mempty,
        bChecks = mempty,
        bScope = mempty,
        bContext = mempty
  }
  b2 <- addBlock brokenRuleBlock b1
  res <- authorizeBiscuit b2 [authorizer|operation("write");allow if true;|]
  res @?= Left InvalidRule

symbolRestrictions :: TestTree
symbolRestrictions = testGroup "Restricted symbols in blocks"
  [ testCase "In facts" $ do
      secret <- newSecret
      b1 <- mkBiscuit secret [block|check if operation("read");|]
      b2 <- addBlock [block|operation("read");|] b1
      res <- authorizeBiscuit b2 [authorizer|allow if true;|]
      res @?= Left (Executor.ResultError $ Executor.FailedChecks $ pure [check|check if operation("read")|])
  , testCase "In rules" $ do
      secret <- newSecret
      b1 <- mkBiscuit secret [block|check if operation("read");|]
      b2 <- addBlock [block|operation($ambient, "read") <- operation($ambient, $any);|] b1
      res <- authorizeBiscuit b2 [authorizer|operation("write");allow if true;|]
      res @?= Left (Executor.ResultError $ Executor.FailedChecks $ pure [check|check if operation("read")|])
  ]

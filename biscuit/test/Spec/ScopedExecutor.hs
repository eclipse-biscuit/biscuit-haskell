{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{- HLINT ignore "Reduce duplication" -}
{-
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
-}
module Spec.ScopedExecutor (specs) where

import           Control.Arrow                       ((&&&))
import           Data.Either                         (isRight)
import           Data.Map.Strict                     as Map
import           Data.Set                            as Set
import           Data.Text                           (Text, pack, unpack)
import           Test.Tasty                          hiding (Timeout)
import           Test.Tasty.HUnit

import           Auth.Biscuit                        (addBlock, addSignedBlock,
                                                      authorizeBiscuit,
                                                      mkBiscuit, newSecret,
                                                      queryAuthorizerFacts,
                                                      queryRawBiscuitFacts)
import           Auth.Biscuit.Crypto
import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Datalog.Executor       (ExecutionError (..),
                                                      Limits (..),
                                                      ResultError (..),
                                                      defaultLimits)
import           Auth.Biscuit.Datalog.Parser         (authorizer, block, check,
                                                      query, run)
import           Auth.Biscuit.Datalog.ScopedExecutor
import           Auth.Biscuit.Timer                  (timerIO)

specs :: TestTree
specs = testGroup "Block-scoped Datalog Evaluation"
  [ authorizerOnlySeesAuthority
  , authorityOnlySeesItselfAndAuthorizer
  , block1OnlySeesAuthorityAndAuthorizer
  , block2OnlySeesAuthorityAndAuthorizer
  , block1SeesAuthorityAndAuthorizer
  , thirdPartyBlocks
  , iterationCountWorks
  , maxFactsCountWorks
  , allChecksAreCollected
  , revocationIdsAreInjected
  , authorizerFactsAreQueried
  , biscuitFactsAreQueried
  , evaluationReachesTimeout
  ]

authorizerOnlySeesAuthority :: TestTree
authorizerOnlySeesAuthority = testCase "Authorizer only accesses facts from authority" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         is_allowed(1234, "file1", "write");
       |]
      verif =
       [authorizer|
         allow if is_allowed(1234, "file1", "write");
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left (ResultError (NoPoliciesMatched []))

authorityOnlySeesItselfAndAuthorizer :: TestTree
authorityOnlySeesItselfAndAuthorizer = testCase "Authority rules only see authority and authorizer facts" $ do
  let authority =
       [block|
         user(1234);
         is_allowed($user, $resource) <- right($user, $resource, "read");
       |]
      block1 =
       [block|
         right(1234, "file1", "read");
       |]
      verif =
       [authorizer|
         allow if is_allowed(1234, "file1");
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left (ResultError (NoPoliciesMatched []))

block1OnlySeesAuthorityAndAuthorizer :: TestTree
block1OnlySeesAuthorityAndAuthorizer = testCase "Arbitrary blocks only see previous blocks" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         is_allowed($user, $resource) <- right($user, $resource, "read");
         check if is_allowed(1234, "file1");
       |]
      block2 =
       [block|
         right(1234, "file1", "read");
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing), (block2, "", Nothing)] verif @?= Left (ResultError (FailedChecks $ pure [check|check if is_allowed(1234, "file1") |]))

block1SeesAuthorityAndAuthorizer :: TestTree
block1SeesAuthorityAndAuthorizer = testCase "Arbitrary blocks see previous blocks" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         is_allowed($user, $resource) <- user($user), right($user, $resource, "read");
         right(1234, "file1", "read");
         check if is_allowed(1234, "file1");
       |]
      verif =
       [authorizer| allow if false;
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left (ResultError $ NoPoliciesMatched [])

block2OnlySeesAuthorityAndAuthorizer :: TestTree
block2OnlySeesAuthorityAndAuthorizer = testCase "Arbitrary blocks only see previous blocks" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         right(1234, "file1", "read");
       |]
      block2 =
       [block|
         is_allowed($user, $resource) <- right($user, $resource, "read");
         check if is_allowed(1234, "file1");
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing), (block2, "", Nothing)] verif @?= Left (ResultError (FailedChecks $ pure [check|check if is_allowed(1234, "file1") |]))

thirdPartyBlocks :: TestTree
thirdPartyBlocks = testCase "Third party blocks are correctly scoped" $ do
    (sk1, pkOne) <- (id &&& toPublic) <$> generateSecretKey
    let authority =
          [block|
            user(1234);
            check if from3rd(1, true) trusting {pkOne};
            check if from3rd(2, true) trusting {pkOne};
          |]
        block1 =
          [block|
          from3rd(1, true);
          |]
        block2 =
          [block|
          from3rd(2, true);
          |]
        verif =
          [authorizer|
            deny if from3rd(1, true);
            allow if from3rd(1, true), from3rd(2, true) trusting {pkOne};
          |]
    let result = runAuthorizerNoTimeout defaultLimits
                   (authority, "", Nothing)
                   [ (block1, "", Just pkOne)
                   , (block2, "", Just pkOne)
                   ]
                   verif
    isRight result @?= True

iterationCountWorks :: TestTree
iterationCountWorks = testCase "ScopedExecutions stops when hitting the iterations threshold" $ do
  let limits = defaultLimits { maxIterations = 8 }
      authority =
       [block|
         a("yolo");
         b($a) <- a($a);
         c($b) <- b($b);
         d($c) <- c($c);
         e($d) <- d($d);
         f($e) <- e($e);
         g($f) <- f($f);
       |]
      block1 =
       [block|
         h($g) <- g($g);
         i($h) <- h($h);
         j($i) <- i($i);
         k($j) <- j($j);
         l($k) <- k($k);
         m($l) <- l($l);
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout limits (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left TooManyIterations

maxFactsCountWorks :: TestTree
maxFactsCountWorks = testCase "ScopedExecutions stops when hitting the facts threshold" $ do
  let limits = defaultLimits { maxFacts = 8 }
      authority =
       [block|
         a("yolo");
         b($a) <- a($a);
         c($b) <- b($b);
         d($c) <- c($c);
         e($d) <- d($d);
         f($e) <- e($e);
         g($f) <- f($f);
       |]
      block1 =
       [block|
         h($g) <- g($g);
         i($h) <- h($h);
         j($i) <- i($i);
         k($j) <- j($j);
         l($k) <- k($k);
         m($l) <- l($l);
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout limits (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left TooManyFacts

allChecksAreCollected :: TestTree
allChecksAreCollected = testCase "ScopedExecutions collects all facts results even after a failure" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         check if false;
       |]
      block2 =
       [block|
         check if false;
       |]
      verif =
       [authorizer|
         allow if user(4567);
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing), (block2, "", Nothing)] verif @?= Left (ResultError $ NoPoliciesMatched [[check|check if false|], [check|check if false|]])

revocationIdsAreInjected :: TestTree
revocationIdsAreInjected = testCase "ScopedExecutions injects revocation ids" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|yolo("block1");|]
      block2 =
       [block|yolo("block2");|]
      verif =
       [authorizer|
         check if revocation_id(0, hex:61),
                  revocation_id(1, hex:62),
                  revocation_id(2, hex:63);
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "a", Nothing) [(block1, "b", Nothing), (block2, "c", Nothing)] verif @?= Left (ResultError $ NoPoliciesMatched [])

authorizerFactsAreQueried :: TestTree
authorizerFactsAreQueried = testGroup "AuthorizedBiscuit can be queried"
  [ testCase "Attenuation blocks are ignored" $ do
      (p,s) <- (toPublic &&& id) <$> newSecret
      b <- mkBiscuit s [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      result <- authorizeBiscuit b1 [authorizer|allow if true;|]
      let getUser s = queryAuthorizerFacts s [query|user($user)|]
          expected = Set.singleton $ Map.fromList
            [ ("user", LInteger 1234)
            ]
      getUser <$> result @?= Right (Right expected)
  , testCase "Attenuation blocks can be accessed if asked nicely" $ do
      (p,s) <- (toPublic &&& id) <$> newSecret
      b <- mkBiscuit s [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      result <- authorizeBiscuit b1 [authorizer|allow if true;|]
      let getUser s = queryAuthorizerFacts s [query|user($user) trusting previous|]
          expected = Set.fromList
            [ Map.fromList [("user", LInteger 1234)]
            , Map.fromList [("user", LString "tampered value")]
            ]
      getUser <$> result @?= Right (Right expected)
  , testCase "Signed blocks can be accessed if asked nicely" $ do
      (p,s) <- (toPublic &&& id) <$> newSecret
      (p1,s1) <- (toPublic &&& id) <$> newSecret
      b <- mkBiscuit s [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      b2 <- addSignedBlock s1 [block|user("from signed");|] b1
      result <- authorizeBiscuit b2 [authorizer|allow if true;|]
      let getUser s = queryAuthorizerFacts s [query|user($user) trusting authority, {p1}|]
          expected = Set.fromList
            [ Map.fromList [("user", LInteger 1234)]
            , Map.fromList [("user", LString "from signed")]
            ]
      getUser <$> result @?= Right (Right expected)
  ]

biscuitFactsAreQueried :: TestTree
biscuitFactsAreQueried = testGroup "Biscuit can be queried"
  [ testCase "Attenuation blocks are ignored" $ do
      (p,s) <- (toPublic &&& id) <$> newSecret
      b <- mkBiscuit s [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      let user = queryRawBiscuitFacts b1 [query|user($user)|]
          expected = Set.singleton $ Map.fromList
            [ ("user", LInteger 1234)
            ]
      user @?= Right expected
  , testCase "Attenuation blocks can be accessed if asked nicely" $ do
      (p,s) <- (toPublic &&& id) <$> newSecret
      b <- mkBiscuit s [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      let user = queryRawBiscuitFacts b1 [query|user($user) trusting previous|]
          expected = Set.fromList
            [ Map.fromList [("user", LInteger 1234)]
            , Map.fromList [("user", LString "tampered value")]
            ]
      user @?= Right expected
  , testCase "Signed blocks can be accessed if asked nicely" $ do
      (p,s) <- (toPublic &&& id) <$> newSecret
      (p1,s1) <- (toPublic &&& id) <$> newSecret
      b <- mkBiscuit s [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      b2 <- addSignedBlock s1 [block|user("from signed");|] b1
      let user = queryRawBiscuitFacts b2 [query|user($user) trusting authority, {p1}|]
          expected = Set.fromList
            [ Map.fromList [("user", LInteger 1234)]
            , Map.fromList [("user", LString "from signed")]
            ]
      user @?= Right expected
  ]

evaluationReachesTimeout :: TestTree
evaluationReachesTimeout = testCase "Timeout is reached while runnning authorization" $ do
    let limits = defaultLimits { maxTime = 10 }
        input = pack $ Prelude.take 1000 $ repeat 'a'
        regex = pack $ "^" <> Prelude.take 1000 (cycle "a?") <> Prelude.take 1000 (repeat 'a') <> "$"
        authority = [block|fact(true);rule($t) <- fact($t), {input}.matches({regex});|]
        auth = [authorizer|allow if rule(true);|]
    res <- runAuthorizerWithTimer timerIO limits (authority, "", Nothing) [] auth
    res @?= Left Timeout

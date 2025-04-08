{-# LANGUAGE OverloadedLists   #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
-}
module Spec.Executor (specs) where

import           Data.Map.Strict                     as Map
import           Data.Set                            as Set
import           Data.Text                           (Text, unpack)
import           Numeric.Natural                     (Natural)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Datalog.Executor       (ExecutionError (..),
                                                      Limits (..),
                                                      defaultLimits,
                                                      evaluateExpression)
import           Auth.Biscuit.Datalog.Parser         (expressionParser, fact,
                                                      rule)
import           Auth.Biscuit.Datalog.ScopedExecutor hiding (limits)
import           Spec.Parser                         (parseExpression)

specs :: TestTree
specs = testGroup "Datalog evaluation"
  [ grandparent
  , ancestor
  , scopedRules
  , exprEval
  , exprEvalError
  , rulesWithConstraints
  , ruleHeadWithNoVars
  , limits
  , overflow
  ]

authGroup :: Set Fact -> FactGroup
authGroup = FactGroup . Map.singleton (Set.singleton 0)

authRulesGroup :: Set Rule -> Map Natural (Set EvalRule)
authRulesGroup = Map.singleton 0 . adaptRules

adaptRules :: Set Rule -> Set EvalRule
adaptRules = Set.map (toEvaluation [])

grandparent :: TestTree
grandparent = testCase "Basic grandparent rule" $
  let rules = authRulesGroup $ Set.fromList
                [ [rule|grandparent($a,$b) <- parent($a,$c), parent($c,$b)|]
                ]
      facts = authGroup $ Set.fromList
                [ [fact|parent("alice", "bob")|]
                , [fact|parent("bob", "jean-pierre")|]
                , [fact|parent("alice", "toto")|]
                ]
   in runFactGeneration defaultLimits 1 rules facts @?= Right (authGroup $ Set.fromList
        [ [fact|parent("alice", "bob")|]
        , [fact|parent("bob", "jean-pierre")|]
        , [fact|parent("alice", "toto")|]
        , [fact|grandparent("alice", "jean-pierre")|]
        ])

ancestor :: TestTree
ancestor = testCase "Ancestor rule" $
  let rules = authRulesGroup $ Set.fromList
                [ [rule|ancestor($a,$b) <- parent($a,$c), ancestor($c,$b)|]
                , [rule|ancestor($a,$b) <- parent($a,$b)|]
                ]
      facts = authGroup $ Set.fromList
                [ [fact|parent("alice", "bob")|]
                , [fact|parent("bob", "jean-pierre")|]
                , [fact|parent("alice", "toto")|]
                ]
   in runFactGeneration defaultLimits 1 rules facts @?= Right (authGroup $ Set.fromList
        [ [fact|parent("alice", "bob")|]
        , [fact|parent("bob", "jean-pierre")|]
        , [fact|parent("alice", "toto")|]
        , [fact|ancestor("alice", "bob")|]
        , [fact|ancestor("bob", "jean-pierre")|]
        , [fact|ancestor("alice", "toto")|]
        , [fact|ancestor("alice", "jean-pierre")|]
        ])

expr :: Text -> Expression
expr = either error id . parseExpression

exprEval :: TestTree
exprEval = do
  let bindings = Map.fromList
        [ ("var1", LInteger 0)
        , ("topDomain", LString "example.com")
        , ("domain", LString "test.example.com")
        ]
      eval (e, r) = testCase (unpack e) $
        evaluateExpression defaultLimits bindings (expr e) @?= Right r

   --   ("1 / 0") @?= Left "Divide by 0"
  testGroup "Expressions evaluation" $ eval <$>
    [ ("!(1 < $var1)", LBool True)
    , ("[0].contains($var1)", LBool True)
    , ("1 + 2 * 3", LInteger 7)
    , ("!(1 + 2 * 3 > 4)", LBool False)
    , ("!true", LBool False)
    , ("!false", LBool True)
    , ("(true)", LBool True)
    , ("\"test\".length()", LInteger 4)
    , ("\"é\".length()", LInteger 2)
    , ("hex:ababab.length()", LInteger 3)
    , ("[].length()", LInteger 0)
    , ("[\"test\", \"test\"].length()", LInteger 1)
    , ("1 == 1", LBool True)
    , ("2 == 1", LBool False)
    , ("\"toto\" == \"toto\"", LBool True)
    , ("\"toto\" == \"truc\"", LBool False)
    , ("\"toto\".matches(\"to(to)?\")", LBool True)
    , ("\"toto\".matches(\"^to$\")", LBool False)
    , ("2021-05-07T18:00:00Z == 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z == 2021-05-07T19:00:00Z", LBool False)
    , ("hex:ababab == hex:ababab", LBool True)
    , ("hex:ababab == hex:ababac", LBool False)
    , ("true == true", LBool True)
    , ("true == false", LBool False)
    , ("[1,2,3] == [1,2,3]", LBool True)
    , ("[1,2,3] == [1,2,4]", LBool False)
    , ("1 < 2", LBool True)
    , ("2 < 1", LBool False)
    , ("2021-05-07T18:00:00Z < 2021-05-07T19:00:00Z", LBool True)
    , ("2021-05-07T19:00:00Z < 2021-05-07T18:00:00Z", LBool False)
    , ("2 > 1", LBool True)
    , ("1 > 2", LBool False)
    , ("2021-05-07T19:00:00Z > 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z > 2021-05-07T19:00:00Z", LBool False)
    , ("1 <= 2", LBool True)
    , ("1 <= 1", LBool True)
    , ("2 <= 1", LBool False)
    , ("2021-05-07T18:00:00Z <= 2021-05-07T19:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z <= 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T19:00:00Z <= 2021-05-07T18:00:00Z", LBool False)
    , ("2 >= 1", LBool True)
    , ("2 >= 2", LBool True)
    , ("1 >= 2", LBool False)
    , ("2021-05-07T19:00:00Z >= 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z >= 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z >= 2021-05-07T19:00:00Z", LBool False)
    , ("\"my string\".starts_with(\"my\")", LBool True)
    , ("\"my string\".starts_with(\"string\")", LBool False)
    , ("\"my string\".ends_with(\"string\")", LBool True)
    , ("\"my string\".ends_with(\"my\")", LBool False)
    , ("$domain.ends_with(\".\" + $topDomain)", LBool True)
    , ("2 + 1", LInteger 3)
    , ("2 - 1", LInteger 1)
    , ("5 / 2", LInteger 2)
    , ("2 * 1", LInteger 2)
    , ("true && true", LBool True)
    , ("true && false", LBool False)
    , ("false && true", LBool False)
    , ("false && false", LBool False)
    , ("true || true", LBool True)
    , ("true || false", LBool True)
    , ("false || true", LBool True)
    , ("false || false", LBool False)
    , ("[1].contains([1])", LBool True)
    , ("[1].contains(1)", LBool True)
    , ("[].contains(1)", LBool False)
    , ("[\"test\"].contains(2)", LBool False)
    , ("[1].intersection([1])", TermSet (Set.fromList [LInteger 1]))
    , ("[1].intersection([\"test\"])", TermSet (Set.fromList []))
    , ("[1].union([1])", TermSet (Set.fromList [LInteger 1]))
    , ("[1].union([\"test\"])", TermSet (Set.fromList [LInteger 1, LString "test"]))
    ]

exprEvalError :: TestTree
exprEvalError = do
  let bindings = Map.fromList
        [ ("var1", LInteger 0)
        ]
      l = defaultLimits { allowRegexes = False }
      evalFail (e, r) = testCase (unpack e) $
        evaluateExpression l bindings (expr e) @?= Left r

  testGroup "Expressions evaluation (expected errors)" $ evalFail <$>
    [ ("1 / 0", "Divide by 0")
    , ("\"toto\".matches(\"to\")", "Regex evaluation is disabled")
    , ("9223372036854775807 + 1", "integer overflow")
    , ("-9223372036854775808 - 1", "integer underflow")
    ]

rulesWithConstraints :: TestTree
rulesWithConstraints = testCase "Rule with constraints" $
  let rules = authRulesGroup $ Set.fromList
                   [ [rule|valid_date("file1") <- time($0), resource("file1"), $0 <= 2019-12-04T09:46:41+00:00|]
                   , [rule|valid_date("file2") <- time($0), resource("file2"), $0 <= 2010-12-04T09:46:41+00:00|]
                   ]
      facts = authGroup $ Set.fromList
                   [ [fact|time(2019-12-04T01:00:00Z)|]
                   , [fact|resource("file1")|]
                   , [fact|resource("file2")|]
                   ]
   in runFactGeneration defaultLimits 1 rules facts @?= Right (authGroup $ Set.fromList
        [ [fact|time(2019-12-04T01:00:00Z)|]
        , [fact|resource("file1")|]
        , [fact|resource("file2")|]
        , [fact|valid_date("file1")|]
        ])

ruleHeadWithNoVars :: TestTree
ruleHeadWithNoVars = testCase "Rule head with no variables" $
  let rules = authRulesGroup $ Set.fromList
                   [ [rule|operation("authority", "read") <- test($yolo, "nothing")|]
                   ]
      facts = authGroup $ Set.fromList
                   [ [fact|test("whatever", "notNothing")|]
                   ]
   in runFactGeneration defaultLimits 1 rules facts @?= Right (authGroup $ Set.fromList
        [ [fact|test("whatever", "notNothing")|]
        ])

limits :: TestTree
limits =
  let rules = authRulesGroup $ Set.fromList
                   [ [rule|ancestor($a,$b) <- parent($a,$c), ancestor($c,$b)|]
                   , [rule|ancestor($a,$b) <- parent($a,$b)|]
                   ]
      facts = authGroup $ Set.fromList
                   [ [fact|parent("alice", "bob")|]
                   , [fact|parent("bob", "jean-pierre")|]
                   , [fact|parent("bob", "marielle")|]
                   , [fact|parent("alice", "toto")|]
                   ]
      factLimits = defaultLimits { maxFacts = 10 }
      iterLimits = defaultLimits { maxIterations = 2 }
   in testGroup "Facts generation limits"
        [ testCase "max facts" $
            runFactGeneration factLimits 1 rules facts @?= Left Facts
        , testCase "max iterations" $
            runFactGeneration iterLimits 1 rules facts @?= Left Iterations
        ]

scopedRules :: TestTree
scopedRules = testGroup "Rules and facts in different scopes"
  [ testCase "with default scoping for rules" $
      let rules :: Map Natural (Set Rule)
          rules = [ (0, [ [rule|ancestor($a,$b) <- parent($a,$b)|] ])
                  , (1, [ [rule|ancestor($a,$b) <- parent($a,$c), ancestor($c,$b)|] ])
                  ]
          facts :: FactGroup
          facts = FactGroup
                    [ ([0], [ [fact|parent("alice", "bob")|]
                            , [fact|parent("bob", "trudy")|]
                            ])
                    , ([1], [ [fact|parent("bob", "jean-pierre")|]
                            ])
                    , ([2], [ [fact|parent("toto", "toto")|]
                            ])
                    ]
       in runFactGeneration defaultLimits 3 (adaptRules <$> rules) facts @?= Right (FactGroup
            [ ([0],   [ [fact|parent("alice", "bob")|]
                      , [fact|ancestor("alice", "bob")|]
                      , [fact|parent("bob", "trudy")|]
                      , [fact|ancestor("bob", "trudy")|]
                      ])
            , ([1],   [ [fact|parent("bob", "jean-pierre")|]
                      ])
            , ([0,1], [ [fact|ancestor("alice", "trudy")|]
                      ])
            , ([2],   [ [fact|parent("toto", "toto")|] ])
            ])
  , testCase "with explicit scoping for rules (authority)" $
      let rules :: Map Natural (Set Rule)
          rules = [ (0, [ [rule|ancestor($a,$b) <- parent($a,$b) trusting authority |] ])
                  , (1, [ [rule|ancestor($a,$b) <- parent($a,$c), ancestor($c,$b) trusting authority |] ])
                  , (2, [ [rule|family($a,$b) <- parent($a,$b) trusting authority |] ])
                  ]
          facts :: FactGroup
          facts = FactGroup
                    [ ([0], [ [fact|parent("alice", "bob")|]
                            , [fact|parent("bob", "trudy")|]
                            ])
                    , ([1], [ [fact|parent("bob", "jean-pierre")|]
                            ])
                    , ([2], [ [fact|parent("toto", "toto")|]
                            ])
                    ]
       in runFactGeneration defaultLimits 3 (adaptRules <$> rules) facts @?= Right (FactGroup
            [ ([0],   [ [fact|parent("alice", "bob")|]
                      , [fact|ancestor("alice", "bob")|]
                      , [fact|parent("bob", "trudy")|]
                      , [fact|ancestor("bob", "trudy")|]
                      ])
            , ([1],   [ [fact|parent("bob", "jean-pierre")|]
                      ])
            , ([0,1], [ [fact|ancestor("alice", "trudy")|]
                      ])
            , ([2],   [ [fact|parent("toto", "toto")|]
                      , [fact|family("toto", "toto")|]
                      ])
            , ([0,2], [ [fact|family("alice", "bob")|]
                      , [fact|family("bob", "trudy")|]
                      ])
            ])
  ]

overflow :: TestTree
overflow =
  let subtraction = authRulesGroup $ Set.singleton
                   [rule|test(true) <- -9223372036854775808 - 1 != 0|]
      multiplication = authRulesGroup $ Set.singleton
                   [rule|test(true) <- 10000000000 * 10000000000 != 0|]
      addition = authRulesGroup $ Set.singleton
                   [rule|test(true) <- 9223372036854775807 + 1 != 0|]
   in testGroup "Arithmetic overflow"
        [ testCase "subtraction" $
            runFactGeneration defaultLimits 1 subtraction mempty @?= Left (BadExpression "integer underflow")
        , testCase "multiplication" $
            runFactGeneration defaultLimits 1 multiplication mempty @?= Left (BadExpression "integer overflow")
        , testCase "addition" $
            runFactGeneration defaultLimits 1 addition mempty @?= Left (BadExpression "integer overflow")
        ]

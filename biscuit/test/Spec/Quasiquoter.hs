{-# LANGUAGE OverloadedLists   #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
-}
module Spec.Quasiquoter (specs) where

import           Data.Text                   (Text)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Datalog.Parser (fact, rule)

specs :: TestTree
specs = testGroup "Datalog quasiquoter"
  [ basicFact
  , basicRule
  , antiquotedFact
  , antiquotedRule
  ]

basicFact :: TestTree
basicFact = testCase "Basic fact" $
  let actual :: Fact
      actual = [fact|right("file1", "read")|]
   in actual @?=
    Predicate "right" [ LString "file1"
                      , LString "read"
                      ]

basicRule :: TestTree
basicRule = testCase "Basic rule" $
  let actual :: Rule
      actual = [rule|right($0, "read") <- resource( $0), operation("read")|]
   in actual @?=
    Rule (Predicate "right" [Variable "0", LString "read"])
         [ Predicate "resource" [Variable "0"]
         , Predicate "operation" [LString "read"]
         ] [] []

antiquotedFact :: TestTree
antiquotedFact = testCase "Sliced fact" $
  let toto2' :: Text
      toto2' = "test"
      actual :: Fact
      actual = [fact|right({toto2'}, "read")|]
   in actual @?=
    Predicate "right" [ LString "test"
                      , LString "read"
                      ]

antiquotedRule :: TestTree
antiquotedRule = testCase "Sliced rule" $
  let toto :: Text
      toto = "test"
      actual :: Rule
      actual = [rule|right($0, "read") <- resource( $0), operation("read", {toto})|]
   in actual @?=
    Rule (Predicate "right" [Variable "0", LString "read"])
         [ Predicate "resource" [Variable "0"]
         , Predicate "operation" [LString "read", LString "test"]
         ] [] []

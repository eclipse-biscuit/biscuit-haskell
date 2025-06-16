{-# LANGUAGE OverloadedStrings #-}
module Spec.AST (specs) where

import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit.Datalog.AST

specs :: TestTree
specs = testGroup "datalog AST"
  [ toStackClosure
  , fromStackClosure
  ]

toStackClosure :: TestTree
toStackClosure = testCase "Turn a closure expr into a stack" $
  let cE = EClosure
             ["x"]
             (EBinary
               Equal
               (EValue (Variable "x"))
               (EValue (LInteger 42)))
      cO = [COp ["x"]
            [ VOp (Variable "x")
            , VOp (LInteger 42)
            , BOp Equal
            ]]
   in toStack cE @?= cO


fromStackClosure :: TestTree
fromStackClosure = testCase "Turn a closure op into an expression" $
  let cO = [COp ["x"]
            [ VOp (Variable "x")
            , VOp (LInteger 42)
            , BOp Equal
            ]]
      cE = EClosure
            ["x"]
            (EBinary
              Equal
              (EValue (Variable "x"))
              (EValue (LInteger 42)))
   in fromStack cO @?= Right cE

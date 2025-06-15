{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedLists   #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
-}
module Spec.Parser (specs, parseExpression, parseBlock, parseAuthorizer) where

import           Control.Monad               ((<=<))
import           Data.Bifunctor              (first)
import           Data.Either                 (isLeft)
import           Data.List.NonEmpty          (NonEmpty)
import           Data.Maybe                  (fromJust)
import qualified Data.Set                    as Set
import           Data.Text                   (Text)
import           Test.Tasty
import           Test.Tasty.HUnit
import           Validation                  (Validation, validationToEither)

import           Auth.Biscuit                (PublicKey, parsePublicKeyHex)
import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Datalog.Parser (Parser, authorizerParser,
                                              blockParser, checkParser,
                                              expressionParser, policyParser,
                                              predicateParser,
                                              predicateTermParser, ruleParser,
                                              run)

pk1, pk2, pk3, pk4, pk5 :: PublicKey
pk1 = fromJust $ parsePublicKeyHex "a1b712761c609039f878edad694d762652f1548a68acccc96735b3196a240e8b"
pk2 = fromJust $ parsePublicKeyHex "b82c748be51784a58496675752e04cc48009a7e78bcfae8cad51fba959102af1"
pk3 = fromJust $ parsePublicKeyHex "083aae4ba29a9a3781cdee7a800f4f8ab90591f65ca983fc429687628311aedd"
pk4 = fromJust $ parsePublicKeyHex "c6864578bc03596d52878bd70025ec966c95c60727cb6573198453e82132510d"
pk5 = fromJust $ parsePublicKeyHex "a0d3dc7ab62a0a2732ba267e0d57894170458ec1659ca1226240b99764554a2e"

runWithNoParams :: Parser a
                -> (a -> Validation (NonEmpty Text) b)
                -> Text
                -> Either String b
runWithNoParams p s = validationToEither . first show . s <=< run p

parseTerm :: Text -> Either String Term
parseTerm = runWithNoParams predicateTermParser $ substitutePTerm mempty

parseTermQQ :: Text -> Either String QQTerm
parseTermQQ = run predicateTermParser

parsePredicate :: Text -> Either String Predicate
parsePredicate = runWithNoParams predicateParser $ substitutePredicate mempty

parseRule :: Text -> Either String Rule
parseRule = runWithNoParams (ruleParser False) $ substituteRule mempty mempty

parseExpression :: Text -> Either String Expression
parseExpression = runWithNoParams expressionParser $ substituteExpression mempty

parseCheck :: Text -> Either String Check
parseCheck = runWithNoParams (checkParser False) $ substituteCheck mempty mempty

parseAuthorizer :: Text -> Either String Authorizer
parseAuthorizer = runWithNoParams authorizerParser $ substituteAuthorizer mempty mempty

parsePolicy :: Text -> Either String Policy
parsePolicy = runWithNoParams policyParser $ substitutePolicy mempty mempty

parseBlock :: Text -> Either String Block
parseBlock = runWithNoParams blockParser $ substituteBlock mempty mempty

specs :: TestTree
specs = testGroup "datalog parser"
  [ factWithDate
  , factWithNull
  , simpleFact
  , oneLetterFact
  , simpleRule
  , multilineRule
  , termsGroup
  , termsGroupQQ
  , constraints
  , constrainedRule
  , constrainedRuleOrdering
  , ruleVariables
  , ruleWithScopeParsing
  , checkParsing
  , policyParsing
  , authorizerParsing
  , blockParsing
  ]

termsGroup :: TestTree
termsGroup = testGroup "Parse terms"
  [ testCase "String" $ parseTerm "\"file1 a hello - 123_\"" @?= Right (LString "file1 a hello - 123_")
  , testCase "Positive integer" $ parseTerm "123" @?= Right (LInteger 123)
  , testCase "Negative integer" $ parseTerm "-42" @?= Right (LInteger (-42))
  , testCase "Positive integer (too large)" $ isLeft (parseTerm "9223372036854775808") @? "Integer literals must fit in the int64 range"
  , testCase "Negative integer (too small)" $ isLeft (parseTerm "-9223372036854775809") @? "Integer literals must fit in the int64 range"
  , testCase "Date" $ parseTerm "2019-12-02T13:49:53Z" @?=
        Right (LDate $ read "2019-12-02 13:49:53 UTC")
  , testCase "Variable" $ parseTerm "$1" @?= Right (Variable "1")
  , testCase "Antiquote" $ isLeft (parseTerm "{toto}") @? "Unsubstituted parameters triggers an error"
  ]

termsGroupQQ :: TestTree
termsGroupQQ = testGroup "Parse terms (in a QQ setting)"
  [ testCase "String" $ parseTermQQ "\"file1 a hello - 123_\"" @?= Right (LString "file1 a hello - 123_")
  , testCase "Positive integer" $ parseTermQQ "123" @?= Right (LInteger 123)
  , testCase "Negative integer" $ parseTermQQ "-42" @?= Right (LInteger (-42))
  , testCase "Date" $ parseTermQQ "2019-12-02T13:49:53Z" @?=
        Right (LDate $ read "2019-12-02 13:49:53 UTC")
  , testCase "Variable" $ parseTermQQ "$1" @?= Right (Variable "1")
  , testGroup "Antiquote"
     [ testCase "Variable name" $ parseTermQQ "{toto2_'}" @?= Right (Antiquote "toto2_'")
     , testCase "Leading underscore" $ parseTermQQ "{_toto}" @?= Right (Antiquote "_toto")
     , testCase "`_` is reserved" $ parseTermQQ "{_}" @?= Left "1:3:\n  |\n1 | {_}\n  |   ^\nunexpected '}'\nexpecting letter\n"
     , testCase "Variables are lower-cased" $ parseTermQQ "{Toto}" @?= Left "1:2:\n  |\n1 | {Toto}\n  |  ^^^^^\nunexpected \"Toto}\"\nexpecting '_', lowercase letter, map (eg. {\"key\": 1}), or set (eg. {1,2,3})\n"
     , testCase "_ is lower-case" $ parseTermQQ "{_Toto}" @?= Right (Antiquote "_Toto")
     , testCase "unicode is allowed" $ parseTermQQ "{éllo}" @?= Right (Antiquote "éllo")
     ]
  ]

simpleFact :: TestTree
simpleFact = testCase "Parse simple fact" $
  parsePredicate "right(\"file1\", \"read\")" @?=
    Right (Predicate "right" [LString "file1", LString "read"])

oneLetterFact :: TestTree
oneLetterFact = testCase "Parse one-letter fact" $
  parsePredicate "a(12)" @?=
    Right (Predicate "a" [LInteger 12])

factWithDate :: TestTree
factWithDate = testCase "Parse fact containing a date" $ do
  parsePredicate "date(2019-12-02T13:49:53Z)" @?=
    Right (Predicate "date" [LDate $ read "2019-12-02 13:49:53 UTC"])
  parsePredicate "date(2019-12-02T13:49:53.001Z)" @?=
    Right (Predicate "date" [LDate $ read "2019-12-02 13:49:53.001 UTC"])
  parsePredicate "date(2019-12-02T13:49:53+00:00)" @?=
    Right (Predicate "date" [LDate $ read "2019-12-02 13:49:53 UTC"])

factWithNull :: TestTree
factWithNull = testCase "Parse fact containing a null value" $ do
  parsePredicate "date(null)" @?=
    Right (Predicate "date" [LNull])

simpleRule :: TestTree
simpleRule = testCase "Parse simple rule" $
  parseRule "right($0, \"read\") <- resource( $0), operation(\"read\")" @?=
    Right (Rule (Predicate "right" [Variable "0", LString "read"])
                [ Predicate "resource" [Variable "0"]
                , Predicate "operation" [LString "read"]
                ] [] [])

multilineRule :: TestTree
multilineRule = testCase "Parse multiline rule" $
  parseRule "right($0, \"read\") <-\n resource( $0),\n operation(\"read\")" @?=
    Right (Rule (Predicate "right" [Variable "0", LString "read"])
                [ Predicate "resource" [Variable "0"]
                , Predicate "operation" [LString "read"]
                ] [] [])

constrainedRule :: TestTree
constrainedRule = testCase "Parse constained rule" $
  parseRule "valid_date(\"file1\") <- time($0), resource(\"file1\"), $0 <= 2019-12-04T09:46:41+00:00" @?=
    Right (Rule (Predicate "valid_date" [LString "file1"])
                [ Predicate "time" [Variable "0"]
                , Predicate "resource" [LString "file1"]
                ]
                [ EBinary LessOrEqual
                    (EValue $ Variable "0")
                    (EValue $ LDate $ read "2019-12-04 09:46:41 UTC")
                ] [])

constrainedRuleOrdering :: TestTree
constrainedRuleOrdering = testCase "Parse constained rule (interleaved)" $
  parseRule "valid_date(\"file1\") <- time($0), $0 <= 2019-12-04T09:46:41+00:00, resource(\"file1\")" @?=
    Right (Rule (Predicate "valid_date" [LString "file1"])
                [ Predicate "time" [Variable "0"]
                , Predicate "resource" [LString "file1"]
                ]
                [ EBinary LessOrEqual
                    (EValue $ Variable "0")
                    (EValue $ LDate $ read "2019-12-04 09:46:41 UTC")
                ] [])

constraints :: TestTree
constraints = testGroup "Parse expressions"
  [ testCase "date comparison (LTE)" $
      parseExpression "$0 <= 2030-12-31T12:59:59+00:00" @?=
        Right (EBinary LessOrEqual
                 (EValue (Variable "0"))
                 (EValue (LDate $ read "2030-12-31 12:59:59 UTC"))
                 )
  , testCase "date comparison (GTE)" $
      parseExpression "$0 >= 2030-12-31T12:59:59+00:00" @?=
        Right (EBinary GreaterOrEqual
                 (EValue (Variable "0"))
                 (EValue (LDate $ read "2030-12-31 12:59:59 UTC"))
                 )
  , testCase "int comparison (LT)" $
      parseExpression "$0 < 1234" @?=
        Right (EBinary LessThan
                 (EValue (Variable "0"))
                 (EValue (LInteger 1234))
                 )
  , testCase "int comparison (GT)" $
      parseExpression "$0 > 1234" @?=
        Right (EBinary GreaterThan
                 (EValue (Variable "0"))
                 (EValue (LInteger 1234))
                 )
  , testCase "int comparison (LTE)" $
      parseExpression "$0 <= 1234" @?=
        Right (EBinary LessOrEqual
                 (EValue (Variable "0"))
                 (EValue (LInteger 1234))
                 )
  , testCase "int comparison (EQ)" $
      parseExpression "$0 === 1" @?=
        Right (EBinary Equal
                 (EValue (Variable "0"))
                 (EValue (LInteger 1))
                 )
  , testCase "int comparison (NEQ)" $
      parseExpression "$0 !== 1" @?=
        Right (EBinary NotEqual
                 (EValue (Variable "0"))
                 (EValue (LInteger 1))
                 )
  , testCase "int comparison (HEQ)" $
      parseExpression "$0 == 1" @?=
        Right (EBinary HeterogeneousEqual
                 (EValue (Variable "0"))
                 (EValue (LInteger 1))
                 )
  , testCase "int comparison (HNEQ)" $
      parseExpression "$0 != 1" @?=
        Right (EBinary HeterogeneousNotEqual
                 (EValue (Variable "0"))
                 (EValue (LInteger 1))
                 )
  , testCase "negative int comparison (GTE)" $
      parseExpression "$0 >= -1234" @?=
        Right (EBinary GreaterOrEqual
                 (EValue (Variable "0"))
                 (EValue (LInteger (-1234)))
                 )
  , testCase "string comparison" $
      parseExpression "$0 === \"abc\"" @?=
        Right (EBinary Equal
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (NEQ)" $
      parseExpression "$0 !== \"abc\"" @?=
        Right (EBinary NotEqual
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (starts_with)" $
      parseExpression "$0.starts_with(\"abc\")" @?=
        Right (EBinary Prefix
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (ends_with)" $
      parseExpression "$0.ends_with(\"abc\")" @?=
        Right (EBinary Suffix
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (matches)" $
      parseExpression "$0.matches(\"abc\")" @?=
        Right (EBinary Regex
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "int set operation" $
      parseExpression "{1, 2}.contains($0)" @?=
        Right (EBinary Contains
                 (EValue (TermSet $ Set.fromList [LInteger 1, LInteger 2]))
                 (EValue (Variable "0"))
                 )
  , testCase "negated int set operation" $
      parseExpression "!{1, 2}.contains($0)" @?=
        Right (EUnary Negate
                 (EBinary Contains
                    (EValue (TermSet $ Set.fromList [LInteger 1, LInteger 2]))
                    (EValue (Variable "0"))
                    ))
  , testCase "string set operation" $
      parseExpression "{\"abc\", \"def\"}.contains($0)" @?=
        Right (EBinary Contains
                 (EValue (TermSet $ Set.fromList [LString "abc", LString "def"]))
                 (EValue (Variable "0"))
                 )
  , testCase "negated string set operation" $
      parseExpression "!{\"abc\", \"def\"}.contains($0)" @?=
        Right (EUnary Negate
                 (EBinary Contains
                    (EValue (TermSet $ Set.fromList [LString "abc", LString "def"]))
                    (EValue (Variable "0"))
                    ))
  , testCase "empty set operation" $
      parseExpression "{,}.length()" @?=
        Right (EUnary Length
                (EValue (TermSet $ Set.fromList []))
                )
  , testCase "arithmetic operation that looks like the beginning of a RFC3339 date" $
      parseExpression "2022-12-10===2000" @?=
        Right (EBinary Equal
                 (EBinary Sub
                    (EBinary Sub
                       (EValue $ LInteger 2022)
                       (EValue $ LInteger 12)
                    )
                    (EValue $ LInteger 10)
                 )
                 (EValue $ LInteger 2000)
              )
  , testCase "chained method calls" $
      parseExpression "$var.intersection({1}).union({2}).length()" @?=
        Right (EUnary Length
                 (EBinary Union
                    ( EBinary Intersection
                        (EValue $ Variable "var")
                        (EValue $ TermSet [LInteger 1])
                    )
                    (EValue $ TermSet [LInteger 2])
                 )
              )
  , testCase "nullary closures" $
      parseExpression "true || 1 === 2" @?=
        Right (EBinary LazyOr
                (EValue $ LBool True)
                  (EClosure []
                      (EBinary Equal
                          (EValue $ LInteger 1)
                          (EValue $ LInteger 2)
                      )
                  )
              )
  , testCase "unary closures" $
      parseExpression "{1}.all($p -> $p === 1)" @?=
        Right (EBinary All
                (EValue . TermSet . Set.singleton $ LInteger 1)
                (EClosure ["p"]
                    (EBinary Equal
                      (EValue $ Variable "p")
                      (EValue $ LInteger 1)
                    )
                )
              )
  , operatorPrecedences
  ]

operatorPrecedences :: TestTree
operatorPrecedences = testGroup "mixed-precedence operators"
  [ testCase "< +" $
      parseExpression " 1 < $test + 2 " @?=
        Right (EBinary LessThan
                 (EValue $ LInteger 1)
                 (EBinary Add
                    (EValue $ Variable "test")
                    (EValue $ LInteger 2)
                 )
              )
  , testCase "< && starts_with" $
      parseExpression " 2 < $test && $var2.starts_with(\"test\") && true " @?=
        Right (EBinary LazyAnd
                 (EBinary LazyAnd
                    (EBinary LessThan
                       (EValue $ LInteger 2)
                       (EValue $ Variable "test")
                    )
                    (EClosure []
                      (EBinary Prefix
                        (EValue $ Variable "var2")
                        (EValue $ LString "test")
                      )
                    )
                 )
                 (EClosure [] (EValue $ LBool True))
              )
  , testCase "+ *" $
      parseExpression "1 + 2 * 3" @?=
        Right (EBinary Add
                 (EValue $ LInteger 1)
                 (EBinary Mul
                    (EValue $ LInteger 2)
                    (EValue $ LInteger 3)
                 )
              )
  , testCase "+ * parens" $
      parseExpression "(1 + 2) * 3" @?=
        Right (EBinary Mul
                 (EUnary Parens
                    (EBinary Add
                       (EValue $ LInteger 1)
                       (EValue $ LInteger 2)
                    )
                 )
                 (EValue $ LInteger 3)
              )
  , testCase "+ & | *" $
      parseExpression "1 + 2 | 4 * 3 & 4" @?=
        Right (EBinary BitwiseOr
                  (EBinary Add
                    (EValue $ LInteger 1)
                    (EValue $ LInteger 2)
                  )
                  (EBinary BitwiseAnd
                    (EBinary Mul
                      (EValue $ LInteger 4)
                      (EValue $ LInteger 3)
                    )
                    (EValue $ LInteger 4)
                  )
              )
  ]

ruleVariables :: TestTree
ruleVariables = testGroup "Make sure rule & query variables are correctly introduced"
  [ testCase "Head variables are correctly introduced" $
      parseRule "head($unbound) <- body(true)" @?=
        Left "1:1:\n  |\n1 | head($unbound) <- body(true)\n  | ^\nUnbound variables: unbound\n"
  , testCase "Expression variables are correctly introduced (rule)" $
      parseRule "head(true) <- body(true), $unbound" @?=
        Left "1:1:\n  |\n1 | head(true) <- body(true), $unbound\n  | ^\nUnbound variables: unbound\n"
  , testCase "Expression variables are correctly introduced (check)" $
      parseCheck "check if body(true), $unbound" @?=
        Left "1:10:\n  |\n1 | check if body(true), $unbound\n  |          ^\nUnbound variables: unbound\n"
  , testCase "Expression variables are correctly introduced (allow policy)" $
      parsePolicy "allow if body(true), $unbound" @?=
        Left "1:10:\n  |\n1 | allow if body(true), $unbound\n  |          ^\nUnbound variables: unbound\n"
  , testCase "Expression variables are correctly introduced (deny policy)" $
      parsePolicy "deny if body(true), $unbound" @?=
        Left "1:9:\n  |\n1 | deny if body(true), $unbound\n  |         ^\nUnbound variables: unbound\n"
  ]

ruleWithScopeParsing :: TestTree
ruleWithScopeParsing = testCase "Parse constained rule with scope annotation" $
  parseRule "valid_date(\"file1\") <- time($0), resource(\"file1\"), $0 <= 2019-12-04T09:46:41+00:00 trusting previous" @?=
    Right (Rule (Predicate "valid_date" [LString "file1"])
                [ Predicate "time" [Variable "0"]
                , Predicate "resource" [LString "file1"]
                ]
                [ EBinary LessOrEqual
                    (EValue $ Variable "0")
                    (EValue $ LDate $ read "2019-12-04 09:46:41 UTC")
                ] [Previous])

checkParsing :: TestTree
checkParsing = testGroup "check blocks"
  [ testCase "Simple check" $
      parseCheck "check if true" @?=
        Right Check
          { cQueries = [QueryItem [] [EValue $ LBool True] []]
          , cKind = CheckOne
          }
  , testCase "Simple check all" $
      parseCheck "check all true" @?=
        Right Check
          { cQueries = [QueryItem [] [EValue $ LBool True] []]
          , cKind = CheckAll
          }
  , testCase "Simple reject if" $
      parseCheck "reject if true" @?=
        Right Check
          { cQueries = [QueryItem [] [EValue $ LBool True] []]
          , cKind = Reject
          }
  , testCase "Multiple groups" $
      parseCheck
        "check if fact($var), $var === true or \
        \other($var), $var === 2" @?=
          Right Check
            { cQueries =
                [ QueryItem [Predicate "fact" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                            []
                , QueryItem [Predicate "other" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                            []
                ]
            , cKind = CheckOne
            }
  , testCase "Multiple check all groups" $
      parseCheck
        "check all fact($var), $var === true or \
        \other($var), $var === 2" @?=
          Right Check
            { cQueries =
                [ QueryItem [Predicate "fact" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                            []
                , QueryItem [Predicate "other" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                            []
                ]
            , cKind = CheckAll
            }
  , testCase "Multiple reject if groups" $
      parseCheck
        "reject if fact($var), $var === true or \
        \other($var), $var === 2" @?=
          Right Check
            { cQueries =
                [ QueryItem [Predicate "fact" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                            []
                , QueryItem [Predicate "other" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                            []
                ]
            , cKind = Reject
            }
  , testCase "Multiple groups, scoped" $
      parseCheck
        "check if fact($var), $var === true trusting previous or \
        \other($var), $var === 2 trusting authority" @?=
          Right Check
            { cQueries =
                [ QueryItem [Predicate "fact" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                            [Previous]
                , QueryItem [Predicate "other" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                            [OnlyAuthority]
                ]
            , cKind = CheckOne
            }
  , testCase "Multiple check all groups, scoped" $
      parseCheck
        "check all fact($var), $var === true trusting previous or \
        \other($var), $var === 2 trusting authority" @?=
          Right Check
            { cQueries =
                [ QueryItem [Predicate "fact" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                            [Previous]
                , QueryItem [Predicate "other" [Variable "var"]]
                            [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                            [OnlyAuthority]
                ]
            , cKind = CheckAll
            }
  ]

policyParsing :: TestTree
policyParsing = testGroup "policy blocks"
  [ testCase "Simple allow policy" $
      parsePolicy "allow if true" @?=
        Right (Allow, [QueryItem [] [EValue $ LBool True] []])
  , testCase "Simple deny policy" $
      parsePolicy "deny if true" @?=
        Right (Deny, [QueryItem [] [EValue $ LBool True] []])
  , testCase "Allow with multiple groups" $
      parsePolicy
        "allow if fact($var), $var === true or \
        \other($var), $var === 2" @?=
          Right
            ( Allow
            , [ QueryItem [Predicate "fact" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                          []
              , QueryItem [Predicate "other" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                          []
              ]
            )
  , testCase "Deny with multiple groups" $
      parsePolicy
        "deny if fact($var), $var === true or \
        \other($var), $var === 2" @?=
          Right
            ( Deny
            , [ QueryItem [Predicate "fact" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                          []
              , QueryItem [Predicate "other" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                          []
              ]
            )
  , testCase "Deny with multiple groups, multiline" $
      parsePolicy
        "deny if\n\
           \fact($var), $var === true or //comment\n\
           \other($var), $var === 2" @?=
          Right
            ( Deny
            , [ QueryItem [Predicate "fact" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                          []
              , QueryItem [Predicate "other" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                          []
              ]
            )
  , testCase "Allow with multiple groups, scoped" $
      parsePolicy
        "allow if fact($var), $var === true trusting authority or \
        \other($var), $var === 2 trusting ed25519/a1b712761c609039f878edad694d762652f1548a68acccc96735b3196a240e8b,ed25519/083aae4ba29a9a3781cdee7a800f4f8ab90591f65ca983fc429687628311aedd,ed25519/c6864578bc03596d52878bd70025ec966c95c60727cb6573198453e82132510d " @?=
          Right
            ( Allow
            , [ QueryItem [Predicate "fact" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                          [OnlyAuthority]
              , QueryItem [Predicate "other" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                          [BlockId pk1, BlockId pk3, BlockId pk4]
              ]
            )
  ]

authorizerParsing :: TestTree
authorizerParsing = testGroup "Simple authorizers"
  [ testCase "Just a deny" $
      parseAuthorizer "deny if true;" @?=
        Right (Authorizer [(Deny, [QueryItem [] [EValue (LBool True)] []])] mempty
              )
  , testCase "Allow and deny" $
      parseAuthorizer "allow if operation(\"read\");\n deny if true;" @?=
        Right (Authorizer
                 [  (Allow, [QueryItem [Predicate "operation" [LString "read"]] [] []])
                 , (Deny, [QueryItem [] [EValue (LBool True)] []])
                 ]
                 mempty
              )
  , testCase "Previous is denied at the top level" $
      parseAuthorizer "trusting previous; allow if true;" @?=
        Left "1:10:\n  |\n1 | trusting previous; allow if true;\n  |          ^\n'previous' can't appear in an authorizer scope\n"
  , testCase "Previous is denied in rules" $
      parseAuthorizer "head(true) <- tail(true) trusting previous;" @?=
        Left "1:35:\n  |\n1 | head(true) <- tail(true) trusting previous;\n  |                                   ^\n'previous' can't appear in an authorizer scope\n"
  , testCase "Previous is denied in checks" $
      parseAuthorizer "check if true trusting previous;" @?=
        Left "1:24:\n  |\n1 | check if true trusting previous;\n  |                        ^\n'previous' can't appear in an authorizer scope\n"
  , testCase "Previous is denied in policies" $
      parseAuthorizer "allow if true trusting previous;" @?=
        Left "1:24:\n  |\n1 | allow if true trusting previous;\n  |                        ^\n'previous' can't appear in an authorizer scope\n"
  , testCase "Complete authorizer" $ do
      let spec :: Text
          spec =
            " trusting authority;\n\
            \// the owner has all rights\n\
            \right($blog_id, $article_id, $operation) <-\n\
            \    article($blog_id, $article_id),\n\
            \    operation($operation),\n\
            \    user($user_id),\n\
            \    owner($user_id, $blog_id);\n\
            \// premium users can access some restricted articles\n\
            \right($blog_id, $article_id, \"read\") <-\n\
            \  article($blog_id, $article_id),\n\
            \  premium_readable($blog_id, $article_id),\n\
            \  user($user_id),\n\
            \  premium_user($user_id, $blog_id);\n\
            \// define teams and roles\n\
            \right($blog_id, $article_id, $operation) <-\n\
            \  article($blog_id, $article_id),\n\
            \  operation($operation),\n\
            \  user($user_id),\n\
            \  member($user_id, $team_id),\n\
            \  team_role($team_id, $blog_id, \"contributor\"),\n\
            \  {\"read\", \"write\"}.contains($operation);\n\
            \// unauthenticated users have read access on published articles\n\
            \allow if\n\
            \  operation(\"read\"),\n\
            \  article($blog_id, $article_id),\n\
            \  readable($blog_id, $article_id);\n\
            \// authorize if got the rights on this blog and article\n\
            \allow if\n\
            \  blog($blog_id),\n\
            \  article($blog_id, $article_id),\n\
            \  operation($operation),\n\
            \  right($blog_id, $article_id, $operation);\n\
            \// catch all rule in case the allow did not match\n\
            \deny if true;\
            \ "
          p = Predicate
          sRead = LString "read"
          sWrite = LString "write"
          sContributor = LString "contributor"
          vBlogId = Variable "blog_id"
          vArticleId = Variable "article_id"
          vUserId = Variable "user_id"
          vTeamId = Variable "team_id"
          vOp = Variable "operation"
          bRules =
            [ Rule (p "right" [vBlogId, vArticleId, vOp])
                   [ p "article" [vBlogId, vArticleId]
                   , p "operation" [vOp]
                   , p "user" [vUserId]
                   , p "owner" [vUserId, vBlogId]
                   ] [] []
            , Rule (p "right" [vBlogId, vArticleId, sRead])
                   [ p "article" [vBlogId, vArticleId]
                   , p "premium_readable" [vBlogId, vArticleId]
                   , p "user" [vUserId]
                   , p "premium_user" [vUserId, vBlogId]
                   ] [] []
            , Rule (p "right" [vBlogId, vArticleId, vOp])
                   [ p "article" [vBlogId, vArticleId]
                   , p "operation" [vOp]
                   , p "user" [vUserId]
                   , p "member" [vUserId, vTeamId]
                   , p "team_role" [vTeamId, vBlogId, sContributor]
                   ] [EBinary Contains (EValue (TermSet $ Set.fromList [sRead, sWrite]))
                                       (EValue vOp)] []
           ]
          bFacts = []
          bChecks = []
          bContext = Nothing
          bScope = [OnlyAuthority]
          vPolicies =
            [ (Allow, [QueryItem [ p "operation" [sRead]
                                 , p "article"   [vBlogId, vArticleId]
                                 , p "readable"  [vBlogId, vArticleId]
                                 ] [] []])
            , (Allow, [QueryItem [ p "blog" [vBlogId]
                                 , p "article" [vBlogId, vArticleId]
                                 , p "operation" [vOp]
                                 , p "right" [vBlogId, vArticleId, vOp]
                                 ] [] []])
            , (Deny, [QueryItem [] [EValue (LBool True)] []])
            ]
      parseAuthorizer spec @?= Right Authorizer{vBlock = Block{..}, ..}
  ]

blockParsing :: TestTree
blockParsing = testCase "Full block" $ do
  let spec :: Text
      spec =
        " trusting ed25519/b82c748be51784a58496675752e04cc48009a7e78bcfae8cad51fba959102af1,ed25519/083aae4ba29a9a3781cdee7a800f4f8ab90591f65ca983fc429687628311aedd,ed25519/a0d3dc7ab62a0a2732ba267e0d57894170458ec1659ca1226240b99764554a2e;\n\
        \// the owner has all rights\n\
        \right($blog_id, $article_id, $operation) <-\n\
        \    article($blog_id, $article_id),\n\
        \    operation($operation),\n\
        \    user($user_id),\n\
        \    owner($user_id, $blog_id);\n\
        \// premium users can access some restricted articles\n\
        \right($blog_id, $article_id, \"read\") <-\n\
        \  article($blog_id, $article_id),\n\
        \  premium_readable($blog_id, $article_id),\n\
        \  user($user_id),\n\
        \  premium_user($user_id, $blog_id);\n\
        \// define teams and roles\n\
        \right($blog_id, $article_id, $operation) <-\n\
        \  article($blog_id, $article_id),\n\
        \  operation($operation),\n\
        \  user($user_id),\n\
        \  member($user_id, $team_id),\n\
        \  team_role($team_id, $blog_id, \"contributor\"),\n\
        \  {\"read\", \"write\"}.contains($operation);\n\
        \ "
      p = Predicate
      sRead = LString "read"
      sWrite = LString "write"
      sContributor = LString "contributor"
      vBlogId = Variable "blog_id"
      vArticleId = Variable "article_id"
      vUserId = Variable "user_id"
      vTeamId = Variable "team_id"
      vOp = Variable "operation"
      bRules =
        [ Rule (p "right" [vBlogId, vArticleId, vOp])
               [ p "article" [vBlogId, vArticleId]
               , p "operation" [vOp]
               , p "user" [vUserId]
               , p "owner" [vUserId, vBlogId]
               ] [] []
        , Rule (p "right" [vBlogId, vArticleId, sRead])
               [ p "article" [vBlogId, vArticleId]
               , p "premium_readable" [vBlogId, vArticleId]
               , p "user" [vUserId]
               , p "premium_user" [vUserId, vBlogId]
               ] [] []
        , Rule (p "right" [vBlogId, vArticleId, vOp])
               [ p "article" [vBlogId, vArticleId]
               , p "operation" [vOp]
               , p "user" [vUserId]
               , p "member" [vUserId, vTeamId]
               , p "team_role" [vTeamId, vBlogId, sContributor]
               ] [EBinary Contains (EValue (TermSet $ Set.fromList [sRead, sWrite]))
                                   (EValue vOp)] []
       ]
      bFacts = []
      bChecks = []
      bContext = Nothing
      bScope = Set.fromList $ BlockId <$> [pk2,pk3,pk5]
  parseBlock spec @?= Right Block{..}

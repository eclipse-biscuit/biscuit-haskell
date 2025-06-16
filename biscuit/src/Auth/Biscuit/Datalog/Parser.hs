{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TemplateHaskellQuotes #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeApplications      #-}
{-|
  Module      : Auth.Biscuit.Datalog.AST
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
  Maintainer  : clement@delafargue.name
  Parser for the authorization language
-}
module Auth.Biscuit.Datalog.Parser
  where

import           Auth.Biscuit.Crypto            (PublicKey,
                                                 readEd25519PublicKey)
import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Utils             (decodeHex)
import           Control.Monad                  (join)
import qualified Control.Monad.Combinators.Expr as Expr
import           Data.Bifunctor
import           Data.ByteString                (ByteString)
import qualified Data.ByteString.Char8          as C8
import           Data.Char
import           Data.Either                    (partitionEithers)
import           Data.Function                  ((&))
import           Data.Int                       (Int64)
import           Data.List.NonEmpty             (NonEmpty)
import qualified Data.List.NonEmpty             as NE
import           Data.Map.Strict                (Map)
import qualified Data.Map.Strict                as Map
import           Data.Maybe                     (isJust)
import           Data.Set                       (Set)
import qualified Data.Set                       as Set
import           Data.Text                      (Text)
import qualified Data.Text                      as T
import           Data.Time                      (UTCTime, defaultTimeLocale,
                                                 parseTimeM)
import           Instances.TH.Lift              ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Quote      (QuasiQuoter (..))
import           Language.Haskell.TH.Syntax     (Lift)
import           Text.Megaparsec
import qualified Text.Megaparsec.Char           as C
import qualified Text.Megaparsec.Char.Lexer     as L
import           Validation                     (Validation (..),
                                                 validationToEither)

type Parser = Parsec SemanticError Text

type Span = (Int, Int)

data SemanticError =
    VarInFact Span
  | VarInCollection  Span
  | NestedSet Span
  | InvalidBs Text Span
  | InvalidPublicKey Text Span
  | UnboundVariables (NonEmpty Text) Span
  | PreviousInAuthorizer Span
  deriving stock (Eq, Ord)

instance ShowErrorComponent SemanticError where
  showErrorComponent = \case
    VarInFact _            -> "Variables can't appear in a fact"
    VarInCollection  _     -> "Variables can't appear in a collection (set, array, map"
    NestedSet _            -> "Sets cannot be nested"
    InvalidBs e _          -> "Invalid bytestring literal: " <> T.unpack e
    InvalidPublicKey e _   -> "Invalid public key: " <> T.unpack e
    UnboundVariables e _   -> "Unbound variables: " <> T.unpack (T.intercalate ", " $ NE.toList e)
    PreviousInAuthorizer _ -> "'previous' can't appear in an authorizer scope"

run :: Parser a -> Text -> Either String a
run p = first errorBundlePretty . runParser (l (pure ()) *> l p <* eof) ""

l :: Parser a -> Parser a
l = L.lexeme $ L.space C.space1 (L.skipLineComment "//") empty

getSpan :: Parser a -> Parser (Span, a)
getSpan p = do
  begin <- getOffset
  a <- p
  end <- getOffset
  pure ((begin, end), a)

registerError :: (Span -> SemanticError) -> Span -> Parser a
registerError mkError sp = do
  let err = FancyError (fst sp) (Set.singleton (ErrorCustom $ mkError sp))
  registerParseError err
  pure $ error "delayed parsing error"

forbid :: (Span -> SemanticError) -> Parser a -> Parser b
forbid mkError p = do
  (sp, _) <- getSpan p
  registerError mkError sp

identifierParser :: Parser Text
identifierParser = takeWhile1P (Just "_, :, or any alphanumeric char") (\c -> c == '_' || c == ':' || isAlphaNum c)

variableParser :: Parser Text
variableParser =
  C.char '$' *> identifierParser

haskellVariableParser :: Parser Text
haskellVariableParser = l $ do
  _ <- chunk "{"
  leadingUS <- optional $ C.char '_'
  x <- if isJust leadingUS then C.letterChar else C.lowerChar
  xs <- takeWhileP (Just "_, ', or any alphanumeric char") (\c -> c == '_' || c == '\'' || isAlphaNum c)
  _ <- C.char '}'
  pure . maybe id T.cons leadingUS $ T.cons x xs

setParser :: Parser (Set (Term' 'WithinSet 'InFact 'WithSlices))
setParser = choice [emptySetParser, nonEmptySetParser]

emptySetParser :: Parser (Set (Term' 'WithinSet 'InFact 'WithSlices))
emptySetParser = mempty <$ chunk "{,}"

setTermParser :: Parser (Term' 'WithinSet 'InFact 'WithSlices)
setTermParser = termParser
  (forbid VarInCollection variableParser)
  (forbid NestedSet setParser)
  (forbid NestedSet arrayParser)
  (forbid NestedSet mapParser)

nonEmptySetParser :: Parser (Set (Term' 'WithinSet 'InFact 'WithSlices))
nonEmptySetParser = do
  _ <- l $ C.char '{'
  ts <- sepBy1 setTermParser (l $ C.char ',')
  _ <- l $ C.char '}'
  pure $ Set.fromList ts

valueParser :: Parser (Term' 'NotWithinSet 'InFact 'WithSlices)
valueParser = termParser
  (forbid VarInCollection variableParser)
  setParser
  arrayParser
  mapParser

arrayParser :: Parser [Term' 'NotWithinSet 'InFact 'WithSlices]
arrayParser = do
  _ <- l $ C.char '['
  ts <- sepBy1 valueParser (l $ C.char ',')
  _ <- l $ C.char ']'
  pure ts

mapEntryParser :: Parser (MapKey, Term' 'NotWithinSet 'InFact 'WithSlices)
mapEntryParser = do
  k <- l $ choice [ IntKey <$> intParser
                  , StringKey <$> stringParser
                  ]
  _ <- l $ C.char ':'
  v <- l valueParser
  pure (k, v)

mapParser :: Parser (Map MapKey (Term' 'NotWithinSet 'InFact 'WithSlices))
mapParser = do
  _ <- l $ C.char '{'
  ts <- sepBy1 mapEntryParser (l $ C.char ',')
  _ <- l $ C.char '}'
  pure $ Map.fromList ts

factTermParser :: Parser (Term' 'NotWithinSet 'InFact 'WithSlices)
factTermParser = termParser (forbid VarInFact variableParser)
                            setParser
                            arrayParser
                            mapParser

predicateTermParser :: Parser (Term' 'NotWithinSet 'InPredicate 'WithSlices)
predicateTermParser = termParser variableParser
                                 setParser
                                 arrayParser
                                 mapParser

termParser :: Parser (VariableType inSet pof)
           -> Parser (SetType inSet 'WithSlices)
           -> Parser (ArrayType inSet 'WithSlices)
           -> Parser (MapType inSet 'WithSlices)
           -> Parser (Term' inSet pof 'WithSlices)
termParser parseVar parseSet parseArray parseMap = l $ choice
  [ TermSet <$> try parseSet <?> "set (eg. {1,2,3})"
  , TermArray <$> try parseArray <?> "array (eg. [1, 2, 3])"
  , TermMap <$> try parseMap <?> "map (eg. {\"key\": 1})"
  , Antiquote . Slice <$> haskellVariableParser <?> "parameter (eg. {paramName})"
  , Variable <$> parseVar <?> "datalog variable (eg. $variable)"
  , LBytes <$> (chunk "hex:" *> hexParser) <?> "hex-encoded bytestring (eg. hex:00ff99)"
  , LDate <$> rfc3339DateParser <?> "RFC3339-formatted timestamp (eg. 2022-11-29T00:00:00Z)"
  , LInteger <$> intParser <?> "(signed) integer"
  , LString <$> stringParser <?> "string literal"
  , LBool <$> choice [ True <$ chunk "true"
                     , False <$ chunk "false"
                     ]
          <?> "boolean value (eg. true or false)"
  , LNull <$ chunk "null" <?> "null value"
  ]

stringParser :: Parser Text
stringParser = T.pack <$> (C.char '"' *> manyTill L.charLiteral (C.char '"'))

intParser :: Parser Int64
intParser = do
  integer :: Integer <- L.signed C.space L.decimal <?> "(signed) integer"
  if integer < fromIntegral (minBound @Int64)
     || integer > fromIntegral (maxBound @Int64)
  then fail "integer literals must fit in the int64 range"
  else pure $ fromIntegral integer

hexParser :: Parser ByteString
hexParser = do
  (sp, hexStr) <- getSpan $ C8.pack <$> some C.hexDigitChar
  case decodeHex hexStr of
    Left e   -> registerError (InvalidBs e) sp
    Right bs -> pure bs

publicKeyParser :: Parser PublicKey
publicKeyParser = do
  (sp, hexStr) <- getSpan $ C8.pack <$> (chunk "ed25519/" *> some C.hexDigitChar)
  case decodeHex hexStr of
    Left e -> registerError (InvalidPublicKey e) sp
    Right bs -> case readEd25519PublicKey bs of
      Nothing -> registerError (InvalidPublicKey "Invalid ed25519 public key") sp
      Just pk -> pure pk

rfc3339DateParser :: Parser UTCTime
rfc3339DateParser = do
  let parseDate = parseTimeM False defaultTimeLocale "%FT%T%Q%EZ"
  input <- sequenceA [
      try (sequenceA [
        C.digitChar,
        C.digitChar,
        C.digitChar,
        C.digitChar,
        C.char '-',
        C.digitChar,
        C.digitChar,
        C.char '-',
        C.digitChar,
        C.digitChar,
        C.char 'T'
      ]),
      pure <$> C.digitChar,
      pure <$> C.digitChar,
      pure <$> C.char ':',
      pure <$> C.digitChar,
      pure <$> C.digitChar,
      pure <$> C.char ':',
      pure <$> C.digitChar,
      pure <$> C.digitChar,
      foldMap join <$> optional (sequenceA [
        pure <$> C.char '.',
        some C.digitChar
      ]),
      choice [
        pure <$> C.char 'Z',
        sequenceA [
           choice [C.char '+', C.char '-'],
           C.digitChar,
           C.digitChar,
           C.char ':',
           C.digitChar,
           C.digitChar
        ]
      ]
    ]
  parseDate $ join input

predicateParser' :: Parser (Term' 'NotWithinSet pof 'WithSlices)
                 -> Parser (Predicate' pof 'WithSlices)
predicateParser' parseTerm = l $ do
  name <- try . (<?> "predicate name") $ do
    x      <- C.letterChar
    xs     <- takeWhileP (Just "_, :, or any alphanumeric char") (\c -> c == '_' || c == ':' || isAlphaNum c)
    _      <- l $ C.char '('
    pure $ T.cons x xs
  terms  <- sepBy1 parseTerm (l $ C.char ',')
  _      <- l $ C.char ')'
  pure Predicate {
    name,
    terms
  }

factParser :: Parser (Predicate' 'InFact 'WithSlices)
factParser = predicateParser' factTermParser

predicateParser :: Parser (Predicate' 'InPredicate 'WithSlices)
predicateParser = predicateParser' predicateTermParser

closureParser :: Parser (Text, Expression' 'WithSlices)
closureParser = do
    param <- l variableParser
    _ <- l $ chunk "->"
    body <- l expressionParser
    pure (param, body)

expressionParser :: Parser (Expression' 'WithSlices)
expressionParser =
  let base = choice [ try methodsParser
                    , exprTerm
                    ]
   in Expr.makeExprParser base table

table :: [[Expr.Operator Parser (Expression' 'WithSlices)]]
table =
  let infixL name op = Expr.InfixL (makeBinary op <$ l (chunk name) <?> "infix operator")
      infixN name op = Expr.InfixN (makeBinary op <$ l (chunk name) <?> "infix operator")
      prefix name op = Expr.Prefix (EUnary op <$  l (chunk name) <?> "prefix operator")
      makeBinary LazyOr e e'  = EBinary LazyOr e (EClosure [] e')
      makeBinary LazyAnd e e' = EBinary LazyAnd e (EClosure [] e')
      makeBinary op e e'      = EBinary op e e'
   in [ [ prefix "!" Negate]
      , [ infixL  "*" Mul
        , infixL  "/" Div
        ]
      , [ infixL  "+" Add
        , infixL  "-" Sub
        ]
      -- TODO find a better way to avoid eager parsing
      -- of && and || by the bitwise operators
      , [ infixL  "& " BitwiseAnd ]
      , [ infixL  "| " BitwiseOr  ]
      , [ infixL  "^" BitwiseXor ]
      , [ infixN  "<=" LessOrEqual
        , infixN  ">=" GreaterOrEqual
        , infixN  "<"  LessThan
        , infixN  ">"  GreaterThan
        , infixN  "===" Equal
        , infixN  "!==" NotEqual
        , infixN  "==" HeterogeneousEqual
        , infixN  "!=" HeterogeneousNotEqual
        ]
      , [ infixL "&&" LazyAnd ]
      , [ infixL "||" LazyOr ]
      ]

binaryMethodParser :: Parser (Expression' 'WithSlices -> Expression' 'WithSlices)
binaryMethodParser = do
  _ <- C.char '.'
  method <- choice
    [ Contains     <$ chunk "contains"
    , Intersection <$ chunk "intersection"
    , Union        <$ chunk "union"
    , Prefix       <$ chunk "starts_with"
    , Suffix       <$ chunk "ends_with"
    , Regex        <$ chunk "matches"
    , Any          <$ chunk "any"
    , All          <$ chunk "all"
    , Get          <$ chunk "get"
    , BinaryFfi    <$> (chunk "extern::" *> identifierParser)
    , Try          <$ chunk "try_or"
    ]
  _ <- l $ C.char '('
  e2 <- case method of
    Any -> uncurry EClosure . first pure <$> l closureParser
    All -> uncurry EClosure . first pure <$> l closureParser
    _   -> l expressionParser
  _ <- l $ C.char ')'
  pure $ \e1 -> case method of
    Try -> EBinary method (EClosure [] e1) e2
    _   -> EBinary method e1 e2

unaryMethodParser :: Parser (Expression' 'WithSlices -> Expression' 'WithSlices)
unaryMethodParser = do
  _ <- C.char '.'
  method <- choice
            [ Length <$ chunk "length"
            , TypeOf <$ chunk "type"
            , UnaryFfi <$> (chunk "extern::" *> identifierParser)
            ]
  _ <- l $ chunk "()"
  pure $ EUnary method

methodsParser :: Parser (Expression' 'WithSlices)
methodsParser = do
  e1 <- exprTerm
  methods <- some (try binaryMethodParser <|> unaryMethodParser)
  pure $ foldl (&) e1 methods

unaryParens :: Parser (Expression' 'WithSlices)
unaryParens = do
  _ <- l $ C.char '('
  e <- l expressionParser
  _ <- l $ C.char ')'
  pure $ EUnary Parens e

exprTerm :: Parser (Expression' 'WithSlices)
exprTerm = choice
  [ unaryParens <?> "parens"
  , EValue <$> predicateTermParser
  ]

ruleParser :: Bool -> Parser (Rule' 'Repr 'WithSlices)
ruleParser inAuthorizer = do
  begin <- getOffset
  rhead <- try $ l predicateParser <* l (chunk "<-")
  (body, expressions, scope) <- ruleBodyParser inAuthorizer
  end <- getOffset
  case makeRule rhead body expressions scope of
    Failure vs -> registerError (UnboundVariables vs) (begin, end)
    Success r  -> pure r

ruleBodyParser :: Bool -> Parser ([Predicate' 'InPredicate 'WithSlices], [Expression' 'WithSlices], Set.Set (RuleScope' 'Repr 'WithSlices))
ruleBodyParser inAuthorizer = do
  let predicateOrExprParser =
            Left  <$> (predicateParser <?> "predicate")
        <|> Right <$> (expressionParser <?> "expression")
  elems <- l $ sepBy1 (l predicateOrExprParser)
                      (l $ C.char ',')
  scope <- option Set.empty $ scopeParser inAuthorizer
  let (predicates, expressions) = partitionEithers elems
  pure (predicates, expressions, scope)

scopeParser :: Bool -> Parser (Set.Set (RuleScope' 'Repr 'WithSlices))
scopeParser inAuthorizer = (<?> "scope annotation") $ do
  _ <- l $ chunk "trusting "
  let elemParser = do
        (sp, s) <- getSpan $ choice [ OnlyAuthority <$  chunk "authority"
                                    , Previous      <$  chunk "previous"
                                    , BlockId       <$>
                                       choice [ PkSlice <$> haskellVariableParser <?> "parameter (eg. {paramName})"
                                              , Pk <$> publicKeyParser <?> "public key (eg. ed25519/00ff99)"
                                              ]
                                    ]
        if inAuthorizer && s == Previous
        then registerError PreviousInAuthorizer sp
        else pure s
  Set.fromList <$> sepBy1 (l elemParser)
                          (l $ C.char ',')

queryItemParser :: Bool -> Parser (QueryItem' 'Repr 'WithSlices)
queryItemParser inAuthorizer = do
  (sp, (predicates, expressions, scope)) <- getSpan $ ruleBodyParser inAuthorizer
  case makeQueryItem predicates expressions scope of
    Failure e  -> registerError (UnboundVariables e) sp
    Success qi -> pure qi

queryParser :: Bool -> Parser [QueryItem' 'Repr 'WithSlices]
queryParser inAuthorizer =
   sepBy1 (queryItemParser inAuthorizer) (l $ C.string' "or" <* C.space)
     <?> "datalog query"

checkParser :: Bool -> Parser (Check' 'Repr 'WithSlices)
checkParser inAuthorizer = do
  cKind <- l $ choice [ CheckOne <$ chunk "check if"
                      , CheckAll <$ chunk "check all"
                      , Reject <$ chunk "reject if"
                      ]
  cQueries <- queryParser inAuthorizer
  pure Check{..}

policyParser :: Parser (Policy' 'Repr 'WithSlices)
policyParser = do
  policy <- l $ choice [ Allow <$ chunk "allow if"
                       , Deny  <$ chunk "deny if"
                       ]
  (policy, ) <$> queryParser True

blockElementParser :: Bool -> Parser (BlockElement' 'Repr 'WithSlices)
blockElementParser inAuthorizer = choice
  [ BlockCheck   <$> checkParser inAuthorizer <* C.char ';' <?> "check"
  , BlockRule    <$> ruleParser  inAuthorizer <* C.char ';' <?> "rule"
  , BlockFact    <$> factParser <* C.char ';' <?> "fact"
  ]

authorizerElementParser :: Parser (AuthorizerElement' 'Repr 'WithSlices)
authorizerElementParser = choice
  [ AuthorizerPolicy  <$> policyParser <* C.char ';' <?> "policy"
  , BlockElement    <$> blockElementParser True
  ]

blockParser :: Parser (Block' 'Repr 'WithSlices)
blockParser = do
  bScope <- option Set.empty $ l (scopeParser False <* C.char ';' <?> "scope annotation")
  elems <- many $ l $ blockElementParser False
  pure $ (foldMap elementToBlock elems) { bScope = bScope }

authorizerParser :: Parser (Authorizer' 'Repr 'WithSlices)
authorizerParser = do
  bScope <- option Set.empty $ l (scopeParser True <* C.char ';' <?> "scope annotation")
  elems <- many $ l authorizerElementParser
  let addScope a = a { vBlock = (vBlock a) { bScope = bScope } }
  pure $ addScope $ foldMap elementToAuthorizer elems

parseWithParams :: Parser (a 'WithSlices)
                -> (Map Text Value -> Map Text PublicKey -> a 'WithSlices -> Validation (NonEmpty Text) (a 'Representation))
                -> Text
                -> Map Text Value -> Map Text PublicKey
                -> Either (NonEmpty Text) (a 'Representation)
parseWithParams parser substitute input termMapping keyMapping = do
  withSlices <- first (pure . T.pack) $ run parser input
  validationToEither $ substitute termMapping keyMapping withSlices

parseBlock :: Text -> Map Text Value -> Map Text PublicKey
           -> Either (NonEmpty Text) Block
parseBlock = parseWithParams blockParser substituteBlock

parseAuthorizer :: Text -> Map Text Value -> Map Text PublicKey
                -> Either (NonEmpty Text) Authorizer
parseAuthorizer = parseWithParams authorizerParser substituteAuthorizer

compileParser :: Lift a => Parser a -> (a -> Q Exp) -> String -> Q Exp
compileParser p build =
  either fail build . run p . T.pack

-- | Quasiquoter for a rule expression. You can reference haskell variables
-- like this: @{variableName}@.
--
-- You most likely want to directly use 'block' or 'authorizer' instead.
rule :: QuasiQuoter
rule = QuasiQuoter
  { quoteExp = compileParser (ruleParser False) $ \result -> [| result :: Rule |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Quasiquoter for a predicate expression. You can reference haskell variables
-- like this: @{variableName}@.
--
-- You most likely want to directly use 'block' or 'authorizer' instead.
predicate :: QuasiQuoter
predicate = QuasiQuoter
  { quoteExp = compileParser predicateParser $ \result -> [| result :: Predicate |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Quasiquoter for a fact expression. You can reference haskell variables
-- like this: @{variableName}@.
--
-- You most likely want to directly use 'block' or 'authorizer' instead.
fact :: QuasiQuoter
fact = QuasiQuoter
  { quoteExp = compileParser factParser $ \result -> [| result :: Fact |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Quasiquoter for a check expression. You can reference haskell variables
-- like this: @{variableName}@.
--
-- You most likely want to directly use 'block' or 'authorizer' instead.
check :: QuasiQuoter
check = QuasiQuoter
  { quoteExp = compileParser (checkParser False) $ \result -> [| result :: Check |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Compile-time parser for a block expression, intended to be used with the
-- @QuasiQuotes@ extension.
--
-- A typical use of 'block' looks like this:
--
-- > let fileName = "data.pdf"
-- >  in [block|
-- >       // datalog can reference haskell variables with {variableName}
-- >       resource({fileName});
-- >       rule($variable) <- fact($value), other_fact($value);
-- >       check if operation("read");
-- >     |]
block :: QuasiQuoter
block = QuasiQuoter
  { quoteExp = compileParser blockParser $ \result -> [| result :: Block |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Compile-time parser for an authorizer expression, intended to be used with the
-- @QuasiQuotes@ extension.
--
-- A typical use of 'authorizer' looks like this:
--
-- > do
-- >   now <- getCurrentTime
-- >   pure [authorizer|
-- >          // datalog can reference haskell variables with {variableName}
-- >          current_time({now});
-- >          // authorizers can contain facts, rules and checks like blocks, but
-- >          // also declare policies. While every check has to pass for a biscuit to
-- >          // be valid, policies are tried in order. The first one to match decides
-- >          // if the token is valid or not
-- >          allow if resource("file1");
-- >          deny if true;
-- >        |]
authorizer :: QuasiQuoter
authorizer = QuasiQuoter
  { quoteExp = compileParser authorizerParser $ \result -> [| result :: Authorizer |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Compile-time parser for a query expression, intended to be used with the
-- @QuasiQuotes@ extension.
--
-- A typical use of 'query' looks like this:
--
-- > [query|user($user_id) or group($group_id)|]
query :: QuasiQuoter
query = QuasiQuoter
  { quoteExp = compileParser (queryParser False) $ \result -> [| result :: Query |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

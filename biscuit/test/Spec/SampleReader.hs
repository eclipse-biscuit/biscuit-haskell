{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DeriveTraversable     #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE TypeApplications      #-}
{-
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
-}
module Spec.SampleReader where

import           Control.Arrow                 ((&&&))
import           Control.Lens                  ((^?))
import           Control.Monad                 (join, void, when)
import           Data.Aeson
import           Data.Aeson.Lens               (key)
import           Data.Aeson.Types              (typeMismatch, unexpected)
import           Data.Bifunctor                (Bifunctor (..))
import           Data.ByteString               (ByteString)
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Base16        as Hex
import qualified Data.ByteString.Lazy          as LBS
import           Data.Foldable                 (fold, traverse_)
import           Data.List.NonEmpty            (NonEmpty (..), toList)
import           Data.Map.Strict               (Map)
import qualified Data.Map.Strict               as Map
import           Data.Maybe                    (fromJust, isJust, isNothing)
import           Data.Text                     (Text, pack, unpack)
import           Data.Text.Encoding            (decodeUtf8, encodeUtf8)
import           Data.Traversable              (for)
import           GHC.Generics                  (Generic)
import           GHC.Records                   (HasField (getField))

import           Test.Tasty                    hiding (Timeout)
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Datalog.AST      (renderAuthorizer, renderBlock)
import           Auth.Biscuit.Datalog.Executor (ExecutionError (..),
                                                ResultError (..))
import           Auth.Biscuit.Datalog.Parser   (authorizerParser, blockParser)
import           Auth.Biscuit.Token
import           Auth.Biscuit.Utils            (encodeHex)

import           Spec.Parser                   (parseAuthorizer, parseBlock)

getB :: ParsedSignedBlock -> Block
getB ((_, b), _, _, _) = b

getAuthority :: Biscuit p Verified -> Block
getAuthority = getB . authority

getBlocks :: Biscuit p Verified -> [Block]
getBlocks = fmap getB . blocks

instance FromJSON SecretKey where
  parseJSON = withText "Ed25519 secret key" $ \t -> do
    let bs = encodeUtf8 t
        res = parseSecretKeyHex bs
        notSk = typeMismatch "Ed25519 secret key" (String t)
    maybe notSk pure res

instance ToJSON SecretKey where
  toJSON = toJSON . decodeUtf8 . serializeSecretKeyHex

instance FromJSON PublicKey where
  parseJSON = withText "Ed25519 public key" $ \t -> do
    let bs = encodeUtf8 t
        res = parsePublicKeyHex bs
        notPk = typeMismatch "Ed25519 public key" (String t)
    maybe notPk pure res

instance ToJSON PublicKey where
  toJSON = toJSON . decodeUtf8 . serializePublicKeyHex

instance FromJSON Authorizer where
  parseJSON = withText "authorizer" $ \t -> do
    let res = parseAuthorizer t
        notAuthorizer e = typeMismatch e (String t)
    either notAuthorizer pure res

instance ToJSON Authorizer where
  toJSON = toJSON . renderAuthorizer

data SampleFile a
  = SampleFile
  { root_private_key :: SecretKey
  , root_public_key  :: PublicKey
  , testcases        :: [TestCase a]
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass (FromJSON, ToJSON)

data RustResult e a
  = Err e
  | Ok a
  deriving stock (Generic, Eq, Show, Functor)

instance Bifunctor RustResult where
  bimap f g = \case
    Err e -> Err $ f e
    Ok  a -> Ok $ g a

instance (FromJSON e, FromJSON a) => FromJSON (RustResult e a) where
   parseJSON = genericParseJSON $
     defaultOptions { sumEncoding = ObjectWithSingleField }

instance (ToJSON e, ToJSON a) => ToJSON (RustResult e a) where
   toJSON = genericToJSON $
     defaultOptions { sumEncoding = ObjectWithSingleField }

type RustError = Value

data ValidationR
  = ValidationR
  { world           :: Maybe WorldDesc
  , result          :: RustResult RustError Int
  , authorizer_code :: Text
  , revocation_ids  :: [Text]
  } deriving stock (Eq, Show, Generic)
    deriving anyclass (FromJSON, ToJSON)

checkResult :: Show a
            => (a -> RustError -> Assertion)
            -> RustResult RustError Int
            -> Either a b
            -> Assertion
checkResult f r e = case (r, e) of
  (Err es, Right _) -> assertFailure $ "Got success, but expected failure: " <> show es
  (Ok   _, Left  e) -> assertFailure $ "Expected success, but got failure: " <> show e
  (Err es, Left e) -> f e es
  _ -> pure ()


data TestCase a
  = TestCase
  { title       :: String
  , filename    :: a
  , token       :: NonEmpty BlockDesc
  , validations :: Map String ValidationR
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass (FromJSON, ToJSON)

data BlockDesc
  = BlockDesc
  { symbols      :: [Text]
  , code         :: Text
  , public_keys  :: [Text]
  , external_key :: Maybe Text
  , version      :: Int
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

data FactSet
  = FactSet
  { origin :: [Maybe Integer]
  , facts  :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

data RuleSet
  = RuleSet
  { origin :: Maybe Integer
  , rules  :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

data CheckSet
  = CheckSet
  { origin :: Maybe Integer
  , checks :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

data WorldDesc
  =  WorldDesc
  { facts    :: [FactSet]
  , rules    :: [RuleSet]
  , checks   :: [CheckSet]
  , policies :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

instance Semigroup WorldDesc where
  a <> b = WorldDesc
    { facts = getField @"facts" a <> getField @"facts" b
    , rules = getField @"rules" a <> getField @"rules" b
    , checks = getField @"checks" a <> getField @"checks" b
    , policies = policies a <> policies b
    }

instance Monoid WorldDesc where
  mempty = WorldDesc [] [] [] []

readBiscuits :: SampleFile FilePath -> IO (SampleFile (FilePath, ByteString))
readBiscuits =
   traverse $ traverse (BS.readFile . ("test/samples/current/" <>)) . join (&&&) id

readSamplesFile :: IO (SampleFile (FilePath, ByteString))
readSamplesFile = do
  f <- either fail pure =<< eitherDecodeFileStrict' "test/samples/current/samples.json"
  readBiscuits f

checkTokenBlocks :: (String -> IO ())
                 -> Biscuit OpenOrSealed Verified
                 -> NonEmpty BlockDesc
                 -> Assertion
checkTokenBlocks step b blockDescs = do
  step "Checking blocks"
  let bs = getAuthority b :| getBlocks b
      expected = traverse (parseBlock . code) blockDescs
  expected @?= Right bs

processTestCase :: (String -> IO ())
                -> PublicKey -> TestCase (FilePath, ByteString)
                -> Assertion
processTestCase step rootPk TestCase{..} =
  if fst filename == "test018_unbound_variables_in_rule.bc"
  then
    step "Skipping for now (unbound variables are now caught before evaluation)"
  else if fst filename `elem` ["test029_reject_if.bc", "test030_null.bc", "test031_heterogeneous_equal.bc", "test032_laziness_closures.bc", "test033_typeof.bc", "test034_array_map.bc", "test035_ffi.bc", "test036_secp256r1.bc", "test037_secp256r1_third_party.bc", "test038_try_op.bc"]
  then
    step "Skipping for now (not supported yet)"
  else do
    step "Parsing "
    let vList = Map.toList validations
    case parse rootPk (snd filename) of
      Left parseError -> traverse_ (processFailedValidation step parseError) vList
      Right biscuit   -> do
        checkTokenBlocks step biscuit token
        traverse_ (processValidation step biscuit) vList

compareParseErrors :: ParseError -> RustError -> Assertion
compareParseErrors pe re =
  let mustMatch p = assertBool (show (re,pe)) $ isJust $ re ^? p
      mustMatchEither ps = assertBool (show (re, pe)) $ any (isJust . (re ^?)) ps
   in case pe of
        InvalidHexEncoding ->
          assertFailure $ "InvalidHexEncoding can't appear here " <> show re
        InvalidB64Encoding ->
          mustMatch $ key "Base64"
        InvalidProtobufSer True s ->
          mustMatch $ key "Format" . key "DeserializationError"
        InvalidProtobuf True s ->
          mustMatch $ key "Format" . key "DeserializationError"
        InvalidProtobufSer False s ->
          mustMatch $ key "Format" . key "BlockDeserializationError"
        InvalidProtobuf False s ->
          mustMatch $ key "Format" . key "BlockDeserializationError"
        -- the signature size is now verified just before verifying the
        -- signature itself, not at deserialization time, since we want
        -- to interpret signatures only relative to the verifying public
        -- key.
        InvalidSignatures ->
          mustMatchEither
            [ key "Format" . key "Signature" . key "InvalidSignature"
            , key "Format" . key "InvalidSignatureSize"
            , key "Format" . key "BlockSignatureDeserializationError"
            ]
        InvalidProof ->
          assertFailure $ "InvalidProof can't appear here " <> show re
        RevokedBiscuit ->
          assertFailure $ "RevokedBiscuit can't appear here " <> show re

compareExecErrors :: ExecutionError -> RustError -> Assertion
compareExecErrors ee re =
  let errorMessage = "ExecutionError mismatch: " <> show ee <> " " <> unpack (decodeUtf8 . LBS.toStrict $ encode re)
      mustMatch p = assertBool errorMessage $ isJust $ re ^? p
      -- todo compare `Unauthorized` contents
   in case ee of
        Timeout                            -> mustMatch $ key "RunLimit" . key "Timeout"
        TooManyFacts                       -> mustMatch $ key "RunLimit" . key "TooManyFacts"
        TooManyIterations                  -> mustMatch $ key "RunLimit" . key "TooManyIterations"
        InvalidRule                        -> mustMatch $ key "FailedLogic" . key "InvalidBlockRule"
        EvaluationError _                  -> mustMatch $ key "Execution"
        ResultError (NoPoliciesMatched cs) -> mustMatch $ key "FailedLogic" . key "Unauthorized"
        ResultError (FailedChecks cs)      -> mustMatch $ key "FailedLogic" . key "Unauthorized"
        ResultError (DenyRuleMatched cs q) -> mustMatch $ key "FailedLogic" . key "Unauthorized"

processFailedValidation :: (String -> IO ())
                        -> ParseError
                        -> (String, ValidationR)
                        -> Assertion
processFailedValidation step e (name, ValidationR{result}) = do
  step $ "Checking validation " <> name
  checkResult compareParseErrors result (Left e)

processValidation :: (String -> IO ())
                  -> Biscuit OpenOrSealed Verified
                  -> (String, ValidationR)
                  -> Assertion
processValidation step b (name, ValidationR{..}) = do
  when (name /= "") $ step ("Checking " <> name)
  let w = fold world
  pols <- either (assertFailure . show) pure $ parseAuthorizer $ foldMap (<> ";") (policies w)
  authorizer <- either (assertFailure . show)  pure $ parseAuthorizer authorizer_code
  res <- authorizeBiscuit b (authorizer <> pols)
  checkResult compareExecErrors result res
  let revocationIds = encodeHex <$> toList (getRevocationIds b)
  step "Comparing revocation ids"
  revocation_ids @?= revocationIds


runTests :: (String -> IO ())
         -> Assertion
runTests step = do
  step "Parsing sample file"
  SampleFile{..} <- readSamplesFile
  traverse_ (processTestCase step root_public_key) testcases

mkTestCase :: PublicKey -> TestCase (FilePath, ByteString) -> TestTree
mkTestCase root_public_key tc@TestCase{filename} =
  testCaseSteps (fst filename) (\step -> processTestCase step root_public_key tc)

getSpecs :: IO TestTree
getSpecs = do
  SampleFile{..} <- readSamplesFile
  pure $ testGroup "Biscuit samples - compliance checks"
       $ mkTestCase root_public_key <$> testcases

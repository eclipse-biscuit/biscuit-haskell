{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TupleSections     #-}
{-
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
-}
module Spec.Roundtrip
  ( specs
  ) where

import           Control.Arrow       ((&&&))
import           Data.ByteString     (ByteString)
import           Data.List.NonEmpty  (NonEmpty ((:|)))
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit        hiding (Biscuit, ParseError, PublicKey,
                                      addBlock, mkBiscuit, publicKey)
import           Auth.Biscuit.Crypto
import           Auth.Biscuit.Token

specs :: TestTree
specs = testGroup "Serde roundtrips"
  [ testGroup "Raw serde"
      [ singleBlock    (serialize, parse)
      , multipleBlocks (serialize, parse)
      , thirdPartyBlocks (serialize, parse)
      ]
  , testGroup "B64 serde"
      [ singleBlock    (serializeB64, parseB64)
      , multipleBlocks (serializeB64, parseB64)
      ]
  , testGroup "Keys serde"
      [ secret
      , public
      ]
  ]

type Roundtrip = ( Biscuit Open Verified -> ByteString
                 , PublicKey -> ByteString -> Either ParseError (Biscuit OpenOrSealed Verified)
                 )

roundtrip :: Roundtrip
          -> NonEmpty Block
          -> Assertion
roundtrip r bs = roundtrip' r $ (Nothing,) <$> bs

roundtrip' :: Roundtrip
           -> NonEmpty (Maybe SecretKey, Block)
           -> Assertion
roundtrip' (s,p) i@(authority' :| blocks') = do
  let addBlocks bs biscuit = case bs of
        ((Just sk, b):rest) -> addBlocks rest =<< addSignedBlock sk b biscuit
        ((Nothing, b):rest) -> addBlocks rest =<< addBlock b biscuit
        []                  -> pure biscuit
  sk <- generateSecretKey
  let pk = toPublic sk
  init' <- mkBiscuitWith (Just 1) sk (snd authority')
  final <- addBlocks blocks' init'
  let serialized = s final
      parsed = p pk serialized
      getBlock ((_, b), _, _, _, _) = b
      getBlocks b = getBlock <$> authority b :| blocks b
  getBlocks <$> parsed @?= Right (snd <$> i)
  rootKeyId <$> parsed @?= Right (Just 1)

roundtrip'' :: Bool
            -> Roundtrip
            -> NonEmpty (Maybe SecretKey, Block)
            -> Assertion
roundtrip'' direct (s,p) i@(authority' :| blocks') = do
  let addSignedBlock' :: SecretKey -> Block -> Biscuit Open check -> IO (Biscuit Open check)
      addSignedBlock' sk block biscuit = do
        if direct
          then
            addSignedBlock sk block biscuit
          else do
            let req = mkThirdPartyBlockReq biscuit
            thirdPartyBlock <- either (fail . ("req " <>)) pure $ mkThirdPartyBlock sk req block
            either (fail . ("apply " <>)) id $ applyThirdPartyBlock biscuit thirdPartyBlock
      addBlocks bs biscuit = case bs of
        ((Just sk, b):rest) -> addBlocks rest =<< addSignedBlock' sk b biscuit
        ((Nothing, b):rest) -> addBlocks rest =<< addBlock b biscuit
        []                  -> pure biscuit
  sk <- generateSecretKey
  let pk = toPublic sk
  init' <- mkBiscuitWith (Just 1) sk (snd authority')
  final <- addBlocks blocks' init'
  let serialized = s final
      parsed = p pk serialized
      getBlock ((_, b), _, _, _, _) = b
      getBlocks b = getBlock <$> authority b :| blocks b
  getBlocks <$> parsed @?= Right (snd <$> i)
  rootKeyId <$> parsed @?= Right (Just 1)

singleBlock :: Roundtrip -> TestTree
singleBlock r = testCase "Single block" $ roundtrip r $ pure
  [block|
    right("file1", "read");
    right("file2", "read");
    right("file1", "write");
  |]

multipleBlocks :: Roundtrip -> TestTree
multipleBlocks r = testCase "Multiple block" $ roundtrip r $
    [block|
      right("file1", "read");
      right("file2", "read");
      right("file1", "write");
    |] :|
  [ [block|
      valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59+00:00;
      valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59+00:00, !{"file1"}.contains($1);
      check if valid_date($0), resource($0);
    |]
  , [block|
      check if true;
      check if !false;
      check if !false;
      check if false or true;
      check if 1 < 2;
      check if 2 > 1;
      check if 1 <= 2;
      check if 1 <= 1;
      check if 2 >= 1;
      check if 2 >= 2;
      check if 3 === 3;
      check if 1 + 2 * 3 - 4 / 2 === 5;
      check if "hello world".starts_with("hello") && "hello world".ends_with("world");
      check if "aaabde".matches("a*c?.e");
      check if "abcD12" === "abcD12";
      check if 2019-12-04T09:46:41+00:00 < 2020-12-04T09:46:41+00:00;
      check if 2020-12-04T09:46:41+00:00 > 2019-12-04T09:46:41+00:00;
      check if 2019-12-04T09:46:41+00:00 <= 2020-12-04T09:46:41+00:00;
      check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
      check if 2020-12-04T09:46:41+00:00 >= 2019-12-04T09:46:41+00:00;
      check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
      check if 2020-12-04T09:46:41+00:00 === 2020-12-04T09:46:41+00:00;
      check if hex:12ab === hex:12ab;
      check if {1, 2}.contains(2);
      check if {2019-12-04T09:46:41+00:00, 2020-12-04T09:46:41+00:00}.contains(2020-12-04T09:46:41+00:00);
      check if {false, true}.contains(true);
      check if {"abc", "def"}.contains("abc");
      check if {hex:12ab, hex:34de}.contains(hex:34de);
      check if {"hello", "world"}.contains("hello");
    |]
  , [block|
      check if
        resource($0),
        operation("read"),
        right($0, "read");
    |]
  , [block|
      check if resource("file1");
      check if time($date), $date <= 2018-12-20T00:00:00+00:00;
    |]
  ]

thirdPartyBlocks :: Roundtrip -> TestTree
thirdPartyBlocks r =
  let mkBlocks = do
        (sk1, pkOne) <- (id &&& toPublic) <$> generateSecretKey
        (sk2, pkTwo) <- (id &&& toPublic) <$> generateSecretKey
        (sk3, pkThree) <- (id &&& toPublic) <$> generateSecretKey
        pure $ (Nothing, [block|
                   query("authority");
                   right("file1", "read");
                   right("file2", "read");
                   right("file1", "write");
                   check if true trusting previous, {pkOne};
               |]) :|
               [ (Just sk1, [block|
                   query("block1");
                   check if right("file2", "read") trusting {pkTwo};
                   check if right("file3", "read") trusting {pkOne};
                 |])
               , (Just sk2, [block|
                   query("block2");
                   check if right("file2", "read") trusting {pkTwo};
                   check if right("file3", "read") trusting {pkOne};
                 |])
               , (Nothing, [block|
                   query("block3");
                   check if right("file2", "read") trusting {pkTwo};
                   check if right("file3", "read") trusting {pkThree};
                 |])
               ]
   in testGroup "Third party blocks"
        [ testCase "Direct append" $ roundtrip'' True r =<< mkBlocks
        , testCase "Indirect append" $ roundtrip'' False r =<< mkBlocks
        ]

secret :: TestTree
secret = testGroup "Secret key serde"
  [ testCase "Raw bytes" $ do
      sk <- newSecret
      parseSecretKey (serializeSecretKey sk) @?= Just sk
  , testCase "Hex encoding" $ do
      sk <- newSecret
      parseSecretKeyHex (serializeSecretKeyHex sk) @?= Just sk
  ]

public :: TestTree
public = testGroup "Public key serde"
  [ testCase "Raw bytes" $ do
      pk <- toPublic <$> newSecret
      parsePublicKey (serializePublicKey pk) @?= Just pk
  , testCase "Hex encoding" $ do
      pk <- toPublic <$> newSecret
      parsePublicKeyHex (serializePublicKeyHex pk) @?= Just pk
  ]

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-|
  Module      : Auth.Biscuit.Example
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
  Maintainer  : clement@delafargue.name
  Working examples of biscuit-haskell
-}
module Auth.Biscuit.Example where

import           Data.ByteString (ByteString)
import           Data.Functor    (($>))
import           Data.Maybe      (fromMaybe)
import           Data.Text       (Text)
import           Data.Time       (getCurrentTime)

import           Auth.Biscuit

privateKey' :: SecretKey
privateKey' = fromMaybe (error "Error parsing private key") $ parseSecretKeyHex "a2c4ead323536b925f3488ee83e0888b79c2761405ca7c0c9a018c7c1905eecc"

publicKey' :: PublicKey
publicKey' = fromMaybe (error "Error parsing public key") $ parsePublicKeyHex "24afd8171d2c0107ec6d5656aa36f8409184c2567649e0a7f66e629cc3dbfd70"

creation :: IO ByteString
creation = do
  let allowedOperations = ["read", "write"] :: [Text]
      networkLocal = "192.168.0.1" :: Text
  let authority = [block|
       // this is a comment
       right("file1", {allowedOperations});
       check if source_ip($source_ip), ["127.0.0.1", {networkLocal}].contains($source_ip);
       |]
  biscuit <- mkBiscuit privateKey' authority
  let block1 = [block|check if time($time), $time < 2025-05-08T00:00:00Z;|]
  newBiscuit <- addBlock block1 biscuit
  pure $ serializeB64 newBiscuit

verification :: ByteString -> IO Bool
verification serialized = do
  now <- getCurrentTime
  biscuit <- either (fail . show) pure $ parseB64 publicKey' serialized
  let authorizer' = [authorizer|
        time({now});
        source_ip("127.0.0.1");
        allow if right("file1", $ops), $ops.contains("read");
      |]
  result <- authorizeBiscuit biscuit authorizer'
  case result of
    Left e  -> print e $> False
    Right _ -> pure True

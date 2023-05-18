{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import           Auth.Biscuit                   (SecretKey, mkBiscuit,
                                                 parseSecretKeyHex,
                                                 serializeB64, toPublic)
import           Data.Maybe                     (fromMaybe)
import           Network.HTTP.Client            (Response (responseStatus),
                                                 applyBearerAuth,
                                                 defaultManagerSettings,
                                                 httpLbs, newManager,
                                                 parseRequest)
import           Network.HTTP.Types             (Status (..), badRequest400,
                                                 ok200)
import           Network.Wai                    (Application,
                                                 Request (pathInfo), ifRequest,
                                                 responseLBS)
import qualified Network.Wai.Handler.Warp       as Warp
import           Network.Wai.Middleware.Biscuit (getBiscuit, parseBiscuit)
import           Test.Hspec                     (around, describe, hspec, it,
                                                 shouldBe)

secretKey :: SecretKey
secretKey = fromMaybe (error "Failed parsing secret key") $ parseSecretKeyHex "ac40d48ac474b6d41a58cbb91facc6317e32afdc21edfe23b9967e9d07c039be"

otherSecretKey :: SecretKey
otherSecretKey = fromMaybe (error "Failed parsing secret key") $ parseSecretKeyHex "1b53545e9ca6d1368bb222cb4c2183aac3304d8a3d0fea53173bca82f57b95a8"

app :: Application
app =
  let endpoint req sendResponse = case getBiscuit req of
        Just _  -> sendResponse $ responseLBS ok200 mempty mempty
        Nothing -> sendResponse $ responseLBS badRequest400 mempty mempty
      checkBiscuit = parseBiscuit (toPublic secretKey)
      isProtected = (== ["protected"]) . take 1 . pathInfo
   in ifRequest isProtected checkBiscuit endpoint

withApp :: (Warp.Port -> IO ()) -> IO ()
withApp =
  --testWithApplication makes sure the action is executed after the server has
  -- started and is being properly shutdown.
  -- exceptions thrown by the app are bubbled up to the test suite.
  Warp.testWithApplication (pure app)

main :: IO ()
main = do
  manager <- newManager defaultManagerSettings
  hspec $
    around withApp $
      describe "biscuit wai middleware" $ do
        describe "on protected endpoints" $ do
          it "rejects unauthenticated calls" $ \port -> do
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected"
            res <- httpLbs req manager
            statusCode (responseStatus res) `shouldBe` 401
          it "rejects gibberish tokens" $ \port -> do
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected"
            let withAuth = applyBearerAuth "whatevs" req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 403
          it "rejects tokens signed by the wrong keypair" $ \port -> do
            badToken <- mkBiscuit otherSecretKey mempty
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected"
            let withAuth = applyBearerAuth (serializeB64 badToken) req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 403
          it "accepts properly signed tokens" $ \port -> do
            goodToken <- mkBiscuit secretKey mempty
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected"
            let withAuth = applyBearerAuth (serializeB64 goodToken) req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 200
        describe "on open endpoints" $ do
          it "accepts unauthenticated calls, but doesn't provide a parsed token" $ \port -> do
            req <- parseRequest $ "http://localhost:" <> show port
            res <- httpLbs req manager
            statusCode (responseStatus res) `shouldBe` 400

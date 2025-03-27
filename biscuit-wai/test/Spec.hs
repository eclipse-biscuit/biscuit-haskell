{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Main (main) where

import           Auth.Biscuit                   (SecretKey, authorizer, block,
                                                 mkBiscuit, parseSecretKeyHex,
                                                 serializeB64, toPublic)
import           Data.Maybe                     (fromMaybe)
import           Data.Text.Encoding             (decodeUtf8)
import           Network.HTTP.Client            (Response (responseStatus),
                                                 applyBearerAuth,
                                                 defaultManagerSettings,
                                                 httpLbs, newManager,
                                                 parseRequest)
import           Network.HTTP.Types             (Status (..), badRequest400,
                                                 notFound404, ok200)
import           Network.Wai                    (Application,
                                                 Request (pathInfo, rawPathInfo),
                                                 ifRequest, responseLBS)
import qualified Network.Wai.Handler.Warp       as Warp
import           Network.Wai.Middleware.Biscuit (authorizeBiscuit',
                                                 getAuthorizedBiscuit,
                                                 getBiscuit, parseBiscuit)
import           Test.Hspec                     (around, describe, hspec, it,
                                                 shouldBe)

secretKey :: SecretKey
secretKey = fromMaybe (error "Failed parsing secret key") $ parseSecretKeyHex "ac40d48ac474b6d41a58cbb91facc6317e32afdc21edfe23b9967e9d07c039be"

otherSecretKey :: SecretKey
otherSecretKey = fromMaybe (error "Failed parsing secret key") $ parseSecretKeyHex "1b53545e9ca6d1368bb222cb4c2183aac3304d8a3d0fea53173bca82f57b95a8"

app :: Application
app =
  let endpoint req sendResponse = case pathInfo req of
        ["protected", "parsed"] ->
          case getBiscuit req of
            Just _  -> sendResponse $ responseLBS ok200 mempty mempty
            Nothing -> sendResponse $ responseLBS badRequest400 mempty mempty
        ["protected", "authed"] ->
          case getAuthorizedBiscuit req of
            Just _  -> sendResponse $ responseLBS ok200 mempty mempty
            Nothing -> sendResponse $ responseLBS badRequest400 mempty mempty
        [] -> sendResponse $ responseLBS ok200 mempty mempty
        _ -> sendResponse $ responseLBS notFound404 mempty mempty
      checkBiscuit = parseBiscuit (toPublic secretKey)
      checkBiscuit' = authorizeBiscuit' (toPublic secretKey) $ \req ->
        let path = decodeUtf8 $ rawPathInfo req
         in pure [authorizer|allow if right({path});|]
      isProtectedParsed = (== ["protected", "parsed"]) . take 2 . pathInfo
      isProtectedAuthed = (== ["protected", "authed"]) . take 2 . pathInfo
   in ifRequest isProtectedParsed checkBiscuit $
        ifRequest isProtectedAuthed checkBiscuit' endpoint

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
        describe "on open endpoints" $ do
          it "accepts unauthenticated calls" $ \port -> do
            req <- parseRequest $ "http://localhost:" <> show port
            res <- httpLbs req manager
            statusCode (responseStatus res) `shouldBe` 200
        describe "on protected endpoints (parsing)" $ do
          it "rejects unauthenticated calls" $ \port -> do
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected/parsed"
            res <- httpLbs req manager
            statusCode (responseStatus res) `shouldBe` 401
          it "rejects gibberish tokens" $ \port -> do
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected/parsed"
            let withAuth = applyBearerAuth "whatevs" req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 403
          it "rejects tokens signed by the wrong keypair" $ \port -> do
            badToken <- mkBiscuit otherSecretKey mempty
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected/parsed"
            let withAuth = applyBearerAuth (serializeB64 badToken) req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 403
          it "accepts properly signed tokens" $ \port -> do
            goodToken <- mkBiscuit secretKey mempty
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected/parsed"
            let withAuth = applyBearerAuth (serializeB64 goodToken) req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 200
        describe "on protected endpoints (auth)" $ do
          it "rejects unauthenticated calls" $ \port -> do
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected/authed"
            res <- httpLbs req manager
            statusCode (responseStatus res) `shouldBe` 401
          it "rejects gibberish tokens" $ \port -> do
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected/authed"
            let withAuth = applyBearerAuth "whatevs" req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 403
          it "rejects tokens signed by the wrong keypair" $ \port -> do
            badToken <- mkBiscuit otherSecretKey mempty
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected/authed"
            let withAuth = applyBearerAuth (serializeB64 badToken) req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 403
          it "rejects properly signed tokens which fail authorization" $ \port -> do
            badToken <- mkBiscuit secretKey mempty
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected/authed"
            let withAuth = applyBearerAuth (serializeB64 badToken) req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 403
          it "accepts properly signed tokens which succeed authorization" $ \port -> do
            goodToken <- mkBiscuit secretKey [block|right("/protected/authed");|]
            req <- parseRequest $ "http://localhost:" <> show port <> "/protected/authed"
            let withAuth = applyBearerAuth (serializeB64 goodToken) req
            res <- httpLbs withAuth manager
            statusCode (responseStatus res) `shouldBe` 200

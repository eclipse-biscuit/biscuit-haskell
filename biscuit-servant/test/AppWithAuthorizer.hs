{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TypeApplications  #-}
{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE TypeOperators     #-}
{-
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
-}
module AppWithAuthorizer where

import           Auth.Biscuit
import           Auth.Biscuit.Servant
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Reader   (ask)
import           Data.Text              (Text)
import           Data.Time              (getCurrentTime)
import           Servant
import           Servant.Client

import           ClientHelpers

call1 :: Text -> ClientM Int
call1 b =
  let (e1 :<|> _) = client @API Proxy (protect b)
   in e1

call2 :: Text -> Int -> ClientM Int
call2 b =
  let (_ :<|> e2 :<|> _) = client @API Proxy (protect b)
   in e2

call3 :: Text -> ClientM Int
call3 b =
  let (_ :<|> _ :<|> e3 :<|> _) = client @API Proxy (protect b)
   in e3

call4 :: Text -> ClientM Int
call4 b =
  let (_ :<|> _ :<|> _ :<|> e4) = client @API Proxy (protect b)
   in e4

type H = WithAuthorizer Handler
type H' = WithAuthorizer' Int Handler
type API = RequireBiscuit :> ProtectedAPI
type ProtectedAPI =
       "endpoint1" :> Get '[JSON] Int
  :<|> "endpoint2" :> Capture "int" Int :> Get '[JSON] Int
  :<|> "endpoint3" :> Get '[JSON] Int
  :<|> "endpoint4" :> Get '[JSON] Int

app :: PublicKey -> Application
app appPublicKey =
  serveWithContext @API Proxy (genBiscuitCtx appPublicKey) server

server :: Server API
server b =
  let nowFact = do
        now <- liftIO getCurrentTime
        pure [authorizer|time({now});|]
      handleAuth :: WithAuthorizer Handler x -> Handler x
      handleAuth =
          handleBiscuit b
        . withPriorityAuthorizerM nowFact
        . withPriorityAuthorizer [authorizer|allow if right("admin");|]
        . withFallbackAuthorizer [authorizer|allow if right("anon");|]
      handlers = handler1 :<|> handler2 :<|> handler3 :<|> handler4
   in hoistServer @ProtectedAPI Proxy handleAuth handlers

handler1 :: H Int
handler1 = withAuthorizer [authorizer|allow if right("one");|] $ pure 1

handler2 :: Int -> H Int
handler2 v = withAuthorizer [authorizer|allow if right("two", {v});|] $ pure 2

handler3 :: H Int
handler3 = withAuthorizer [authorizer|deny if true;|] $ pure 3

handler4 :: H Int
handler4 = withTransformation extractUserId $
  withAuthorizer [authorizer|allow if user($user_id); |] $ do
    ask

extractUserId :: AuthorizedBiscuit OpenOrSealed -> Handler Int
extractUserId AuthorizedBiscuit{authorizationSuccess} = do
  let b = getBindings authorizationSuccess
   in maybe (throwError err403) pure $ getSingleVariableValue b "user_id"

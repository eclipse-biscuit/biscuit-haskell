{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
{-
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
-}
module ClientHelpers where

import           Data.Bifunctor           (first)
import           Data.ByteString          (ByteString)
import           Data.ByteString.Lazy     (toStrict)
import           Data.Text                (Text)
import           Network.HTTP.Client      (defaultManagerSettings, newManager)
import qualified Network.Wai.Handler.Warp as Warp
import           Servant
import           Servant.Client
import qualified Servant.Client.Core      as ClientCore
import           Servant.Client.Core      (AuthClientData, AuthenticatedRequest,
                                           mkAuthenticatedRequest)

protect :: Text -> AuthenticatedRequest (AuthProtect "biscuit")
protect b = mkAuthenticatedRequest b (ClientCore.addHeader "Authorization" . ("Bearer " <>))

type instance AuthClientData (AuthProtect "biscuit") = Text

withApp :: Application -> (Warp.Port -> IO ()) -> IO ()
withApp app =
  --testWithApplication makes sure the action is executed after the server has
  -- started and is being properly shutdown.
  Warp.testWithApplication (pure app)

runC :: Warp.Port -> ClientM a -> IO (Either (Maybe ByteString) a)
runC p c = do
  baseUrl <- parseBaseUrl $ "http://localhost:" <> show p
  manager <- newManager defaultManagerSettings
  let clientEnv = mkClientEnv manager baseUrl
  first extractBody <$> runClientM c clientEnv

extractBody :: ClientError -> Maybe ByteString
extractBody (FailureResponse _ Response{responseBody}) = Just $ toStrict responseBody
extractBody _                                          = Nothing

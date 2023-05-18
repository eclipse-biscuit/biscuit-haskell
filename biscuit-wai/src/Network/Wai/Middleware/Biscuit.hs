{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.Wai.Middleware.Biscuit (parseBiscuit, getBiscuit) where

import           Auth.Biscuit       (Biscuit, OpenOrSealed, ParseError,
                                     PublicKey, Verified, parseB64)
import           Control.Monad      ((<=<))
import           Data.Bifunctor     (first)
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as BS
import qualified Data.List          as List
import qualified Data.Vault.Lazy    as Vault
import           GHC.IO             (unsafePerformIO)
import           Network.HTTP.Types (forbidden403, hAuthorization,
                                     unauthorized401)
import           Network.Wai        (Middleware, Request (..), Response,
                                     responseLBS)

-- todo explain why
{-# NOINLINE  biscuitKey #-}
biscuitKey :: Vault.Key (Biscuit OpenOrSealed Verified)
biscuitKey = unsafePerformIO Vault.newKey

getBiscuit :: Request -> Maybe (Biscuit OpenOrSealed Verified)
getBiscuit = Vault.lookup biscuitKey . vault

parseBiscuit :: PublicKey -> Middleware
parseBiscuit = parseBiscuitWith . defaultExtractionConfig

parseBiscuitWith :: ExtractionConfig e -> Middleware
parseBiscuitWith config app req sendResponse = do
  let ExtractionConfig{extractToken,parseToken,handleError} = config
      onError = sendResponse <=< handleError
      forward t = do
         let newVault = Vault.insert biscuitKey t (vault req)
         app req { vault = newVault } sendResponse
  eBiscuit <- either (pure . Left) parseToken =<< extractToken req
  either onError forward eBiscuit

data ExtractionConfig e
  = ExtractionConfig
  { extractToken :: Request -> IO (Either e ByteString)
  , parseToken   :: ByteString -> IO (Either e (Biscuit OpenOrSealed Verified))
  , handleError  :: e -> IO Response
  }

data BiscuitError
  = NoToken
  | ParseError ParseError

defaultExtractionConfig :: PublicKey -> ExtractionConfig BiscuitError
defaultExtractionConfig publicKey = ExtractionConfig
  { extractToken = pure . maybe (Left NoToken) Right . defaultExtractToken
  , parseToken = pure . Data.Bifunctor.first ParseError . parseB64 publicKey
  , handleError = defaultHandleError
  }

defaultExtractToken :: Request -> Maybe ByteString
defaultExtractToken req = do
  (_, authHeader) <- List.find ((== hAuthorization) . fst) $ requestHeaders req
  BS.stripPrefix "Bearer " authHeader

defaultHandleError :: BiscuitError -> IO Response
defaultHandleError = \case
  NoToken      -> do
    putStrLn "Missing biscuit token"
    pure $ responseLBS unauthorized401 mempty mempty
  ParseError e -> do
    putStrLn $ "Parsing or verification error: " <> show e
    pure $ responseLBS forbidden403 mempty mempty

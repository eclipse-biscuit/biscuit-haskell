{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.Wai.Middleware.Biscuit (parseBiscuit, getBiscuit) where

import           Auth.Biscuit       (Biscuit, OpenOrSealed, ParseError,
                                     PublicKey, Verified, parseB64)
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
parseBiscuit publicKey app req sendResponse = case defaultExtractToken req of
    Nothing -> sendResponse =<< defaultHandleError NoToken
    Just s -> case defaultParseToken publicKey s of
      Left e -> sendResponse =<< defaultHandleError (ParseError e)
      Right t -> do
         let newVault = Vault.insert biscuitKey t (vault req)
         app req { vault = newVault } sendResponse

data BiscuitError
  = NoToken
  | ParseError ParseError

defaultExtractToken :: Request -> Maybe ByteString
defaultExtractToken req = do
  (_, authHeader) <- List.find ((== hAuthorization) . fst) $ requestHeaders req
  BS.stripPrefix "Bearer " authHeader

defaultParseToken :: PublicKey -> ByteString -> Either ParseError (Biscuit OpenOrSealed Verified)
defaultParseToken = parseB64

defaultHandleError :: BiscuitError -> IO Response
defaultHandleError = \case
  NoToken      -> do
    putStrLn "Missing biscuit token"
    pure $ responseLBS unauthorized401 mempty mempty
  ParseError e -> do
    putStrLn $ "Parsing or verification error: " <> show e
    pure $ responseLBS forbidden403 mempty mempty

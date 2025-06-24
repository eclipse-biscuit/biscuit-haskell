{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-|
  Module      : Network.Wai.Middleware.Biscuit
  Copyright   : © Clément Delafargue, 2025
  License     : BSD-3-Clause
  Maintainer  : clement@delafargue.name
  WAI support for biscuit tokens

  This module provides WAI middlewares as well as builder functions for WAI middlewares, that allow protecting an HTTP application with biscuit tokens.

  The middlewares use the request vault to store either a verified biscuit token (see 'parseBiscuit', 'parseOptionalBiscuit', and 'parseBiscuitWith'),
  letting the application perform authorization, or the result of the authorization for cases where authorization is the same for all requests and can be performed directly in the middleware (see 'authorizeBiscuit'' and 'authorizeBiscuitWith')
-}
module Network.Wai.Middleware.Biscuit
  (
  -- * Biscuit parsing
    parseBiscuit
  , parseOptionalBiscuit
  , getBiscuit
  , parseBiscuitWith
  , ExtractionConfig (..)
  , defaultExtractionConfig
  , defaultOptionalExtractionConfig
  -- * Biscuit authorization
  , authorizeBiscuit'
  , getAuthorizedBiscuit
  , authorizeBiscuitWith
  , AuthorizationConfig (..)
  , defaultAuthorizationConfig
  -- * Helpers
  , defaultExtractToken
  , defaultHandleError
  ) where

import           Auth.Biscuit       (AuthorizedBiscuit, Authorizer, Biscuit,
                                     ExecutionError, OpenOrSealed, ParseError,
                                     PublicKey, Verified, authorizeBiscuit,
                                     parseB64)
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

-- | Key where the verified biscuit is stored in the request context. The
-- 'Data.Vault.Lazy' module is designed to make keys opaque and unique, hence the use of
-- 'IO' for key generation. Here we don’t care about unicity, we want the token
-- to be easily accessible. Hence the call to 'unsafePerformIO'.
{-# NOINLINE  biscuitKey #-}
biscuitKey :: Vault.Key (Biscuit OpenOrSealed Verified)
biscuitKey = unsafePerformIO Vault.newKey

-- | Key where the authorized biscuit is stored in the request context. The
-- 'Data.Vault.Lazy' module is designed to make keys opaque and unique, hence the use of
-- 'IO' for key generation. Here we don’t care about unicity, we want the token
-- to be easily accessible. Hence the call to 'unsafePerformIO'.
{-# NOINLINE  authorizedBiscuitKey #-}
authorizedBiscuitKey :: Vault.Key (AuthorizedBiscuit OpenOrSealed)
authorizedBiscuitKey = unsafePerformIO Vault.newKey

-- | Retrieve the parsed token from the request context. It is meant to be used
-- in conjunction with the 'parseBiscuit' (or 'parseBiscuitWith') middleware.
-- It will not be set by the 'authorizeBiscuit'' (or 'authorizeBiscuitWith')
-- middleware.
--
-- @since 0.1.0.0
getBiscuit :: Request -> Maybe (Biscuit OpenOrSealed Verified)
getBiscuit = Vault.lookup biscuitKey . vault

-- | Retrieve the result of the successful authorization from the request
-- context. It is meant to be used in conjunction with the 'authorizeBiscuit''
-- (or the 'authorizeBiscuitWith') middleware.
--
-- @since 0.1.0.0
getAuthorizedBiscuit :: Request -> Maybe (AuthorizedBiscuit OpenOrSealed)
getAuthorizedBiscuit = Vault.lookup authorizedBiscuitKey . vault

-- | Given a public key, generate a middleware that will extract a biscuit
-- token from incoming requests, parse it, and verify its signature. Requests
-- without a verified biscuit are rejected, and the verified biscuit is added
-- to the request context.
-- __The token is not authorized, only parsed and has its signature verified__.
-- Authorization is meant to be carried out in the application itself. If you
-- want to carry out authorization in the middleware, have a look at
-- 'authorizeBiscuit'' (or 'authorizeBiscuitWith').
--
-- The token is expected as a base64-encoded string, provided as a bearer token
-- in the @Authorization@ header. A missing header results in a bodyless 401
-- HTTP response. An invalid token results in a bodyless 403 HTTP response.
-- Errors are logged to stdout.
--
-- If you need custom extraction, parsing or error handling, have a look at
-- 'parseBiscuitWith'.
--
-- @since 0.1.0.0
parseBiscuit :: PublicKey -> Middleware
parseBiscuit = parseBiscuitWith . defaultExtractionConfig

-- | Given a public key, generate a middleware that will extract a biscuit
-- token from incoming requests, parse it, and verify its signature.
--
-- Requests without a verified biscuit are __not__ rejected.
-- The verified biscuit is added to the request context (if available).
-- Requests with a token that fails parsing or verification are rejected.
-- __The token is not authorized, only parsed and has its signature verified__.
-- Authorization is meant to be carried out in the application itself. If you
-- want to carry out authorization in the middleware, have a look at
-- 'authorizeBiscuit'' (or 'authorizeBiscuitWith').
--
-- The token is expected as a base64-encoded string, provided as a bearer token
-- in the @Authorization@ header. A missing header results in a bodyless 401
-- HTTP response. An invalid token results in a bodyless 403 HTTP response.
-- Errors are logged to stdout.
--
-- If you need custom extraction, parsing or error handling, have a look at
-- 'parseBiscuitWith'.
--
-- @since 0.1.0.0
parseOptionalBiscuit :: PublicKey -> Middleware
parseOptionalBiscuit = parseBiscuitWith . defaultOptionalExtractionConfig

-- | Given a way to extract a token from a request, parse it, and handle errors,
-- generate a middleware that will extract a biscuit token from incoming
-- requests, parse it, and verify its signature. Requests without a verified
-- biscuit are rejected, and the verified biscuit is added to the request
-- context.
-- __The token is not authorized, only parsed and has its signature verified__.
-- Authorization is meant to be carried out in the application itself. If you
-- want to carry out authorization in the middleware, have a look at
-- 'authorizeBiscuit'' (or 'authorizeBiscuitWith').
--
-- If you don’t need custom extraction, parsing or error handling logic, have a
-- look at 'parseBiscuit'.
--
-- @since 0.1.0.0
parseBiscuitWith :: ExtractionConfig e -> Middleware
parseBiscuitWith config app req sendResponse = do
  let ExtractionConfig{extractToken,parseToken,handleError, onMissingBiscuit} = config
      noBiscuit = pure $ Nothing <$ onMissingBiscuit
      parse = fmap (fmap Just) . parseToken
      onError = sendResponse <=< handleError
      forward t = do
         let oldVault = vault req
             newVault = maybe id (Vault.insert biscuitKey) t $ oldVault
         app req { vault = newVault } sendResponse
  emBiscuit <- either (pure . Left) (maybe noBiscuit parse) =<< extractToken req
  either onError forward emBiscuit

-- | Given a public key and a way to generate an authorizer from a request,
-- generate a middleware that will extract a biscuit token from incoming
-- requests, parse it, verify its signature and authorize it. Requests without
-- an authorized biscuit are rejected, and the authorized biscuit is added to
-- the request context.
-- __The underlying application will only receive requests where the whole authorization process succeeded.__
-- If you want to only parse tokens and delegate actual authorization to the
-- underlying application, have a look at 'parseBiscuit'
-- (or 'parseBiscuitWith').
--
-- The token is expected as a base64-encoded string, provided as a bearer token
-- in the @Authorization@ header. A missing header results in a bodyless 401
-- HTTP response. An invalid token results in a bodyless 403 HTTP response. A
-- failed authorization process results in a bodyless 403 HTTP response.
-- Errors are logged to stdout.
--
-- If you need custom extraction, parsing, authorization or error handling,
-- have a look at 'authorizeBiscuitWith'.
--
-- @since 0.1.0.0
authorizeBiscuit' :: PublicKey -> (Request -> IO Authorizer) -> Middleware
authorizeBiscuit' publicKey = authorizeBiscuitWith . defaultAuthorizationConfig publicKey

-- | Given a way to extract a token from a request, parse it, authorized it and
-- handle errors, generate a middleware that will extract a biscuit token from
-- incoming requests, parse it, verify its signature and authorize it.
-- Requests without an authorized biscuit are rejected, and the authorized
-- biscuit is added to the request context.
-- __The underlying application will only receive requests where the whole authorization process succeeded__.
-- If you want to only parse tokens and delegate actual authorization to the
-- underlying application, have a look at 'parseBiscuit' (or
-- 'parseBiscuitWith').
--
-- If you don’t need custom extraction, parsing, authorization, or error
-- handling logic, have a look at 'authorizeBiscuit''.
--
-- @since 0.1.0.0
authorizeBiscuitWith :: AuthorizationConfig e -> Middleware
authorizeBiscuitWith config app req sendResponse = do
  let AuthorizationConfig{extractToken,parseToken,authorizeToken,handleError} = config
      onError = sendResponse <=< handleError
      forward t = do
         let newVault = Vault.insert authorizedBiscuitKey t (vault req)
         app req { vault = newVault } sendResponse
  eBiscuit <- either (pure . Left) parseToken =<< extractToken req
  eResult <- either (pure . Left) (authorizeToken req) eBiscuit
  either onError forward eResult

-- | Configuration for 'parseBiscuitWith'.
--
-- @since 0.1.0.0
data ExtractionConfig e
  = ExtractionConfig
  -- | How to extract a token from a request
  { extractToken :: Request -> IO (Either e (Maybe ByteString))
  -- | How to parse a token from the extracted serialized bytestring
  , parseToken   :: ByteString -> IO (Either e (Biscuit OpenOrSealed Verified))
  -- | How to handle errors (this does not allow recovery)
  , handleError  :: e -> IO Response
  -- | How to handle requests with no biscuits
  , onMissingBiscuit :: Either e ()
  }

-- | Configuration for 'authorizeBiscuitWith'.
--
-- @since 0.1.0.0
data AuthorizationConfig e
  = AuthorizationConfig
  -- | How to extract a token from a request
  { extractToken :: Request -> IO (Either e ByteString)
  -- | How to parse a token from the extracted serialized bytestring
  , parseToken   :: ByteString -> IO (Either e (Biscuit OpenOrSealed Verified))
  -- | How to authorize a token
  , authorizeToken :: Request -> Biscuit OpenOrSealed Verified -> IO (Either e (AuthorizedBiscuit OpenOrSealed))
  -- | How to handle errors (this does not allow recovery)
  , handleError  :: e -> IO Response
  }

-- | Errors that can happen during token authorization
--
-- @since 0.1.0.0
data BiscuitError
  -- | No token was provided
  = NoToken
  -- | The provided token could not be parsed or verified
  | ParseError ParseError
  -- | The provided token was successfully parsed, but authorization failed
  | AuthorizationError ExecutionError

-- | Default behaviour for token extraction and parsing.
--
-- - Extract the token as a bearer token from the @Authorization@ header;
-- - Parse the token as URL-safe base64 strings, using the provided public
--   key;
-- - Errors are logged to stdout;
-- - Missing tokens are rejected with a bodyless 401 HTTP response;
-- - Parsing errors are rejected with a bodyless 403 HTTP response.
--
-- @since 0.1.0.0
defaultExtractionConfig :: PublicKey -> ExtractionConfig BiscuitError
defaultExtractionConfig publicKey = ExtractionConfig
  { extractToken = pure . Right . defaultExtractToken
  , parseToken = pure . Data.Bifunctor.first ParseError . parseB64 publicKey
  , handleError = defaultHandleError
  , onMissingBiscuit = Left NoToken
  }

-- | Default behaviour for optional token extraction and parsing.
--
-- - Extract the token as a bearer token from the @Authorization@ header;
-- - Parse the token as URL-safe base64 strings, using the provided public
--   key;
-- - Errors are logged to stdout;
-- - Missing tokens are not rejected;
-- - Parsing errors are rejected with a bodyless 403 HTTP response.
--
-- @since 0.1.0.0
defaultOptionalExtractionConfig :: PublicKey -> ExtractionConfig BiscuitError
defaultOptionalExtractionConfig publicKey = ExtractionConfig
  { extractToken = pure . Right . defaultExtractToken
  , parseToken = pure . Data.Bifunctor.first ParseError . parseB64 publicKey
  , handleError = defaultHandleError
  , onMissingBiscuit = Right ()
  }

-- | Default behaviour for token extraction, parsing and authorization.
--
-- - Extract the token as a bearer token from the @Authorization@ header;
-- - Parse the token as URL-safe base64 strings, using the provided public
--   key;
-- - Authorize the request with the generated authorizer;
-- - Errors are logged to stdout;
-- - Missing tokens are rejected with a bodyless 401 HTTP response;
-- - Parsing errors are rejected with a bodyless 403 HTTP response.
-- - Authorization errors are rejected with a bodyless 403 HTTP response.
--
-- @since 0.1.0.0
defaultAuthorizationConfig :: PublicKey -> (Request -> IO Authorizer) -> AuthorizationConfig BiscuitError
defaultAuthorizationConfig publicKey mkAuthorizer = AuthorizationConfig
  { extractToken = pure . maybe (Left NoToken) Right . defaultExtractToken
  , parseToken = pure . Data.Bifunctor.first ParseError . parseB64 publicKey
  , authorizeToken = \req token -> first AuthorizationError <$> (authorizeBiscuit token =<< mkAuthorizer req)
  , handleError = defaultHandleError
  }

-- | Extract a token from the @Authorization@ header, stripping the @Bearer @
-- prefix.
--
-- @since 0.1.0.0
defaultExtractToken :: Request -> Maybe ByteString
defaultExtractToken req = do
  (_, authHeader) <- List.find ((== hAuthorization) . fst) $ requestHeaders req
  BS.stripPrefix "Bearer " authHeader

-- | Generate HTTP responses based on authorization errors. Errors are logged
-- to stdout.
--
-- - Missing tokens result in a 401 bodyless response;
-- - Parsing errors result in a 403 bodyless response;
-- - Authorization errors result in a 403 bodyless response.
--
-- @since 0.1.0.0
defaultHandleError :: BiscuitError -> IO Response
defaultHandleError = \case
  NoToken      -> do
    putStrLn "Missing biscuit token"
    pure $ responseLBS unauthorized401 mempty mempty
  ParseError e -> do
    putStrLn $ "Parsing or verification error: " <> show e
    pure $ responseLBS forbidden403 mempty mempty
  AuthorizationError e -> do
    putStrLn $ "Authorization error: " <> show e
    pure $ responseLBS forbidden403 mempty mempty

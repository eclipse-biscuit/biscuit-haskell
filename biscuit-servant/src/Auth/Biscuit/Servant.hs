{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeFamilies      #-}
module Auth.Biscuit.Servant
  (
  -- * Protecting a servant API with biscuits
  -- $presentation

  -- ** Annotating servant API types
  -- $apitypes
    RequireBiscuit
  , authHandler
  , genBiscuitCtx
  -- *** Custom parsing and error handling
  , authHandlerWith
  , genBiscuitCtxWith
  , BiscuitConfig (..)
  , defaultBiscuitConfig
  -- ** Supplying a authorizer for a single endpoint
  -- $singleEndpointAuthorizer
  , checkBiscuit
  , checkBiscuitM
  -- *** Custom parsing and error handling
  , checkBiscuitWith
  , checkBiscuitMWith
  -- ** Decorate regular handlers with composable authorizers
  -- $composableAuthorizers
  , WithAuthorizer' (..)
  , WithAuthorizer
  , handleBiscuit
  , handleBiscuitWith
  , withAuthorizer
  , withAuthorizer_
  , withAuthorizerM
  , withAuthorizerM_
  , noAuthorizer
  , noAuthorizer_
  , withFallbackAuthorizer
  , withPriorityAuthorizer
  , withFallbackAuthorizerM
  , withPriorityAuthorizerM
  -- *** Extract information from an authorized token
  -- $tokenPostProcessing
  , withTransformation

  , module Biscuit
  ) where

import           Auth.Biscuit                     as Biscuit
import           Control.Applicative              (liftA2)
import           Control.Monad.Except             (MonadError, throwError)
import           Control.Monad.IO.Class           (MonadIO, liftIO)
import           Control.Monad.Reader             (ReaderT (..), lift,
                                                   runReaderT, withReaderT)
import           Data.ByteString                  (ByteString)
import qualified Data.ByteString                  as BS
import qualified Data.ByteString.Char8            as C8
import qualified Data.ByteString.Lazy             as LBS
import           Data.Either                      (fromRight)
import           Data.Kind                        (Type)
import           Network.Wai
import           Servant                          (AuthProtect)
import           Servant.Server
import           Servant.Server.Experimental.Auth

-- $presentation
--
-- Biscuit are bearer tokens that can be used to protect API endpoints.
-- This package provides utilities to protect servant endpoints with such
-- tokens.
--
-- The token will be extracted from the @Authorization@ header, and must
-- be base64-encoded, prefixed with the @Bearer @ string.

-- $apitypes
--
-- To protect an endpoint (or a whole API tree), you can use 'RequireBiscuit'
-- like so:
--
-- > type API = RequireBiscuit :> ProtectedAPI
-- > type ProtectedAPI =
-- >        "endpoint1" :> Get '[JSON] Int
-- >   :<|> "endpoint2" :> Capture "int" Int :> Get '[JSON] Int
-- >   :<|> "endpoint3" :> Get '[JSON] Int
-- >   :<|> "endpoint4" :> Get '[JSON] Int
-- >
-- > app :: PublicKey -> Application
-- > app publicKey =
-- >   -- servant needs access to the biscuit /public/
-- >   -- key to be able to check biscuit signatures.
-- >   -- The public key can be read from the environment
-- >   -- and parsed using 'parsePublicKeyHex' for instance.
-- >   serveWithContext
-- >     (Proxy :: Proxy API)
-- >     (genBiscuitCtx publicKey)
-- >     server
-- >
-- > -- server :: Biscuit OpenOrSealed Verified -> Server ProtectedAPI
-- > server :: Server API
-- > server biscuit = … -- this will be detailed later
--
-- This will instruct servant to extract the biscuit from the requests and
-- check its signature. /It will not/, however, run any datalog check (as
-- the checks typically depend on the request contents).
--
-- $singleEndpointAuthorizer
--
-- The corresponding @Server API@ value will be a @Biscuit OpenOrSealed Verified -> Server ProtectedAPI@.
-- The next step is to provide a 'Authorizer' so that the biscuit datalog can be
-- verified. For that, you can use 'checkBiscuit' (or 'checkBiscuitM' for effectful checks).
--
-- > server :: Server API
-- > server biscuit = h1 biscuit
-- >             :<|> h2 biscuit
-- >             :<|> h3 biscuit
-- >
-- > h1 :: Biscuit OpenOrSealed Verified -> Handler Int
-- > h1 biscuit =
-- >   checkBiscuit biscuit
-- >     [authorizer|allow if right("one");|]
-- >     -- ^ only allow biscuits granting access to the endpoint tagged "one"
-- >     (pure 1)
-- >
-- > h2 :: Biscuit OpenOrSealed Verified -> Int -> Handler Int
-- > h2 biscuit value =
-- >   let authorizer' = do
-- >         now <- liftIO getCurrentTime
-- >         pure [authorizer|
-- >                // provide the current time so that TTL checks embedded in
-- >                // the biscuit can decide if it's still valid
-- >                // this show how to run an effectful check with
-- >                // checkBiscuitM (getting the current time is an effect)
-- >                time({now});
-- >                // only allow biscuits granting access to the endpoint tagged "two"
-- >                // AND for the provided int value. This shows how the checks can depend
-- >                // on the http request contents.
-- >                allow if right("two", {value});
-- >              |]
-- >   checkBiscuitM biscuit authorizer
-- >     (pure 2)
-- >
-- > h3 :: Biscuit OpenOrSealed Verified -> Handler Int
-- > h3 biscuit =
-- >   checkBiscuit biscuit
-- >     [authorizer|deny if true;|]
-- >     -- ^ reject every biscuit
-- >     (pure 3)
--
-- $composableAuthorizers
--
-- 'checkBiscuit' allows you to describe validation rules endpoint by endpoint. If your
-- application has a lot of endpoints with the same policies, it can become tedious to
-- maintain.
--
-- 'biscuit-servant' provides a way to apply authorizers on whole API trees,
-- in a composable way, thanks to 'hoistServer'. 'hoistServer' is a mechanism
-- provided by servant-server that lets apply a transformation function to whole
-- API trees.
--
-- > -- 'withAuthorizer' wraps a 'Handler' and lets you attach a authorizer to a
-- > -- specific endoint. This authorizer may be combined with other authorizers
-- > -- attached to the whole API tree
-- > handler1 :: WithAuthorizer Handler Int
-- > handler1 = withAuthorizer
-- >   [authorizer|allow if right("one");|]
-- >   (pure 1)
-- >
-- > handler2 :: Int -> WithAuthorizer Handler Int
-- > handler2 value = withAuthorizer
-- >   [authorizer|allow if right("two", {value});|]
-- >   (pure 2)
-- >
-- > handler3 :: WithAuthorizer Handler Int
-- > handler3 = withAuthorizer
-- >   [authorizer|deny if true;|]
-- >   (pure 3)
-- >
-- > server :: Biscuit OpenOrSealed Verified -> Server ProtectedAPI
-- > server biscuit =
-- >  let nowFact = do
-- >        now <- liftIO getCurrentTime
-- >        pure [authorizer|time({now});|]
-- >      handleAuth :: WithAuthorizer Handler x -> Handler x
-- >      handleAuth =
-- >          handleBiscuit biscuit
-- >          -- ^ this runs datalog checks on the biscuit, based on authorizers attached to
-- >          -- the handlers
-- >        . withPriorityAuthorizerM nowFact
-- >          -- ^ this provides the current time to the verification context so that biscuits with
-- >          -- a TTL can check if they are still valid.
-- >          -- Authorizers can be provided in a monadic context (it has to be the same monad as
-- >          -- the handlers themselves, so here it's 'Handler').
-- >        . withPriorityAuthorizer [authorizer|allow if right("admin");|]
-- >          -- ^ this policy will be tried /before/ any endpoint policy, so `endpoint3` will be
-- >          -- reachable with an admin biscuit
-- >        . withFallbackAuthorizer [authorizer|allow if right("anon");|]
-- >          -- ^ this policy will be tried /after/ the endpoints policies, so `endpoint3` will
-- >          -- *not* be reachable with a biscuit carrying a @right("anon")@ fact.
-- >      handlers = handler1 :<|> handler2 :<|> handler3
-- >   in hoistServer @ProtectedAPI Proxy handleAuth handlers
-- >        -- ^ this will apply `handleAuth` on all 'ProtectedAPI' endpoints.
--
-- $tokenPostProcessing
--
-- By default, an `AuthorizedBiscuit` value is available through `MonadReader` in all
-- `WithAuthorizer` handlers. In many cases, a post-processing step is needed to extract
-- meaningful information from the token (for instance extracting a user id and then fetching
-- user information from the database). In order to avoid repeating this operation in every
-- endpoint, `withTransformation` allows to do it for whole API trees.
--
-- > handler4 :: WithAuthorizer Handler Int
-- > handler4 = withTransformation extractUserId $
-- >   withAuthorizer [authorizer|allow if user($user_id); |] $ do
-- >     userId <- ask -- we can access the extracted user id directly
-- >     pure userId
-- >
-- > -- given a @AuthorizedBiscuit OpenOrSealed@, we can extract information from
-- > -- the token. This step can perform effects (for instance `IO`, or `MonadError`).
-- > extractUserId :: AuthorizedBiscuit OpenOrSealed -> Handler Int
-- > extractUserId AuthorizedBiscuit{authorizationSuccess} = do
-- >   let b = bindings $ matchedAllowQuery authorizationSuccess
-- >    in maybe (throwError err403) pure $ getSingleVariableValue b "user_id"

-- | Type used to protect an API tree, requiring a biscuit token
-- to be attached to requests. The associated auth handler will
-- only check the biscuit signature. Checking the datalog part
-- usually requires endpoint-specific information, and has to
-- be performed separately with either 'checkBiscuit' (for simple
-- use-cases) or 'handleBiscuit' (for more complex use-cases).
type RequireBiscuit = AuthProtect "biscuit"

-- | The result of a 'RequireBiscuit' check will be a @Biscuit OpenOrSealed Verified@:
-- a biscuit that's been successfully parsed, with its signatures verified.
type instance AuthServerData RequireBiscuit = Biscuit OpenOrSealed Verified

-- | Wrapper for a servant handler, equipped with a biscuit 'Authorizer'
-- that will be used to authorize the request. If the authorization
-- succeeds, the handler is ran.
-- The handler itself is given access to the authorized biscuit (or another
-- value derived from it) through a @ReaderT@ wrapper
data WithAuthorizer' (t :: Type) (m :: Type -> Type) (a :: Type)
  = WithAuthorizer
  { handler_    :: ReaderT t m a
  -- ^ the wrapped handler, in a 'ReaderT' to give easy access to the biscuit
  , authorizer_ :: m Authorizer
  -- ^ the 'Authorizer' associated to the handler
  }

-- | Default wrapper giving access to the @AuthorizedBiscuit@ directly.
type WithAuthorizer = WithAuthorizer' (AuthorizedBiscuit OpenOrSealed)

-- | Combines the provided 'Authorizer' to the 'Authorizer' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackAuthorizer' puts the provided policies at the /bottom/
-- of the list (ie as /fallback/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityAuthorizer' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried before the ones of the wrapped handler, you
-- can use 'withPriorityAuthorizer'.
--
-- If you need to perform effects to compute the authorizer (eg. to get the current date,
-- or to query a database), you can use 'withFallbackAuthorizerM' instead.
withFallbackAuthorizer :: Functor m
                     => Authorizer
                     -> WithAuthorizer' t m a
                     -> WithAuthorizer' t m a
withFallbackAuthorizer newV h@WithAuthorizer{authorizer_} =
  h { authorizer_ = (<> newV) <$> authorizer_ }

-- | Combines the provided 'Authorizer' to the 'Authorizer' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackAuthorizer' puts the provided policies at the /bottom/
-- of the list (ie as /fallback/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityAuthorizer' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried before the ones of the wrapped handler, you
-- can use 'withPriorityAuthorizer'.
--
-- Here, the 'Authorizer' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withFallbackAuthorizer' instead.
withFallbackAuthorizerM :: Applicative m
                      => m Authorizer
                      -> WithAuthorizer' t m a
                      -> WithAuthorizer' t m a
withFallbackAuthorizerM newV h@WithAuthorizer{authorizer_} =
  h { authorizer_ = liftA2 (<>) authorizer_ newV }

-- | Combines the provided 'Authorizer' to the 'Authorizer' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackAuthorizer' puts the provided policies at the /top/
-- of the list (ie as /priority/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityAuthorizer' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried after the ones of the wrapped handler, you
-- can use 'withFallbackAuthorizer'.
--
-- If you need to perform effects to compute the authorizer (eg. to get the current date,
-- or to query a database), you can use 'withPriorityAuthorizerM' instead.
withPriorityAuthorizer :: Functor m
                     => Authorizer
                     -> WithAuthorizer' t m a
                     -> WithAuthorizer' t m a
withPriorityAuthorizer newV h@WithAuthorizer{authorizer_} =
     h { authorizer_ = (newV <>) <$> authorizer_ }

-- | Combines the provided 'Authorizer' to the 'Authorizer' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackAuthorizer' puts the provided policies at the /top/
-- of the list (ie as /priority/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityAuthorizer' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried after the ones of the wrapped handler, you
-- can use 'withFallbackAuthorizer'.
--
-- Here, the 'Authorizer' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withFallbackAuthorizer' instead.
withPriorityAuthorizerM :: Applicative m
                      => m Authorizer
                      -> WithAuthorizer' t m a
                      -> WithAuthorizer' t m a
withPriorityAuthorizerM newV h@WithAuthorizer{authorizer_} =
     h { authorizer_ = liftA2 (<>) newV authorizer_ }

-- | Wraps an existing handler block, attaching a 'Authorizer'. The handler has
-- to be a @ReaderT (Biscuit OpenOrSealed Verified)' to be able to access the token.
-- If you don't need to access the token from the handler block, you can use
-- 'withAuthorizer_' instead.
--
-- If you need to perform effects to compute the authorizer (eg. to get the current date,
-- or to query a database), you can use 'withAuthorizerM' instead.
withAuthorizer :: Applicative m
               => Authorizer
               -> ReaderT t m a
               -> WithAuthorizer' t m a
withAuthorizer v handler_ =
  WithAuthorizer
    { handler_
    , authorizer_ = pure v
    }

-- | Wraps an existing handler block, attaching a 'Authorizer'. The handler has
-- to be a @ReaderT (Biscuit OpenOrSealed Verified)@ to be able to access the token.
-- If you don't need to access the token from the handler block, you can use
-- 'withAuthorizer_' instead.
--
-- Here, the 'Authorizer' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withAuthorizer' instead.
withAuthorizerM :: m Authorizer
                -> ReaderT t m a
                -> WithAuthorizer' t m a
withAuthorizerM authorizer_ handler_ =
  WithAuthorizer
    { handler_
    , authorizer_
    }

-- | Wraps an existing handler block, attaching a 'Authorizer'. The handler can be
-- any monad, but won't be able to access the biscuit. If you want to read the biscuit
-- token from the handler block, you can use 'withAuthorizer' instead.
--
-- If you need to perform effects to compute the authorizer (eg. to get the current date,
-- or to query a database), you can use 'withAuthorizerM_' instead.
withAuthorizer_ :: Monad m => Authorizer -> m a -> WithAuthorizer' t m a
withAuthorizer_ v = withAuthorizer v . lift

-- | Wraps an existing handler block, attaching a 'Authorizer'. The handler can be
-- any monad, but won't be able to access the 'Biscuit'.
--
-- If you want to read the biscuit token from the handler block, you can use 'withAuthorizer'
-- instead.
--
-- Here, the 'Authorizer' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withAuthorizer_' instead.
withAuthorizerM_ :: Monad m => m Authorizer -> m a -> WithAuthorizer' t m a
withAuthorizerM_ v = withAuthorizerM v . lift

-- | Wraps an existing handler block, attaching an empty 'Authorizer'. The handler has
-- to be a @ReaderT (Biscuit OpenOrSealed Verified)@ to be able to access the token. If you don't need
-- to access the token from the handler block, you can use 'noAuthorizer_'
-- instead.
--
-- This function is useful when the endpoint does not have any specific authorizer
-- context, and the authorizer context is applied on the whole API tree through
-- 'withFallbackAuthorizer' or 'withPriorityAuthorizer' to apply policies on several
-- handlers at the same time (with 'hoistServer' for instance).
noAuthorizer :: Applicative m
           => ReaderT t m a
           -> WithAuthorizer' t m a
noAuthorizer = withAuthorizer mempty

-- | Wraps an existing handler block, attaching an empty 'Authorizer'. The handler can be
-- any monad, but won't be able to access the biscuit. If you want to read the
-- biscuit token from the handler block, you can use 'noAuthorizer' instead.
--
-- This function is useful when the endpoint does not have any specific authorizer
-- context, and the authorizer context is applied on the whole API tree through
-- 'withFallbackAuthorizer' or 'withPriorityAuthorizer' to apply policies on several
-- handlers at the same time (with 'hoistServer' for instance).
noAuthorizer_ :: Monad m => m a -> WithAuthorizer' t m a
noAuthorizer_ = noAuthorizer . lift

-- | Configuration record for use with `authHandlerWith`. If you don't care about details,
-- you should use `authHandler` instead, which provides sensible defaults.
data BiscuitConfig e
  = BiscuitConfig
  { parserConfig             :: ParserConfig Handler
  -- ^ how to parse a serialized biscuit (this includes public key and revocation checks)
  , extractSerializedBiscuit :: Request -> Either e ByteString
  -- ^ how to extract the serialized biscuit from the request
  , onExtractionError        :: forall a. e -> Handler a
  -- ^ what to do when the biscuit cannot be extracted from the request
  , onParseError             :: forall a. ParseError -> Handler a
  -- ^ what to do when the biscuit cannot be parsed
  }

-- | Default configuration used by `authHandler`.
--
-- It assumes:
--
-- - the biscuit is b64-encoded
-- - prefixed with the @Bearer @ string
-- - in the @Authorization@ header
--
-- It always uses the same public key and does not perform revocation checks. It returns
-- text-based 401 errors.
defaultBiscuitConfig :: PublicKey -> BiscuitConfig String
defaultBiscuitConfig publicKey = BiscuitConfig
  { parserConfig = ParserConfig
      { getPublicKey = const publicKey
      , isRevoked = const $ pure False
      , encoding = UrlBase64
      }
  , extractSerializedBiscuit = readFromAuthHeader
  , onExtractionError = throwError . defaultInvalidBiscuitError . Right
  , onParseError      = throwError . defaultInvalidBiscuitError . Left
  }

-- | Read a serialized biscuit from the @Authorization@ header, assuming it is prefixed
-- by @Bearer@.
readFromAuthHeader :: Request -> Either String ByteString
readFromAuthHeader req = do
  let note e = maybe (Left e) Right
  authHeader <- note "Missing Authorization header" . lookup "Authorization" $ requestHeaders req
  note "Not a Bearer token" $ BS.stripPrefix "Bearer " authHeader

-- | Default 401 error returned if the biscuit can't be extracted or fails to parse.
defaultInvalidBiscuitError :: Either ParseError String -> ServerError
defaultInvalidBiscuitError e =
  let s = fromRight "Not a B64-encoded biscuit" e
   in err401 { errBody = LBS.fromStrict (C8.pack s) }

-- | Default 403 error returned if the biscuit fails authorization.
defaultUnauthorizedBiscuitError :: ExecutionError -> ServerError
defaultUnauthorizedBiscuitError _ =
  err403 { errBody = "Biscuit failed checks" }

-- | Servant authorization handler. This extracts the biscuit from the request,
-- checks its signature (but not the datalog part) and returns a 'Biscuit'
-- upon success. See `BiscuitConfig` for configuration details.
authHandlerWith :: BiscuitConfig e
                -> AuthHandler Request (Biscuit OpenOrSealed Verified)
authHandlerWith BiscuitConfig{..} = mkAuthHandler handler
  where
    orExtractionError = either onExtractionError  pure
    orParseError = either onParseError pure
    handler req = do
      bs <- orExtractionError $ extractSerializedBiscuit req
      orParseError =<< parseWith parserConfig bs

-- | Default servant authorization handler. This extracts the biscuit from the request,
-- checks its signature (but not the datalog part) and returns a 'Biscuit'
-- upon success. If you need to customize token extraction or error handling, you can
-- use `authHandlerWith` instead.
authHandler :: PublicKey -> AuthHandler Request (Biscuit OpenOrSealed Verified)
authHandler = authHandlerWith . defaultBiscuitConfig

-- | Helper function generating a servant context containing the authorization
-- handler. The token will be read as a b64-url string (prefixed with @Bearer@)
-- in the @Authorization@ header.
--
-- If you need custom error handling or token parsing, you can use 'genBiscuitCtxWith'
-- instead.
genBiscuitCtx :: PublicKey
              -> Context '[AuthHandler Request (Biscuit OpenOrSealed Verified)]
genBiscuitCtx pk = authHandler pk :. EmptyContext

-- | Helper function generating a servant context containing the authorization
-- handler, with the provided configuration.
--
-- If you don't need custom error handling or token extraction, you can use
-- 'genBiscuitCtx' instead.
genBiscuitCtxWith :: BiscuitConfig e
                  -> Context '[AuthHandler Request (Biscuit OpenOrSealed Verified)]
genBiscuitCtxWith c = authHandlerWith c :. EmptyContext

-- | Given a biscuit (provided by the servant authorization mechanism),
-- verify its validity (with the provided 'Authorizer').
--
-- If you need to perform effects in the verification phase (eg to get the current time,
-- or if you need to issue a DB query to retrieve extra information needed to check the token),
-- you can use 'checkBiscuitM' instead.
--
-- If you don't want to pass the biscuit manually to all the endpoints or want to
-- blanket apply authorizers on whole API trees, you can consider using 'withAuthorizer'
-- (on endpoints), 'withFallbackAuthorizer' and 'withPriorityAuthorizer' (on API sub-trees)
-- and 'handleBiscuit' (on the whole API).
checkBiscuit :: (MonadIO m, MonadError ServerError m)
             => Biscuit OpenOrSealed Verified
             -> Authorizer
             -> m a
             -> m a
checkBiscuit vb = do
  checkBiscuitM vb . pure

-- | Given a biscuit (provided by the servant authorization mechanism),
-- verify its validity (with the provided 'Authorizer').
-- If the authorization fails, the provided error handler will be used to return
-- an error.
--
-- If you need to perform effects in the verification phase (eg to get the current time,
-- or if you need to issue a DB query to retrieve extra information needed to check the token),
-- you can use 'checkBiscuitMWith' instead.
--
-- If you don't want a custom error handler, you can use 'checkBiscuit' instead.
--
-- If you don't want to pass the biscuit manually to all the endpoints or want to
-- blanket apply authorizers on whole API trees, you can consider using 'withAuthorizer'
-- (on endpoints), 'withFallbackAuthorizer' and 'withPriorityAuthorizer' (on API sub-trees)
-- and 'handleBiscuit' (on the whole API).
checkBiscuitWith :: (MonadIO m, MonadError ServerError m)
                 => (forall b. ExecutionError -> m b)
                 -> Biscuit OpenOrSealed Verified
                 -> Authorizer
                 -> ReaderT (AuthorizedBiscuit OpenOrSealed) m a
                 -> m a
checkBiscuitWith onError vb =
  checkBiscuitMWith onError vb . pure

-- | Given a 'Biscuit' (provided by the servant authorization mechanism),
-- verify its validity (with the provided 'Authorizer', which can be effectful).
--
-- If you don't need to run any effects in the verifying phase, you can use 'checkBiscuit'
-- instead.
--
-- If you don't want to pass the biscuit manually to all the endpoints or want to blanket apply
-- authorizers on whole API trees, you can consider using 'withAuthorizer' (on endpoints),
-- 'withFallbackAuthorizer' and 'withPriorityAuthorizer' (on API sub-trees) and 'handleBiscuit'
-- (on the whole API).
checkBiscuitM :: (MonadIO m, MonadError ServerError m)
              => Biscuit OpenOrSealed Verified
              -> m Authorizer
              -> m a
              -> m a
checkBiscuitM vb mv h = do
  let onError = throwError . defaultUnauthorizedBiscuitError
   in checkBiscuitMWith onError vb mv (lift h)

-- | Given a 'Biscuit' (provided by the servant authorization mechanism),
-- verify its validity (with the provided 'Authorizer', which can be effectful).
-- If the authorization fails, the provided error handler will be used to return
-- an error.
--
-- If you don't need to run any effects in the verifying phase, you can use 'checkBiscuitWith'
-- instead.
--
-- If you don't want a custom error handler, you can use 'checkBiscuitM' instead.
--
-- If you don't want to pass the biscuit manually to all the endpoints or want to blanket apply
-- authorizers on whole API trees, you can consider using 'withAuthorizer' (on endpoints),
-- 'withFallbackAuthorizer' and 'withPriorityAuthorizer' (on API sub-trees) and 'handleBiscuit'
-- (on the whole API).
checkBiscuitMWith :: (MonadIO m, MonadError ServerError m)
                  => (forall b. ExecutionError -> m b)
                  -> Biscuit OpenOrSealed Verified
                  -> m Authorizer
                  -> ReaderT (AuthorizedBiscuit OpenOrSealed) m a
                  -> m a
checkBiscuitMWith onError vb mv h = do
  v   <- mv
  res <- liftIO $ authorizeBiscuit vb v
  case res of
    Left e   -> onError e
    Right as -> runReaderT h as

-- | Given a handler wrapped in a 'WithAuthorizer', use the attached 'Authorizer' to
-- verify the provided biscuit and return an error as needed.
--
-- For simpler use cases, consider using 'checkBiscuit' instead, which works on regular
-- servant handlers.
handleBiscuit :: (MonadIO m, MonadError ServerError m)
              => Biscuit OpenOrSealed Verified
              -> WithAuthorizer m a
              -> m a
handleBiscuit b WithAuthorizer{authorizer_, handler_} =
  let onError = throwError . defaultUnauthorizedBiscuitError
   in checkBiscuitMWith onError b authorizer_ handler_

-- | Given a handler wrapped in a 'WithAuthorizer', use the attached 'Authorizer' to
-- verify the provided biscuit and return an error as needed, with the provided error
-- handler.
--
-- If you don't want to provide the error handler, you can use 'handleBiscuit' which
-- uses a default error handler
--
-- For simpler use cases, consider using 'checkBiscuitWith' instead, which works on regular
-- servant handlers.
handleBiscuitWith :: (MonadIO m, MonadError ServerError m)
                  => (forall b. ExecutionError -> m b)
                  -> Biscuit OpenOrSealed Verified
                  -> WithAuthorizer m a
                  -> m a
handleBiscuitWith onError b WithAuthorizer{authorizer_, handler_} =
  checkBiscuitMWith onError b authorizer_ handler_

-- | Transform the context provided by 'WithAuthorizer'' in an effectful way.
-- This is useful to turn an 'AuthorizedBiscuit' into a custom type.
-- Transformations can be chained within an API tree as long as the outermost value
-- is a 'WithAuthorizer', that can be handled by 'handleBiscuit'.
withTransformation :: Monad m
                   => (t -> m t')
                   -- ^ context transformation function. @t@ will usually be
                   -- @AuthorizedBiscuit OpenOrSealed@
                   -> WithAuthorizer' t' m a
                   -- ^ wrapped handler with reader access to a @t'@ value
                   -- (derived from an @AuthorizedBiscuit OpenOrSealed@)
                   -> WithAuthorizer' t  m a
                   -- ^ wrapped handler with reader access to a @t@ value
                   -- (usually @AuthorizedBiscuit OpenOrSealed@)
withTransformation compute wa@WithAuthorizer{handler_} =
  let newHandler = do
        t' <- ReaderT compute
        withReaderT (const t') handler_
   in wa { handler_ = newHandler }

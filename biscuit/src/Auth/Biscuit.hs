{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE EmptyDataDeriving #-}
{-|
  Module      : Auth.Biscuit
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  Haskell implementation for the Biscuit token.
-}
module Auth.Biscuit
  (
  -- * The biscuit auth token
  -- $biscuitOverview

  -- * Creating key pairs
  -- $keypairs
    newSecret
  , toPublic
  , SecretKey
  , PublicKey

  -- ** Parsing and serializing key pairs
  , serializeSecretKeyHex
  , serializePublicKeyHex
  , parseSecretKeyHex
  , parsePublicKeyHex
  , serializeSecretKey
  , serializePublicKey
  , parseSecretKey
  , parsePublicKey

  -- * Creating a biscuit
  -- $biscuitBlocks
  , mkBiscuit
  , mkBiscuitWith
  , block
  , blockContext
  , Biscuit
  , OpenOrSealed
  , Open
  , Sealed
  , Verified
  , Unverified
  , BiscuitProof
  , Block
  -- ** Parsing and serializing biscuits
  , parseB64
  , parse
  , parseWith
  , parseBiscuitUnverified
  , checkBiscuitSignatures
  , BiscuitEncoding (..)
  , ParserConfig (..)
  , fromRevocationList
  , serializeB64
  , serialize
  , fromHex
  -- ** Attenuating biscuits
  -- $attenuatingBiscuits
  , addBlock
  -- ** Third-party blocks
  -- $thirdPartyBlocks
  , addSignedBlock
  , mkThirdPartyBlockReq
  , mkThirdPartyBlockReqB64
  , mkThirdPartyBlock
  , mkThirdPartyBlockB64
  , applyThirdPartyBlock
  , applyThirdPartyBlockB64
  -- ** Sealing biscuits
  -- $sealedBiscuits
  , seal
  , fromOpen
  , fromSealed
  , asOpen
  , asSealed

  -- * Verifying a biscuit
  -- $verifying
  , authorizer
  , Authorizer
  , authorizeBiscuit
  , authorizeBiscuitWithLimits
  , Limits (..)
  , defaultLimits
  , ParseError (..)
  , ExecutionError (..)
  , AuthorizedBiscuit (..)
  , AuthorizationSuccess (..)
  , MatchedQuery (..)
  , getBindings
  , ToTerm (..)
  , FromValue (..)
  , Term
  , Term' (..)

  -- * Retrieving information from a biscuit
  , queryAuthorizerFacts
  , queryRawBiscuitFacts
  , getVariableValues
  , getSingleVariableValue
  , query
  , getRevocationIds
  , getVerifiedBiscuitPublicKey
  ) where

import           Control.Monad                       ((<=<))
import           Control.Monad.Identity              (runIdentity)
import           Data.Bifunctor                      (first)
import           Data.ByteString                     (ByteString)
import qualified Data.ByteString.Base64.URL          as B64
import           Data.Foldable                       (toList)
import           Data.Set                            (Set)
import qualified Data.Set                            as Set
import           Data.Text                           (Text, unpack)

import           Auth.Biscuit.Crypto                 (PublicKey, SecretKey,
                                                      generateSecretKey,
                                                      pkBytes,
                                                      readEd25519PublicKey,
                                                      readEd25519SecretKey,
                                                      skBytes, toPublic)
import           Auth.Biscuit.Datalog.AST            (Authorizer, Block,
                                                      FromValue (..), Term,
                                                      Term' (..), ToTerm (..),
                                                      bContext)
import           Auth.Biscuit.Datalog.Executor       (ExecutionError (..),
                                                      Limits (..),
                                                      MatchedQuery (..),
                                                      defaultLimits)
import           Auth.Biscuit.Datalog.Parser         (authorizer, block, query)
import           Auth.Biscuit.Datalog.ScopedExecutor (AuthorizationSuccess (..),
                                                      getBindings,
                                                      getSingleVariableValue,
                                                      getVariableValues)
import           Auth.Biscuit.Token                  (AuthorizedBiscuit (..),
                                                      Biscuit,
                                                      BiscuitEncoding (..),
                                                      BiscuitProof (..), Open,
                                                      OpenOrSealed,
                                                      ParseError (..),
                                                      ParserConfig (..), Sealed,
                                                      Unverified, Verified,
                                                      addBlock, addSignedBlock,
                                                      applyThirdPartyBlock,
                                                      asOpen, asSealed,
                                                      authorizeBiscuit,
                                                      authorizeBiscuitWithLimits,
                                                      checkBiscuitSignatures,
                                                      fromOpen, fromSealed,
                                                      getRevocationIds,
                                                      getVerifiedBiscuitPublicKey,
                                                      mkBiscuit, mkBiscuitWith,
                                                      mkThirdPartyBlock,
                                                      mkThirdPartyBlockReq,
                                                      parseBiscuitUnverified,
                                                      parseBiscuitWith,
                                                      queryAuthorizerFacts,
                                                      queryRawBiscuitFacts,
                                                      seal, serializeBiscuit)
import           Auth.Biscuit.Utils                  (decodeHex, encodeHex')
import qualified Data.Text                           as Text


-- $biscuitOverview
--
-- <https://github.com/biscuit-auth/biscuit/blob/master/SUMMARY.md Biscuit> is a /bearer token/,
-- allowing /offline attenuation/ (meaning that anyone having a token can craft a new, more
-- restricted token),
-- and /'PublicKey' verification/. Token rights and attenuation are expressed using a logic
-- language, derived from <todo datalog>. Such a language can describe facts (things we know
-- about the world), rules (describing how to derive new facts from existing ones) and checks
-- (ensuring that facts hold). Facts and checks let you describe access control rules, while
-- rules make them modular. /Authorizer policies/ lets the verifying party ensure that a
-- provided biscuit grants access to the required operations.
--
-- Here's how to create a biscuit token:
--
-- > -- Biscuit Open Verified means the token has valid signatures
-- > -- and is open to further restriction
-- > buildToken :: SecretKey -> IO (Biscuit Open Verified)
-- > buildToken secret =
-- >   -- the logic language has its own syntax, which can be typed directly in haskell
-- >   -- source code thanks to QuasiQuotes. The datalog snippets are parsed at compile
-- >   -- time, so a datalog error results in a compilation error, not a runtime error
-- >   mkBiscuit secret [block|
-- >       // the two first lines describe facts:
-- >       // the token holder is identified as `user_1234`
-- >       user("user_1234");
-- >       // the token holder is granted access to resource `file1`
-- >       resource("file1");
-- >       // this last line defines a restriction: properties that need
-- >       // to be verified for the token to be verified:
-- >       // the token can only be used before a specified date
-- >       check if time($time), $time < 2021-05-08T00:00:00Z;
-- >    |]
--
-- Here's how to attenuate a biscuit token:
--
-- > restrictToken :: Biscuit Open Verified -> IO Biscuit Open Verified
-- > restrictToken =
-- >   addBlock [block|
-- >       // restrict the token to local use only
-- >       check if user_ip_address("127.0.0.1");
-- >    |]
--
-- To verify a biscuit token, we need two things:
--
--  - a public key, that will let us verify the token has been emitted by
--    a trusted authority
--  - an authorizer, that will make sure all the checks declared in the token are fulfilled,
--    as well as providing its own checks, and policies which decide if the token is
--    verified or not
--
-- Here's how to verify a base64-serialized biscuit token:
--
-- > verifyToken :: PublicKey -> ByteString -> IO Bool
-- > verifyToken publicKey token = do
-- >   -- complete parsing is only attempted if signatures can be verified,
-- >   -- that's the reason why 'parseB64' takes a public key as a parameter
-- >   parseResult <- parseB64 publicKey token
-- >   case parseResult of
-- >     Left e -> print e $> False
-- >     Right biscuit -> do
-- >       now <- getCurrentTime
-- >       let authorizer' = [authorizer|
-- >                // the datalog snippets can reference haskell variables
-- >                // with the {variableName} syntax
-- >                time({now});
-- >
-- >                // policies are tried in order. The first matching policy
-- >                // will decide if the token is valid or not. If no policies
-- >                // match, the token will fail validation
-- >                allow if resource("file1");
-- >             |]
-- >       result <- authorizeBiscuit biscuit authorizer'
-- >       case result of
-- >         Left e -> print e $> False
-- >         Right _ -> pure True

-- | Build a block containing an explicit freeform context value.
-- The context of a block can't be parsed from datalog,
-- so you'll need an explicit call to `blockContext` to add it
--
-- >     [block|check if time($t), $t < 2021-01-01;|]
-- >  <> blockContext "ttl-check"
blockContext :: Text -> Block
blockContext c = mempty { bContext = Just c }

-- | Decode a base16-encoded bytestring, reporting errors via `MonadFail`
fromHex :: MonadFail m => ByteString -> m ByteString
fromHex = either (fail . Text.unpack) pure . decodeHex

-- $keypairs
--
-- Biscuits rely on public key cryptography: biscuits are signed with a secret key only known
-- to the party which emits it. Verifying a biscuit, on the other hand, can be done with a
-- public key that can be widely distributed. A private key and its corresponding public key
-- is called a key pair, but since a public key can be deterministically computed from a
-- private key, owning a private key is the same as owning a key pair.

-- | Generate a new random 'SecretKey'
newSecret :: IO SecretKey
newSecret = generateSecretKey

-- | Serialize a 'SecretKey' to raw bytes, without any encoding
serializeSecretKey :: SecretKey -> ByteString
serializeSecretKey = skBytes

-- | Serialize a 'PublicKey' to raw bytes, without any encoding
serializePublicKey :: PublicKey -> ByteString
serializePublicKey = pkBytes

-- | Serialize a 'SecretKey' to a hex-encoded bytestring
serializeSecretKeyHex :: SecretKey -> ByteString
serializeSecretKeyHex = encodeHex' . skBytes

-- | Serialize a 'PublicKey' to a hex-encoded bytestring
serializePublicKeyHex :: PublicKey -> ByteString
serializePublicKeyHex = encodeHex' . pkBytes

-- | Read a 'SecretKey' from raw bytes
parseSecretKey :: ByteString -> Maybe SecretKey
parseSecretKey = readEd25519SecretKey

-- | Read a 'SecretKey' from an hex bytestring
parseSecretKeyHex :: ByteString -> Maybe SecretKey
parseSecretKeyHex = parseSecretKey <=< fromHex

-- | Read a 'PublicKey' from raw bytes
parsePublicKey :: ByteString -> Maybe PublicKey
parsePublicKey = readEd25519PublicKey

-- | Read a 'PublicKey' from an hex bytestring
parsePublicKeyHex :: ByteString -> Maybe PublicKey
parsePublicKeyHex = parsePublicKey <=< fromHex

-- | Parse a biscuit from a raw bytestring. If you want to parse
-- from a URL-compatible base 64 bytestring, consider using `parseB64`
-- instead.
-- The biscuit signature is verified with the provided 'PublicKey' before
-- completely decoding blocks
-- The revocation ids are /not/ verified before completely decoding blocks.
-- If you need to check revocation ids before decoding blocks, use 'parseWith'
-- (or 'parseB64With' instead).
parse :: PublicKey -> ByteString -> Either ParseError (Biscuit OpenOrSealed Verified)
parse pk = runIdentity . parseBiscuitWith ParserConfig
  { encoding = RawBytes
  , isRevoked = const $ pure False
  , getPublicKey = pure pk
  }

-- | Parse a biscuit from a URL-compatible base 64 encoded bytestring
parseB64 :: PublicKey -> ByteString -> Either ParseError (Biscuit OpenOrSealed Verified)
parseB64 pk = runIdentity . parseBiscuitWith ParserConfig
  { encoding = UrlBase64
  , isRevoked = const $ pure False
  , getPublicKey = pure pk
  }

-- | Parse a biscuit, with explicitly supplied parsing options:
--
--   - encoding ('RawBytes' or 'UrlBase64')
--   - revocation check
--   - public key (based on the token's @rootKeyId@ field)
--
-- If you don't need dynamic public key selection or revocation checks, you can use
-- 'parse' or 'parseB64' instead.
--
-- The biscuit signature is verified with the selected 'PublicKey' before
-- completely decoding blocks
parseWith :: Applicative m
          => ParserConfig m
          -> ByteString
          -> m (Either ParseError (Biscuit OpenOrSealed Verified))
parseWith = parseBiscuitWith

-- | Helper for building a revocation check from a static list, suitable for use with
-- 'parseWith' and 'ParserConfig'.
fromRevocationList :: (Applicative m, Foldable t)
                   => t ByteString
                   -> Set ByteString
                   -> m Bool
fromRevocationList revokedIds tokenIds =
  pure . not . null $ Set.intersection (Set.fromList $ toList revokedIds) tokenIds

-- | Serialize a biscuit to a binary format. If you intend to send
-- the biscuit over a text channel, consider using `serializeB64` instead
serialize :: BiscuitProof p => Biscuit p Verified -> ByteString
serialize = serializeBiscuit

-- | Serialize a biscuit to URL-compatible base 64, as recommended by the spec
serializeB64 :: BiscuitProof p => Biscuit p Verified -> ByteString
serializeB64 = B64.encodeBase64' . serialize

-- | Generate a base64-encoded third-party block request. It can be used in
-- conjunction with 'mkThirdPartyBlockB64' to generate a base64-encoded
-- third-party block, which can be then appended to a token with
-- 'applyThirdPartyBlockB64'.
mkThirdPartyBlockReqB64 :: Biscuit Open c -> ByteString
mkThirdPartyBlockReqB64 = B64.encodeBase64' . mkThirdPartyBlockReq

-- | Given a base64-encoded third-party block request, generate a base64-encoded
-- third-party block, which can be then appended to a token with
-- 'applyThirdPartyBlockB64'.
mkThirdPartyBlockB64 :: SecretKey -> ByteString -> Block -> Either String ByteString
mkThirdPartyBlockB64 sk reqB64 b = do
  req <- first unpack $ B64.decodeBase64 reqB64
  contents <- mkThirdPartyBlock sk req b
  pure $ B64.encodeBase64' contents

-- | Given a base64-encoded third-party block, append it to a token.
applyThirdPartyBlockB64 :: Biscuit Open check -> ByteString -> Either String (IO (Biscuit Open check))
applyThirdPartyBlockB64 b contentsB64 = do
  contents <- first unpack $ B64.decodeBase64 contentsB64
  applyThirdPartyBlock b contents

-- $biscuitBlocks
--
-- The core of a biscuit is its authority block. This block declares facts and rules and
-- is signed by its creator with a secret key. In addition to this trusted, authority
-- block, a biscuit may carry extra blocks that can only restrict what it can do. By
-- default, biscuits can be restricted, but it's possible to seal a biscuit and prevent
-- further modifications.
--
-- Blocks are defined with a logic language (datalog) that can be used directly from haskell
-- with the `QuasiQuotes` extension.

-- $attenuatingBiscuits
--
-- By default, biscuits can be /attenuated/. It means that any party that holds a biscuit can
-- craft a new biscuit with fewer rights. A common example is taking a long-lived biscuit and
-- adding a short TTL right before sending it over the wire.

-- $thirdPartyBlocks
--
-- Regular blocks can be added by anyone and as such can only /attenuate/ a token: the facts
-- they carry are not visible outside themselves, only their checks are evaluated.
--
-- Third-party blocks lift this limitation by carrying an extra signature, crafted with a
-- dedicated key pair. This way, the token authorizer (as well as blocks themselves) can
-- opt-in to trust facts coming from third-party blocks signed with specific key pairs.
--
-- For instance, adding `check if group("admin") trusting {publicKey};` to a token will
-- make it usable only if it carries a third party-block signed by the corresponding key pair,
-- and carrying a `group("admin")` fact.
--
-- Since it is not desirable to share the token with the external entity providing the third-party
-- block, a request mechanism is available:
--
-- - the token holder generates a /third-party block request/ from the token (it contains technical
--   information needed to generate a third-party block) with 'mkThirdPartyBlockReq';
-- - the token holder forwards this request to the external entity;
-- - the external entity uses this request, a 'Block' value, and a 'SecretKey' to generate a third-party
--   block, with 'mkThirdPartyBlock';
-- - the external entity sends this block back to the token holder;
-- - the token holder can now add the block to the token with 'applyThirdPartyBlock'.
--
-- In some cases, the party holding the token is also the one who's adding the third-party block. It
-- is then possible to directly use 'addSignedBlock' to append a third-party block to the token without
-- having to go through generating a third-party block request.

-- $sealedBiscuits
--
-- An 'Open' biscuit can be turned into a 'Sealed' one, meaning it won't be possible
-- to attenuate it further.
--
-- 'mkBiscuit' creates 'Open' biscuits, while 'parse' returns an 'OpenOrSealed' biscuit (since
-- when you're verifying a biscuit, you're not caring about whether it can be extended further
-- or not). 'authorizeBiscuit' does not care whether a biscuit is 'Open' or 'Sealed' and can be
-- used with both. 'addBlock' and 'seal' only work with 'Open' biscuits.

-- $verifying
--
-- Verifying a biscuit requires providing a list of policies (/allow/ or /deny/), which will
-- decide if the biscuit is accepted. Policies are tried in order, and the first one to match
-- decides whether the biscuit is accepted.
--
-- In addition to policies, an authorizer typically provides facts (such as the current time) so
-- that checks and policies can be verified.
--
-- The authorizer checks and policies only see the content of the authority (first) block. Extra
-- blocks can only carry restrictions and cannot interfere with the authority facts.


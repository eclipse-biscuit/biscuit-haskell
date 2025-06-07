{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE TypeApplications           #-}
{-# OPTIONS_GHC -fno-warn-unused-top-binds #-}
{-|
  Module      : Auth.Biscuit.Crypto
  Copyright   : © Clément Delafargue, 2021
  License     : BSD-3-Clause
  Maintainer  : clement@delafargue.name
  Cryptographic helpers for biscuit signatures
-}
module Auth.Biscuit.Crypto
  ( SignedBlock
  , Blocks
  , signAuthority
  , signAttenuationBlock
  , signExternalBlock
  , sign3rdPartyBlockV1
  , verifyBlocks
  , verifySecretProof
  , verifySignatureProof
  , getSignatureProof
  , verifyExternalSigV1
  , PublicKey
  , pkBytes
  , readEd25519PublicKey
  , SecretKey
  , skBytes
  , readEd25519SecretKey
  , Signature
  , sigBytes
  , signature
  , generateSecretKey
  , toPublic
  , sign
  ) where

import           Control.Arrow              ((&&&))
import           Crypto.Error               (maybeCryptoError)
import qualified Crypto.PubKey.Ed25519      as Ed25519
import           Data.ByteArray             (convert)
import           Data.ByteString            (ByteString)
import           Data.Function              (on)
import           Data.Int                   (Int32)
import           Data.List.NonEmpty         (NonEmpty (..))
import           Data.Maybe                 ( fromJust, fromMaybe,
                                             isJust)
import           Instances.TH.Lift          ()
import           Language.Haskell.TH.Syntax

import qualified Auth.Biscuit.Proto         as PB
import qualified Data.Serialize             as PB

newtype PublicKey = PublicKey Ed25519.PublicKey
  deriving newtype (Eq, Show)

instance Ord PublicKey where
  compare = compare `on` serializePublicKey

instance Lift PublicKey where
  lift pk = [| fromJust $ readEd25519PublicKey $(lift $ pkBytes pk) |]
#if MIN_VERSION_template_haskell(2,17,0)
  liftTyped = liftCode . unsafeTExpCoerce . lift
#else
  liftTyped = unsafeTExpCoerce . lift
#endif

newtype SecretKey = SecretKey Ed25519.SecretKey
  deriving newtype (Eq, Show)
newtype Signature = Signature ByteString
  deriving newtype (Eq, Show)

signature :: ByteString -> Signature
signature = Signature

sigBytes :: Signature -> ByteString
sigBytes (Signature b) = b

readEd25519PublicKey :: ByteString -> Maybe PublicKey
readEd25519PublicKey bs = PublicKey <$> maybeCryptoError (Ed25519.publicKey bs)

readEd25519SecretKey :: ByteString -> Maybe SecretKey
readEd25519SecretKey bs = SecretKey <$> maybeCryptoError (Ed25519.secretKey bs)

readEd25519Signature :: Signature -> Maybe Ed25519.Signature
readEd25519Signature (Signature bs) = maybeCryptoError (Ed25519.signature bs)

-- | Generate a public key from a secret key
toPublic :: SecretKey -> PublicKey
toPublic (SecretKey sk) = PublicKey $ Ed25519.toPublic sk

generateSecretKey :: IO SecretKey
generateSecretKey = SecretKey <$> Ed25519.generateSecretKey

sign :: SecretKey -> PublicKey -> ByteString -> Signature
sign (SecretKey sk) (PublicKey pk) payload =
  Signature . convert $ Ed25519.sign sk pk payload

verify :: PublicKey -> ByteString -> Signature -> Bool
verify (PublicKey pk) payload sig =
  case readEd25519Signature sig of
    Just sig' -> Ed25519.verify pk payload sig'
    Nothing   -> False

pkBytes :: PublicKey -> ByteString
pkBytes (PublicKey pk) = convert pk

skBytes :: SecretKey -> ByteString
skBytes (SecretKey sk) = convert sk

type SignedBlock =
  ( ByteString -- payload
  , Signature -- signature
  , PublicKey -- nextKey
  , Maybe (Signature, PublicKey) -- externalKey
  , Maybe Int -- version
  )
type Blocks = NonEmpty SignedBlock

type AnySignedBlock a =
  ( ByteString -- payload
  , a
  , PublicKey -- nextKey
  , Maybe (Signature, PublicKey) -- externalKey
  , Maybe Int -- version
  )
-- | Biscuit 2.0 allows multiple signature algorithms.
-- For now this lib only supports Ed25519, but the spec mandates flagging
-- each publicKey with an algorithm identifier when serializing it. The
-- serializing itself is handled by protobuf, but we still need to manually
-- serialize keys when we include them in something we want sign (block
-- signatures, and the final signature for sealed tokens).
serializePublicKey :: PublicKey -> ByteString
serializePublicKey pk =
  let keyBytes = pkBytes pk
      algId :: Int32
      algId = fromIntegral $ fromEnum PB.Ed25519
      -- The spec mandates that we serialize the algorithm id as a little-endian int32
      algBytes = PB.runPut $ PB.putInt32le algId
   in algBytes <> keyBytes

signBlockV0 :: SecretKey
            -> ByteString
            -> Maybe (Signature, PublicKey)
            -> IO (SignedBlock, SecretKey)
signBlockV0 sk payload eSig = do
  let pk = toPublic sk
  (nextPk, nextSk) <- (toPublic &&& id) <$> generateSecretKey
  let toSign = getSignaturePayloadV0 (payload, (), nextPk, eSig, Nothing)
      sig = sign sk pk toSign
  pure ((payload, sig, nextPk, eSig, Nothing), nextSk)

signExternalBlockV0 :: SecretKey
                    -> SecretKey
                    -> PublicKey
                    -> ByteString
                    -> IO (SignedBlock, SecretKey)
signExternalBlockV0 sk eSk pk payload =
  let eSig = sign3rdPartyBlockV0 eSk pk payload
   in signBlockV0 sk payload (Just eSig)

sign3rdPartyBlockV0 :: SecretKey
                    -> PublicKey
                    -> ByteString
                    -> (Signature, PublicKey)
sign3rdPartyBlockV0 eSk nextPk payload =
  let toSign = payload <> serializePublicKey nextPk
      ePk = toPublic eSk
      eSig = sign eSk ePk toSign
   in (eSig, ePk)

getSignatureProof :: SignedBlock -> SecretKey -> Signature
getSignatureProof (lastPayload, Signature lastSig, lastPk, _, _) nextSecret =
  let sk = nextSecret
      pk = toPublic nextSecret
      toSign = lastPayload <> serializePublicKey lastPk <> lastSig
   in sign sk pk toSign

getSignaturePayloadV0 :: AnySignedBlock a -> ByteString
getSignaturePayloadV0 (p, _, nextPk, ePk, _) =
  p <> foldMap (sigBytes . fst) ePk <> serializePublicKey nextPk

-- | The data signed by the external key is the payload for the current block + the public key from
-- the previous block: this prevents signature reuse (the external signature cannot be used on another
-- token)
getExternalSignaturePayloadV0 :: PublicKey -> SignedBlock -> Maybe (PublicKey, ByteString, Signature)
getExternalSignaturePayloadV0 pkN (payload, _, _, Just (eSig, ePk), _) = Just (ePk, payload <> serializePublicKey pkN, eSig)
getExternalSignaturePayloadV0 _ _ = Nothing

getAuthoritySignaturePayloadV1 :: ByteString -> PublicKey -> ByteString
getAuthoritySignaturePayloadV1 p nextPk =
  "\0BLOCK\0" <>
  "\0VERSION\0" <> PB.runPut (PB.putInt32le 1) <>
  "\0PAYLOAD\0" <> p <>
  serializePublicKeyV1 nextPk

getBlockSignaturePayloadV1 :: ByteString -> PublicKey -> Maybe (Signature, PublicKey) -> Signature -> ByteString
getBlockSignaturePayloadV1 p nextPk ePk prevSig =
  getAuthoritySignaturePayloadV1 p nextPk <>
    "\0PREVSIG\0" <> sigBytes prevSig <>
    foldMap serializeExternalSignatureV1 ePk

getExternalSignaturePayloadV1 :: ByteString -> Signature -> ByteString
getExternalSignaturePayloadV1 payload prevSig =
  "\0EXTERNAL\0" <>
  "\0VERSION\0" <> PB.runPut (PB.putInt32le 1) <>
  "\0PAYLOAD\0" <> payload <>
  "\0PREVSIG\0" <> sigBytes prevSig

serializePublicKeyV1 :: PublicKey -> ByteString
serializePublicKeyV1 pk =
  let keyBytes = pkBytes pk
      algId :: Int32
      algId = fromIntegral $ fromEnum PB.Ed25519
      -- The spec mandates that we serialize the algorithm id as a little-endian int32
      algBytes = PB.runPut $ PB.putInt32le algId
   in "\0ALGORITHM\0" <> algBytes <>
      "\0NEXTKEY\0" <> keyBytes

serializeExternalSignatureV1 :: (Signature, PublicKey) -> ByteString
serializeExternalSignatureV1 (sig, _) = "\0EXTERNALSIG\0" <> sigBytes sig

getSignature :: SignedBlock -> Signature
getSignature (_, sig, _, _, _) = sig

getPublicKey :: SignedBlock -> PublicKey
getPublicKey (_, _, pk, _, _) = pk

-- | When adding a pre-signed third-party block to a token, we make sure the third-party block is correctly
-- signed (pk-signature match, and the third-party block is pinned to the last biscuit block)
verifyExternalSigV0 :: PublicKey -> (ByteString, Signature, PublicKey) -> Bool
verifyExternalSigV0 previousPk (payload, eSig, ePk) =
  verify ePk (payload <> serializePublicKey previousPk) eSig

-- | When adding a pre-signed third-party block to a token, we make sure the third-party block is correctly
-- signed (pk-signature match, and the third-party block is pinned to the last biscuit block)
verifyExternalSigV1 :: Signature -> (ByteString, Signature, PublicKey) -> Bool
verifyExternalSigV1 prevSig (payload, eSig, ePk) =
  verify ePk (getExternalSignaturePayloadV1 payload prevSig) eSig

verifyAuthorityBlock :: SignedBlock -> PublicKey -> Bool
verifyAuthorityBlock b@(payload, sig, nextPk, _, version) rootPk =
  case fromMaybe 0 version of
    0 -> verify rootPk (getSignaturePayloadV0 b) sig
    1 -> verify rootPk (getAuthoritySignaturePayloadV1 payload nextPk) sig
    _ -> False

verifyAttenuationBlock :: SignedBlock -> SignedBlock -> Bool
verifyAttenuationBlock block previousBlock =
  let (payload, sig, nextPk, eSig', version) = block
      (_, prevSig, pk, _, _) = previousBlock
   in case (fromMaybe 0 version, eSig') of
        (0, Nothing) -> verify pk (getSignaturePayloadV0 block) sig
        (0, Just _)  -> False -- reject third-party blocks with v0 signatures
        (1, Nothing) -> verify pk (getBlockSignaturePayloadV1 payload nextPk eSig' prevSig) sig
        (1, Just (eSig, ePk)) ->
          let sv = verify pk (getBlockSignaturePayloadV1 payload nextPk eSig' prevSig) sig
              ev = verify ePk (getExternalSignaturePayloadV1 payload prevSig) eSig
           in sv && ev
        _          -> False

verifyBlocks :: Blocks
             -> PublicKey
             -> Bool
verifyBlocks (authority :| attenuationBlocks) rootPk =
  let attenuationBlocks' = zip attenuationBlocks (authority : attenuationBlocks)
   in verifyAuthorityBlock authority rootPk
  && all (uncurry verifyAttenuationBlock) attenuationBlocks'

verifySecretProof :: SecretKey
                  -> SignedBlock
                  -> Bool
verifySecretProof nextSecret (_, _, lastPk, _, _) =
  lastPk == toPublic nextSecret


verifySignatureProof :: Signature
                     -> SignedBlock
                     -> Bool
verifySignatureProof extraSig (lastPayload, Signature lastSig, lastPk, _, _) =
  let toSign = lastPayload <> serializePublicKey lastPk <> lastSig
   in verify lastPk toSign extraSig

signAuthorityBlockV1 :: SecretKey -> ByteString -> IO (SignedBlock, SecretKey)
signAuthorityBlockV1 sk payload = do
  let pk = toPublic sk
  (nextPk, nextSk) <- (toPublic &&& id) <$> generateSecretKey
  let toSign = getAuthoritySignaturePayloadV1 payload nextPk
      sig = sign sk pk toSign
  pure ((payload, sig, nextPk, Nothing, Just 1), nextSk)

signAttenuationBlockV1 :: SecretKey -> Signature -> ByteString -> Maybe (Signature, PublicKey) -> IO (SignedBlock, SecretKey)
signAttenuationBlockV1 sk prevSig payload ePk = do
  let pk = toPublic sk
  (nextPk, nextSk) <- (toPublic &&& id) <$> generateSecretKey
  let toSign = getBlockSignaturePayloadV1 payload nextPk ePk prevSig
      sig = sign sk pk toSign
  pure ((payload, sig, nextPk, ePk, Just 1), nextSk)

sign3rdPartyBlockV1 :: SecretKey
                    -> Signature
                    -> ByteString
                    -> (Signature, PublicKey)
sign3rdPartyBlockV1 eSk prevSig payload =
  let toSign = getExternalSignaturePayloadV1 payload prevSig
      ePk = toPublic eSk
      eSig = sign eSk ePk toSign
   in (eSig, ePk)

signAuthority :: SecretKey
              -> (ByteString, Int)
              -> IO (SignedBlock, SecretKey)
signAuthority secretKey (payload, blockVersion)
  | blockVersion >= 6 = signAuthorityBlockV1 secretKey payload
  | otherwise = signBlockV0 secretKey payload Nothing

signAttenuationBlock :: SecretKey
                     -> Signature
                     -> (ByteString, Int)
                     -> Maybe (Signature, PublicKey)
                     -> IO (SignedBlock, SecretKey)
signAttenuationBlock secretKey prevSig (payload, blockVersion) ePk
  | blockVersion >= 6 || isJust ePk = signAttenuationBlockV1 secretKey prevSig payload ePk
  | otherwise = signBlockV0 secretKey payload ePk

signExternalBlock :: SecretKey
                  -> Signature
                  -> (ByteString, Int)
                  -> SecretKey
                  -> IO (SignedBlock, SecretKey)
signExternalBlock secretKey prevSig (payload, blockVersion) eSk =
   let ePk = sign3rdPartyBlockV1 eSk prevSig payload
    in signAttenuationBlock secretKey prevSig (payload, blockVersion) (Just ePk)

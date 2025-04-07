{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE TypeApplications           #-}
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
  , signBlock
  , signExternalBlock
  , sign3rdPartyBlock
  , verifyBlocks
  , verifySecretProof
  , verifySignatureProof
  , getSignatureProof
  , verifyExternalSig
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
import qualified Data.List.NonEmpty         as NE
import           Data.Maybe                 (catMaybes, fromJust)
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

type SignedBlock = (ByteString, Signature, PublicKey, Maybe (Signature, PublicKey))
type Blocks = NonEmpty SignedBlock

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

signBlock :: SecretKey
          -> ByteString
          -> Maybe (Signature, PublicKey)
          -> IO (SignedBlock, SecretKey)
signBlock sk payload eSig = do
  let pk = toPublic sk
  (nextPk, nextSk) <- (toPublic &&& id) <$> generateSecretKey
  let toSign = getToSig (payload, (), nextPk, eSig)
      sig = sign sk pk toSign
  pure ((payload, sig, nextPk, eSig), nextSk)

signExternalBlock :: SecretKey
                  -> SecretKey
                  -> PublicKey
                  -> ByteString
                  -> IO (SignedBlock, SecretKey)
signExternalBlock sk eSk pk payload =
  let eSig = sign3rdPartyBlock eSk pk payload
   in signBlock sk payload (Just eSig)

sign3rdPartyBlock :: SecretKey
                  -> PublicKey
                  -> ByteString
                  -> (Signature, PublicKey)
sign3rdPartyBlock eSk nextPk payload =
  let toSign = payload <> serializePublicKey nextPk
      ePk = toPublic eSk
      eSig = sign eSk ePk toSign
   in (eSig, ePk)

getSignatureProof :: SignedBlock -> SecretKey -> Signature
getSignatureProof (lastPayload, Signature lastSig, lastPk, _todo) nextSecret =
  let sk = nextSecret
      pk = toPublic nextSecret
      toSign = lastPayload <> serializePublicKey lastPk <> lastSig
   in sign sk pk toSign

getToSig :: (ByteString, a, PublicKey, Maybe (Signature, PublicKey)) -> ByteString
getToSig (p, _, nextPk, ePk) =
  p <> foldMap (sigBytes . fst) ePk <> serializePublicKey nextPk

getSignature :: SignedBlock -> Signature
getSignature (_, sig, _, _) = sig

getPublicKey :: SignedBlock -> PublicKey
getPublicKey (_, _, pk, _) = pk

-- | The data signed by the external key is the payload for the current block + the public key from
-- the previous block: this prevents signature reuse (the external signature cannot be used on another
-- token)
getExternalSigPayload :: PublicKey -> SignedBlock -> Maybe (PublicKey, ByteString, Signature)
getExternalSigPayload pkN (payload, _, _, Just (eSig, ePk)) = Just (ePk, payload <> serializePublicKey pkN, eSig)
getExternalSigPayload _ _ = Nothing

-- | When adding a pre-signed third-party block to a token, we make sure the third-party block is correctly
-- signed (pk-signature match, and the third-party block is pinned to the last biscuit block)
verifyExternalSig :: PublicKey -> (ByteString, Signature, PublicKey) -> Bool
verifyExternalSig previousPk (payload, eSig, ePk) =
  verify ePk (payload <> serializePublicKey previousPk) eSig

verifyBlocks :: Blocks
             -> PublicKey
             -> Bool
verifyBlocks blocks rootPk =
  let attachKey pk (payload, sig) = (pk, payload, sig)
      uncurry3 f (a, b, c) = f a b c
      sigs = getSignature <$> blocks
      toSigs = getToSig <$> blocks
      -- key for block 0 is the root key
      -- key for block n is the key from block (n - 1)
      keys = pure rootPk <> (getPublicKey <$> blocks)
      keysPayloadsSigs = NE.zipWith attachKey keys (NE.zip toSigs sigs)

      -- external_signature(block_n) = sign(external_key_n, payload_n <> public_key_n-1)
      -- so we need to pair each block with the public key carried by the previous block
      -- (the authority block can't have an external signature)
      previousKeys = getPublicKey <$> NE.init blocks
      blocksAfterAuthority = NE.tail blocks
      eKeysPayloadsESigs = catMaybes $ zipWith getExternalSigPayload previousKeys blocksAfterAuthority
   in  all (uncurry3 verify) keysPayloadsSigs
    && all (uncurry3 verify) eKeysPayloadsESigs

verifySecretProof :: SecretKey
                  -> SignedBlock
                  -> Bool
verifySecretProof nextSecret (_, _, lastPk, _) =
  lastPk == toPublic nextSecret

verifySignatureProof :: Signature
                     -> SignedBlock
                     -> Bool
verifySignatureProof extraSig (lastPayload, Signature lastSig, lastPk, _) =
  let toSign = lastPayload <> serializePublicKey lastPk <> lastSig
   in verify lastPk toSign extraSig

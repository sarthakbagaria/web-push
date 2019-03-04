{-# LANGUAGE RecordWildCards, OverloadedStrings #-}

module Web.WebPush.Internal where

import Data.Maybe
import GHC.Int                                                 (Int64)
import Data.ByteString                                         (ByteString)
import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Lazy            as LB
import Data.Monoid                                             ((<>))
import Data.Text                                               (Text)

import qualified Crypto.PubKey.ECC.Types         as ECC
import qualified Crypto.PubKey.ECC.ECDSA         as ECDSA
import Crypto.Hash.Algorithms                                  (SHA256(..))
import qualified Crypto.PubKey.ECC.DH            as ECDH
import qualified Crypto.MAC.HMAC                 as HMAC
import Crypto.Cipher.AES                                       (AES128)
import qualified Crypto.Cipher.Types             as Cipher
import Crypto.Error                                            (CryptoFailable(CryptoPassed,CryptoFailed), CryptoError)

import Crypto.JWT                                              (signClaims, emptyClaimsSet, claimSub, claimAud, claimExp)
import qualified Crypto.JWT                      as JWT
import qualified Crypto.JOSE.JWK                 as JWK
import Crypto.JOSE.JWS                                         (newJWSHeader, Alg(ES256))
import qualified Crypto.JOSE.Compact             as JOSE.Compact
import qualified Crypto.JOSE.Error               as JOSE.Error
import qualified Crypto.JOSE.Types               as JOSE

import Data.Aeson                                              (ToJSON, toJSON, (.=), decode, eitherDecode, encode)
import qualified Data.Aeson                      as A
import qualified Data.ByteString.Base64.URL      as B64.URL

import Data.Word                                               (Word8, Word16, Word64)
import qualified Data.Binary                     as Binary
import qualified Data.Bits                       as Bits
import qualified Data.ByteArray                  as ByteArray
import qualified Data.ByteString.Lazy.Char8      as C

import Control.Monad.IO.Class                                  (MonadIO, liftIO)
import Control.Monad.Except                                    (runExceptT)

import Control.Lens.Operators                                  ((&), (?~))
import Text.Printf


type VAPIDKeys = ECDSA.KeyPair

data VAPIDClaims = VAPIDClaims { vapidAud :: JWT.Audience
                               , vapidSub :: JWT.StringOrURI
                               , vapidExp :: JWT.NumericDate
                               }
-- JSON Web Token for VAPID
webPushJWT :: MonadIO m => VAPIDKeys -> VAPIDClaims -> m (Either JOSE.Error.Error LB.ByteString)
webPushJWT vapidKeys vapidClaims = do
    let ECC.Point publicKeyX publicKeyY = ECDSA.public_q $ ECDSA.toPublicKey vapidKeys
        privateKeyNumber = ECDSA.private_d $ ECDSA.toPrivateKey vapidKeys
        ecX = JOSE.SizedBase64Integer 32 $ publicKeyX
        ecY = JOSE.SizedBase64Integer 32 $ publicKeyY
        ecD = JOSE.SizedBase64Integer 32 $ privateKeyNumber
        materialJsonTempl = "{\"kty\": \"EC\", \"crv\": \"P-256\", \"x\": \"%s\", \"y\": \"%s\", \"d\": \"%s\"}"
        materialJson = (printf materialJsonTempl (C.unpack $ encode ecX) (C.unpack $ encode ecY) (C.unpack $ encode ecD)) :: String
    liftIO $ print materialJson
    liftIO $ print (eitherDecode (C.pack materialJson) :: Either String JWK.KeyMaterial)
    let keyMaterial = fromJust $ decode (C.pack materialJson)
    liftIO $ runExceptT $ do
        jwtData <- signClaims (JWK.fromKeyMaterial keyMaterial)
                              (newJWSHeader ((), ES256))
                              (emptyClaimsSet
                                    & claimSub ?~ vapidSub vapidClaims
                                    & claimAud ?~ vapidAud vapidClaims
                                    & claimExp ?~ vapidExp vapidClaims
                              )

        return $ JOSE.Compact.encodeCompact jwtData

            ----------------------------
            {-
            -- Manual implementation without using the JWT libraries.
            -- This works as well.
            -- Kept here mainly as process explanation.

            -- JWT base 64 encoding is without padding
            let messageForJWTSignature = let encodedJWTPayload = b64UrlNoPadding $ LB.toStrict $ A.encode $ A.object $
                                                 [ "aud" .= (TE.decodeUtf8With TE.lenientDecode $
                                                                (if secure initReq then "https://" else "http://") ++ (host initReq)
                                                            )
                                                 -- jwt expiration time
                                                 , "exp" .= (formatTime defaultTimeLocale "%s" $ addUTCTime 3000 time)
                                                 , "sub" .= ("mailto: " ++ (senderEmail pushNotification))
                                                 ]

                                             encodedJWTHeader = b64UrlNoPadding $ LB.toStrict $ A.encode $ A.object $
                                                 [ "typ" .= ("JWT" :: Text), "alg" .= ("ES256" :: Text) ]

                                         in encodedJWTHeader <> "." <> encodedJWTPayload

            -- JWT only accepts SHA256 hash with ECDSA for ES256 signed token
            encodedJWTSignature <- do
                -- ECDSA signing vulnerable to timing attacks
                ECDSA.Signature signR signS <- liftIO $ ECDSA.sign (ECDSA.toPrivateKey vapidKeys)
                                                                   SHA256
                                                                   messageForJWTSignature

                -- 32 bytes of R followed by 32 bytes of S
                return $ b64UrlNoPadding $ LB.toStrict $
                             (Binary.encode $ int32Bytes signR) <>
                             (Binary.encode $ int32Bytes signS)

            return $ Right $ messageForJWTSignature <> "." <> encodedJWTSignature
            -}
            ----------------------------



data PushNotificationMessage = PushNotificationMessage { title :: Text
                                                       , body :: Text
                                                       , icon :: Text
                                                       , url :: Text
                                                       , tag :: Text
                                                       }

instance ToJSON PushNotificationMessage where
   toJSON PushNotificationMessage {..} = A.object
       [ "title" .= title
       , "body" .= body
       , "icon" .= icon
       , "url" .= url
       , "tag" .= tag
       ]

-- All inputs are in raw bytes with no encoding
-- except for the plaintext for which raw bytes are the Base 64 encoded bytes
data WebPushEncryptionInput = EncryptionInput { applicationServerPrivateKey :: ECDH.PrivateNumber
                                              , userAgentPublicKeyBytes :: ByteString
                                              , authenticationSecret :: ByteString
                                              , salt :: ByteString
                                              , plainText :: LB.ByteString
                                              , paddingLength :: Int64
                                              }

-- Intermediate encryption output used in tests
-- All in raw bytes
data WebPushEncryptionOutput = EncryptionOutput { sharedECDHSecretBytes :: ByteString
                                                , inputKeyingMaterialBytes :: ByteString
                                                , contentEncryptionKeyContext :: ByteString
                                                , contentEncryptionKey :: ByteString
                                                , nonceContext :: ByteString
                                                , nonce :: ByteString
                                                , paddedPlainText :: ByteString
                                                , encryptedMessage :: ByteString
                                                }

-- payload encryption
-- https://tools.ietf.org/html/draft-ietf-webpush-encryption-04
webPushEncrypt :: WebPushEncryptionInput -> Either CryptoError WebPushEncryptionOutput
webPushEncrypt EncryptionInput {..} =
    let applicationServerPublicKeyBytes = LB.toStrict $ ecPublicKeyToBytes $
                                              ECDH.calculatePublic (ECC.getCurveByName ECC.SEC_p256r1) $
                                                  applicationServerPrivateKey
        userAgentPublicKey = ecBytesToPublicKey userAgentPublicKeyBytes
        sharedECDHSecret = ECDH.getShared (ECC.getCurveByName ECC.SEC_p256r1) applicationServerPrivateKey userAgentPublicKey


        -- HMAC key derivation (HKDF, here expanded into HMAC steps as specified in web push encryption spec)
        pseudoRandomKeyCombine = HMAC.hmac authenticationSecret sharedECDHSecret :: HMAC.HMAC SHA256
        authInfo = "Content-Encoding: auth" <> "\x00" :: ByteString
        inputKeyingMaterial = HMAC.hmac pseudoRandomKeyCombine (authInfo <> "\x01") :: HMAC.HMAC SHA256

        context = "P-256" <> "\x00" <>
                 "\x00" <> "\x41" <> userAgentPublicKeyBytes <>
                 "\x00" <> "\x41" <> applicationServerPublicKeyBytes

        pseudoRandomKeyEncryption = HMAC.hmac salt inputKeyingMaterial :: HMAC.HMAC SHA256
        contentEncryptionKeyContext = "Content-Encoding: aesgcm" <> "\x00" <> context
        contentEncryptionKey = BS.pack $ take 16 $ ByteArray.unpack (HMAC.hmac pseudoRandomKeyEncryption (contentEncryptionKeyContext <> "\x01") :: HMAC.HMAC SHA256)

        nonceContext = "Content-Encoding: nonce" <> "\x00" <> context
        nonce = BS.pack $ take 12 $ ByteArray.unpack (HMAC.hmac pseudoRandomKeyEncryption (nonceContext <> "\x01") :: HMAC.HMAC SHA256)


        -- HMAC a doesn't have Show instance needed for test suite
        -- so we extract the bytes and store that in WebPushEncryptionOutput
        inputKeyingMaterialBytes = ByteArray.convert inputKeyingMaterial
        sharedECDHSecretBytes = ByteArray.convert sharedECDHSecret

        -- padding length encoded in 2 bytes, followed by
        -- padding length times '0' byte, followed by
        -- message
        paddedPlainText = LB.toStrict $
                              (Binary.encode (fromIntegral paddingLength :: Word16)) <>
                              (LB.replicate paddingLength (0 :: Word8)) <>
                              plainText

        -- aes_gcm is aead (authenticated encryption with associated data)
        -- use cek as the encryption key and nonce as the initialization vector
        eitherAesCipher = Cipher.cipherInit contentEncryptionKey :: CryptoFailable AES128
    in case eitherAesCipher of
            CryptoFailed err -> Left err
            CryptoPassed aesCipher ->
                let eitherAeadGcmCipher = Cipher.aeadInit Cipher.AEAD_GCM aesCipher nonce
                in case eitherAeadGcmCipher of
                    CryptoFailed err -> Left err
                    CryptoPassed aeadGcmCipher ->
                        -- tag length 16 bytes (maximum), anything less than 16 bytes may not be secure enough
                        -- spec says final encrypted size is 16 bits longer than the padded text
                        -- NOTE: the final encrypted message must be sent as raw binary data
                        let encryptedMessage = let (authTagBytes, cipherText) = Cipher.aeadSimpleEncrypt aeadGcmCipher
                                                                                                         BS.empty
                                                                                                         paddedPlainText
                                                                                                         16
                                                   authTag = ByteArray.convert $ Cipher.unAuthTag authTagBytes
                                               in cipherText <> authTag

                        in Right $ EncryptionOutput {..}



-- Conversions among integers and bytes
-- The bytes are in network/big endian order.

 {-
    -- DON'T use DER encoding to extract integer bytes
    -- if a 32 byte number can be written in less bytes with leading zeros,
    -- DER encdoing will be shorter than 32 bytes
    -- and decoding to 4 word64 will fail because of short input
 -}
ecPublicKeyToBytes :: ECC.Point -> LB.ByteString
-- Point0 is the point at infinity, not sure what's the encoding for that
-- CHECK THIS
ecPublicKeyToBytes ECC.PointO = "\x04" <>
                                (Binary.encode $ int32Bytes 0) <>
                                (Binary.encode $ int32Bytes 0)
ecPublicKeyToBytes (ECC.Point x y) = "\x04" <>
                                     (Binary.encode $ int32Bytes x) <>
                                     (Binary.encode $ int32Bytes y)

ecBytesToPublicKey :: ByteString -> ECC.Point
-- the first byte is guarenteed to be \x04 which tells that the key is in uncompressed form
ecBytesToPublicKey bytes = let bothCoordBytes = BS.drop 1 bytes
                               (xBytes, yBytes) = Binary.decode $ LB.fromStrict bothCoordBytes :: (Bytes32, Bytes32)
                               xInteger = bytes32Int xBytes
                               yInteger = bytes32Int yBytes
                           in ECC.Point xInteger yInteger

-- Coordinates on Elliptic Curves are 32 bit integers
type Bytes32 = (Word64, Word64, Word64, Word64)

 -- points on elliptic curve for 256 bit algorithms are 32 bytes (256 bits) unsigned integers each
 -- fixed width big endian format
 -- integer to 4 Word64 (8 bytes each)
int32Bytes :: Integer -> Bytes32
int32Bytes number =  let shift1 = Bits.shiftR number 64
                         shift2 = Bits.shiftR shift1 64
                         shift3 = Bits.shiftR shift2 64
                     in ( fromIntegral shift3
                        , fromIntegral shift2
                        , fromIntegral shift1
                        , fromIntegral number
                       )

bytes32Int :: Bytes32 -> Integer
bytes32Int (d,c,b,a) = (Bits.shiftL (fromIntegral d) (64*3)) +
                       (Bits.shiftL (fromIntegral c) (64*2)) +
                       (Bits.shiftL (fromIntegral b) (64  )) +
                                    (fromIntegral a)

-- at most places we do not need the padding in base64 url encoding
b64UrlNoPadding :: ByteString -> ByteString
b64UrlNoPadding =  fst . BS.breakSubstring "=" . B64.URL.encode

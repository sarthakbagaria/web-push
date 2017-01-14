{-# LANGUAGE RecordWildCards, OverloadedStrings #-}

module Web.WebPush
    (
    -- * Functions
      generateVAPIDKeys
    , readVAPIDKeys
    , vapidPublicKeyBytes
    , sendPushNotification
    -- * Types
    , VAPIDKeys
    , VAPIDKeysMinDetails(..)
    , PushNotificationDetails(..)
    , PushNotificationMessage(..)
    , PushNotificationError(..)
    ) where

import Data.ByteString                                         (ByteString)
import GHC.Int                                                 (Int64)
import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Char8           as C8
import qualified Data.ByteString.Lazy            as LB
import Data.Monoid                                             ((<>))
import  Data.Text                                              (Text)
import qualified Data.Text                       as T
import qualified Data.Text.Encoding              as TE
import qualified Data.Text.Encoding.Error        as TE
import qualified Data.List                       as L
import qualified Data.HashMap.Strict             as HM
import Data.Time.Clock                                         (getCurrentTime)

import Network.HTTP.Client                                     (Manager, httpLbs, parseRequest, HttpException(StatusCodeException), RequestBody(..), requestBody, requestHeaders, method, host, secure)
import Network.HTTP.Types                                      (hContentType, hAuthorization, hContentEncoding)
import Network.HTTP.Types.Status                               (Status(statusCode))

import Data.Time                                               (addUTCTime)

import qualified Crypto.PubKey.ECC.Types         as ECC
import qualified Crypto.PubKey.ECC.Generate      as ECC
import qualified Crypto.PubKey.ECC.ECDSA         as ECDSA
import Crypto.Hash.Algorithms                                  (SHA256(..))
import qualified Crypto.PubKey.ECC.DH            as ECDH
import qualified Crypto.MAC.HMAC                 as HMAC
import Crypto.Random                                           (MonadRandom(getRandomBytes))
import Crypto.Cipher.AES                                       (AES128)
import qualified Crypto.Cipher.Types             as Cipher
import Crypto.Error                                            (CryptoFailable(CryptoPassed,CryptoFailed), CryptoError)

import Crypto.JWT                                              (createJWSJWT, ClaimsSet(..), NumericDate(..))
import qualified Crypto.JWT                      as JWT
import qualified Crypto.JOSE.JWK                 as JWK
import Crypto.JOSE.JWS                                         (JWSHeader(..), Alg(ES256))
import qualified Crypto.JOSE.Types               as JOSE
import qualified Crypto.JOSE.Compact             as JOSE.Compact
import qualified Crypto.JOSE.Error               as JOSE.Error

import Data.Aeson                                              (ToJSON, toJSON, (.=))
import qualified Data.Aeson                      as A
import qualified Data.ByteString.Base64.URL      as B64.URL
import qualified Data.ByteString.Base64.URL.Lazy as B64.URL.Lazy

import Data.Word                                               (Word8, Word16, Word64)
import qualified Data.Binary                     as Binary
import qualified Data.Bits                       as Bits
import qualified Data.ByteArray                  as ByteArray

import System.Random                                           (randomRIO)

import Control.Exception.Base                                  (SomeException(..), fromException)
import Control.Monad.Catch.Pure                                (runCatchT)
import Control.Monad.IO.Class                                  (MonadIO, liftIO)



type VAPIDKeys = ECDSA.KeyPair


-- |Generate the 3 integers minimally representing a unique pair of public and private keys.
--
-- Store them in configuration and use them across multiple push notification requests.
generateVAPIDKeys :: MonadRandom m => m VAPIDKeysMinDetails
generateVAPIDKeys = do
    -- NOTE: SEC_p256r1 is the NIST P-256
    (pubKey, privKey) <- ECC.generate $ ECC.getCurveByName ECC.SEC_p256r1
    let ECC.Point pubX pubY = ECDSA.public_q pubKey
    return $ VAPIDKeysMinDetails { privateNumber = ECDSA.private_d privKey
                                 , publicCoordX = pubX
                                 , publicCoordY = pubY
                                 }


-- |Read VAPID key pair from the 3 integers minimally representing a unique key pair.
readVAPIDKeys :: VAPIDKeysMinDetails -> VAPIDKeys
readVAPIDKeys VAPIDKeysMinDetails {..} =
    let vapidPublicKeyPoint = ECC.Point publicCoordX publicCoordY
    in ECDSA.KeyPair (ECC.getCurveByName ECC.SEC_p256r1) vapidPublicKeyPoint privateNumber


-- |Pass the VAPID public key bytes to front end when subscribing to push notifications.
--
-- Generate application server key using
-- applicationServerKey = new Uint8Array(vapidPublicKeyBytes) in Javascript
vapidPublicKeyBytes :: VAPIDKeys -> [Word8]
vapidPublicKeyBytes keys =
   let ECC.Point vapidPublicKeyX vapidPublicKeyY = ECDSA.public_q $ ECDSA.toPublicKey keys
   -- First byte 04 tells that the EC key is uncompressed
   in 4 : ( (extract32Bytes vapidPublicKeyX) ++ (extract32Bytes vapidPublicKeyY) )

   where
       -- an array of bytes
       -- 32 steps (32 bytes)
       -- in each step extract last 8 bits using fromIntegral
       extract32Bytes :: Integer -> [Word8]
       extract32Bytes number = snd $ L.foldl' (\(integer, bytes) _ -> (Bits.shiftR integer 8, (fromIntegral integer) : bytes))
                                              (number, ([] :: [Word8]))
                                              ([1..32] :: [Int])


-- |Send a Push Message.
--
-- The message sent is base64 URL encoded.
-- Decode the message in notification handler in front end.
sendPushNotification :: MonadIO m
                     => VAPIDKeys
                     -> Manager
                     -> PushNotificationDetails
                     -> m (Either PushNotificationError ())
sendPushNotification vapidKeys httpManager pushNotification = do
    eitherInitReq <- runCatchT $ parseRequest $ T.unpack $ endpoint pushNotification
    case eitherInitReq of
        -- delete endpoint if it cannot be parsed
        Left exc@(SomeException _) -> return $ Left $ EndpointParseFailed exc
        Right initReq -> do
            time <- liftIO $ getCurrentTime

            -- JWT encryption for VAPID
            eitherJwt <- do
                let ECC.Point publicKeyX publicKeyY = ECDSA.public_q $ ECDSA.toPublicKey vapidKeys
                    privateKeyNumber = ECDSA.private_d $ ECDSA.toPrivateKey vapidKeys

                eitherJwtData <- liftIO $ createJWSJWT (JWK.fromKeyMaterial $ JWK.ECKeyMaterial $
                                                           JWK.ECKeyParameters { JWK.ecKty = JWK.EC
                                                                               , JWK.ecCrv = JWK.P_256
                                                                               , JWK.ecX = JOSE.SizedBase64Integer 32 $ publicKeyX
                                                                               , JWK.ecY = JOSE.SizedBase64Integer 32 $ publicKeyY
                                                                               , JWK.ecD = Just $ JOSE.SizedBase64Integer 32 $ privateKeyNumber
                                                                               }
                                                      )

                                                      ( JWSHeader { headerAlg = Just ES256
                                                                  , headerJku = Nothing
                                                                  , headerJwk = Nothing
                                                                  , headerKid = Nothing
                                                                  , headerX5u = Nothing
                                                                  , headerX5c = Nothing
                                                                  , headerX5t = Nothing
                                                                  , headerX5tS256 = Nothing
                                                                  , headerTyp = Just "JWT"
                                                                  , headerCty = Nothing
                                                                  , headerCrit = Nothing
                                                                  }
                                                      )

                                                      ( ClaimsSet { _claimIss = Nothing
                                                                  , _claimSub = Just $ JWT.fromString $ T.append "mailto:" $ senderEmail pushNotification
                                                                  , _claimAud = Just $ JWT.Special $ JWT.fromString $ TE.decodeUtf8With TE.lenientDecode $
                                                                        BS.append (if secure initReq then "https://" else "http://") (host initReq)

                                                                  , _claimExp = Just $ NumericDate $ addUTCTime 3000 time
                                                                  , _claimNbf = Nothing
                                                                  , _claimIat = Nothing
                                                                  , _claimJti = Nothing
                                                                  , _unregisteredClaims = HM.empty
                                                                  }
                                                      )

                case eitherJwtData of
                    Left err -> return $ Left err
                    Right jwtData -> return $ LB.toStrict <$> (JOSE.Compact.encodeCompact $ jwtData)

                ----------------------------
                {-
                -- Manual implementation without using the JWT libraries
                -- This works as well,
                -- kept here mainly as process explanation

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


            case eitherJwt of
                Left err -> return $ Left $ JWTGenerationFailed err
                Right jwt -> do

                    -- payload encryption
                    -- https://tools.ietf.org/html/draft-ietf-webpush-encryption-04
                    -- cek = content encryption key
                    (cek, nonce, salt, ecdhServerPublicKeyBytes) <- do

                        -- first create a new pair of ECDH keys on P-256 curve (SEC_p256r1) and get the sharedSecret
                        ecdhServerPrivateKey <- liftIO $ ECDH.generatePrivate $ ECC.getCurveByName ECC.SEC_p256r1
                        salt <- liftIO $ getRandomBytes 16

                        let ecdhServerPublicKeyBytes = LB.toStrict $ ecPublicKeyToBytes $
                                                           ECDH.calculatePublic (ECC.getCurveByName ECC.SEC_p256r1) ecdhServerPrivateKey

                            ecdhSecretBytes = ECDH.getShared (ECC.getCurveByName ECC.SEC_p256r1) ecdhServerPrivateKey subscriptionPublicKey
                            authSecretBytes = B64.URL.decodeLenient $ TE.encodeUtf8 $ auth pushNotification

                            -- then use HMAC key derivation (HKDF, here expanded into HMAC steps as specified in web push encryption spec)
                            authInfo = "Content-Encoding: auth" <> "\x00" :: ByteString

                            prkCombine = HMAC.hmac authSecretBytes ecdhSecretBytes :: HMAC.HMAC SHA256
                            ikm = HMAC.hmac prkCombine (authInfo <> "\x01") :: HMAC.HMAC SHA256


                            context = "P-256" <> "\x00" <>
                                      "\x00" <> "\x41" <> subscriptionPublicKeyBytes <>
                                      "\x00" <> "\x41" <> ecdhServerPublicKeyBytes

                            cekInfo = "Content-Encoding: aesgcm" <> "\x00" <> context

                            prk = HMAC.hmac salt ikm :: HMAC.HMAC SHA256
                            cek = BS.pack $ take 16 $ ByteArray.unpack $ (HMAC.hmac prk (cekInfo <> "\x01") :: HMAC.HMAC SHA256)

                            nonceInfo = "Content-Encoding: nonce" <> "\x00" <> context
                            nonce = BS.pack $ take 12 $ ByteArray.unpack $ (HMAC.hmac prk (nonceInfo <> "\x01") :: HMAC.HMAC SHA256)

                        return (cek, nonce, salt, ecdhServerPublicKeyBytes)

                    -- padding is required can't skip, add a random length padding (0 - 20 bytes)
                    -- NOTE: 0 length padding is allowed, it just takes 2 bytes to encode the padding length

                    paddedMessage <- do
                        randLen <- liftIO $ randomRIO (0, 20)

                        let plainMessage64Encoded = B64.URL.Lazy.encode $ A.encode $ toJSON $ message pushNotification
                            paddedMessage = LB.toStrict $ pad randLen plainMessage64Encoded

                        return $ paddedMessage

                    -- aes_gcm is aead (authenticated encryption with associated data)
                    -- use cek as the encryption key and nonce as the initialization vector
                    let eitherAesCipher = Cipher.cipherInit cek :: CryptoFailable AES128
                    case eitherAesCipher of
                        CryptoFailed err -> return $ Left $ MessageEncryptionFailed err
                        CryptoPassed aesCipher -> do
                            let eitherAeadGcmCipher = Cipher.aeadInit Cipher.AEAD_GCM aesCipher nonce
                            case eitherAeadGcmCipher of
                                CryptoFailed err -> return $ Left $ MessageEncryptionFailed err
                                CryptoPassed aeadGcmCipher -> do

                                    -- tag length 16 bytes (maximum),  anything less than 16 bytes may not be secure enough
                                    -- spec says final encrypted size is 16 bits longer than the padded text
                                    -- NOTE: the final encrypted message must be sent as raw binary data
                                    let encryptedMessage = let (authTag, cipherText) = Cipher.aeadSimpleEncrypt aeadGcmCipher
                                                                                                                BS.empty
                                                                                                                paddedMessage
                                                                                                                16
                                                           in cipherText <> (BS.pack $ ByteArray.unpack $ Cipher.unAuthTag authTag)

                                        -- content-length is automtically added before making the http request
                                        postHeaders = let authorizationHeader = "WebPush " <> jwt
                                                          cryptoKeyHeader = BS.concat [ "dh=", b64UrlNoPadding ecdhServerPublicKeyBytes
                                                                                      , ";"
                                                                                      -- this base64 should be without padding
                                                                                      -- according to the spec
                                                                                      , "p256ecdsa=", b64UrlNoPadding vapidPublicKeyBytestring
                                                                                      ]

                                                      in [ ("TTL", C8.pack $ show (60*60*(expireInHours pushNotification)))
                                                         , (hContentType, "text/plain;charset=utf8")
                                                         , (hAuthorization, authorizationHeader)
                                                         , ("Crypto-Key", cryptoKeyHeader)
                                                         , (hContentEncoding, "aesgcm")
                                                         , ("Encryption", "salt=" <> (b64UrlNoPadding salt))
                                                         ]

                                        request = initReq { method = "POST"
                                                          , requestHeaders = postHeaders ++
                                                                                 -- avoid duplicates
                                                                                 (filter (\(x, _) -> L.notElem x $ map fst postHeaders)
                                                                                         (requestHeaders initReq)
                                                                                 )
                                                            -- the body is encrypted message in raw bytes
                                                            -- without URL encoding
                                                          , requestBody = RequestBodyBS encryptedMessage
                                                          }


                                    -- httpLbs from Network.HTTP.Client.Conduit takes manager from the Reader environment
                                    eitherResp <- runCatchT $ liftIO $ httpLbs request httpManager
                                    case eitherResp of
                                        Left err@(SomeException _) -> case fromException err of
                                            Just (StatusCodeException status _ _)
                                                -- when the endpoint is invalid, we need to remove it from database
                                                |(statusCode status == 404) -> return $ Left RecepientEndpointNotFound
                                            _ -> return $ Left $ PushRequestFailed err
                                        Right _ -> return $ Right ()

    where

        vapidPublicKeyBytestring = LB.toStrict $ ecPublicKeyToBytes $
                                       ECDSA.public_q $ ECDSA.toPublicKey vapidKeys

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

        -- extract the 65 bytes of ECDH uncompressed public key received from browser in subscription
        subscriptionPublicKeyBytes = B64.URL.decodeLenient $ TE.encodeUtf8 $ p256dh pushNotification

        -- the first byte is guarenteed to be \x04 which tells that the key is in uncompressed form
        subscriptionPublicKey = let bothCoordBytes = BS.drop 1 $ subscriptionPublicKeyBytes
                                    (xBytes, yBytes) = Binary.decode $ LB.fromStrict bothCoordBytes :: (Bytes32, Bytes32)
                                    xInteger = bytes32Int xBytes
                                    yInteger = bytes32Int yBytes
                                in ECC.Point xInteger yInteger


        -- fixed width big endian format
        -- First byte 04 tells that the EC key is uncompressed

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


        -- padding: scheme
        -- the first 2 bytes (16bits) represent length of padding
        -- followed by that many null bytes
        -- padding is added at the beginning of the message
        pad :: Int64 -> LB.ByteString -> LB.ByteString
        pad len message = (Binary.encode (fromIntegral len :: Word16)) <> (LB.replicate len (0 :: Word8)) <> message

        b64UrlNoPadding =  fst . BS.breakSubstring "=" . B64.URL.encode



-- |Web push subscription and message details.
--
-- Get subscription details from front end using
-- subscription.endpoint,
-- subscription.toJSON().keys.p256dh and
-- subscription.toJSON().keys.auth.
--
-- Save subscription details to send messages to the endpoint in future.
data PushNotificationDetails = PushNotificationDetails { endpoint :: Text
                                                       , p256dh :: Text
                                                       , auth :: Text
                                                       , senderEmail :: Text
                                                       , expireInHours :: Int64
                                                       , message :: PushNotificationMessage
                                                       }


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


-- |3 integers minimally representing a unique VAPID key pair.
data VAPIDKeysMinDetails = VAPIDKeysMinDetails { privateNumber :: Integer
                                               , publicCoordX :: Integer
                                               , publicCoordY :: Integer
                                               }


data PushNotificationError = EndpointParseFailed SomeException
                           | JWTGenerationFailed JOSE.Error.Error
                           | MessageEncryptionFailed CryptoError
                           | RecepientEndpointNotFound
                           | PushRequestFailed SomeException


type Bytes32 = (Word64, Word64, Word64, Word64)

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


import Web.WebPush.Internal

import Crypto.Random                                           (MonadRandom(getRandomBytes))
import qualified Crypto.PubKey.ECC.Types         as ECC
import qualified Crypto.PubKey.ECC.Generate      as ECC
import qualified Crypto.PubKey.ECC.ECDSA         as ECDSA
import qualified Crypto.PubKey.ECC.DH            as ECDH

import Crypto.JWT                                              (NumericDate(..))
import qualified Crypto.JWT                      as JWT

import qualified Data.Bits                       as Bits
import Data.Word                                               (Word8)

import GHC.Int                                                 (Int64)
import qualified Data.List                       as L
import Data.Text                                               (Text)
import qualified Data.Text                       as T
import qualified Data.Text.Encoding              as TE
import qualified Data.Text.Encoding.Error        as TE
import Data.String                                             (IsString(fromString))
import Data.Monoid                                             ((<>))
import qualified Data.ByteString.Lazy            as LB
import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Char8           as C8
import qualified Data.Aeson                      as A
import qualified Data.ByteString.Base64.URL      as B64.URL
import qualified Data.ByteString.Base64.URL.Lazy as B64.URL.Lazy


import Data.Time.Clock                                         (getCurrentTime)
import Data.Time                                               (addUTCTime)

import Network.HTTP.Client                                     (Manager, httpLbs, parseRequest, HttpException(HttpExceptionRequest), HttpExceptionContent(StatusCodeException), RequestBody(..), requestBody, requestHeaders, method, host, secure, responseStatus)
import Network.HTTP.Types                                      (hContentType, hAuthorization, hContentEncoding)
import Network.HTTP.Types.Status                               (Status(statusCode))

import qualified Crypto.JOSE.Error               as JOSE.Error
import Crypto.Error                                            (CryptoError)

import Control.Exception.Base                                  (SomeException(..), fromException)
import Control.Monad.Catch.Pure                                (runCatchT)
import Control.Monad.IO.Class                                  (MonadIO, liftIO)

import System.Random                                           (randomRIO)


-- |Generate the 3 integers minimally representing a unique pair of public and private keys.
--
-- Store them in configuration and use them across multiple push notification requests.
generateVAPIDKeys :: MonadRandom m => m VAPIDKeysMinDetails
generateVAPIDKeys = do
    -- SEC_p256r1 is the NIST P-256
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


-- |Pass the VAPID public key bytes to browser when subscribing to push notifications.
-- Generate application server key using
-- applicationServerKey = new Uint8Array(vapidPublicKeyBytes) in Javascript.
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


-- References:
-- NOTE: these references are drafts; the current implementation is based on the versions given below.
-- https://tools.ietf.org/html/draft-ietf-webpush-encryption-04
-- https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-02
-- https://tools.ietf.org/html/draft-ietf-webpush-protocol-10
-- https://tools.ietf.org/html/draft-ietf-webpush-vapid-01

-- |Send a Push Message.
-- The message sent is Base64 URL encoded.
-- Decode the message in Service Worker notification handler in browser before trying to read the JSON.
sendPushNotification :: MonadIO m
                     => VAPIDKeys
                     -> Manager
                     -> PushNotificationDetails
                     -> m (Either PushNotificationError ())
sendPushNotification vapidKeys httpManager pushNotification = do
    eitherInitReq <- runCatchT $ parseRequest $ T.unpack $ endpoint pushNotification
    case eitherInitReq of
        Left exc@(SomeException _) -> return $ Left $ EndpointParseFailed exc
        Right initReq -> do
            time <- liftIO $ getCurrentTime
            eitherJwt <- webPushJWT vapidKeys $ VAPIDClaims { vapidAud =  JWT.Audience [ fromString $ T.unpack $ TE.decodeUtf8With TE.lenientDecode $
                                                                                             BS.append (if secure initReq then "https://" else "http://") (host initReq)
                                                                                       ]
                                                            , vapidSub = fromString $ T.unpack $ T.append "mailto:" $ senderEmail pushNotification
                                                            , vapidExp = NumericDate $ addUTCTime 3000 time
                                                            }
            case eitherJwt of
                Left err -> return $ Left $ JWTGenerationFailed err
                Right jwt -> do

                    ecdhServerPrivateKey <- liftIO $ ECDH.generatePrivate $ ECC.getCurveByName ECC.SEC_p256r1
                    randSalt <- liftIO $ getRandomBytes 16
                    padLen <- liftIO $ randomRIO (0, 20)

                    let authSecretBytes = B64.URL.decodeLenient $ TE.encodeUtf8 $ auth pushNotification
                        -- extract the 65 bytes of ECDH uncompressed public key received from browser in subscription
                        subscriptionPublicKeyBytes = B64.URL.decodeLenient $ TE.encodeUtf8 $ p256dh pushNotification
                        -- encode the message to a safe representation like base64URL before sending it to encryption algorithms
                        -- decode the message through service workers on browsers before trying to read the JSON
                        plainMessage64Encoded = B64.URL.Lazy.encode $ A.encode $ A.toJSON $ message pushNotification

                        eitherEncryptionOutput = webPushEncrypt $ EncryptionInput { applicationServerPrivateKey = ecdhServerPrivateKey
                                                                                  , userAgentPublicKeyBytes = subscriptionPublicKeyBytes
                                                                                  , authenticationSecret = authSecretBytes
                                                                                  , salt = randSalt
                                                                                  , plainText = plainMessage64Encoded
                                                                                  , paddingLength = padLen
                                                                                  }
                    case eitherEncryptionOutput of
                        Left err -> return $ Left $ MessageEncryptionFailed err
                        Right encryptionOutput -> do

                            let ecdhServerPublicKeyBytes = LB.toStrict $ ecPublicKeyToBytes $
                                                               ECDH.calculatePublic (ECC.getCurveByName ECC.SEC_p256r1) $
                                                                   ecdhServerPrivateKey
                            -- content-length is automtically added before making the http request
                            let postHeaders = let authorizationHeader = LB.toStrict $ "WebPush " <> jwt
                                                  cryptoKeyHeader = BS.concat [ "dh=", b64UrlNoPadding ecdhServerPublicKeyBytes
                                                                              , ";"
                                                                              , "p256ecdsa=", b64UrlNoPadding vapidPublicKeyBytestring
                                                                              ]
                                              in [ ("TTL", C8.pack $ show (60*60*(expireInHours pushNotification)))
                                                 , (hContentType, "application/octet-stream")
                                                 , (hAuthorization, authorizationHeader)
                                                 , ("Crypto-Key", cryptoKeyHeader)
                                                 , (hContentEncoding, "aesgcm")
                                                 , ("Encryption", "salt=" <> (b64UrlNoPadding randSalt))
                                                 ]

                                request = initReq { method = "POST"
                                                  , requestHeaders = postHeaders ++
                                                                         -- avoid duplicate headers
                                                                         (filter (\(x, _) -> L.notElem x $ map fst postHeaders)
                                                                                 (requestHeaders initReq)
                                                                         )
                                                    -- the body is encrypted message in raw bytes
                                                    -- without URL encoding
                                                  , requestBody = RequestBodyBS $ encryptedMessage encryptionOutput
                                                  }

                            eitherResp <- runCatchT $ liftIO $ httpLbs request httpManager
                            case eitherResp of
                                Left err@(SomeException _) -> case fromException err of
                                    Just (HttpExceptionRequest _ (StatusCodeException resp _))
                                        -- when the endpoint is invalid, we need to remove it from database
                                        |(statusCode (responseStatus resp) == 404) -> return $ Left RecepientEndpointNotFound
                                    _ -> return $ Left $ PushRequestFailed err
                                Right _ -> return $ Right ()

    where

        vapidPublicKeyBytestring = LB.toStrict $ ecPublicKeyToBytes $
                                       ECDSA.public_q $ ECDSA.toPublicKey vapidKeys






-- |Web push subscription and message details.
--
-- Get subscription details from front end using
-- subscription.endpoint,
-- subscription.toJSON().keys.p256dh and
-- subscription.toJSON().keys.auth.
-- Save subscription details to send messages to the endpoint in future.
data PushNotificationDetails = PushNotificationDetails { endpoint :: Text
                                                       , p256dh :: Text
                                                       , auth :: Text
                                                       , senderEmail :: Text
                                                       , expireInHours :: Int64
                                                       , message :: PushNotificationMessage
                                                       }


-- |3 integers minimally representing a unique VAPID key pair.
data VAPIDKeysMinDetails = VAPIDKeysMinDetails { privateNumber :: Integer
                                               , publicCoordX :: Integer
                                               , publicCoordY :: Integer
                                               } deriving (Show)

-- |'RecepientEndpointNotFound' comes up when the endpoint is no longer recognized by the push service.
-- This may happen if the user has cancelled the push subscription, and hence deleted the endpoint.
-- You may want to delete the endpoint from database in this case.
data PushNotificationError = EndpointParseFailed SomeException
                           | JWTGenerationFailed JOSE.Error.Error
                           | MessageEncryptionFailed CryptoError
                           | RecepientEndpointNotFound
                           | PushRequestFailed SomeException
                            deriving (Show)
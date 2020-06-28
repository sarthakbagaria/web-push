{-# LANGUAGE RecordWildCards, OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts, DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Web.WebPush
    (
    -- * Functions
      generateVAPIDKeys
    , readVAPIDKeys
    , vapidPublicKeyBytes
    , sendPushNotification
    , pushEndpoint
    , pushP256dh
    , pushAuth
    , pushSenderEmail
    , pushExpireInSeconds
    , pushMessage
    , mkPushNotification
    -- * Types
    , VAPIDKeys
    , VAPIDKeysMinDetails(..)
    , PushNotification
    , PushNotificationMessage(..)
    , PushNotificationError(..)
    , PushEndpoint
    , PushP256dh
    , PushAuth
    ) where


import Web.WebPush.Internal

import Crypto.Random                                           (MonadRandom(getRandomBytes))
import Control.Exception                                       (Exception)
import Control.Lens                                            ((^.), Lens', Lens, lens)

import qualified Crypto.PubKey.ECC.Types         as ECC
import qualified Crypto.PubKey.ECC.Generate      as ECC
import qualified Crypto.PubKey.ECC.ECDSA         as ECDSA
import qualified Crypto.PubKey.ECC.DH            as ECDH

import qualified Data.Bits                       as Bits
import Data.Word                                               (Word8)

import GHC.Generics                                            (Generic)
import GHC.Int                                                 (Int64)
import qualified Data.List                       as L
import qualified Data.Text                       as T
import qualified Data.Text.Encoding              as TE
import qualified Data.ByteString.Lazy            as LB
import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Char8           as C8
import qualified Data.Aeson                      as A
import qualified Data.ByteString.Base64.URL      as B64.URL

import Network.HTTP.Client                                     (Manager, httpLbs, parseUrlThrow, HttpException(HttpExceptionRequest)
                                                               , HttpExceptionContent(StatusCodeException), RequestBody(..)
                                                               , requestBody, requestHeaders, method, responseStatus)
import Network.HTTP.Types                                      (hContentType, hAuthorization, hContentEncoding)
import Network.HTTP.Types.Status                               (Status(statusCode))

import Crypto.Error                                            (CryptoError)

import Control.Monad.IO.Class                                  (MonadIO, liftIO)
import Control.Exception.Base                                  (SomeException(..), fromException, toException, throw)
import Control.Exception.Safe                                  (tryAny, handleAny)

import System.Random                                           (randomRIO)


-- |Generate the 3 integers minimally representing a unique pair of public and private keys.
--
-- Store them securely and use them across multiple push notification requests.
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
-- Generate application server key browser using:
--
-- > applicationServerKey = new Uint8Array( #{toJSON vapidPublicKeyBytes} )
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


-- |Send a Push Message. Read the message in Service Worker notification handler in browser:
--
-- > self.addEventListener('push', function(event){ console.log(event.data.json()); });
sendPushNotification :: (MonadIO m, A.ToJSON msg)
                     => VAPIDKeys
                     -> Manager
                     -> PushNotification msg
                     -> m (Either PushNotificationError ())
sendPushNotification vapidKeys httpManager pushNotification = do
    result <- liftIO $ tryAny $ do
        initReq <- handleAny (throw . EndpointParseFailed) $ parseUrlThrow . T.unpack $ pushNotification ^. pushEndpoint
        jwt <- webPushJWT vapidKeys initReq (pushNotification ^. pushSenderEmail)
        ecdhServerPrivateKey <- ECDH.generatePrivate $ ECC.getCurveByName ECC.SEC_p256r1
        randSalt <- getRandomBytes 16
        padLen <- randomRIO (0, 20)

        let authSecretBytes = B64.URL.decodeLenient . TE.encodeUtf8 $ pushNotification ^. pushAuth
            -- extract the 65 bytes of ECDH uncompressed public key received from browser in subscription
            subscriptionPublicKeyBytes = B64.URL.decodeLenient . TE.encodeUtf8 $ pushNotification ^. pushP256dh
            -- encode the message to a safe representation like base64URL before sending it to encryption algorithms
            -- decode the message through service workers on browsers before trying to read the JSON
            plainMessage64Encoded = A.encode . A.toJSON $ pushNotification ^. pushMessage
            encryptionInput =
                EncryptionInput
                    { applicationServerPrivateKey = ecdhServerPrivateKey
                    , userAgentPublicKeyBytes = subscriptionPublicKeyBytes
                    , authenticationSecret = authSecretBytes
                    , salt = randSalt
                    , plainText = plainMessage64Encoded
                    , paddingLength = padLen
                    }
            eitherEncryptionOutput = webPushEncrypt encryptionInput
        encryptionOutput <- either (throw . toException . MessageEncryptionFailed) pure eitherEncryptionOutput
        let ecdhServerPublicKeyBytes = LB.toStrict . ecPublicKeyToBytes . ECDH.calculatePublic (ECC.getCurveByName ECC.SEC_p256r1) $ ecdhServerPrivateKey
            -- content-length is automtically added before making the http request
            authorizationHeader = LB.toStrict $ "WebPush " <> jwt
            cryptoKeyHeader = BS.concat [ "dh=", b64UrlNoPadding ecdhServerPublicKeyBytes
                                        , ";"
                                        , "p256ecdsa=", b64UrlNoPadding vapidPublicKeyBytestring
                                        ]
            postHeaders = [ ("TTL", C8.pack $ show $ pushNotification ^. pushExpireInSeconds)
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
        httpLbs request $ httpManager
    return $ either (Left . onError) (Right . (const ())) result

    where
        vapidPublicKeyBytestring = LB.toStrict . ecPublicKeyToBytes . ECDSA.public_q . ECDSA.toPublicKey $ vapidKeys
        onError :: SomeException -> PushNotificationError
        onError err
            | Just (x :: PushNotificationError) <- fromException err = x
            | Just (HttpExceptionRequest _ (StatusCodeException resp _)) <- fromException err = case statusCode (responseStatus resp) of
                -- when the endpoint is invalid, we need to remove it from database
                404 -> RecepientEndpointNotFound
                410 -> RecepientEndpointNotFound
                _ -> PushRequestFailed err
            | otherwise = PushRequestFailed err


type PushEndpoint = T.Text
type PushP256dh = T.Text
type PushAuth = T.Text

-- |Web push subscription and message details. Use 'mkPushNotification' to construct push notification.
data PushNotification msg = PushNotification {  _pnEndpoint :: PushEndpoint
                                              , _pnP256dh :: PushP256dh
                                              , _pnAuth :: PushAuth
                                              , _pnSenderEmail :: T.Text
                                              , _pnExpireInSeconds :: Int64
                                              , _pnMessage :: msg
                                              }

pushEndpoint :: Lens' (PushNotification msg) PushEndpoint
pushEndpoint = lens _pnEndpoint (\d v -> d {_pnEndpoint = v})

pushP256dh :: Lens' (PushNotification msg) PushP256dh
pushP256dh = lens _pnP256dh (\d v -> d {_pnP256dh = v})

pushAuth :: Lens' (PushNotification msg) PushAuth
pushAuth = lens _pnAuth (\d v -> d {_pnAuth = v})

pushSenderEmail :: Lens' (PushNotification msg) T.Text
pushSenderEmail = lens _pnSenderEmail (\d v -> d {_pnSenderEmail = v})

pushExpireInSeconds :: Lens' (PushNotification msg) Int64
pushExpireInSeconds = lens _pnExpireInSeconds (\d v -> d {_pnExpireInSeconds = v})

pushMessage :: (A.ToJSON msg) => Lens (PushNotification a) (PushNotification msg) a msg
pushMessage = lens _pnMessage (\d v -> d {_pnMessage = v})

-- |Constuct a push notification.
--
-- 'PushEndpoint', 'PushP256dh' and 'PushAuth' should be obtained from push subscription in client's browser.
-- Push message can be set through 'pushMessage'; text and json messages are usually supported by browsers.
-- 'pushSenderEmail' and 'pushExpireInSeconds' can be used to set additional details.
mkPushNotification :: PushEndpoint -> PushP256dh -> PushAuth -> PushNotification ()
mkPushNotification endpoint p256dh auth =
    PushNotification {
         _pnEndpoint = endpoint
       , _pnP256dh = p256dh
       , _pnAuth = auth
       , _pnSenderEmail = ""
       , _pnExpireInSeconds = 3600
       , _pnMessage = ()
    }

-- |Example payload structure for web-push.
-- Any datatype with JSON instance can also be used instead.
-- See 'mkPushNotification'.
data PushNotificationMessage = PushNotificationMessage
    { title :: T.Text
    , body :: T.Text
    , icon :: T.Text
    , url :: T.Text
    , tag :: T.Text
    } deriving (Eq, Show, Generic, A.ToJSON)


-- |3 integers minimally representing a unique VAPID public-private key pair.
data VAPIDKeysMinDetails = VAPIDKeysMinDetails { privateNumber :: Integer
                                               , publicCoordX :: Integer
                                               , publicCoordY :: Integer
                                               } deriving (Show)

-- |'RecepientEndpointNotFound' comes up when the endpoint is no longer recognized by the push service.
-- This may happen if the user has cancelled the push subscription, and hence deleted the endpoint.
-- You may want to delete the endpoint from database in this case, or if 'EndpointParseFailed'.
data PushNotificationError = EndpointParseFailed SomeException
                           | MessageEncryptionFailed CryptoError
                           | RecepientEndpointNotFound
                           | PushRequestFailed SomeException
                            deriving (Show, Exception)

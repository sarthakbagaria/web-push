{-# LANGUAGE RecordWildCards, OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts, DeriveAnyClass #-}

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
    , pushExpireInHours
    , pushMessage
    , mkPushNotification
    -- * Types
    , VAPIDKeys
    , VAPIDKeysMinDetails(..)
    , PushNotification
    , PushNotificationError(..)
    ) where


import Web.WebPush.Internal

import Crypto.Random                                           (MonadRandom(getRandomBytes))
import Control.Monad.Except
import Control.Exception
import qualified Crypto.PubKey.ECC.Types         as ECC
import qualified Crypto.PubKey.ECC.Generate      as ECC
import qualified Crypto.PubKey.ECC.ECDSA         as ECDSA
import qualified Crypto.PubKey.ECC.DH            as ECDH

import qualified Data.Bits                       as Bits
import Data.Word                                               (Word8)

import GHC.Int                                                 (Int64)
import qualified Data.List                       as L
import qualified Data.Text                       as T
import qualified Data.Text.Encoding              as TE
import qualified Data.ByteString.Lazy            as LB
import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Char8           as C8
import qualified Data.Aeson                      as A
import qualified Data.ByteString.Base64.URL      as B64.URL


import Network.HTTP.Client                                     (Manager, httpLbs, parseRequest, HttpException(HttpExceptionRequest), HttpExceptionContent(StatusCodeException), RequestBody(..), requestBody, requestHeaders, method, responseStatus)
import Network.HTTP.Types                                      (hContentType, hAuthorization, hContentEncoding)
import Network.HTTP.Types.Status                               (Status(statusCode))

import Crypto.Error                                            (CryptoError)

import Control.Exception.Base                                  (SomeException(..), fromException)
import Control.Monad.Catch.Pure                                (runCatchT)
import Control.Monad.IO.Class                                  (MonadIO, liftIO)

import System.Random                                           (randomRIO)
import Control.Lens


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
sendPushNotification :: (MonadIO m, A.ToJSON msg)
                     => VAPIDKeys
                     -> Manager
                     -> PushNotification msg
                     -> m (Either PushNotificationError ())
sendPushNotification vapidKeys httpManager pushNotification = do
    eitherInitReq <- runCatchT . parseRequest . T.unpack $ pushNotification ^. pushEndpoint
    result <- runExceptT $ do
        initReq <- either (throwError . EndpointParseFailed) pure eitherInitReq
        jwt <- webPushJWT vapidKeys initReq (pushNotification ^. pushSenderEmail)
        ecdhServerPrivateKey <- liftIO $ ECDH.generatePrivate $ ECC.getCurveByName ECC.SEC_p256r1
        randSalt <- liftIO $ getRandomBytes 16
        padLen <- liftIO $ randomRIO (0, 20)

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
        encryptionOutput <- either (throwError . MessageEncryptionFailed) pure eitherEncryptionOutput
        let ecdhServerPublicKeyBytes = LB.toStrict . ecPublicKeyToBytes . ECDH.calculatePublic (ECC.getCurveByName ECC.SEC_p256r1) $ ecdhServerPrivateKey
            -- content-length is automtically added before making the http request
            authorizationHeader = LB.toStrict $ "WebPush " <> jwt
            cryptoKeyHeader = BS.concat [ "dh=", b64UrlNoPadding ecdhServerPublicKeyBytes
                                        , ";"
                                        , "p256ecdsa=", b64UrlNoPadding vapidPublicKeyBytestring
                                        ]
            postHeaders = [ ("TTL", C8.pack $ show (60 * 60 * (pushNotification ^. pushExpireInHours)))
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

        eitherResp <- runCatchT . liftIO . httpLbs request $ httpManager
        either onError pure eitherResp
    either (pure . Left) (fmap Right . void  . liftIO . print) result -- TODO: make result more verbose
    where
        vapidPublicKeyBytestring = LB.toStrict . ecPublicKeyToBytes . ECDSA.public_q . ECDSA.toPublicKey $ vapidKeys
        onError err = case fromException err of
            Just (HttpExceptionRequest _ (StatusCodeException resp _))
                -- when the endpoint is invalid, we need to remove it from database
                | (statusCode (responseStatus resp) == 404) -> throwError RecepientEndpointNotFound
            _ -> throwError $ PushRequestFailed err
            


-- |Web push subscription and message details.
--
-- Get subscription details from front end using
-- subscription.endpoint,
-- subscription.toJSON().keys.p256dh and
-- subscription.toJSON().keys.auth.
-- Save subscription details to send messages to the endpoint in future.
data PushNotification msg = PushNotification {  _pnEndpoint :: T.Text
                                              , _pnP256dh :: T.Text
                                              , _pnAuth :: T.Text
                                              , _pnSenderEmail :: T.Text
                                              , _pnExpireInHours :: Int64
                                              , _pnMessage :: msg
                                              }

pushEndpoint :: Lens' (PushNotification msg) T.Text
pushEndpoint = lens _pnEndpoint (\d v -> d {_pnEndpoint = v})

pushP256dh :: Lens' (PushNotification msg) T.Text
pushP256dh = lens _pnP256dh (\d v -> d {_pnP256dh = v})

pushAuth :: Lens' (PushNotification msg) T.Text
pushAuth = lens _pnAuth (\d v -> d {_pnAuth = v})

pushSenderEmail :: Lens' (PushNotification msg) T.Text
pushSenderEmail = lens _pnSenderEmail (\d v -> d {_pnSenderEmail = v})

pushExpireInHours :: Lens' (PushNotification msg) Int64
pushExpireInHours = lens _pnExpireInHours (\d v -> d {_pnExpireInHours = v})

pushMessage :: (A.ToJSON msg) => Lens (PushNotification a) (PushNotification msg) a msg
pushMessage = lens _pnMessage (\d v -> d {_pnMessage = v})

mkPushNotification :: T.Text -> T.Text -> T.Text -> PushNotification ()
mkPushNotification endpoint p256dh auth =
    PushNotification {
         _pnEndpoint = endpoint
       , _pnP256dh = p256dh
       , _pnAuth = auth
       , _pnSenderEmail = ""
       , _pnExpireInHours = 1
       , _pnMessage = ()
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
                           | MessageEncryptionFailed CryptoError
                           | RecepientEndpointNotFound
                           | PushRequestFailed SomeException
                            deriving (Show, Exception)
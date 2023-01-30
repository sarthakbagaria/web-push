{-# LANGUAGE MultiParamTypeClasses, OverloadedStrings, QuasiQuotes, TemplateHaskell, TypeFamilies, ViewPatterns, DeriveAnyClass, DeriveGeneric #-}

module Main where

import Yesod
import qualified Web.WebPush as WP
import Data.Time (getCurrentTime, addUTCTime)
import Network.HTTP.Conduit (newManager, Manager(..), tlsManagerSettings)
import Text.Hamlet (hamletFile)
import Text.Julius (juliusFile)
import Control.Lens ((.~), (&))
import Data.Text (pack, Text)
import qualified Data.Text as T
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (toJSON)
import qualified Data.Aeson as A
import GHC.Generics

data PushNotificationMessage = PushNotificationMessage
    { title :: T.Text
    , body :: T.Text
    , icon :: T.Text
    , url :: T.Text
    , tag :: T.Text
    } deriving (Eq, Show, Generic, A.ToJSON)

data App = App { appManager :: Manager
               , appConfigVAPIDKeys :: WP.VAPIDKeys
               }

instance Yesod App

instance RenderMessage App FormMessage where
    renderMessage _ _ = defaultFormMessage

mkYesod "App" [parseRoutes|
/                    HomeR          GET
/service-worker.js   ServiceWorkerR GET
/notify              NotifyR        POST
|]

-- This handler receives the notification details from front end
-- and generates and sends a push notification
postNotifyR :: Handler Value
postNotifyR = do
    time <- liftIO $ getCurrentTime
    master <- getYesod
    formResult <- runInputPostResult $ (,,,)
                                    <$> ireq textField "endpoint"
                                    <*> ireq textField "auth"
                                    <*> ireq textField "p256dh"
                                    <*> ireq textField "text"
    case formResult of
        FormFailure e -> return $ object [("success" .= False), ("errors" .= e)]
        FormMissing -> return $ object [("success" .= False), ("errors" .= ( "The form was not complete." :: Text) )]
        FormSuccess (endpoint, auth, p256dh, text) -> do
            let message = PushNotificationMessage { title = "Web Push Test"
                                                  , body = text
                                                  , icon = ""
                                                  , url = "http://localhost:3000"
                                                  , tag = pack $ show time
                                                  }
                pushDetails = (WP.mkPushNotification endpoint p256dh auth)
                                & WP.pushExpireInSeconds .~ 60 * 60 * 24
                                & WP.pushMessage .~ message

            notificationResult <- WP.sendPushNotification (appConfigVAPIDKeys master)
                                                          (appManager master)
                                                          pushDetails
            case notificationResult of
                Left err -> return $ object [("success" .= False), ("errors" .= (show err))]
                Right () -> return $ object [("success" .= True)]

-- Install the service worker
-- Check for existing push subscriptions and subscribe if not already subscribed
getHomeR :: Handler Html
getHomeR = do
    master <- getYesod
    render <- getUrlRenderParams
    let applicationServerKey = WP.vapidPublicKeyBytes $ appConfigVAPIDKeys master
    defaultLayout $ do
        addScriptRemote "https://code.jquery.com/jquery-3.1.1.min.js"
        toWidget $ $(juliusFile "js/home.julius") render
        toWidget $ $(hamletFile "js/home.hamlet") render

-- Service Worker handles receiving the push notifications
-- Chrome and Firefox allow installing Service Worker on localhost without secure connection
getServiceWorkerR :: Handler TypedContent
getServiceWorkerR = do
  render <- getUrlRenderParams
  return $ TypedContent typeJavascript $ toContent $ $(juliusFile "js/service-worker.julius") render

main :: IO ()
main = do
  vapidKeys <- WP.readVAPIDKeys <$> WP.generateVAPIDKeys
  manager <- newManager tlsManagerSettings
  warp 3000 $ App { appManager = manager
                  , appConfigVAPIDKeys = vapidKeys
                  }

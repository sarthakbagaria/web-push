{-# LANGUAGE OverloadedStrings #-}

module WebPushEncryptionSpec where

import Web.WebPush.Internal

import Test.Hspec

import qualified Data.Binary                     as Binary
import qualified Data.ByteString.Base64.URL      as B64.URL
import Data.ByteString                                         (ByteString)
import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Lazy            as LB


-- Test to match input and output from the specification.
-- https://tools.ietf.org/html/draft-ietf-webpush-encryption-04
spec :: Spec
spec = describe "Web Push Encryption Test" $ do

    let encryptionInput = EncryptionInput
          { applicationServerPrivateKey = bytes32Int $ bsTo32Bytes $ BS.concat [ "nCScek-QpEjmOOlT-rQ38nZ"
                                                                               , "zvdPlqa00Zy0i6m2OJvY"
                                                                               ]
          , userAgentPublicKeyBytes = B64.URL.decodeLenient $ BS.concat [ "BCEkBjzL8Z3C-oi2Q7oE5t2Np-"
                                                                        , "p7osjGLg93qUP0wvqR"
                                                                        , "T21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU"
                                                                        ]
          , authenticationSecret = B64.URL.decodeLenient "R29vIGdvbyBnJyBqb29iIQ"
          , salt = B64.URL.decodeLenient "lngarbyKfMoi9Z75xYXmkg"
          , plainText = "I am the walrus"
          , paddingLength = 0
          }

        encryptionOutput = webPushEncrypt encryptionInput

        expectedEncryptionOutput = EncryptionOutput
            { sharedECDHSecretBytes = B64.URL.decodeLenient $ BS.concat [ "RNjC-"
                                                                        -- NOTE: the specs example might have printed this wrong
                                                                        -- there should be two consecutive hyphens and not one
                                                                        -- near the end of the encoded string, just before "NOQ6Y"
                                                                        , "NVW4BGJbxWPW7G2mowsLeDa53LYKYm4--NOQ6Y"
                                                                        ]
            , inputKeyingMaterialBytes = B64.URL.decodeLenient $ BS.concat [ "EhpZec37Ptm4IRD5-jtZ0q6r1iK5vYmY1tZwtN8"
                                                                           , "fbZY"
                                                                           ]
            , contentEncryptionKeyContext = B64.URL.decodeLenient $ BS.concat [ "Q29udGVudC1FbmNvZGluZzogYWVzZ2NtAFAtMjU2AABB BCEkBjzL8Z3C-"
                                                                              , "oi2Q7oE5t2Np-p7osjGLg93qUP0wvqR"
                                                                              , "T21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQUA"
                                                                              , "QQTaEQ22_OCRpvIOWeQhcbq0qrF1iddSLX1xFmFSxPOW"
                                                                              , "OwmJA417CBHOGqsWGkNRvAapFwiegz6Q61rXVo_5roB1"
                                                                              ]
            , contentEncryptionKey = B64.URL.decodeLenient "AN2-xhvFWeYh5z0fcDu0Ww"
            , nonceContext = B64.URL.decodeLenient $ BS.concat [ "Q29udGVudC1FbmNvZGluZzogbm9uY2UAUC0yNT"
                                                               , "YAAEEE ISQGPMvxncL6iLZDugTm3Y2n6nuiyMYuD3epQ_TC-pFP"
                                                               , "bUQRbJ_RxANBxqRAyrPiFApg5DeKXac1ly3geABRBQBB"
                                                               , "BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7"
                                                               , "CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU"
                                                               ]
            , nonce = B64.URL.decodeLenient "JY1Okw5rw1Drkg9J"
            , paddedPlainText = B64.URL.decodeLenient "AABJIGFtIHRoZSB3YWxydXM"
            , encryptedMessage = B64.URL.decodeLenient $ BS.concat [ "6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA" ]
            }

    it "should match the shared secret" $ do
        (sharedECDHSecretBytes <$> encryptionOutput) `shouldBe` Right (sharedECDHSecretBytes expectedEncryptionOutput)

    it "should match the input keying material" $ do
        (inputKeyingMaterialBytes <$> encryptionOutput) `shouldBe` Right (inputKeyingMaterialBytes expectedEncryptionOutput)

    it "should match the context for content encryption key derivation" $ do
        (contentEncryptionKeyContext <$> encryptionOutput) `shouldBe` Right (contentEncryptionKeyContext expectedEncryptionOutput)

    it "should match the content encryption key" $ do
        (contentEncryptionKey <$> encryptionOutput) `shouldBe` Right (contentEncryptionKey expectedEncryptionOutput)

    it "should match the context for nonce derivation" $ do
        (nonceContext <$> encryptionOutput) `shouldBe` Right (nonceContext expectedEncryptionOutput)

    it "should match the nonce" $ do
        (nonce <$> encryptionOutput) `shouldBe` Right (nonce expectedEncryptionOutput)

    it "should match the paddded plain text" $ do
        (paddedPlainText <$> encryptionOutput) `shouldBe` Right (paddedPlainText expectedEncryptionOutput)

    it "should match the encrypted message" $ do
        (encryptedMessage <$> encryptionOutput) `shouldBe` Right (encryptedMessage expectedEncryptionOutput)



    where
        bsTo32Bytes :: ByteString -> Bytes32
        bsTo32Bytes = Binary.decode . LB.fromStrict . B64.URL.decodeLenient

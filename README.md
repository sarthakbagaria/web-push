# web-push

Helper functions to send messages using Web Push protocol.

## Usage

The `sendPushNotification` function encodes the message into Base64 URL form before encrypting and sending. Decode the message in Service Worker notification handler in browser before trying to read the JSON message.

Guides to using Web Push API in browsers can be found on [Mozilla's](https://developer.mozilla.org/en/docs/Web/API/Push_API) and [Google's](https://developers.google.com/web/fundamentals/engage-and-retain/push-notifications/) docs, or you can check out [this](https://gist.github.com/sarthakbagaria/c08c0d7b84e1165760bb429a4064cfff) _untested_ Yesod app demonstrating the use of this library.

## To Do

- Add recognition of more error/status codes from send notification HTTP response.
- Clearly differentiate between ByteString encodings (Raw, Base64URL etc).
- Extend tests to verify that push messages are sent properly.

## References

Current implementation is based on the following versions of the drafts:
- [https://tools.ietf.org/html/draft-ietf-webpush-encryption-04](https://tools.ietf.org/html/draft-ietf-webpush-encryption-04)
- [https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-02](https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-02)
- [https://tools.ietf.org/html/draft-ietf-webpush-protocol-10](https://tools.ietf.org/html/draft-ietf-webpush-protocol-10)
- [https://tools.ietf.org/html/draft-ietf-webpush-vapid-01](https://tools.ietf.org/html/draft-ietf-webpush-vapid-01)

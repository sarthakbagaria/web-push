# web-push [![Hackage](https://img.shields.io/hackage/v/web-push.svg)](https://hackage.haskell.org/package/web-push)

Helper functions to send messages using Web Push protocol.

## Usage

Guides to using Web Push API in browsers can be found on [Mozilla's](https://developer.mozilla.org/en/docs/Web/API/Push_API) and [Google's](https://developers.google.com/web/fundamentals/engage-and-retain/push-notifications/) docs, or you can check out the demo app in the example folder. To run the demo app:

    cd example
    stack build
    stack --docker-network=bridge --docker-run-args='--publish=3000:3000' exec web-push-example

Then access localhost:3000 from a browser. Keep the browser console open to check if there are errors. For use with docker, the above command requires [stack](https://docs.haskellstack.org/en/stable/README/) 2.4 or above.

For production use, store a set of VAPID keys securely and use them for all push notification subscriptions and messages; public key will have to be exposed to client's browser when subscribing to push notifications, but private key must be kept secret and used when generating push notifications on the server. If VAPID keys are re-generated, all push notifications will require re-subscriptions. Also save the latest subscription details such as endpoint from user's browser session securely in the database and use them to send push notifications to the user later.

## References

Current implementation is based on the following versions of the drafts:
- [https://tools.ietf.org/html/draft-ietf-webpush-encryption-04](https://tools.ietf.org/html/draft-ietf-webpush-encryption-04)
- [https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-02](https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-02)
- [https://tools.ietf.org/html/draft-ietf-webpush-protocol-10](https://tools.ietf.org/html/draft-ietf-webpush-protocol-10)
- [https://tools.ietf.org/html/draft-ietf-webpush-vapid-01](https://tools.ietf.org/html/draft-ietf-webpush-vapid-01)

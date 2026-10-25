# Flowplan push relay – protocol v1

The relay (default `https://push.flowplan.org`) is the only party that holds
Flowplan's APNs key and Firebase credentials. Instances – the operator's own
and anyone's self-hosted ones – send through it without any credentials of
their own. Content is end-to-end encrypted between instance and device: the
relay, Apple and Google only see ciphertext.

## Parties

- **App**: the Flowplan iOS/Android app (bundle `app.flowplan.mobile`).
- **Instance**: a Flowplan server (any origin, e.g. `https://app.flowplan.org`).
- **Relay**: this service.

## 1. Instance identity

Every instance has an Ed25519 key pair, created on first use and stored in its
database. The public key is published at

```
GET {instance}/.well-known/flowplan-push
→ 200 application/json
{ "version": 1, "keys": [{ "id": "<kid>", "alg": "Ed25519", "publicKey": "<base64url, 32 bytes>" }] }
```

Several keys may be listed (rotation). The relay fetches this document over
HTTPS only (http only for `localhost` in development), follows no redirects to
other origins, caches it for at most 1 hour and re-fetches on an unknown `kid`
(at most once per minute per origin). SSRF rules: no private, loopback,
link-local or reserved addresses unless the relay runs with
`ALLOW_PRIVATE_INSTANCES=true` (development/self-hosted relay only).

## 2. Registering a device (app → relay)

```
POST {relay}/v1/devices
Content-Type: application/json
{
  "platform": "ios" | "android",
  "token": "<APNs device token (hex) | FCM registration token>",
  "environment": "production" | "sandbox",      // iOS only; TestFlight/App Store = production
  "bundleId": "app.flowplan.mobile",
  "instance": "https://app.flowplan.org"        // origin only: scheme://host[:port]
}
→ 201 { "relayToken": "<opaque string>", "expiresAt": "<ISO>" }
```

- One registration per (device token, instance). Registering again returns a
  fresh relay token and invalidates the old one for that pair.
- The relay stores device tokens encrypted at rest (AES-256-GCM with
  `RELAY_STORAGE_KEY`). The relay token is an opaque random id (≥ 128 bit,
  base64url) mapped to the record; it carries no device data.
- Relay tokens expire after 180 days without use; every successful send
  extends them. The app re-registers at least every 30 days and whenever the
  APNs/FCM token changes.
- `bundleId` must be on the relay's allow list (`ALLOWED_BUNDLE_IDS`).
- Rate limit: 30 registrations per IP and hour.

```
DELETE {relay}/v1/devices/{relayToken}      → 204   (sign-out, app removed from an instance)
```

Live Activities (iOS): the app registers an activity's push token the same
way with `"platform": "ios-liveactivity"` and gets a separate relay token.

## 3. Sending (instance → relay)

```
POST {relay}/v1/send
Content-Type: application/json
Flowplan-Instance: https://app.flowplan.org
Flowplan-Signature: kid=<kid>, ts=<unix seconds>, sig=<base64url Ed25519 signature>
{ "messages": [ Message, … ] }     // 1–100 messages
```

The signature covers the UTF-8 bytes of
`"flowplan-push-v1\n" + instance + "\n" + ts + "\n" + sha256_hex(body)`.
The relay rejects `ts` older/newer than 5 minutes, unknown keys after one
re-fetch, and any message whose relay token was registered for a different
instance (→ status `forbidden`, the token is not revealed to exist).

```
Message = {
  "to": "<relayToken>",
  "type": "alert" | "background" | "liveactivity",
  "payload": "<base64url ciphertext, ≤ 3000 bytes decoded>",   // alert/background
  "category": "task" | "comment" | "default" | null,            // iOS action buttons / Android actions
  "collapseId": "<≤ 64 chars>" | null,                           // replaces an earlier notification
  "badge": <0–9999> | null,
  "priority": "high" | "normal",
  "ttl": <seconds, ≤ 2419200>,
  "liveActivity": {                                             // only for type liveactivity
     "event": "update" | "end",
     "contentState": { … },        // plain JSON, ≤ 2 KB – rendered by the system, cannot be encrypted
     "staleDate": <unix> | null,
     "dismissalDate": <unix> | null
  } | null
}
→ 200 { "results": [ { "status": "ok" | "gone" | "forbidden" | "invalid" | "rate_limited" | "error", "retryAfter": <s>? } ] }
```

Results are in message order. `gone` means the device is no longer reachable
(APNs 410/BadDeviceToken, FCM UNREGISTERED): the instance deletes the device.
Rate limits per instance origin: 600 messages per minute, burst 100
(`rate_limited` with `retryAfter`). The relay never logs payloads or device
tokens.

### What reaches Apple / Google

- **iOS alert**: `aps: { alert: { title: "Flowplan", body: <localized "New notification"> }, mutable-content: 1, category, thread-id: collapseId, badge, sound: "default" }`, plus `fp: <payload>`, `apns-collapse-id`, `apns-priority`, `apns-expiration`. The Notification Service Extension decrypts `fp` and replaces title/body/userInfo. If decryption fails the placeholder stays.
- **iOS background**: `aps: { content-available: 1 }`, `fp: <payload>`, push type background, priority 5.
- **iOS liveactivity**: push type liveactivity, topic `<bundleId>.push-type.liveactivity`, `aps: { timestamp, event, content-state, stale-date, dismissal-date }`.
- **Android**: FCM data-only message `{ fp: <payload>, category, collapseId, badge }`, `android.priority: high|normal`, `collapse_key`, `ttl`. The app's messaging service decrypts and shows the notification itself.

## 4. End-to-end encryption

- The app creates an X25519 key pair per (installation, instance) and keeps
  the private key in the Keychain (iOS, access group shared with the
  Notification Service Extension, `kSecAttrAccessibleAfterFirstUnlock`) or the
  Android Keystore-protected storage. It sends the public key (base64url,
  32 bytes) to the instance together with the relay token when registering
  the device with the instance (instance API, not the relay).
- Encrypting (instance), per message:
  1. ephemeral X25519 key pair `e`;
  2. `shared = X25519(e.private, device.public)`;
  3. `key = HKDF-SHA256(ikm = shared, salt = e.public || device.public, info = "flowplan-push-v1", L = 32)`;
  4. `nonce` = 12 random bytes;
  5. `ct = AES-256-GCM(key, nonce, plaintext, aad = "flowplan-push-v1")`;
  6. `payload = base64url( 0x01 || e.public (32) || nonce (12) || ct||tag )`.
- Plaintext JSON:
  `{ "title": string, "body": string, "url": string|null, "id": string, "category": string|null, "data": object|null, "sentAt": unix }`
  (`id` = notification id for the action buttons; `url` must be on the instance's origin – the app checks).
- Decryption failure → placeholder notification ("New notification"), never a crash.

## 5. Fallback and migration

Instances keep sending through Expo to devices that registered an Expo push
token only (older app versions). A device registered with a relay token is
sent through the relay; if the relay answers `gone` the device is removed. An
instance can disable the relay (`PUSH_RELAY=off`) or point to another relay
(`PUSH_RELAY_URL`).

## 6. Amendments (v1.1, binding)

Decided after the first relay implementation; all three sides implement these.

1. **Payload size**: `payload` ≤ 2800 bytes decoded (keeps the final APNs/FCM
   message under 4096 bytes). Instances shorten `body` before encrypting.
2. **Registration rate**: 120 registrations per IP and hour (IPv6 per /64).
3. **`forbidden`** is answered for unknown, expired and other-instance tokens
   alike. Instances treat `forbidden` like `gone` and drop the device's relay
   registration.
4. **Android**: the FCM data message also carries `type: "alert" | "background"`.
5. **Replay**: the send body carries a random top-level `requestId`
   (base64url, 16 bytes). The relay rejects a repeated `(instance, requestId)`
   within the timestamp window with `409`. Unknown top-level fields are ignored.
6. **HTTP errors** (whole request): 400 invalid body, 401 bad/missing signature
   or unknown key, 403 blocked instance, 409 replayed, 413 too large,
   415 not JSON, 429 rate limited (`Retry-After`), 502 upstream failure.
   `Flowplan-Instance` must equal `new URL(x).origin` exactly.
7. **Defaults**: priority `high` for alert, `normal` for background;
   `ttl` 86400.
8. **iOS placeholder**: the relay sends `alert: { "title-loc-key":
   "FP_PUSH_TITLE", "loc-key": "FP_PUSH_BODY" }` (no literal text); the app
   ships these keys in its Localizable.strings (de/en/fr). The Notification
   Service Extension replaces them after decrypting.
9. **Instance binding of ciphertext**: AES-GCM `aad` and HKDF `info` are both
   `"flowplan-push-v1\n" + instance` (the instance origin exactly as in
   `Flowplan-Instance`). The app stores keys per instance and uses that
   instance's origin when decrypting. The app also ignores messages whose
   `sentAt` is older than 7 days and notification `id`s it has already shown
   (remember the last 200).
10. **Notes for the Flowplan app (informational, no wire change)**:
    - `category` (`task` | `comment` | `default`) reaches APNs as
      `aps.category` unchanged and is deliberately *not* one of the app's
      registered category identifiers (`flowplan.task`, `flowplan.comment`,
      `flowplan.read`). Buttons come only from the encrypted plaintext's
      `category`, which the Notification Service Extension (iOS) or the
      messaging service (Android) sets after decrypting; a placeholder the
      extension could not replace therefore never shows buttons without a
      notification id. Android ignores the outer `category`.
    - `liveActivity.contentState` is the app's ActivityKit content state as
      expo-widgets defines it: `{ "name": "<view>", "props": "<the view's props
      as a JSON string>" }` (views `FlowplanFocus`, `FlowplanTimer`). A push
      replaces the whole state, so the instance sends every prop the view
      reads, using the texts the app registered with it (language, time
      zone, labels).

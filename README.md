# Flowplan push relay

The push relay delivers notifications from [Flowplan](https://github.com/yannicschuller/flowplan)
instances to the Flowplan iOS and Android app. It runs at **https://push.flowplan.org** and is
the only service that holds Flowplan's Apple Push Notification service (APNs) key and Firebase
credentials. Every instance can send through it without credentials of its own: the operator's
instance and any self-hosted one.

The relay never sees what a notification says. Content is **end-to-end encrypted** between the
instance and the device. The relay, Apple and Google only ever handle ciphertext.

- Protocol (binding contract between relay, instance and app): [`PROTOCOL.md`](PROTOCOL.md)
- Threat model and how to report vulnerabilities: [`SECURITY.md`](SECURITY.md)
- Test vectors for signatures and the end-to-end encryption: [`docs/test-vectors.json`](docs/test-vectors.json)
- Reference implementation of the instance side (signing, encryption) and of the device-side
  decryption: [`examples/instance.ts`](examples/instance.ts)

## Contents

- [Why a relay?](#why-a-relay)
- [Security model](#security-model)
- [Cost](#cost)
- [Setup](#setup)
  1. [Apple: APNs auth key](#1-apple-apns-auth-key)
  2. [Firebase: Android app and service account](#2-firebase-android-app-and-service-account)
  3. [Storage key](#3-storage-key)
  4. [Deploy on Coolify at push.flowplan.org](#4-deploy-on-coolify-at-pushflowplanorg)
  5. [App build settings](#5-app-build-settings-flowplan-app)
  6. [Instance settings](#6-instance-settings-flowplan)
  7. [Operations](#7-operations)
  8. [Running your own relay](#8-running-your-own-relay)
- [Configuration reference](#configuration-reference)
- [API summary](#api-summary)
- [Development](#development)

## Why a relay?

Apple and Google deliver pushes only to the app vendor that holds the credentials for the app's
bundle ID (`app.flowplan.mobile`). A self-hosted Flowplan instance cannot have those credentials,
and handing them out would let anyone impersonate Flowplan towards Apple and Google. Until now,
pushes went through Expo's push service, which only carries plain text. The relay replaces that
with a service that:

- holds the credentials in one place, so **instances need no secrets** to send pushes;
- **cannot read the notifications** (end-to-end encryption, PROTOCOL §4);
- **binds every device registration to one instance**, so no instance can push to devices
  registered with another instance;
- costs nothing to run beyond a small container.

## Security model

```
 ┌──────────────┐  1. register (APNs/FCM token, instance origin)   ┌──────────────┐
 │              │ ───────────────────────────────────────────────▶ │              │
 │   App        │ ◀─────────────────── relayToken ──────────────── │    Relay     │
 │ (device key  │                                                  │  push.flow-  │
 │  X25519,     │  2. relayToken + device public key               │  plan.org    │
 │  Keychain /  │ ──────────────────────────▶ ┌──────────────┐     │              │
 │  Keystore)   │                             │  Instance    │     │ holds APNs   │
 │              │                             │ (Ed25519 key,│     │ key + FCM    │
 │              │                             │  /.well-known│     │ service acc. │
 │              │                             │  /flowplan-  │ 3.  │              │
 │              │                             │  push)       │ ──▶ │ verifies sig │
 │              │                             └──────────────┘ signed  against the │
 │              │                                encrypted     │ instance's   │
 │              │  4. ciphertext only (APNs / FCM)  payload    │ well-known   │
 │              │ ◀─────────────────────────────────────────── │ key          │
 └──────────────┘   decrypts on the device                     └──────────────┘
```

1. **The app registers** its APNs or FCM token with the relay, together with the origin of the
   instance it belongs to (`https://app.flowplan.org`). The relay returns an opaque
   **relay token** (256 random bits). The relay stores the device token encrypted
   (AES-256-GCM) and keeps the relay token **only as a SHA-256 hash**.
2. **The app gives the instance** the relay token and the public half of an X25519 key pair
   that it created for this instance. The private key never leaves the device (Keychain, shared
   with the Notification Service Extension, or Android Keystore-protected storage).
3. **The instance sends** a batch of messages to the relay, signed with its Ed25519 key. The
   relay fetches the instance's public keys from `{instance}/.well-known/flowplan-push`
   (SSRF-guarded, cached at most one hour) and verifies the signature, the timestamp (±5 minutes)
   and that the request is not a replay. A relay token **only works for the instance it was
   registered for**. For any other instance the relay answers `forbidden`, which looks the same
   as an unknown token.
4. **The relay forwards** the ciphertext to APNs or FCM. On iOS the notification carries only the
   localized placeholder (`title-loc-key: "FP_PUSH_TITLE"`, `loc-key: "FP_PUSH_BODY"`, which the
   app's Localizable.strings resolve) plus the encrypted `fp` field. The Notification Service
   Extension decrypts it and shows the real title and text. On Android a data-only
   message is decrypted by the app's messaging service.

What this gives you:

| Threat | Mitigation |
| --- | --- |
| Someone wants to push to devices of another instance | Relay tokens are bound to the instance origin; sends are signed with that origin's key, published on that origin over HTTPS |
| Relay database leaks | Device tokens are AES-256-GCM encrypted (key outside the DB); relay tokens are stored as SHA-256 hashes only; no content is ever stored |
| Relay operator, Apple or Google read notifications | End-to-end encryption (X25519 + HKDF-SHA256 + AES-256-GCM); the relay holds no decryption keys |
| A ciphertext is re-sent through another instance | HKDF info and AES-GCM aad are `"flowplan-push-v1\n" + instance`, so a payload only decrypts for the instance it was made for; the app also drops stale (`sentAt` > 7 days) and already shown notification ids |
| Captured send request is replayed | Timestamp window ±5 min, and a repeated `(instance, requestId)` (and an identical signature) is rejected with 409 within the window |
| Relay abused for SSRF / port scans | Well-known fetch: HTTPS only, DNS resolved once and every address checked (private, loopback, link-local, CGNAT, multicast, reserved, IPv4-mapped/NAT64/6to4 IPv6), connection pinned to the checked address, no cross-origin redirects, 5 s timeout, 16 KB limit, at most one fetch per origin per minute; origins without any registration are never fetched |
| Flooding | Per-IP limits (120 registrations/hour, 120 requests/minute, lock-out after repeated auth failures), per-instance limit (600 messages/minute, burst 100), body ≤ 512 KB, ≤ 100 messages |
| Abusive instance | `admin block <origin>`: registrations and sends refused immediately |

The full threat model, including what the relay *cannot* protect against, is in
[`SECURITY.md`](SECURITY.md).

## Cost

- **APNs** is free with the Apple Developer Program (99 USD/year), which Flowplan already needs
  to publish the iOS app.
- **Firebase Cloud Messaging** is free, with no message limits that matter here.
- **The relay** is a single small container (tens of MB of RAM, mostly idle CPU) with a SQLite
  file. It fits next to the Flowplan instance on the same Coolify server.

## Setup

These steps set up the official relay at `push.flowplan.org`. Steps 5 and 6 cover the app
build and the instances. Self-hosters of Flowplan need **none of this**: their instances use
`push.flowplan.org` by default.

### 1. Apple: APNs auth key

1. Sign in at [developer.apple.com](https://developer.apple.com/account) with the account of
   team **V7N2K54KJN**.
2. **Certificates, Identifiers & Profiles → Keys → +** (Create a key).
3. Name it e.g. `Flowplan Push Relay`. Tick **Apple Push Notifications service (APNs)**, then
   **Configure** and choose environment **Sandbox & Production** and key restriction
   **Team Scoped (All Topics)**. **Continue → Register**.
4. **Download** the key file `AuthKey_XXXXXXXXXX.p8`. Apple lets you download it **only once**.
   Store it in your password manager.
5. Note the **Key ID**: the ten characters in the file name, also shown on the key's page.
   This is `APNS_KEY_ID`.
6. Note the **Team ID** (top right, or Membership): `V7N2K54KJN`. This is `APNS_TEAM_ID`, and
   it is also the default.

One token-based key works for all apps of the team and for both sandbox and production, and
it does not expire. Do not create a push *certificate*. The relay uses token-based
authentication only.

The App ID `app.flowplan.mobile` must have the **Push Notifications** capability. The app's
**iOS setup** workflow already registers it (see step 5).

### 2. Firebase: Android app and service account

1. Open the [Firebase console](https://console.firebase.google.com/) → **Add project**, for
   example `flowplan`. Google Analytics is not needed. Note the **project ID**, for example
   `flowplan-1a2b3`.
2. **Project overview → Add app → Android**. Package name **`app.flowplan.mobile`**. The
   nickname is optional, and the SHA-1 is not needed for FCM. **Register app**.
3. **Download `google-services.json`**. This file is for the **app build**, not for the
   relay. Put its full contents into the flowplan-app repository as the **secret**
   `GOOGLE_SERVICES_JSON` (Settings → Secrets and variables → Actions). The build writes the
   file from it. See step 5.
4. Make sure the **Firebase Cloud Messaging API (V1)** is enabled: **Project settings → Cloud
   Messaging**. If it says *disabled*, follow the link to the Google Cloud console and
   **Enable** "Firebase Cloud Messaging API". The legacy API is not used.
5. Create a **service account for the relay** with the least privileges it needs:
   - In the [Google Cloud console](https://console.cloud.google.com/iam-admin/serviceaccounts),
     with the Firebase project selected: **IAM & Admin → Service Accounts → Create service
     account**, name `flowplan-push-relay`.
   - Role: **Firebase Cloud Messaging API Admin** (`roles/firebasecloudmessaging.admin`).
     Give it no other roles.
   - Open the account → **Keys → Add key → Create new key → JSON**. This downloads the key
     file.
   - (Firebase's **Project settings → Service accounts → Generate new private key** also works,
     but that account has broad *Firebase Admin SDK* rights. Prefer the dedicated account.)
6. The **contents** of this JSON file become `FCM_SERVICE_ACCOUNT` on the relay. The project ID
   is read from the file. `FCM_PROJECT_ID` is only needed to override it.

### 3. Storage key

The relay encrypts device tokens at rest with a 32-byte key:

```sh
openssl rand -base64 32
```

Store the output in your password manager and set it as `RELAY_STORAGE_KEY`. **If you lose the
key, every registration becomes useless.** Apps re-register by themselves within 30 days, but
until then they get no pushes. The relay refuses to start without a key, or with a key that
is too short or obviously weak.

Optional: a token for the Prometheus endpoint, `openssl rand -hex 32` → `METRICS_TOKEN`.

### 4. Deploy on Coolify at push.flowplan.org

The image is built by GitHub Actions on every push to `main` and published as
`ghcr.io/yannicschuller/flowplan-push:latest`. Every build is also tagged with its commit:
`:<full sha>` and `:sha-<short sha>`. The repository is public, so the image is public, and
Coolify needs no registry credentials. After the first workflow run, check that the package
is public: GitHub → your profile → **Packages → flowplan-push → Package settings → Change
visibility**.

1. **DNS**: create an `A`/`AAAA` record `push.flowplan.org` → your Coolify server.
2. Coolify → your project → **+ New → Docker Image**. Image
   `ghcr.io/yannicschuller/flowplan-push:latest`. Alternatively **Docker Compose** with
   [`docker-compose.yml`](docker-compose.yml) from this repository.
3. **General → Domains**: `https://push.flowplan.org`. Coolify (Traefik) gets a Let's Encrypt
   certificate and redirects HTTP to HTTPS. **Ports Exposes**: `8080`.
4. **Environment variables**. Tick *Is Literal?* or *Multiline* where your Coolify version
   offers it, so that `$` and newlines are kept:

   | Variable | Value |
   | --- | --- |
   | `RELAY_STORAGE_KEY` | from step 3 |
   | `APNS_KEY_ID` | from step 1 |
   | `APNS_TEAM_ID` | `V7N2K54KJN` |
   | `APNS_KEY` | full contents of the `.p8` file, including the `-----BEGIN PRIVATE KEY-----` lines (multi-line, `\n`-escaped single line, or base64 of the file are all accepted) |
   | `FCM_SERVICE_ACCOUNT` | full contents of the service-account JSON (or base64 of it) |
   | `TRUST_PROXY` | `1` (Coolify's Traefik is one proxy hop; with Cloudflare in front, `2`) |
   | `METRICS_TOKEN` | optional, from step 3 |

   Instead of pasting keys into variables you can mount them as files. Use `APNS_KEY_FILE`
   and `FCM_SERVICE_ACCOUNT_FILE` with Coolify's **Storages → File mount**.
5. **Storages → + Add → Volume**: name `flowplan-push-data`, destination path **`/data`**.
   This volume holds the SQLite database. Without it, all registrations are lost on every
   deploy.
6. **Healthcheck**: the image has a `HEALTHCHECK` (`GET /healthz` with Node, no curl needed).
   In Coolify you can also enable it under **Healthcheck**: path `/healthz`, port `8080`.
7. Hardening, optional but recommended: in **Advanced → Custom Docker Options** add
   `--read-only --tmpfs /tmp:size=16m --cap-drop=ALL --security-opt=no-new-privileges`. The
   container runs as the unprivileged `node` user and only writes to `/data`.
8. **Deploy**. Check the logs. You should see `flowplan-push relay listening` with
   `"apns":true,"fcm":true`. If APNs or FCM is not configured, the relay still starts and
   answers `error` for that platform.
9. Check: `curl https://push.flowplan.org/healthz` → `{"status":"ok"}`.
10. Auto-deploy: enable the Coolify **webhook** for the image, or add a deploy step to the
    workflow. Otherwise press **Redeploy** after a new image is published.

### 5. App build settings (flowplan-app)

What the app build needs:

| Setting | Where | Value |
| --- | --- | --- |
| `PUSH_RELAY_URL` | repository **variable** of flowplan-app (optional) | Default `https://push.flowplan.org`. Only set it for a build that should use another relay |
| `GOOGLE_SERVICES_JSON` | repository **secret** of flowplan-app | contents of `google-services.json` from step 2.3 |
| Notification Service Extension | App ID **`app.flowplan.mobile.notifications`** | Created by **Actions → iOS setup** (identifiers), with the App Group `group.app.flowplan.mobile`. The extension needs Keychain sharing with the app (same access group) to read the device keys, and its provisioning profile comes from match like the others |
| Push capability | App ID `app.flowplan.mobile` | *Push Notifications* (already registered by iOS setup) |
| aps-environment | entitlements | `production` for TestFlight/App Store builds (the app then registers with `"environment": "production"`), `development` for debug builds from Xcode (`"environment": "sandbox"`) |

After adding the extension, run **iOS setup** once with *Register the App IDs* and
*force_profiles* on, so that the new App ID and its profile exist.

The app registers with the relay directly (`POST /v1/devices`). It creates one X25519 key pair
per (installation, instance) and passes the relay token and the public key to the instance. It
decrypts with that instance's origin in the HKDF info and AES-GCM aad (PROTOCOL §6.9). It
ignores notifications whose `sentAt` is older than 7 days and ids it has already shown (the
last 200). The app ships the placeholder keys `FP_PUSH_TITLE` and `FP_PUSH_BODY` in its
Localizable.strings (de/en/fr). It re-registers at least every 30 days and whenever the APNs/FCM token changes. The test vectors
in [`docs/test-vectors.json`](docs/test-vectors.json) let the Swift/Kotlin decryption be checked
against the reference implementation.

### 6. Instance settings (flowplan)

Instances need **nothing** by default:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PUSH_RELAY_URL` | `https://push.flowplan.org` | Relay to send through, e.g. your own relay |
| `PUSH_RELAY` | on | `PUSH_RELAY=off` disables the relay; the instance then only sends through Expo to older app versions |
| `MOBILE_PUSH_CONTENT` | on (with the relay) | With the relay, content is end-to-end encrypted, so title and text are included by default and the action buttons (Done, Tomorrow, Reply) work. Only Expo pushes to old app versions stay content-free unless `MOBILE_PUSH_CONTENT=on` |

The instance creates its Ed25519 key on first use, stores it in its database and publishes the
public key at `/.well-known/flowplan-push`. The relay must reach that URL over HTTPS at the
instance's public origin. Behind a reverse proxy or auth gateway, `/.well-known/flowplan-push`
must stay publicly accessible.

### 7. Operations

**Admin CLI.** There is no web admin UI. Run the CLI inside the container (Coolify: **Terminal**,
or `docker exec`):

```sh
node dist/src/cli.js help
node dist/src/cli.js stats                 # registrations, instances, deliveries of the last 7 days
node dist/src/cli.js stats 30 --json
node dist/src/cli.js block https://abuse.example.com "sent spam"   # refuse registrations and sends
node dist/src/cli.js blocked               # list
node dist/src/cli.js unblock https://abuse.example.com
node dist/src/cli.js delete-instance https://abuse.example.com     # also drop its registrations
node dist/src/cli.js purge                 # expired registrations (also runs hourly)
```

Blocking takes effect immediately, with no restart. A blocked instance gets `403
instance_blocked` on send, and apps get the same when they register for it. Registrations are
kept, so unblocking restores delivery. Use `delete-instance` to remove them.

**Rotating the storage key.**

1. Generate a new key (`openssl rand -base64 32`).
2. Set `RELAY_STORAGE_KEYS_OLD` to the **current** key. Use a comma-separated list if there
   are several. Set `RELAY_STORAGE_KEY` to the **new** key. Redeploy. New registrations use the
   new key, and old ones are still readable.
3. Run `node dist/src/cli.js rotate-keys`. It re-encrypts every registration with the new key.
   `stats` shows the registrations per key id.
4. Remove `RELAY_STORAGE_KEYS_OLD` and redeploy.

**Rotating the APNs key.** Create a second key in the developer portal and set `APNS_KEY` and
`APNS_KEY_ID` to it. Redeploy, check that iOS deliveries work (`stats`, metrics), then revoke
the old key. Apple allows two APNs keys per team.

**Rotating the FCM key.** Add a new key to the service account, set `FCM_SERVICE_ACCOUNT`,
redeploy, then delete the old key in the Google Cloud console.

**Backups.** Everything lives in `/data/relay.db` (SQLite, WAL mode). Back up the volume, for
example with Coolify's volume backups or `sqlite3 /data/relay.db ".backup '/backup/relay.db'"`
from a sidecar. A backup is only useful together with `RELAY_STORAGE_KEY`, so keep the key
elsewhere, in your password manager. Losing the database is not a disaster: apps re-register
within 30 days, or when they next start with a changed token.

**Monitoring.**

- `GET /healthz` → `{"status":"ok"}`. It checks the database and reveals nothing else. Point
  an uptime monitor (Uptime Kuma, Coolify) at it.
- `GET /metrics` with `Authorization: Bearer $METRICS_TOKEN` gives Prometheus metrics. The
  endpoint returns 404 if `METRICS_TOKEN` is not set. Useful series:
  `flowplan_push_messages_total{platform,status}`, `flowplan_push_auth_failures_total{reason}`,
  `flowplan_push_rate_limited_total{scope}`, `flowplan_push_wellknown_fetches_total{outcome}`,
  `flowplan_push_devices`. Alert on a rising share of `status="error"` (credentials, Apple or
  Google outage).
- Logs are JSON lines on stdout. They never contain device tokens, relay tokens, payloads or
  signatures (sensitive field names are redacted as a second line of defence). IP addresses
  are logged truncated (/24, /48). `LOG_LEVEL=debug|info|warn|error`.

**Upgrading.** Push to `main` → CI tests and publishes the image → redeploy in Coolify. The
database schema migrates itself on start. Pin a commit tag (`:sha-abc1234`) if you want
controlled rollouts. Roll back by deploying the previous tag.

**Scaling.** One container is plenty for this workload. Rate limits and the replay cache live in
memory, so run **one replica**. Several replicas would need a shared store for
both.

### 8. Running your own relay

Forks and self-built apps (another bundle ID, such as the `app.flowplan.mobile.personal`
build) cannot use `push.flowplan.org`. Apple and Google only deliver to apps whose credentials
the relay holds. To run your own:

1. Create your own APNs key (step 1) in **your** Apple team and your own Firebase project
   (step 2) for your bundle ID.
2. Deploy this image with your keys, `APNS_TEAM_ID=<your team>` and
   `ALLOWED_BUNDLE_IDS=<your bundle id>`.
3. Build the app with `PUSH_RELAY_URL=https://push.example.com` and your `google-services.json`.
4. Point your instances at it with `PUSH_RELAY_URL=https://push.example.com`.

For local development against a Flowplan instance on `http://localhost:3000`, run a relay with
`ALLOW_PRIVATE_INSTANCES=true`. It then accepts private addresses and `http://localhost`
origins. **Never enable this on a public relay.**

## Configuration reference

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RELAY_STORAGE_KEY` | **yes** | – | 32 random bytes, base64 (`openssl rand -base64 32`). Encrypts device tokens at rest. The relay refuses to start if it is missing or weak |
| `RELAY_STORAGE_KEYS_OLD` | no | – | Comma-separated previous keys, readable during a rotation (see Operations) |
| `RELAY_PUBLIC_URL` | no | `https://push.flowplan.org` | Public URL; `https://` enables HSTS |
| `PORT` | no | `8080` | Listen port |
| `HOST` | no | `0.0.0.0` | Listen address |
| `DATA_DIR` | no | `./data` (image: `/data`) | Directory of `relay.db`; mount a volume here |
| `APNS_KEY_ID` | for iOS | – | 10-character key ID of the `.p8` key |
| `APNS_TEAM_ID` | no | `V7N2K54KJN` | Apple team ID |
| `APNS_KEY` / `APNS_KEY_FILE` | for iOS | – | `.p8` contents (PEM; `\n`-escaped or base64 also accepted) or a path to it |
| `FCM_SERVICE_ACCOUNT` / `FCM_SERVICE_ACCOUNT_FILE` | for Android | – | Service-account JSON (or base64 of it) or a path to it |
| `FCM_PROJECT_ID` | no | from the JSON | Firebase project ID override |
| `ALLOWED_BUNDLE_IDS` | no | `app.flowplan.mobile` | Comma-separated bundle IDs / Android package names apps may register with |
| `ALLOW_PRIVATE_INSTANCES` | no | `false` | Development only: allow private/loopback instance addresses and `http://localhost` |
| `TRUST_PROXY` | no | `false` | Number of reverse-proxy hops whose `X-Forwarded-For` is trusted for the client IP (`true` = 1). Coolify/Traefik: `1` |
| `METRICS_TOKEN` | no | – | Enables `/metrics` with this bearer token (≥ 32 characters) |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error`, `silent` |

If APNs or FCM is not configured, the relay starts anyway and answers `error` for messages to
that platform. If only half of a platform's settings is given (for example a key without a key
ID), the relay refuses to start.

## API summary

The full contract is in [`PROTOCOL.md`](PROTOCOL.md). Implementation details beyond it:

| Endpoint | Success | Errors |
| --- | --- | --- |
| `POST /v1/devices` | `201 {relayToken, expiresAt}` | `400 invalid_request` (with `fields`), `400 invalid_instance`, `403 bundle_not_allowed`, `403 instance_blocked`, `413`, `415`, `429 rate_limited` (+ `Retry-After`) |
| `DELETE /v1/devices/{relayToken}` | `204`, whether or not the token existed | `400`, `429` |
| `POST /v1/send` | `200 {results}` | `400 invalid_request` / `invalid_instance`, `401 invalid_signature` / `stale_timestamp` / `unknown_key`, `403 instance_blocked`, `409 replayed`, `413`, `415`, `429`, `502 instance_keys_unavailable` |
| `GET /healthz` | `200 {status:"ok"}` | `503` |
| `GET /metrics` | Prometheus text | `401`, `404` if disabled |

Notes for implementers:

- `Flowplan-Instance` must be the canonical origin, exactly as `new URL(x).origin` produces it.
  It is part of the signed string.
- Every send body needs a top-level `requestId`: 16 random bytes, base64url (PROTOCOL §6.5).
  Without it the request is `400`. A repeated `(instance, requestId)` within the timestamp
  window gives `409 replayed`, so use a fresh id for every request, retries included. Unknown
  top-level fields are ignored.
- `payload` may be at most 2800 bytes decoded (§6.1). Instances shorten `body` before
  encrypting.
- Defaults (§6.7): `priority` is `high` for alert and `normal` for background, and `ttl` is
  86400.
- Unknown, expired and foreign relay tokens all give `forbidden` (§6.3). The instance treats
  `forbidden` like `gone` and drops the device's relay registration.
- Ciphertext is bound to the instance (§6.9): HKDF info and AES-GCM aad are both
  `"flowplan-push-v1\n" + instance`, with the origin exactly as in `Flowplan-Instance`.
- Android data messages carry `fp`, `type` (`alert`/`background`) and, when set, `category`,
  `collapseId` and `badge` (strings).
- Requests to the relay must use `Content-Type: application/json` and no content encoding.

## Development

Requires Node 22.18+ (TypeScript runs natively through type stripping).

```sh
npm ci
npm test            # node:test, ~150 tests incl. mock APNs (HTTP/2) and FCM servers
npm run lint        # Biome
npm run typecheck
npm run build       # → dist/
RELAY_STORAGE_KEY=$(openssl rand -base64 32) ALLOW_PRIVATE_INSTANCES=true npm run dev
```

Layout:

```
src/
  index.ts            entry point (config, HTTP server, shutdown)
  cli.ts              admin CLI
  config.ts           environment parsing and validation
  relay.ts            protocol logic: register, unregister, send
  protocol.ts         request schemas and limits (zod)
  http/server.ts      node:http server, body limits, security headers, client IP
  auth/signature.ts   Ed25519 request signatures, replay cache
  instance/keys.ts    /.well-known/flowplan-push fetch + cache
  net/                SSRF guard (address policy, pinned fetch), origin canonicalisation
  crypto/             storage encryption (AES-256-GCM, key ids), relay token hashing
  push/               APNs (HTTP/2, ES256 JWT) and FCM v1 (OAuth2 RS256 JWT) clients, payload building
  db.ts               SQLite (node:sqlite) storage
  metrics.ts, log.ts, ratelimit.ts
examples/instance.ts  reference instance/device implementation (signing, E2E encryption)
scripts/gen-vectors.ts generator of tests/vectors.json = docs/test-vectors.json
```

`docs/test-vectors.json` contains X25519 device and ephemeral key pairs, shared secrets, HKDF
salts and keys, nonces, plaintexts and the resulting payloads. It also has negative cases
(tampered tag, ciphertext, key, nonce, unknown version, truncated) and Ed25519 signature
vectors with seed, public key, signing string and header. The tests check the reference
implementation against them. The instance and app implementations should do the same.

## License

[AGPL-3.0](LICENSE), like Flowplan.

# Flowplan push relay

The push relay delivers notifications from [Flowplan](https://github.com/yannicschuller/flowplan)
instances to the Flowplan iOS and Android app. It is the only service that holds the app's Apple
Push Notification service (APNs) key and Firebase credentials. Every instance can send through
it without credentials of its own: the operator's instance and any self-hosted one.

The **official Flowplan relay** runs at `https://push.flowplan.org`, and the Flowplan app and
instances use it by default. This README describes how to run a relay in general; the examples
use `push.example.com`. Anyone who builds the app with their own bundle ID runs their own relay
(see [Running your own relay](#9-running-your-own-relay)).

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
  4. [Deploy](#4-deploy)
  5. [App build settings](#5-app-build-settings-flowplan-app)
  6. [Instance settings](#6-instance-settings-flowplan)
  7. [Admin dashboard (OIDC)](#7-admin-dashboard-oidc)
  8. [Operations](#8-operations)
  9. [Running your own relay](#9-running-your-own-relay)
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
   instance it belongs to (for example `https://app.flowplan.org`). The relay returns an opaque
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
| Abusive instance | Block it in the [admin dashboard](#7-admin-dashboard-oidc) or with `cli.js block <origin>`: registrations and sends are refused immediately; an emergency switch pauses all sending |

The full threat model, including what the relay *cannot* protect against, is in
[`SECURITY.md`](SECURITY.md).

## Cost

- **APNs** is free with the Apple Developer Program (99 USD/year), which Flowplan already needs
  to publish the iOS app.
- **Firebase Cloud Messaging** is free, with no message limits that matter here.
- **The relay** is a single small container (tens of MB of RAM, mostly idle CPU) with a SQLite
  file. It fits next to a Flowplan instance on the same server.

## Setup

These steps set up a relay, here at `push.example.com`. The official relay at
`push.flowplan.org` is set up the same way. Steps 5 and 6 cover the app build and the
instances, step 7 the optional admin dashboard. People who self-host Flowplan need **none of
this**: their instances use the official relay by default.

### 1. Apple: APNs auth key

1. Sign in at [developer.apple.com](https://developer.apple.com/account) with the Apple
   Developer account (team) that publishes the app.
2. **Certificates, Identifiers & Profiles → Keys → +** (Create a key).
3. Name it e.g. `Flowplan Push Relay`. Tick **Apple Push Notifications service (APNs)**, then
   **Configure** and choose environment **Sandbox & Production** and key restriction
   **Team Scoped (All Topics)**. **Continue → Register**.
4. **Download** the key file `AuthKey_XXXXXXXXXX.p8`. Apple lets you download it **only once**.
   Store it in your password manager.
5. Note the **Key ID**: the ten characters in the file name, also shown on the key's page.
   This is `APNS_KEY_ID`.
6. Note your **Team ID**: 10 characters such as `ABCDE12345`, shown under **Account →
   Membership details** (also top right in Certificates, Identifiers & Profiles). This is
   `APNS_TEAM_ID`. It is required whenever APNs is configured; there is no built-in default.

One token-based key works for all apps of the team and for both sandbox and production, and
it does not expire. Do not create a push *certificate*. The relay uses token-based
authentication only.

The App ID of the app (Flowplan: `app.flowplan.mobile`) must have the **Push Notifications**
capability. Flowplan's **iOS setup** workflow already registers it (see step 5).

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

### 4. Deploy

The relay is one container with one volume. Any platform that runs containers works.

#### What every deployment needs

- **The image.** GitHub Actions builds it on every push to `main` and publishes
  `ghcr.io/yannicschuller/flowplan-push:latest` for `linux/amd64` and `linux/arm64`. Every build
  is also tagged with its commit (`:<full sha>` and `:sha-<short sha>`); pin one of these for
  controlled rollouts. The image is public, so no registry credentials are needed. You can also
  build it yourself from this repository: `docker build -t flowplan-push .` (the
  [`Dockerfile`](Dockerfile) is a two-stage build, the base image is pinned by digest). If you
  publish an image from a fork to GHCR, make the package public (**Packages → Package settings
  → Change visibility**) or give your platform registry credentials.
- **A TLS-terminating reverse proxy** with a certificate for your host name
  (`push.example.com`), forwarding to port **8080** of the container. The relay itself speaks
  plain HTTP and must not be reachable from the internet without the proxy. Caddy, Traefik,
  nginx, a Kubernetes ingress or your platform's router all work. Redirect HTTP to HTTPS.
- **`TRUST_PROXY` = the number of proxies in front of the relay**, so that per-IP rate limits,
  IP blocks and `ADMIN_ALLOWED_IPS` see the real client address. The relay takes the address
  that many hops back in `X-Forwarded-For` and ignores everything the client added itself.
  One proxy (Caddy, Traefik, nginx, Coolify, an ingress controller) = `1`; a CDN such as
  Cloudflare in front of that proxy = `2`. Never set it higher than the real number of hops:
  a client could then choose its own IP. The proxy must append to `X-Forwarded-For` (Traefik,
  Caddy and ingress-nginx do by default; plain nginx needs
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`).
- **A persistent volume on `/data`.** It holds the SQLite database (registrations, blocklists,
  statistics, admin sessions and audit log). Without it all registrations are lost on every
  deploy.
- **Environment variables** (full list in the [configuration reference](#configuration-reference)):

  | Variable | Value |
  | --- | --- |
  | `RELAY_PUBLIC_URL` | `https://push.example.com` (your public URL; enables HSTS and is the base of the admin redirect URI) |
  | `RELAY_STORAGE_KEY` | from step 3 |
  | `APNS_KEY_ID` | from step 1 |
  | `APNS_TEAM_ID` | your Team ID from step 1, e.g. `ABCDE12345` |
  | `APNS_KEY` | full contents of the `.p8` file, including the `-----BEGIN PRIVATE KEY-----` lines (multi-line, `\n`-escaped single line, or base64 of the file are all accepted) |
  | `FCM_SERVICE_ACCOUNT` | full contents of the service-account JSON (or base64 of it) |
  | `TRUST_PROXY` | number of proxy hops, see above (usually `1`) |
  | `ALLOWED_BUNDLE_IDS` | only if your app is not `app.flowplan.mobile` |
  | `METRICS_TOKEN` | optional, from step 3 |

  Instead of pasting keys into variables you can mount them as files (Docker/Kubernetes
  secrets) and set `APNS_KEY_FILE`, `FCM_SERVICE_ACCOUNT_FILE` and
  `ADMIN_OIDC_CLIENT_SECRET_FILE` to their paths.
- **Health check:** `GET /healthz` → `200 {"status":"ok"}`. The image has a Docker
  `HEALTHCHECK` (uses Node, no curl needed); point your platform's check or an uptime monitor at
  the same path.
- **Hardening** (recommended): run the container with a read-only root file system and no
  capabilities: `--read-only --tmpfs /tmp:size=16m --cap-drop=ALL
  --security-opt=no-new-privileges`. The container runs as the unprivileged `node` user and only
  writes to `/data`. Run **one replica**: rate limits and the replay cache live in memory.

After the first start, check the logs for `flowplan-push relay listening` with
`"apns":true,"fcm":true`. If APNs or FCM is not configured, the relay still starts and answers
`error` for that platform. Then `curl https://push.example.com/healthz` → `{"status":"ok"}`.

#### Docker Compose

[`docker-compose.yml`](docker-compose.yml) contains a hardened service definition (read-only,
no capabilities, `/data` volume, port bound to localhost):

```sh
cp .env.example .env        # fill in the values, never commit .env
docker compose up -d
docker compose logs -f push
```

Put your reverse proxy in front of `127.0.0.1:8080`, for example with Caddy:

```
push.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

#### Plain `docker run`

```sh
docker volume create flowplan-push-data
docker run -d --name flowplan-push --restart unless-stopped \
  --read-only --tmpfs /tmp:size=16m --cap-drop=ALL --security-opt=no-new-privileges \
  -v flowplan-push-data:/data -p 127.0.0.1:8080:8080 \
  --env-file .env \
  ghcr.io/yannicschuller/flowplan-push:latest
```

`--env-file` takes one line per variable: use the `\n`-escaped or base64 form of `APNS_KEY` and
`FCM_SERVICE_ACCOUNT`, or mount the files and use the `*_FILE` variables.

With nginx as the proxy:

```nginx
server {
    listen 443 ssl;
    server_name push.example.com;
    # ssl_certificate … (e.g. from certbot)
    client_max_body_size 600k;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

#### Coolify (example)

1. **DNS**: an `A`/`AAAA` record `push.example.com` → your Coolify server.
2. Coolify → your project → **+ New → Docker Image** with
   `ghcr.io/yannicschuller/flowplan-push:latest`, or **Docker Compose** with
   [`docker-compose.yml`](docker-compose.yml) from this repository.
3. **General → Domains**: `https://push.example.com`. Coolify's Traefik gets a Let's Encrypt
   certificate and redirects HTTP to HTTPS. **Ports Exposes**: `8080`.
4. **Environment variables** as in the table above, with `TRUST_PROXY=1` (Traefik is one hop).
   Tick *Is Literal?* or *Multiline* where your Coolify version offers it, so that `$` and
   newlines are kept. Keys can also be mounted with **Storages → File mount** and the `*_FILE`
   variables.
5. **Storages → + Add → Volume**: name `flowplan-push-data`, destination path **`/data`**.
6. **Healthcheck**: path `/healthz`, port `8080`.
7. Hardening: **Advanced → Custom Docker Options**:
   `--read-only --tmpfs /tmp:size=16m --cap-drop=ALL --security-opt=no-new-privileges`.
8. **Deploy** and check the logs and `/healthz` as described above.
9. Updates: enable the Coolify **webhook** for the image, or press **Redeploy** after a new
   image is published. Admin CLI: Coolify's **Terminal** tab opens a shell in the container.

#### Kubernetes and other platforms

- One `Deployment` with `replicas: 1` and `strategy: Recreate` (two pods must never share the
  SQLite file), a `PersistentVolumeClaim` mounted at `/data`, a `Service` on port 8080 and an
  `Ingress` with TLS.
- `securityContext`: `runAsNonRoot: true`, `runAsUser: 1000` (the image's `node` user),
  `fsGroup: 1000`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`,
  `capabilities: {drop: [ALL]}`, plus an `emptyDir` on `/tmp`.
- Secrets as `Secret` objects, either as environment variables or mounted files with the
  `*_FILE` variables.
- `TRUST_PROXY=1` behind ingress-nginx or Traefik; add one per extra hop (load balancer that
  appends `X-Forwarded-For`, CDN).
- Liveness and readiness probes: `GET /healthz` on port 8080.

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

### 7. Admin dashboard (OIDC)

An optional web dashboard at `https://push.example.com/admin` for the operator. It is **off
unless configured** (every `/admin` path answers 404) and sits behind an OpenID Connect login
with your own identity provider (Authentik, Keycloak, Pocket ID, Zitadel, Google, …).

What it shows, refreshed every 5 seconds:

- **Health**: APNs and FCM configured, time of the last successful delivery and of the last
  error (with the provider's reason), database, uptime, version and commit, emergency pause.
- **Live counters** per minute over the last hour (inline sparklines): messages by result
  (`ok`, `gone`, `forbidden`, `invalid`, `rate_limited`, `error`), authentication failures by
  reason (bad signatures, replays, stale timestamps, unknown keys), rate-limit hits by scope,
  refused requests (blocked instance or IP, paused).
- **Registrations**: total, per platform, new in the last 24 hours, number of instances.
- **Top instances** by volume: messages in the last hour and 24 hours, devices, error rate,
  last seen, blocked state. Each has a **detail page** with devices per platform and
  environment, results over 1 h / 24 h / 30 days, hourly sparkline, auth failures, rate-limit
  hits and recent events. Events are anonymized: hashed 10-character device ids, IPs truncated
  to /24 (IPv4) or /48 (IPv6), never tokens or payloads.
- **Blocked instances** and **blocked IP ranges** with reason, time, expiry and who blocked
  them; the **audit log** of every admin action.

What it can do (each action has a confirmation step, needs a reason and is written to the
append-only audit log with who, when, what, reason and client IP, and to the log output):

| Action | Effect |
| --- | --- |
| Block instance (1 h, 24 h, 7 d, 30 d or until unblocked) | Its sends get `403 instance_blocked`, apps cannot register for it. Registrations are kept |
| Unblock instance | Normal service again |
| Delete all registrations of an instance | Its relay tokens stop working at once; cannot be undone |
| Block an IP or range for registrations (1 h – 30 d, at least /8 IPv4 or /16 IPv6) | `POST /v1/devices` from it gets `403 ip_blocked`; sends are not affected (they are signed) |
| **Pause all sending** (kill switch) | Every `POST /v1/send` gets `503 relay_paused` with `Retry-After: 300`, before any processing: no key fetch, nothing reaches Apple or Google. Registrations keep working. Survives restarts until resumed. Metric `flowplan_push_sending_paused` = 1 |
| Resume sending | Ends the pause |
| Purge expired registrations now | Same as the hourly job |

The CLI has the same actions (they write audit entries with actor `cli`), so you can still act
when the identity provider is down.

#### Step 1: create an OIDC client at your identity provider

Generic settings, the same for every provider:

| Setting | Value |
| --- | --- |
| Application type | Web application, **confidential** client (with a client secret). A public client with PKCE works too: leave `ADMIN_OIDC_CLIENT_SECRET` empty |
| Grant / flow | **Authorization Code** only (no implicit, no password grant). PKCE `S256` is always sent |
| Redirect URI | `https://push.example.com/admin/callback` (official relay: `https://push.flowplan.org/admin/callback`), exact match |
| Post-logout redirect URI | `https://push.example.com/admin` |
| Scopes | `openid email profile` (add `groups` or a roles scope if your provider needs one for the groups claim) |
| ID token signing | An asymmetric algorithm (RS256, ES256, PS256, EdDSA). Symmetric HS256 tokens are rejected |
| Claims used | `sub`; `email` and `email_verified` for `ADMIN_EMAILS`; a groups/roles claim for `ADMIN_GROUPS` |

Then note the **issuer URL** (the `issuer` value of the provider's
`/.well-known/openid-configuration`), the **client ID** and the **client secret**.

**Authentik**

1. **Applications → Providers → Create → OAuth2/OpenID Provider**. Name `flowplan-push-admin`,
   authorization flow *default-provider-authorization-explicit-consent* (or *implicit*).
2. Client type **Confidential**. Redirect URIs: `Strict` → `https://push.example.com/admin/callback`.
3. **Signing Key**: select a certificate (for example *authentik Self-signed Certificate*).
   Without one, Authentik signs with HS256, which the relay refuses.
4. Scopes: keep `openid`, `email`, `profile`. Authentik puts the user's groups into the
   `groups` claim with the `profile` scope.
5. **Applications → Create**: name `Flowplan push`, slug `flowplan-push`, provider from step 1.
   Under **Policy / Group / User Bindings** bind your admin group, so nobody else can even sign
   in to this application.
6. Issuer: `https://auth.example.com/application/o/flowplan-push/` (shown on the provider page
   as *OpenID Configuration Issuer*).
7. Relay: `ADMIN_GROUPS=<your admin group name>` and/or `ADMIN_EMAILS=…`.

**Pocket ID**

1. **OIDC Clients → Add OIDC Client**. Name `Flowplan push`.
2. Callback URLs: `https://push.example.com/admin/callback`; Logout Callback URLs:
   `https://push.example.com/admin`. Leave *Public Client* off; PKCE may be on.
3. Save; copy **Client ID** and **Client Secret**. Restrict **Allowed User Groups** to your
   admins.
4. Issuer: your Pocket ID URL, e.g. `https://id.example.com`.
5. Relay: `ADMIN_EMAILS=…`, or `ADMIN_GROUPS=<group name>`. Pocket ID only puts the `groups`
   claim into tokens for the `groups` scope; the relay requests it by itself when
   `ADMIN_GROUPS` is set and the provider lists the scope (you can also set
   `ADMIN_OIDC_SCOPES="openid email profile groups"`). Pocket ID sign-ins use passkeys, which
   already gives you phishing-resistant MFA.

If a sign-in ends with **Not authorized**, the page lists what the provider sent about you:
the subject, the e-mail and whether it is verified, and the groups in `ADMIN_GROUPS_CLAIM` (or
that the claim is missing). Set `ADMIN_SUBJECTS`, `ADMIN_EMAILS` or `ADMIN_GROUPS` to match.
Group names match regardless of case and of a leading slash (Keycloak sends `/admins`).

**Keycloak**

1. Realm → **Clients → Create client**: type *OpenID Connect*, Client ID `flowplan-push-admin`.
2. **Client authentication** on; flows: **Standard flow** only (turn off *Direct access grants*).
3. Valid redirect URIs: `https://push.example.com/admin/callback`; Valid post logout redirect
   URIs: `https://push.example.com/admin`. **Advanced → Proof Key for Code Exchange Code
   Challenge Method**: `S256`.
4. **Credentials** tab: copy the client secret.
5. Issuer: `https://keycloak.example.com/realms/<realm>`.
6. For groups add a mapper: **Client scopes → flowplan-push-admin-dedicated → Add mapper → By
   configuration → Group Membership**, token claim name `groups`, *Full group path* off →
   `ADMIN_GROUPS=<group>`. Realm roles work without a mapper:
   `ADMIN_GROUPS_CLAIM=realm_access.roles`, `ADMIN_GROUPS=<role>`.
7. `email_verified` comes from the user's *Email verified* flag; with `ADMIN_EMAILS` it must be on.

**Zitadel**: project → **New application → Web**, authentication method *Code* (or *PKCE*),
redirect and post-logout URIs as above. Issuer is your instance domain. For roles, enable
*Assert Roles on Authentication* on the project and *User roles inside ID Token* in the
application's token settings, and set
`ADMIN_GROUPS_CLAIM=urn:zitadel:iam:org:project:roles` (the claim is an object keyed by role;
the relay understands that).

**Google**: Google Cloud console → **APIs & Services → Credentials → Create credentials → OAuth
client ID → Web application**, authorized redirect URI as above. Issuer
`https://accounts.google.com`. Google has no groups claim and no logout endpoint: use
`ADMIN_EMAILS` (or `ADMIN_SUBJECTS`); logout is local only.

#### Step 2: configure the relay

| Variable | Example | Notes |
| --- | --- | --- |
| `ADMIN_OIDC_ISSUER` | `https://auth.example.com/application/o/flowplan-push/` | Enables the dashboard. https only |
| `ADMIN_OIDC_CLIENT_ID` | `flowplan-push-admin` | |
| `ADMIN_OIDC_CLIENT_SECRET` (or `_FILE`) | from step 1 | Empty for a public client |
| `ADMIN_EMAILS` | `you@example.com` | Comma-separated; at least one of these three lists is required |
| `ADMIN_SUBJECTS` | `a1b2c3…` | The `sub` claim; the most robust choice (never changes, not reusable) |
| `ADMIN_GROUPS` | `push-admins` | Matched against `ADMIN_GROUPS_CLAIM` (default `groups`) |
| `ADMIN_ALLOWED_IPS` | `203.0.113.7, 2001:db8:1::/48` | Strongly recommended: only these addresses reach `/admin` at all |

`RELAY_PUBLIC_URL` must be the public https URL (the redirect URI is derived from it) and
`TRUST_PROXY` must match your proxy hops, otherwise `ADMIN_ALLOWED_IPS` sees the proxy's
address. On **Coolify** add the variables under **Environment Variables** (tick *Is Literal?*
for the secret), keep `TRUST_PROXY=1` and redeploy; nothing else changes (same domain, same
port, sessions live in the `/data` volume, which works with `--read-only`). With Docker Compose,
fill the `ADMIN_*` lines in `.env` and run `docker compose up -d`.

The log line `flowplan-push relay listening` then contains `"admin":{"issuer":…}`. The relay
refuses to start if the admin configuration is incomplete (for example an issuer without any
admin rule, a non-https issuer, or an http `RELAY_PUBLIC_URL` other than localhost).

#### Step 3: sign in

Open `https://push.example.com/admin` → **Sign in with SSO**. Accounts that sign in successfully
but match none of the rules get "not authorized"; the attempt is in the audit log
(`login_denied`).

#### How it is protected

- Authorization Code flow with **PKCE (S256)**, `state` and `nonce`; login state is stored
  server-side, bound to the browser by a short-lived cookie, valid for 10 minutes and single-use.
- ID tokens are verified with [`jose`](https://github.com/panva/jose): signature against the
  provider's JWKS (cached, refetched on an unknown key id at most every 30 s, so key rotation
  works), `iss` (and the RFC 9207 `iss` response parameter), `aud`, `azp`, `exp`, `nbf`, `iat`
  (at most 10 minutes old) with 60 s clock skew, `nonce`. Only asymmetric algorithms.
- Every request to the provider: https only, no redirects, 5 s timeout, 256 KB limit.
- Sessions are stored server-side (SQLite, only a hash of the id). Cookie `__Host-fp_admin`:
  `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`. A new id at every login. **30 minutes
  idle** (the live refresh does not count as activity), **8 hours** at most. Changing the admin
  configuration (issuer, client, secret, allow lists) ends all sessions. Logout ends the local
  session and, if the provider has an `end_session_endpoint`, its session too
  (`ADMIN_OIDC_RP_LOGOUT=false` turns that off).
- Every POST needs the exact `Origin` of `RELAY_PUBLIC_URL`, a per-session CSRF token and a form
  content type; `Sec-Fetch-Site` must be `same-origin` when the browser sends it. Actions need
  a second, HMAC-bound confirmation (5 minutes) that covers the exact parameters.
- 10 sign-in requests per IP per 10 minutes (starting a login and the callback count
  separately). `ADMIN_ALLOWED_IPS` hides `/admin` (404) from everyone else.
- Responses: CSP `default-src 'none'; script-src 'self'; style-src 'self'; …` (no inline code;
  the small script and stylesheet are served by the relay itself, no CDNs or web fonts),
  `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: same-origin` (not
  `no-referrer`, because browsers then send `Origin: null` on form posts, which would defeat the
  Origin check; no referrer ever goes to another origin). All values are HTML-escaped.
- The dashboard never shows device tokens, relay tokens, payloads, signatures or secrets.

**Recommendations**: restrict `ADMIN_ALLOWED_IPS` to your VPN or home address, require MFA (or
passkeys) for the admin accounts at the identity provider, bind the OIDC application to an
admin group there as well, and prefer `ADMIN_SUBJECTS` or groups over e-mail addresses.

**Statistics storage**: counters are kept per minute for 2 hours and per hour for 30 days in
`relay.db` (tables `stats_minute`, `stats_hourly`), written every 10 seconds, so they survive
restarts. Provider health and the recent events of the detail page are kept in memory only and
start empty after a restart.

**Endpoints** (all under `/admin`): `GET /admin` (dashboard or sign-in page), `GET /admin/login`,
`GET /admin/callback`, `POST /admin/logout`, `GET /admin/instance?origin=…`,
`GET /admin/audit`, `POST /admin/action`, `GET /admin/api/summary`,
`GET /admin/api/instance?origin=…` (JSON for the live refresh, session required),
`GET /admin/assets/admin.js|admin.css`.

### 8. Operations

**Admin CLI.** Everything the dashboard can do also works from the command line inside the
container (`docker exec -it <container> sh`, `kubectl exec`, or your platform's terminal).
Changes take effect immediately and are written to the audit log with actor `cli`:

```sh
node dist/src/cli.js help
node dist/src/cli.js stats                 # registrations, instances, deliveries of the last 7 days
node dist/src/cli.js stats 30 --json
node dist/src/cli.js block https://abuse.example.com "sent spam"   # refuse registrations and sends
node dist/src/cli.js block https://abuse.example.com --for 24h "load test"
node dist/src/cli.js blocked               # list
node dist/src/cli.js unblock https://abuse.example.com
node dist/src/cli.js delete-instance https://abuse.example.com     # also drop its registrations
node dist/src/cli.js block-ip 198.51.100.0/24 24h "registration flood"
node dist/src/cli.js blocked-ips
node dist/src/cli.js unblock-ip 198.51.100.0/24
node dist/src/cli.js pause "APNs key leaked"   # emergency: refuse all sends (503 relay_paused)
node dist/src/cli.js status
node dist/src/cli.js resume
node dist/src/cli.js audit 50              # last admin actions
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
example with your platform's volume backups or `sqlite3 /data/relay.db ".backup '/backup/relay.db'"`
from a sidecar. A backup is only useful together with `RELAY_STORAGE_KEY`, so keep the key
elsewhere, in your password manager. Losing the database is not a disaster: apps re-register
within 30 days, or when they next start with a changed token.

**Monitoring.**

- `GET /healthz` → `{"status":"ok"}`. It checks the database and reveals nothing else. Point
  an uptime monitor (Uptime Kuma, your platform's health check) at it.
- `GET /metrics` with `Authorization: Bearer $METRICS_TOKEN` gives Prometheus metrics. The
  endpoint returns 404 if `METRICS_TOKEN` is not set. Useful series:
  `flowplan_push_messages_total{platform,status}`, `flowplan_push_auth_failures_total{reason}`,
  `flowplan_push_rate_limited_total{scope}`, `flowplan_push_wellknown_fetches_total{outcome}`,
  `flowplan_push_devices`, `flowplan_push_sending_paused`. Alert on a rising share of
  `status="error"` (credentials, Apple or Google outage) and on `flowplan_push_sending_paused == 1`.
- The [admin dashboard](#7-admin-dashboard-oidc) shows the same numbers live, per instance.
- Logs are JSON lines on stdout. They never contain device tokens, relay tokens, payloads or
  signatures (sensitive field names are redacted as a second line of defence). IP addresses
  are logged truncated (/24, /48). `LOG_LEVEL=debug|info|warn|error`.

**Upgrading.** Push to `main` → CI tests and publishes the image → redeploy (pull the new image
and restart the container). The database schema migrates itself on start. Pin a commit tag (`:sha-abc1234`) if you want
controlled rollouts. Roll back by deploying the previous tag.

**Scaling.** One container is plenty for this workload. Rate limits and the replay cache live in
memory, so run **one replica**. Several replicas would need a shared store for
both.

### 9. Running your own relay

Forks and self-built apps (another bundle ID, such as the `app.flowplan.mobile.personal`
build) cannot use the official relay at `push.flowplan.org`. Apple and Google only deliver to
apps whose credentials the relay holds. To run your own:

1. Create your own APNs key (step 1) in **your** Apple team and your own Firebase project
   (step 2) for your bundle ID.
2. Deploy this image (step 4) with your keys, `APNS_TEAM_ID=<your Team ID>` and
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
| `RELAY_PUBLIC_URL` | yes for your own relay | `https://push.flowplan.org` (the official relay) | Public URL of this relay, without a path; `https://` enables HSTS; base of the admin redirect URI |
| `PORT` | no | `8080` | Listen port |
| `HOST` | no | `0.0.0.0` | Listen address |
| `DATA_DIR` | no | `./data` (image: `/data`) | Directory of `relay.db`; mount a volume here |
| `APNS_KEY_ID` | for iOS | – | 10-character key ID of the `.p8` key |
| `APNS_TEAM_ID` | for iOS | – | Your 10-character Apple Team ID (developer.apple.com → Account → Membership details), e.g. `ABCDE12345` |
| `APNS_KEY` / `APNS_KEY_FILE` | for iOS | – | `.p8` contents (PEM; `\n`-escaped or base64 also accepted) or a path to it |
| `FCM_SERVICE_ACCOUNT` / `FCM_SERVICE_ACCOUNT_FILE` | for Android | – | Service-account JSON (or base64 of it) or a path to it |
| `FCM_PROJECT_ID` | no | from the JSON | Firebase project ID override |
| `ALLOWED_BUNDLE_IDS` | no | `app.flowplan.mobile` | Comma-separated bundle IDs / Android package names apps may register with |
| `ALLOW_PRIVATE_INSTANCES` | no | `false` | Development only: allow private/loopback instance addresses and `http://localhost` |
| `TRUST_PROXY` | no | `false` | Number of reverse-proxy hops whose `X-Forwarded-For` is trusted for the client IP (`true` = 1). One Caddy/Traefik/nginx/ingress = `1`, plus one per CDN or load balancer in front |
| `METRICS_TOKEN` | no | – | Enables `/metrics` with this bearer token (≥ 32 characters) |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error`, `silent` |
| `RELAY_COMMIT` | no | – (set by the image build) | Commit shown on the admin dashboard |
| `ADMIN_OIDC_ISSUER` | for the dashboard | – | OIDC issuer URL (https). Unset = admin dashboard disabled, `/admin` answers 404 |
| `ADMIN_OIDC_CLIENT_ID` | for the dashboard | – | Client ID at the identity provider |
| `ADMIN_OIDC_CLIENT_SECRET` / `ADMIN_OIDC_CLIENT_SECRET_FILE` | no | – | Client secret (confidential client); empty = public client with PKCE |
| `ADMIN_OIDC_SCOPES` | no | `openid email profile` | Space- or comma-separated; must contain `openid` |
| `ADMIN_EMAILS` | one of these three | – | Comma-separated admin e-mail addresses (case-insensitive; `email_verified` must be true when the provider sends it) |
| `ADMIN_SUBJECTS` | one of these three | – | Comma-separated `sub` values |
| `ADMIN_GROUPS` | one of these three | – | Comma-separated groups/roles; any match grants access |
| `ADMIN_GROUPS_CLAIM` | no | `groups` | Claim holding groups/roles; dots for nested claims (`realm_access.roles`); arrays, strings and objects keyed by role are understood |
| `ADMIN_ALLOWED_IPS` | no (recommended) | – | Comma-separated IPs/CIDRs allowed to reach `/admin`; everyone else gets 404. Uses the `TRUST_PROXY` client IP |
| `ADMIN_OIDC_RP_LOGOUT` | no | `true` | Also end the session at the provider (`end_session_endpoint`) on logout |

If APNs or FCM is not configured, the relay starts anyway and answers `error` for messages to
that platform. If only half of a platform's settings is given (for example a key without a key
ID or Team ID), the relay refuses to start. The same applies to an incomplete admin
configuration: an issuer without client ID or without any of `ADMIN_EMAILS`, `ADMIN_SUBJECTS`,
`ADMIN_GROUPS`, a non-https issuer, an http `RELAY_PUBLIC_URL` other than localhost, or `ADMIN_*`
variables without `ADMIN_OIDC_ISSUER`.

## API summary

The full contract is in [`PROTOCOL.md`](PROTOCOL.md). Implementation details beyond it:

| Endpoint | Success | Errors |
| --- | --- | --- |
| `POST /v1/devices` | `201 {relayToken, expiresAt}` | `400 invalid_request` (with `fields`), `400 invalid_instance`, `403 bundle_not_allowed`, `403 instance_blocked`, `403 ip_blocked` (operator block of the client's IP range), `413`, `415`, `429 rate_limited` (+ `Retry-After`) |
| `DELETE /v1/devices/{relayToken}` | `204`, whether or not the token existed | `400`, `429` |
| `POST /v1/send` | `200 {results}` | `400 invalid_request` / `invalid_instance`, `401 invalid_signature` / `stale_timestamp` / `unknown_key`, `403 instance_blocked`, `409 replayed`, `413`, `415`, `429`, `502 instance_keys_unavailable`, `503 relay_paused` (+ `Retry-After: 300`, operator kill switch) |
| `GET /healthz` | `200 {status:"ok"}` | `503` |
| `GET /metrics` | Prometheus text | `401`, `404` if disabled |
| `/admin/…` | admin dashboard (HTML, OIDC login) | `404` if not configured or the client IP is not in `ADMIN_ALLOWED_IPS` |

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
npm test            # node:test, ~220 tests incl. mock APNs (HTTP/2), FCM and OIDC provider
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
  admin/              admin dashboard: OIDC client (jose), sessions, authorization, actions + audit log, views
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
  stats.ts            per-minute/per-hour statistics for the dashboard (SQLite, 30 days)
  metrics.ts, log.ts, ratelimit.ts, version.ts
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

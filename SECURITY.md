# Security

## Reporting a vulnerability

Please report vulnerabilities **privately**. Use GitHub's
[private vulnerability reporting](https://github.com/yannicschuller/flowplan-push/security/advisories/new)
(Security → Report a vulnerability), or email the maintainer at the address on the GitHub
profile. Do not open a public issue. Please include steps to reproduce. You will get an
answer within a few days. Fixes are released as a new image, and an advisory is published
once a fix is deployed to `push.flowplan.org`.

Out of scope: denial of service by volume against the public relay, which the rate limits and
the hosting provider handle, reports from automated scanners without a demonstrated impact,
and missing headers on endpoints that serve no HTML.

## Threat model

### Assets

| Asset | Where | Protection |
| --- | --- | --- |
| APNs auth key (`.p8`), FCM service-account key | relay environment only | never logged, never sent anywhere but Apple/Google; least-privilege FCM role |
| Device tokens (APNs/FCM) | relay DB | AES-256-GCM with `RELAY_STORAGE_KEY` (HKDF-derived subkeys, key id per record, AAD binds a ciphertext to its record); equality lookups via keyed HMAC |
| Relay tokens | app, instance | 256 random bits; relay stores SHA-256 only |
| Notification content | instance → device | end-to-end encrypted (X25519, HKDF-SHA256, AES-256-GCM); relay, Apple and Google see ciphertext only |
| Instance signing keys (Ed25519) | instance DB | private key never leaves the instance; public keys at `/.well-known/flowplan-push` |
| Device decryption keys (X25519) | Keychain / Android Keystore | never leave the device |

### Attackers and what stops them

**A malicious or compromised instance** wants to push to devices it does not own. Every relay
token is bound to the canonical origin of the instance it was registered for. A send must be
signed with a key published at that origin over HTTPS. Tokens of other instances give
`forbidden`, the same answer as unknown tokens, so no oracle exists. An instance can only
reach devices whose app registered for it, and it can block itself (`PUSH_RELAY=off`) or be
blocked (`admin block`).

**A network attacker or anyone who obtains a relay token** (for example from an instance
database leak) cannot send without the instance's private key. A token alone only allows
`DELETE` of that registration, which the app repairs by re-registering.

**An attacker replaying a captured send request**: requests older or newer than 5 minutes are
rejected. Within the window the relay remembers every accepted `(instance, requestId)` and
every accepted signature, and rejects repeats with `409`. TLS between instance and relay normally prevents capture in the first place.

**An attacker who reads the relay database** (backup leak, disk access) gets ciphertext device
tokens, without `RELAY_STORAGE_KEY`, which lives only in the environment, and relay token
hashes, which cannot be used to send. Instance origins and timestamps are visible. Content is
never stored.

**The relay operator, Apple, Google**: they see which instance sends how many notifications to
which device token, and when. That metadata is unavoidable for push delivery. They cannot read
content, which is end-to-end encrypted. Live Activity `contentState` is the exception: iOS
renders it, so it cannot be encrypted (PROTOCOL §2/§3), and instances should keep it minimal.

**An attacker using the relay as an SSRF proxy**: the only outbound requests to
attacker-chosen hosts are `GET {origin}/.well-known/flowplan-push`. They are made only for
origins that have at least one registration, and only after the request passed the
timestamp check. They are throttled to one per origin per minute, and failures are cached.
They use HTTPS only. The host name is resolved once, every resolved address must be globally
routable (private, loopback, link-local incl. 169.254.169.254, CGNAT, multicast,
documentation, benchmarking and reserved ranges are refused, as are IPv4-mapped,
IPv4-compatible, NAT64-embedded, 6to4 and Teredo IPv6 forms), and the TCP connection is
pinned to the checked address, so DNS rebinding between check and connect does not work.
Cross-origin redirects are refused. The timeout is 5 s and responses are limited to 16 KB.
Response bodies are parsed only as the well-known JSON and never reflected to the caller.

**An attacker flooding the relay**: request bodies are limited (512 KB for send, 8 KB for
register), as are message counts (100), header size, and request and header timeouts.
Per-IP limits apply (120 registrations/hour, 120 send/delete requests/minute; IPv6 counted per
/64), as does a per-IP lock-out after 30 authentication failures in 10 minutes. The
per-instance limit (600 messages/minute, burst 100) is counted only after the signature has
been verified, so nobody can use up another instance's quota. All in-memory tables are
bounded.

**An attacker abusing the registration endpoint** (registering junk for random origins): the
registration rate limit, the bundle ID allow list, origin validation (HTTPS, public address
literals only, no paths or credentials) and the blocklist. Junk registrations expire after 180
days without use.

**A browser-based attacker**: the relay sends no CORS headers, so cross-origin browser calls
fail. Apps and instances are not browsers. Responses carry `nosniff`, a `default-src 'none'`
CSP, `frame-ancestors 'none'`, `no-store` and HSTS.

### Not covered

- A compromised **instance** can read its own users' notifications. It produces them.
- A compromised **relay host** can drop, delay or count pushes, and read the APNs/FCM
  credentials, which allows sending placeholder pushes to known device tokens. It still cannot
  read content or forge content that the app accepts: payloads are authenticated by AES-GCM
  under a key only the instance and the device can derive. Revoke the APNs key and the FCM
  service-account key if the host is compromised.
- **Sender authentication of payloads**: the E2E scheme is ECIES-style. It proves that the
  sender knew the device's public key, not that the sender was a specific instance. The device
  public key is only given to the instance, and the relay binds tokens to instances, so a third
  party would need both the relay token and the instance's signing key. The ciphertext is bound
  to the instance origin (HKDF info and AES-GCM aad `"flowplan-push-v1\n" + instance`), so a
  payload made for one instance does not decrypt as another instance's notification. A
  malicious relay could re-deliver an old ciphertext of the same instance. The app limits that
  by ignoring messages whose `sentAt` is older than 7 days and ids it has already shown.
- Traffic analysis by timing and size. Payloads are not padded, so instances that care should
  pad plaintexts to a few fixed sizes.

### Implementation notes

- Ed25519 verification, X25519, HKDF, AES-GCM, ES256 and RS256 use only `node:crypto`. The
  only runtime dependency is `zod`, pinned and audited in CI (`npm audit --audit-level=low`).
  Dependabot watches npm, GitHub Actions and the base image.
- Secrets are compared in constant time (`crypto.timingSafeEqual` over SHA-256 digests).
- Base64url input is decoded strictly (canonical encodings only).
- Logs are structured JSON with field-name redaction. Tokens, payloads and signatures are never
  passed to the logger, and IPs are truncated.
- The container runs as an unprivileged user, works with a read-only root file system, writes
  only to `/data` (mode 0700, database 0600) and ships without npm.
- The image build is pinned by digest, and GitHub Actions are pinned by commit SHA. Images are
  published with provenance and an SBOM.

/**
 * Generates tests/vectors.json and docs/test-vectors.json (PROTOCOL §3 and §4
 * test vectors) with node:crypto. Run once: `npm run vectors`. The committed
 * vectors are verified by tests/vectors.test.ts; regenerating changes all
 * random values, so only do it when the protocol changes.
 */
import {
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import { writeFileSync } from "node:fs";
import path from "node:path";
import {
  CONTEXT,
  decryptPayload,
  deriveKey,
  encryptPayload,
  instanceKeyFromSeed,
  rawPrivate,
  rawPublic,
  signingString,
  signRequest,
  wellKnownDocument,
} from "../examples/instance.ts";

const root = path.resolve(import.meta.dirname, "..");
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const plaintexts = [
  {
    title: "Review release notes",
    body: "Anna assigned a task to you",
    url: "https://app.flowplan.org/tasks/42",
    id: "notif_01J9Z6K5X2",
    category: "task",
    data: { taskId: "42" },
    sentAt: 1767225600,
  },
  {
    title: "Neuer Kommentar 💬",
    body: "Jörg: „Sieht gut aus – bitte bis Freitag“",
    url: null,
    id: "notif_ümlaut",
    category: "comment",
    data: null,
    sentAt: 1767225661,
  },
  { title: "", body: "", url: null, id: "x", category: null, data: null, sentAt: 0 },
];

const e2e = plaintexts.map((p, i) => {
  const device = generateKeyPairSync("x25519");
  const ephemeral = generateKeyPairSync("x25519");
  const nonce = randomBytes(12);
  const plaintext = JSON.stringify(p);
  const devicePublic = rawPublic(device.publicKey);
  const ephemeralPublic = rawPublic(ephemeral.publicKey);
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: device.publicKey });
  const key = deriveKey(shared, ephemeralPublic, devicePublic);
  const payload = encryptPayload(b64u(devicePublic), plaintext, {
    ephemeralPrivateKey: ephemeral.privateKey,
    nonce,
  });
  if (decryptPayload(device.privateKey, payload) !== plaintext)
    throw new Error("round trip failed");
  const raw = Buffer.from(payload, "base64url");
  return {
    name: ["ascii", "unicode", "minimal"][i],
    devicePrivateKey: b64u(rawPrivate(device.privateKey)),
    devicePublicKey: b64u(devicePublic),
    ephemeralPrivateKey: b64u(rawPrivate(ephemeral.privateKey)),
    ephemeralPublicKey: b64u(ephemeralPublic),
    sharedSecretHex: hex(shared),
    hkdfSaltHex: hex(Buffer.concat([ephemeralPublic, devicePublic])),
    hkdfInfo: CONTEXT,
    keyHex: hex(key),
    nonceHex: hex(nonce),
    aad: CONTEXT,
    plaintext,
    ciphertextAndTagHex: hex(raw.subarray(45)),
    payload,
  };
});

const first = e2e[0] as (typeof e2e)[number];
const firstRaw = Buffer.from(first.payload, "base64url");
const flip = (b: Buffer, i: number) => {
  const c = Buffer.from(b);
  c[i] = (c[i] ?? 0) ^ 0x01;
  return b64u(c);
};
const invalid = [
  { name: "tampered tag", payload: flip(firstRaw, firstRaw.length - 1) },
  { name: "tampered ciphertext", payload: flip(firstRaw, 50) },
  { name: "tampered ephemeral key", payload: flip(firstRaw, 5) },
  { name: "tampered nonce", payload: flip(firstRaw, 40) },
  {
    name: "unknown version byte",
    payload: b64u(Buffer.concat([Buffer.from([0x02]), firstRaw.subarray(1)])),
  },
  { name: "truncated", payload: b64u(firstRaw.subarray(0, 60)) },
].map((v) => ({
  ...v,
  devicePrivateKey: first.devicePrivateKey,
  expected: "decryption must fail → placeholder",
}));

const signatures = [
  { instance: "https://app.flowplan.org", ts: 1767225600, body: '{"messages":[]}' },
  {
    instance: "https://flowplan.example.com:8443",
    ts: 1767225999,
    body: JSON.stringify({
      messages: [
        {
          to: "A".repeat(43),
          type: "alert",
          payload: first.payload,
          category: "task",
          priority: "high",
          ttl: 3600,
        },
      ],
    }),
  },
].map((v) => {
  const seed = randomBytes(32);
  const kid = createHash("sha256").update(seed).digest("base64url").slice(0, 16);
  const key = instanceKeyFromSeed(b64u(seed), kid);
  const headers = signRequest({
    instance: v.instance,
    kid,
    privateKey: key.privateKey,
    body: v.body,
    ts: v.ts,
  });
  return {
    instance: v.instance,
    ts: v.ts,
    body: v.body,
    bodySha256Hex: createHash("sha256").update(v.body).digest("hex"),
    signingString: signingString(v.instance, v.ts, v.body),
    kid,
    privateKeySeed: b64u(seed),
    publicKey: key.publicKey,
    signature: /sig=([A-Za-z0-9_-]+)/.exec(headers["flowplan-signature"])?.[1],
    headers,
    wellKnown: wellKnownDocument([key]),
  };
});

// Sanity: the public key derived from the seed must match createPublicKey().
for (const s of signatures) {
  const pub = createPublicKey(instanceKeyFromSeed(s.privateKeySeed, s.kid).privateKey).export({
    format: "jwk",
  }).x;
  if (pub !== s.publicKey) throw new Error("seed import mismatch");
}

const doc = {
  description:
    "Flowplan push protocol v1 test vectors (PROTOCOL.md §3 signatures, §4 end-to-end encryption). " +
    "All binary values are base64url without padding unless the field name ends in Hex. " +
    "X25519/Ed25519 private keys are the raw 32-byte forms (RFC 7748 scalar before clamping / RFC 8032 seed), " +
    "as used by CryptoKit rawRepresentation, Tink, libsodium (seed) and JWK 'd'.",
  generatedBy: "scripts/gen-vectors.ts (node:crypto)",
  e2e: {
    algorithm:
      "shared = X25519(ephemeralPrivate, devicePublic); key = HKDF-SHA256(ikm=shared, salt=ephemeralPublic||devicePublic, info='flowplan-push-v1', L=32); " +
      "ct||tag = AES-256-GCM(key, nonce, plaintext, aad='flowplan-push-v1'); payload = base64url(0x01 || ephemeralPublic || nonce || ct||tag)",
    vectors: e2e,
    invalid,
  },
  signatures: {
    algorithm:
      "sig = Ed25519(privateKey, UTF-8('flowplan-push-v1\\n' + instance + '\\n' + ts + '\\n' + hex(sha256(body)))); " +
      "header Flowplan-Signature: kid=<kid>, ts=<ts>, sig=<base64url(sig)>",
    vectors: signatures,
  },
};

const json = `${JSON.stringify(doc, null, 2)}\n`;
writeFileSync(path.join(root, "tests", "vectors.json"), json);
writeFileSync(path.join(root, "docs", "test-vectors.json"), json);
process.stdout.write("wrote tests/vectors.json and docs/test-vectors.json\n");

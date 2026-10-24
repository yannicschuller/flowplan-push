/**
 * Reference implementation of the instance side of PROTOCOL v1 (and of the
 * device-side decryption), using only node:crypto. The relay's tests use it;
 * instance and app implementations can be checked against it and against
 * docs/test-vectors.json.
 *
 *   const id = generateInstanceKey();                 // persist id.privateKey
 *   GET /.well-known/flowplan-push → wellKnownDocument([id])
 *   const payload = encryptPayload(devicePublicKey, { title, body, … });
 *   const body = JSON.stringify({ messages: [{ to, type: "alert", payload, … }] });
 *   fetch(`${relay}/v1/send`, { method: "POST", body,
 *     headers: { "content-type": "application/json", ...signRequest({ instance, kid, privateKey, body }) } });
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  type KeyObject,
  randomBytes,
  sign,
} from "node:crypto";

export const CONTEXT = "flowplan-push-v1";

// ---- Ed25519 instance identity (§1, §3) ----------------------------------

export interface InstanceKey {
  kid: string;
  privateKey: KeyObject;
  /** base64url, 32 bytes */
  publicKey: string;
}

export function generateInstanceKey(kid?: string): InstanceKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const x = publicKey.export({ format: "jwk" }).x as string;
  return {
    kid: kid ?? createHash("sha256").update(x).digest("base64url").slice(0, 16),
    privateKey,
    publicKey: x,
  };
}

/** Imports an Ed25519 key from its 32-byte seed (base64url). */
export function instanceKeyFromSeed(seed: string, kid: string): InstanceKey {
  const d = Buffer.from(seed, "base64url");
  // PKCS#8 prefix for an Ed25519 private key.
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), d]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const x = createPublicKey(privateKey).export({ format: "jwk" }).x as string;
  return { kid, privateKey, publicKey: x };
}

export function wellKnownDocument(keys: Array<Pick<InstanceKey, "kid" | "publicKey">>) {
  return {
    version: 1,
    keys: keys.map((k) => ({ id: k.kid, alg: "Ed25519", publicKey: k.publicKey })),
  };
}

export function signingString(
  instance: string,
  ts: number | string,
  body: string | Uint8Array,
): string {
  const bodyHash = createHash("sha256").update(body).digest("hex");
  return `${CONTEXT}\n${instance}\n${ts}\n${bodyHash}`;
}

/** Headers for POST {relay}/v1/send. `body` must be the exact bytes that are sent. */
export function signRequest(opts: {
  instance: string;
  kid: string;
  privateKey: KeyObject;
  body: string | Uint8Array;
  ts?: number;
}): { "flowplan-instance": string; "flowplan-signature": string } {
  const ts = opts.ts ?? Math.floor(Date.now() / 1000);
  const sig = sign(
    null,
    Buffer.from(signingString(opts.instance, ts, opts.body), "utf8"),
    opts.privateKey,
  );
  return {
    "flowplan-instance": opts.instance,
    "flowplan-signature": `kid=${opts.kid}, ts=${ts}, sig=${sig.toString("base64url")}`,
  };
}

// ---- X25519 + HKDF + AES-256-GCM end-to-end encryption (§4) -------------

export function x25519PublicKey(raw: string): KeyObject {
  return createPublicKey({ key: { kty: "OKP", crv: "X25519", x: raw }, format: "jwk" });
}

export function x25519PrivateKey(d: string): KeyObject {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"),
    Buffer.from(d, "base64url"),
  ]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

export function rawPublic(key: KeyObject): Buffer {
  return Buffer.from(key.export({ format: "jwk" }).x as string, "base64url");
}

export function rawPrivate(key: KeyObject): Buffer {
  return Buffer.from(key.export({ format: "jwk" }).d as string, "base64url");
}

/** Device side: a fresh key pair; the app sends `publicKey` to the instance. */
export function generateDeviceKey(): { privateKey: KeyObject; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  return { privateKey, publicKey: rawPublic(publicKey).toString("base64url") };
}

export function deriveKey(shared: Buffer, ephemeralPublic: Buffer, devicePublic: Buffer): Buffer {
  return Buffer.from(
    hkdfSync("sha256", shared, Buffer.concat([ephemeralPublic, devicePublic]), CONTEXT, 32),
  );
}

export interface EncryptOptions {
  /** Test vectors only: fixed ephemeral key and nonce. Never reuse in production. */
  ephemeralPrivateKey?: KeyObject;
  nonce?: Buffer;
}

export function encryptPayload(
  devicePublicKey: string,
  plaintext: string | object,
  opts: EncryptOptions = {},
): string {
  const devicePub = Buffer.from(devicePublicKey, "base64url");
  if (devicePub.length !== 32) throw new Error("device public key must be 32 bytes");
  const ephemeral = opts.ephemeralPrivateKey ?? generateKeyPairSync("x25519").privateKey;
  const ephemeralPub = rawPublic(createPublicKey(ephemeral));
  const shared = diffieHellman({
    privateKey: ephemeral,
    publicKey: x25519PublicKey(devicePublicKey),
  });
  const key = deriveKey(shared, ephemeralPub, devicePub);
  const nonce = opts.nonce ?? randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(CONTEXT, "utf8"));
  const text = typeof plaintext === "string" ? plaintext : JSON.stringify(plaintext);
  const ct = Buffer.concat([cipher.update(text, "utf8"), cipher.final(), cipher.getAuthTag()]);
  return Buffer.concat([Buffer.from([0x01]), ephemeralPub, nonce, ct]).toString("base64url");
}

/** Device side (what the Notification Service Extension / messaging service does). Throws on failure. */
export function decryptPayload(devicePrivateKey: KeyObject, payload: string): string {
  const raw = Buffer.from(payload, "base64url");
  if (raw.length < 1 + 32 + 12 + 16 || raw[0] !== 0x01) throw new Error("unsupported payload");
  const ephemeralPub = raw.subarray(1, 33);
  const nonce = raw.subarray(33, 45);
  const ct = raw.subarray(45, raw.length - 16);
  const tag = raw.subarray(raw.length - 16);
  const devicePub = rawPublic(createPublicKey(devicePrivateKey));
  const shared = diffieHellman({
    privateKey: devicePrivateKey,
    publicKey: x25519PublicKey(ephemeralPub.toString("base64url")),
  });
  const key = deriveKey(shared, ephemeralPub, devicePub);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(Buffer.from(CONTEXT, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

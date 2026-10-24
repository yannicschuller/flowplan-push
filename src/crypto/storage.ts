import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import { decodeBase64Any } from "./encoding.ts";

/**
 * Encryption at rest for device tokens (AES-256-GCM) and keyed lookup hashes
 * (HMAC-SHA256), derived from RELAY_STORAGE_KEY via HKDF.
 *
 * Ciphertext format: "v1.<keyId>.<base64url(nonce(12) || ciphertext || tag(16))>"
 * The key id is derived from the key itself, so rotating only requires moving
 * the old key to RELAY_STORAGE_KEYS_OLD and setting a new RELAY_STORAGE_KEY.
 */

const KEY_ID_INFO = "flowplan-push/key-id/v1";
const ENC_INFO = "flowplan-push/storage-enc/v1";
const LOOKUP_INFO = "flowplan-push/storage-lookup/v1";

/** Keys that appear in documentation/examples and must never be used. */
const KNOWN_BAD_KEYS = new Set([
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "REPLACE_ME_WITH_openssl_rand_base64_32_OUTPUT=",
]);

export class StorageKeyError extends Error {}

interface DerivedKey {
  id: string;
  enc: Buffer;
  lookup: Buffer;
}

export function parseStorageKey(raw: string | undefined, name = "RELAY_STORAGE_KEY"): Buffer {
  if (!raw || raw.trim() === "") {
    throw new StorageKeyError(`${name} is required (generate one with: openssl rand -base64 32)`);
  }
  if (KNOWN_BAD_KEYS.has(raw.trim())) {
    throw new StorageKeyError(`${name} is a documentation placeholder; generate a real key`);
  }
  const key = decodeBase64Any(raw);
  if (key?.length !== 32) {
    throw new StorageKeyError(
      `${name} must be exactly 32 bytes, base64 encoded (openssl rand -base64 32)`,
    );
  }
  // A uniformly random 32-byte key has ~27 distinct byte values; anything
  // with fewer than 16 is almost certainly hand-made (e.g. a repeated pattern).
  if (new Set(key).size < 16) {
    throw new StorageKeyError(`${name} looks weak (too few distinct bytes); generate a random key`);
  }
  return key;
}

function derive(key: Buffer): DerivedKey {
  const id = createHash("sha256").update(KEY_ID_INFO).update(key).digest("hex").slice(0, 12);
  const enc = Buffer.from(hkdfSync("sha256", key, Buffer.alloc(0), ENC_INFO, 32));
  const lookup = Buffer.from(hkdfSync("sha256", key, Buffer.alloc(0), LOOKUP_INFO, 32));
  return { id, enc, lookup };
}

export class StorageCipher {
  readonly current: DerivedKey;
  private readonly byId = new Map<string, DerivedKey>();
  private readonly all: DerivedKey[];

  constructor(currentKey: Buffer, oldKeys: Buffer[] = []) {
    this.current = derive(currentKey);
    this.all = [this.current];
    this.byId.set(this.current.id, this.current);
    for (const k of oldKeys) {
      const d = derive(k);
      if (this.byId.has(d.id)) continue;
      this.byId.set(d.id, d);
      this.all.push(d);
    }
  }

  get currentKeyId(): string {
    return this.current.id;
  }

  encrypt(plaintext: string, aad: string): string {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.current.enc, nonce);
    cipher.setAAD(Buffer.from(aad, "utf8"));
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1.${this.current.id}.${Buffer.concat([nonce, ct, tag]).toString("base64url")}`;
  }

  /** Returns the plaintext or throws if the key is unknown or the data was tampered with. */
  decrypt(blob: string, aad: string): string {
    const parts = blob.split(".");
    if (parts.length !== 3 || parts[0] !== "v1") throw new StorageKeyError("bad ciphertext format");
    const key = this.byId.get(parts[1] ?? "");
    if (!key) throw new StorageKeyError("ciphertext encrypted with an unknown storage key");
    const raw = Buffer.from(parts[2] ?? "", "base64url");
    if (raw.length < 12 + 16) throw new StorageKeyError("ciphertext too short");
    const decipher = createDecipheriv("aes-256-gcm", key.enc, raw.subarray(0, 12));
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    return Buffer.concat([
      decipher.update(raw.subarray(12, raw.length - 16)),
      decipher.final(),
    ]).toString("utf8");
  }

  keyIdOf(blob: string): string | null {
    const parts = blob.split(".");
    return parts.length === 3 ? (parts[1] ?? null) : null;
  }

  /** Keyed hash for equality lookups; with the current key. */
  lookupHash(value: string): string {
    return createHmac("sha256", this.current.lookup).update(value, "utf8").digest("base64url");
  }

  /** Lookup hashes for every configured key (current first), to find records written before a rotation. */
  lookupHashesAllKeys(value: string): string[] {
    return this.all.map((k) =>
      createHmac("sha256", k.lookup).update(value, "utf8").digest("base64url"),
    );
  }
}

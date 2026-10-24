import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, it } from "node:test";
import { decodeBase64Url, safeEqual } from "../src/crypto/encoding.ts";
import { parseStorageKey, StorageCipher, StorageKeyError } from "../src/crypto/storage.ts";
import { generateRelayToken, hashRelayToken, RELAY_TOKEN_PATTERN } from "../src/crypto/tokens.ts";
import { Store } from "../src/db.ts";
import { apnsToken, INSTANCE, randomKey } from "./helpers.ts";

describe("relay tokens", () => {
  it("are 256-bit base64url and only stored as SHA-256 hashes", () => {
    const store = new Store(":memory:", new StorageCipher(randomKey()));
    const device = apnsToken();
    const { relayToken } = store.register({
      platform: "ios",
      environment: "production",
      bundleId: "app.flowplan.mobile",
      instance: INSTANCE,
      deviceToken: device,
    });
    assert.match(relayToken, RELAY_TOKEN_PATTERN);
    assert.equal(Buffer.from(relayToken, "base64url").length, 32);
    const rows = store.db.prepare("SELECT * FROM devices").all() as Array<Record<string, unknown>>;
    assert.equal(rows.length, 1);
    const dump = JSON.stringify(rows);
    assert.ok(!dump.includes(relayToken), "relay token must not be stored");
    assert.ok(
      !dump.toLowerCase().includes(device),
      "device token must not be stored in plain text",
    );
    assert.equal(rows[0]?.token_hash, hashRelayToken(relayToken));
    assert.match(String(rows[0]?.token_hash), /^[0-9a-f]{64}$/);
    assert.notEqual(generateRelayToken(), generateRelayToken());
    store.close();
  });

  it("re-registering the same (device token, instance) invalidates the old relay token", () => {
    const store = new Store(":memory:", new StorageCipher(randomKey()));
    const input = {
      platform: "ios" as const,
      environment: "production" as const,
      bundleId: "app.flowplan.mobile",
      instance: INSTANCE,
      deviceToken: apnsToken(),
    };
    const a = store.register(input);
    const b = store.register(input);
    const other = store.register({ ...input, instance: "https://other.example.com" });
    assert.equal(store.findByRelayToken(a.relayToken), null);
    assert.ok(store.findByRelayToken(b.relayToken));
    assert.ok(
      store.findByRelayToken(other.relayToken),
      "other instance keeps its own registration",
    );
    assert.equal(b.replaced, 1);
    store.close();
  });
});

describe("encryption at rest", () => {
  it("round-trips and binds ciphertext to its record (AAD)", () => {
    const c = new StorageCipher(randomKey());
    const blob = c.encrypt("secret-token", "aad-1");
    assert.match(blob, /^v1\.[0-9a-f]{12}\.[A-Za-z0-9_-]+$/);
    assert.equal(c.decrypt(blob, "aad-1"), "secret-token");
    assert.throws(() => c.decrypt(blob, "aad-2"));
    assert.notEqual(c.encrypt("secret-token", "aad-1"), blob, "random nonce per encryption");
  });

  it("detects tampering", () => {
    const c = new StorageCipher(randomKey());
    const blob = c.encrypt("secret-token", "a");
    const parts = blob.split(".");
    const raw = Buffer.from(parts[2] as string, "base64url");
    raw[14] = (raw[14] ?? 0) ^ 1;
    assert.throws(() => c.decrypt(`${parts[0]}.${parts[1]}.${raw.toString("base64url")}`, "a"));
  });

  it("supports key rotation via key id and re-encryption", () => {
    const oldKey = randomKey();
    const newKey = randomKey();
    const dir = mkdtempSync(path.join(tmpdir(), "fp-push-"));
    try {
      const s1 = new Store(dir, new StorageCipher(oldKey));
      const device = apnsToken();
      const input = {
        platform: "ios" as const,
        environment: "sandbox" as const,
        bundleId: "app.flowplan.mobile",
        instance: INSTANCE,
        deviceToken: device,
      };
      const { relayToken } = s1.register(input);
      s1.close();
      assert.equal(statSync(path.join(dir, "relay.db")).mode & 0o777, 0o600);

      // Without the old key the record cannot be decrypted.
      const s2 = new Store(dir, new StorageCipher(newKey));
      const rec2 = s2.findByRelayToken(relayToken);
      assert.ok(rec2);
      assert.throws(() => s2.decryptDeviceToken(rec2), StorageKeyError);
      s2.close();

      // With the old key configured as RELAY_STORAGE_KEYS_OLD it can, and rotate-keys re-encrypts.
      const s3 = new Store(dir, new StorageCipher(newKey, [oldKey]));
      const rec3 = s3.findByRelayToken(relayToken);
      assert.ok(rec3);
      assert.equal(s3.decryptDeviceToken(rec3), device);
      // Re-registration before rotation still finds (and replaces) the old record.
      const again = s3.register(input);
      assert.equal(again.replaced, 1);
      const { relayToken: t2 } = s3.register({ ...input, deviceToken: apnsToken() });
      s3.close();

      const s3b = new Store(dir, new StorageCipher(oldKey));
      s3b.register({ ...input, deviceToken: apnsToken() }); // one more record with the old key
      s3b.close();

      const s4 = new Store(dir, new StorageCipher(newKey, [oldKey]));
      assert.deepEqual(s4.reencryptAll(), { reencrypted: 1, failed: 0 });
      s4.close();

      // After rotation the old key is no longer needed.
      const s5 = new Store(dir, new StorageCipher(newKey));
      const counts = s5.stats().devicesByKeyId;
      assert.deepEqual(Object.keys(counts), [new StorageCipher(newKey).currentKeyId]);
      const rec5 = s5.findByRelayToken(again.relayToken);
      assert.ok(rec5);
      assert.equal(s5.decryptDeviceToken(rec5), device);
      assert.ok(s5.findByRelayToken(t2));
      s5.close();

      // The database file contains no plaintext device token.
      const db = new DatabaseSync(path.join(dir, "relay.db"));
      const dump = JSON.stringify(db.prepare("SELECT * FROM devices").all());
      assert.ok(!dump.includes(device));
      db.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses missing, malformed and weak storage keys", () => {
    assert.throws(() => parseStorageKey(undefined), StorageKeyError);
    assert.throws(() => parseStorageKey(""), StorageKeyError);
    assert.throws(() => parseStorageKey("c2hvcnQ="), StorageKeyError);
    assert.throws(() => parseStorageKey(Buffer.alloc(32, 7).toString("base64")), StorageKeyError);
    assert.throws(
      () => parseStorageKey(Buffer.from("ab".repeat(16)).toString("base64")),
      StorageKeyError,
    );
    assert.throws(
      () => parseStorageKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
      StorageKeyError,
    );
    assert.throws(() => parseStorageKey(`${randomKey().toString("base64")}!`), StorageKeyError);
    const k = randomKey();
    assert.deepEqual(parseStorageKey(k.toString("base64")), k);
    assert.deepEqual(parseStorageKey(k.toString("base64url")), k);
  });
});

describe("encoding helpers", () => {
  it("decodes base64url strictly", () => {
    assert.deepEqual(decodeBase64Url("AQID"), Buffer.from([1, 2, 3]));
    assert.deepEqual(decodeBase64Url("AQ"), Buffer.from([1]));
    assert.deepEqual(decodeBase64Url("AQ=="), Buffer.from([1]));
    assert.equal(decodeBase64Url("AR"), null, "non-canonical trailing bits");
    assert.equal(decodeBase64Url("A+B/"), null, "standard alphabet");
    assert.equal(decodeBase64Url("A"), null);
    assert.equal(decodeBase64Url("AQID", 2), null, "size limit");
  });

  it("compares secrets in constant time", () => {
    assert.ok(safeEqual("abc", "abc"));
    assert.ok(!safeEqual("abc", "abd"));
    assert.ok(!safeEqual("abc", "abcd"));
    assert.ok(!safeEqual("", "x"));
  });
});

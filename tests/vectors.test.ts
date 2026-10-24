import assert from "node:assert/strict";
import { createHash, createPublicKey, diffieHellman, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  decryptPayload,
  deriveKey,
  encryptPayload,
  instanceKeyFromSeed,
  signingString,
  signRequest,
  x25519PrivateKey,
  x25519PublicKey,
} from "../examples/instance.ts";
import { parseSignatureHeader, signingInput, verifySignature } from "../src/auth/signature.ts";
import { parseWellKnown } from "../src/instance/keys.ts";
import { messageSchema } from "../src/protocol.ts";

const vectors = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const docsCopy = readFileSync(new URL("../docs/test-vectors.json", import.meta.url), "utf8");

describe("test vectors (PROTOCOL §3, §4)", () => {
  it("docs/test-vectors.json is identical to tests/vectors.json", () => {
    assert.equal(docsCopy, readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
  });

  for (const v of vectors.e2e.vectors) {
    it(`e2e vector "${v.name}": derivation, encryption and decryption match`, () => {
      const devicePriv = x25519PrivateKey(v.devicePrivateKey);
      const ephPriv = x25519PrivateKey(v.ephemeralPrivateKey);
      assert.equal(createPublicKey(devicePriv).export({ format: "jwk" }).x, v.devicePublicKey);
      assert.equal(createPublicKey(ephPriv).export({ format: "jwk" }).x, v.ephemeralPublicKey);
      const shared = diffieHellman({
        privateKey: ephPriv,
        publicKey: x25519PublicKey(v.devicePublicKey),
      });
      assert.equal(shared.toString("hex"), v.sharedSecretHex);
      // Both sides compute the same shared secret.
      const shared2 = diffieHellman({
        privateKey: devicePriv,
        publicKey: x25519PublicKey(v.ephemeralPublicKey),
      });
      assert.equal(shared2.toString("hex"), v.sharedSecretHex);
      const key = deriveKey(
        shared,
        Buffer.from(v.ephemeralPublicKey, "base64url"),
        Buffer.from(v.devicePublicKey, "base64url"),
        v.instance,
      );
      assert.equal(key.toString("hex"), v.keyHex);
      assert.equal(v.hkdfInfo, `flowplan-push-v1\n${v.instance}`);
      assert.equal(v.aad, v.hkdfInfo);
      assert.equal(Buffer.from(v.aadHex, "hex").toString("utf8"), v.aad);
      const payload = encryptPayload(v.instance, v.devicePublicKey, v.plaintext, {
        ephemeralPrivateKey: ephPriv,
        nonce: Buffer.from(v.nonceHex, "hex"),
      });
      assert.equal(payload, v.payload);
      assert.equal(decryptPayload(devicePriv, v.instance, v.payload), v.plaintext);
      // The ciphertext is bound to the instance origin (PROTOCOL §6.9).
      assert.throws(() => decryptPayload(devicePriv, "https://other.example.com", v.payload));
      // The relay accepts the payload as a message payload.
      assert.ok(
        messageSchema.safeParse({ to: "A".repeat(43), type: "alert", payload: v.payload }).success,
      );
    });
  }

  for (const v of vectors.e2e.invalid) {
    it(`e2e invalid vector "${v.name}" fails to decrypt`, () => {
      assert.throws(() =>
        decryptPayload(x25519PrivateKey(v.devicePrivateKey), v.instance, v.payload),
      );
    });
  }

  for (const v of vectors.signatures.vectors) {
    it(`signature vector for ${v.instance} verifies (reference + relay)`, () => {
      assert.equal(createHash("sha256").update(v.body).digest("hex"), v.bodySha256Hex);
      assert.equal(signingString(v.instance, v.ts, v.body), v.signingString);
      assert.equal(
        signingInput(v.instance, String(v.ts), v.body).toString("utf8"),
        v.signingString,
      );
      const key = instanceKeyFromSeed(v.privateKeySeed, v.kid);
      assert.equal(key.publicKey, v.publicKey);
      // Ed25519 is deterministic: re-signing gives the same signature.
      const headers = signRequest({
        instance: v.instance,
        kid: v.kid,
        privateKey: key.privateKey,
        body: v.body,
        ts: v.ts,
      });
      assert.deepEqual(headers, v.headers);
      const [pub] = parseWellKnown(JSON.stringify(v.wellKnown));
      assert.ok(pub);
      const parsed = parseSignatureHeader(v.headers["flowplan-signature"]);
      assert.ok(parsed);
      assert.ok(verifySignature(pub.key, v.instance, parsed, v.body));
      assert.ok(
        verify(null, Buffer.from(v.signingString), pub.key, Buffer.from(v.signature, "base64url")),
      );
    });
  }
});

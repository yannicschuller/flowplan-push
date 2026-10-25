import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { isTimestampFresh, parseSignatureHeader, ReplayCache } from "../src/auth/signature.ts";
import { ConfigError, loadConfig } from "../src/config.ts";
import { StorageKeyError } from "../src/crypto/storage.ts";
import { createLogger } from "../src/log.ts";
import { TokenBucketLimiter } from "../src/ratelimit.ts";
import { randomKey } from "./helpers.ts";

const sig = Buffer.alloc(64, 7).toString("base64url");

describe("signature header", () => {
  it("parses the protocol format", () => {
    const p = parseSignatureHeader(`kid=k1, ts=1767225600, sig=${sig}`);
    assert.equal(p?.kid, "k1");
    assert.equal(p?.ts, "1767225600");
    assert.equal(p?.sig.length, 64);
    assert.ok(parseSignatureHeader(`sig=${sig},kid=k1,ts=1`), "order and whitespace do not matter");
  });
  for (const h of [
    undefined,
    "",
    `kid=k1, ts=1767225600`,
    `kid=k1, ts=1767225600, sig=${sig}, extra=1`,
    `kid=k1, kid=k2, ts=1, sig=${sig}`,
    `kid=k1, ts=-1, sig=${sig}`,
    `kid=k1, ts=0123, sig=${sig}`,
    `kid=k1, ts=1.5, sig=${sig}`,
    `kid=, ts=1, sig=${sig}`,
    `kid=k 1, ts=1, sig=${sig}`,
    `kid=k1, ts=1, sig=${Buffer.alloc(63).toString("base64url")}`,
    `kid=k1, ts=1, sig=${sig}!`,
    `kid=k1, ts=1, sig=${"A".repeat(600)}`,
  ]) {
    it(`rejects ${JSON.stringify(h)?.slice(0, 50)}`, () =>
      assert.equal(parseSignatureHeader(h), null));
  }

  it("accepts timestamps within ±5 minutes only", () => {
    const now = 1_767_225_600_000;
    assert.ok(isTimestampFresh(1_767_225_600, now));
    assert.ok(isTimestampFresh(1_767_225_600 - 300, now));
    assert.ok(isTimestampFresh(1_767_225_600 + 300, now));
    assert.ok(!isTimestampFresh(1_767_225_600 - 301, now));
    assert.ok(!isTimestampFresh(1_767_225_600 + 301, now));
  });

  it("replay cache rejects duplicates inside the window and is bounded", () => {
    let t = 1_000_000_000;
    const c = new ReplayCache(3, () => t);
    const ts = t / 1000;
    assert.ok(c.checkAndRemember("a", ts));
    assert.ok(!c.checkAndRemember("a", ts));
    assert.ok(c.checkAndRemember("b", ts));
    assert.ok(c.checkAndRemember("c", ts));
    assert.ok(c.checkAndRemember("d", ts));
    assert.ok(c.size <= 3);
    t += 306_000; // window over → entries expire
    assert.ok(c.checkAndRemember("e", t / 1000));
    assert.ok(c.size <= 3);
  });
});

describe("token bucket", () => {
  it("grants bursts, refills over time and reports retryAfter", () => {
    let t = 0;
    const l = new TokenBucketLimiter(100, 600, 60_000, 1000, () => t);
    assert.equal(l.take("i", 100).granted, 100);
    const r = l.take("i", 5);
    assert.equal(r.granted, 0);
    assert.equal(r.retryAfter, 1);
    t += 1000;
    assert.equal(l.take("i", 20).granted, 10);
    t += 60_000;
    assert.equal(l.take("i", 200).granted, 100, "capped at burst");
  });

  it("bounds memory", () => {
    const l = new TokenBucketLimiter(1, 1, 1000, 10, () => 0);
    for (let i = 0; i < 100; i++) l.take(`k${i}`);
    assert.ok(l.size <= 10);
  });
});

describe("logger", () => {
  it("redacts sensitive fields and truncates long strings", () => {
    const lines: string[] = [];
    const log = createLogger("debug", (l) => lines.push(l));
    log.info("x", {
      token: "secret",
      relayToken: "secret",
      payload: "secret",
      nested: { deviceToken: "secret", authorization: "secret" },
      kid: "k1",
      long: "y".repeat(1000),
    });
    const entry = JSON.parse(lines[0] ?? "{}");
    assert.ok(!lines[0]?.includes("secret"));
    assert.equal(entry.kid, "k1");
    assert.ok(entry.long.length < 400);
    const quiet = createLogger("warn", (l) => lines.push(l));
    quiet.info("hidden");
    assert.equal(lines.length, 1);
  });
});

describe("configuration", () => {
  const key = randomKey().toString("base64");
  it("refuses to start without or with a weak RELAY_STORAGE_KEY", () => {
    assert.throws(() => loadConfig({}), StorageKeyError);
    assert.throws(() => loadConfig({ RELAY_STORAGE_KEY: "changeme" }), StorageKeyError);
    assert.throws(
      () => loadConfig({ RELAY_STORAGE_KEY: Buffer.alloc(32).toString("base64") }),
      StorageKeyError,
    );
    assert.throws(
      () => loadConfig({ RELAY_STORAGE_KEY: key, RELAY_STORAGE_KEYS_OLD: key }),
      ConfigError,
    );
  });

  it("has safe defaults and starts without APNs/FCM", () => {
    const c = loadConfig({ RELAY_STORAGE_KEY: key });
    assert.equal(c.apns, null);
    assert.equal(c.fcm, null);
    assert.equal(c.port, 8080);
    assert.equal(c.allowPrivateInstances, false);
    assert.equal(c.trustProxyHops, 0);
    assert.deepEqual(c.allowedBundleIds, ["app.flowplan.mobile"]);
    assert.equal(c.publicUrl, "https://push.flowplan.org");
    assert.equal(c.metricsToken, null);
  });

  it("parses APNs and FCM credentials (PEM, escaped newlines, base64)", () => {
    const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
      format: "pem",
      type: "pkcs8",
    }) as string;
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
      format: "pem",
      type: "pkcs8",
    }) as string;
    const sa = JSON.stringify({
      type: "service_account",
      project_id: "flowplan-12345",
      client_email: "a@b.iam.gserviceaccount.com",
      private_key: rsa,
    });
    for (const apnsKey of [ec, ec.replace(/\n/g, "\\n"), Buffer.from(ec).toString("base64")]) {
      const c = loadConfig({
        RELAY_STORAGE_KEY: key,
        APNS_KEY: apnsKey,
        APNS_KEY_ID: "ABCDEFGHIJ",
        APNS_TEAM_ID: "ABCDE12345",
        FCM_SERVICE_ACCOUNT: sa,
      });
      assert.equal(c.apns?.teamId, "ABCDE12345");
      assert.equal(c.fcm?.projectId, "flowplan-12345");
    }
    assert.throws(
      () => loadConfig({ RELAY_STORAGE_KEY: key, APNS_KEY: ec }),
      ConfigError,
      "key id missing",
    );
    assert.throws(
      () => loadConfig({ RELAY_STORAGE_KEY: key, APNS_KEY: ec, APNS_KEY_ID: "ABCDEFGHIJ" }),
      /APNS_TEAM_ID/,
      "team id is required (no built-in default)",
    );
    assert.throws(
      () =>
        loadConfig({
          RELAY_STORAGE_KEY: key,
          APNS_KEY: rsa,
          APNS_KEY_ID: "ABCDEFGHIJ",
          APNS_TEAM_ID: "ABCDE12345",
        }),
      ConfigError,
      "not EC",
    );
    assert.throws(
      () => loadConfig({ RELAY_STORAGE_KEY: key, FCM_SERVICE_ACCOUNT: "{}" }),
      ConfigError,
    );
    assert.throws(
      () => loadConfig({ RELAY_STORAGE_KEY: key, METRICS_TOKEN: "short" }),
      ConfigError,
    );
    assert.throws(() => loadConfig({ RELAY_STORAGE_KEY: key, TRUST_PROXY: "maybe" }), ConfigError);
    assert.equal(loadConfig({ RELAY_STORAGE_KEY: key, TRUST_PROXY: "true" }).trustProxyHops, 1);
    assert.equal(loadConfig({ RELAY_STORAGE_KEY: key, TRUST_PROXY: "2" }).trustProxyHops, 2);
  });
});

describe("admin CLI", () => {
  it("blocks, lists, unblocks and reports stats", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "fp-cli-"));
    const env = {
      ...process.env,
      RELAY_STORAGE_KEY: randomKey().toString("base64"),
      DATA_DIR: dir,
    };
    const cli = (...args: string[]) =>
      execFileSync(
        process.execPath,
        [
          "--disable-warning=ExperimentalWarning",
          path.resolve(import.meta.dirname, "../src/cli.ts"),
          ...args,
        ],
        {
          env,
          encoding: "utf8",
        },
      );
    try {
      assert.match(
        cli("block", "https://Spam.example.com/", "sends", "spam"),
        /blocked https:\/\/spam\.example\.com/,
      );
      assert.match(cli("blocked"), /https:\/\/spam\.example\.com\t.*\tsends spam/);
      assert.match(cli("unblock", "https://spam.example.com"), /unblocked/);
      assert.match(cli("blocked"), /no blocked instances/);
      assert.match(cli("stats"), /Registrations by platform/);
      assert.equal(JSON.parse(cli("stats", "--json")).blocked, 0);
      assert.match(cli("rotate-keys"), /re-encrypted 0/);
      assert.equal(Buffer.from(cli("generate-key").trim(), "base64").length, 32);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

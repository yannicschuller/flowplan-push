import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { newRequestId } from "../examples/instance.ts";
import { StorageCipher } from "../src/crypto/storage.ts";
import { Store } from "../src/db.ts";
import { HOURLY_RETENTION, StatsCollector, shortDeviceId } from "../src/stats.ts";
import { INSTANCE, randomKey, startRelay, type TestRelay } from "./helpers.ts";

function setup(startMs = Date.UTC(2026, 9, 25, 12, 0, 30)) {
  let now = startMs;
  const store = new Store(":memory:", new StorageCipher(randomKey()), () => Math.floor(now / 1000));
  const mk = () =>
    new StatsCollector(store, { apns: true, fcm: false, now: () => now, autoFlush: false });
  return {
    store,
    stats: mk(),
    mk,
    advance(ms: number) {
      now += ms;
    },
    get now() {
      return now;
    },
  };
}

describe("statistics aggregation", () => {
  it("aggregates per minute and per hour, globally and per instance", () => {
    const s = setup();
    const A = "https://a.example.com";
    const B = "https://b.example.com";
    s.stats.message({ instance: A, platform: "ios", status: "ok" });
    s.stats.message({ instance: A, platform: "ios", status: "ok" });
    s.stats.message({ instance: B, platform: "android", status: "error", reason: "x" });
    s.advance(60_000);
    s.stats.message({ instance: A, platform: "ios", status: "gone" });
    const series = s.stats.minuteSeries("msg", null);
    assert.equal(series.length, 60);
    assert.deepEqual(series.slice(-2), [3, 1]);
    assert.deepEqual(s.stats.minuteSeries("msg", ["ok"], A).slice(-2), [2, 0]);
    assert.deepEqual(s.stats.lastMinutes("msg"), { ok: 2, error: 1, gone: 1 });
    assert.deepEqual(s.stats.lastMinutes("msg", B), { error: 1 });
    assert.deepEqual(s.stats.lastHours("msg", A, 24), { ok: 2, gone: 1 });
    assert.deepEqual(s.stats.lastMinutes("msgp"), {
      "ios:ok": 2,
      "android:error": 1,
      "ios:gone": 1,
    });
    const top = s.stats.topInstances();
    assert.equal(top[0]?.instance, A);
    assert.equal(top[0]?.messages24h, 3);
    assert.equal(top[1]?.errors24h, 1);
  });

  it("counts the instances that sent within 24 hours and 7 days", () => {
    const s = setup();
    s.stats.message({ instance: "https://a.example.com", platform: "ios", status: "ok" });
    s.stats.count("reg", "ios", "https://c.example.com"); // registered only, never sent
    s.stats.flush();
    s.advance(3 * 86_400_000);
    s.stats.message({ instance: "https://b.example.com", platform: "android", status: "error" });
    s.stats.flush();
    assert.equal(s.store.activeInstanceCount(24), 1);
    assert.equal(s.store.activeInstanceCount(24 * 7), 2);
    s.advance(5 * 86_400_000);
    assert.equal(s.store.activeInstanceCount(24 * 7), 1);
  });

  it("rolls the live window: data older than 60 minutes leaves the last-hour view", () => {
    const s = setup();
    s.stats.count("auth", "invalid_signature", null);
    s.advance(30 * 60_000);
    s.stats.count("auth", "replayed", null);
    assert.deepEqual(s.stats.lastMinutes("auth"), { invalid_signature: 1, replayed: 1 });
    s.advance(31 * 60_000);
    assert.deepEqual(s.stats.lastMinutes("auth"), { replayed: 1 });
    assert.deepEqual(s.stats.lastHours("auth", "", 24), { invalid_signature: 1, replayed: 1 });
    const hours = s.stats.hourSeries("auth", null, "", 24);
    assert.equal(
      hours.reduce((a, b) => a + b, 0),
      2,
    );
  });

  it("persists across restarts (new collector, same database)", () => {
    const s = setup();
    s.stats.message({ instance: INSTANCE, platform: "ios", status: "ok" });
    s.stats.close(); // flushes
    const again = s.mk();
    assert.deepEqual(again.lastMinutes("msg"), { ok: 1 });
    assert.deepEqual(again.lastHours("msg", INSTANCE), { ok: 1 });
  });

  it("prunes minute rows after 2 hours and hourly rows after 30 days", () => {
    const s = setup();
    s.stats.count("reg", "ios", INSTANCE);
    s.stats.flush();
    s.advance(3 * 3600_000);
    s.stats.prune();
    assert.equal(
      (s.store.db.prepare("SELECT COUNT(*) AS n FROM stats_minute").get() as { n: number }).n,
      0,
    );
    assert.equal(s.stats.lastHours("reg", INSTANCE, 24 * 31).ios, 1);
    s.advance((HOURLY_RETENTION + 1) * 3600_000);
    s.stats.prune();
    assert.equal(
      (s.store.db.prepare("SELECT COUNT(*) AS n FROM stats_hourly").get() as { n: number }).n,
      0,
    );
  });

  it("tracks provider health and anonymized recent events", () => {
    const s = setup();
    s.stats.message({ instance: INSTANCE, platform: "ios", status: "ok" });
    s.advance(1000);
    s.stats.message({
      instance: INSTANCE,
      platform: "ios-liveactivity",
      status: "error",
      reason: "BadTopic",
    });
    assert.ok(s.stats.providers.apns.lastOkAt);
    assert.equal(s.stats.providers.apns.lastErrorReason, "BadTopic");
    assert.equal(s.stats.providers.fcm.configured, false);
    s.stats.registration({
      instance: INSTANCE,
      platform: "ios",
      deviceId: shortDeviceId("h"),
      ip: "203.0.113.77",
    });
    s.stats.sendCompleted({
      instance: INSTANCE,
      ip: "2001:db8:1:2::7",
      results: { ok: 3, gone: 1 },
    });
    const ev = s.stats.recentEvents(INSTANCE);
    assert.equal(ev[0]?.detail, "send: 3 ok, 1 gone");
    assert.equal(ev[0]?.ip, "2001:db8:1::");
    assert.equal(ev[1]?.ip, "203.0.113.0");
    assert.match(ev[1]?.device ?? "", /^[0-9a-f]{10}$/);
    for (let i = 0; i < 80; i++)
      s.stats.sendCompleted({ instance: INSTANCE, ip: "203.0.113.1", results: {} });
    assert.equal(s.stats.recentEvents(INSTANCE).length, 50, "bounded");
  });
});

describe("relay integration of statistics, kill switch and IP blocks", () => {
  let relay: TestRelay | null = null;
  afterEach(async () => {
    await relay?.close();
    relay = null;
  });

  it("paused relay answers 503 relay_paused without contacting APNs; resume restores delivery", async () => {
    relay = await startRelay();
    const { relayToken } = await relay.registerIos();
    const msg = { to: relayToken, type: "background", payload: "AQ".padEnd(40, "A") };
    relay.store.setPause({ by: "test", reason: "incident" });
    const paused = await relay.send([msg]);
    assert.equal(paused.status, 503);
    assert.equal(paused.headers.get("retry-after"), "300");
    assert.deepEqual(paused.json, { error: "relay_paused", retryAfter: 300 });
    assert.equal(relay.apnsMock?.calls.length, 0);
    assert.equal(relay.fetches.length, 0, "no key fetch while paused");
    relay.store.setPause(null);
    const ok = await relay.sendRaw(JSON.stringify({ requestId: newRequestId(), messages: [msg] }));
    assert.equal(ok.status, 200);
  });

  it("refuses registrations from blocked IP ranges until the block expires", async () => {
    let now = Date.now();
    relay = await startRelay({ now: () => now });
    relay.store.blockIp("127.0.0.0/8", "flood", Math.floor(now / 1000) + 60, "test");
    const r = await relay.register({
      platform: "ios",
      token: "ab".repeat(32),
      environment: "production",
      bundleId: "app.flowplan.mobile",
      instance: INSTANCE,
    });
    assert.equal(r.status, 403);
    assert.deepEqual(r.json, { error: "ip_blocked" });
    now += 61_000;
    await relay.registerIos();
  });

  it("temporary instance blocks expire", async () => {
    let now = Date.now();
    relay = await startRelay({ now: () => now });
    relay.store.block(INSTANCE, "x", { expiresAt: Math.floor(now / 1000) + 60 });
    assert.equal(relay.store.isBlocked(INSTANCE), true);
    now += 61_000;
    assert.equal(relay.store.isBlocked(INSTANCE), false);
    assert.equal(relay.store.listBlocked().length, 0);
  });
});

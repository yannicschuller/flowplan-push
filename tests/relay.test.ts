import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import {
  encryptPayload,
  generateDeviceKey,
  generateInstanceKey,
  signRequest,
} from "../examples/instance.ts";
import { apnsToken, BUNDLE, fcmToken, INSTANCE, startRelay, type TestRelay } from "./helpers.ts";

const device = generateDeviceKey();
const plaintext = {
  title: "Hi",
  body: "There",
  url: null,
  id: "n1",
  category: "task",
  data: null,
  sentAt: 1,
};
const payload = () => encryptPayload(device.publicKey, plaintext);
const alert = (to: string, extra: Record<string, unknown> = {}) => ({
  to,
  type: "alert",
  payload: payload(),
  category: "task",
  priority: "high",
  ttl: 3600,
  ...extra,
});

let relay: TestRelay | null = null;
afterEach(async () => {
  await relay?.close();
  relay = null;
});

describe("registration (POST /v1/devices)", () => {
  it("registers iOS and Android devices", async () => {
    relay = await startRelay();
    const r = await relay.register({
      platform: "ios",
      token: apnsToken(),
      environment: "sandbox",
      bundleId: BUNDLE,
      instance: INSTANCE,
    });
    assert.equal(r.status, 201);
    assert.match(String(r.json?.relayToken), /^[A-Za-z0-9_-]{43}$/);
    const exp = Date.parse(String(r.json?.expiresAt));
    assert.ok(Math.abs(exp - (Date.now() + 180 * 86400_000)) < 60_000);
    assert.equal(r.headers.get("cache-control"), "no-store");
    assert.equal(r.headers.get("x-content-type-options"), "nosniff");
    assert.equal(r.headers.get("access-control-allow-origin"), null, "no CORS");
    assert.ok(r.headers.get("strict-transport-security"));
    const rec = relay.store.findByRelayToken(String(r.json?.relayToken));
    assert.equal(rec?.environment, "sandbox");
    assert.equal(rec?.instance, INSTANCE);

    const a = await relay.register({
      platform: "android",
      token: fcmToken(),
      bundleId: BUNDLE,
      instance: "https://App.Flowplan.org/",
    });
    assert.equal(a.status, 201);
    assert.equal(
      relay.store.findByRelayToken(String(a.json?.relayToken))?.instance,
      INSTANCE,
      "origin canonicalised",
    );

    const la = await relay.register({
      platform: "ios-liveactivity",
      token: apnsToken(),
      environment: "production",
      bundleId: BUNDLE,
      instance: INSTANCE,
    });
    assert.equal(la.status, 201);
  });

  it("re-registration returns a fresh token and invalidates the old one", async () => {
    relay = await startRelay();
    const token = apnsToken();
    const body = {
      platform: "ios",
      token,
      environment: "production",
      bundleId: BUNDLE,
      instance: INSTANCE,
    };
    const a = await relay.register(body);
    const b = await relay.register({ ...body, token: token.toUpperCase() });
    assert.notEqual(a.json?.relayToken, b.json?.relayToken);
    assert.equal(relay.store.findByRelayToken(String(a.json?.relayToken)), null);
    assert.ok(relay.store.findByRelayToken(String(b.json?.relayToken)));
  });

  it("validates input", async () => {
    relay = await startRelay();
    const base = {
      platform: "ios",
      token: apnsToken(),
      environment: "production",
      bundleId: BUNDLE,
      instance: INSTANCE,
    };
    assert.equal((await relay.register({ ...base, platform: "windows" })).status, 400);
    assert.equal((await relay.register({ ...base, token: "nothex" })).status, 400);
    assert.equal((await relay.register({ ...base, token: "ab".repeat(10) })).status, 400);
    assert.equal(
      (await relay.register({ ...base, platform: "android", token: "short" })).status,
      400,
    );
    assert.equal((await relay.register({ ...base, environment: "staging" })).status, 400);
    assert.deepEqual((await relay.register({ ...base, token: 5 })).json, {
      error: "invalid_request",
      fields: ["token"],
    });
    assert.deepEqual((await relay.register({ ...base, bundleId: "com.evil.app" })).json, {
      error: "bundle_not_allowed",
    });
    for (const instance of [
      "http://app.flowplan.org",
      "https://127.0.0.1",
      "https://app.flowplan.org/x",
      "https://localhost",
    ]) {
      const r = await relay.register({ ...base, instance });
      assert.equal(r.status, 400, instance);
      assert.deepEqual(r.json, { error: "invalid_instance" });
    }
  });

  it("rejects wrong content types, oversized bodies and malformed JSON", async () => {
    relay = await startRelay();
    const post = (body: string, ctype = "application/json") =>
      fetch(`${relay?.url}/v1/devices`, {
        method: "POST",
        headers: { "content-type": ctype },
        body,
      });
    assert.equal((await post("{}", "text/plain")).status, 415);
    assert.equal((await post("{not json")).status, 400);
    assert.equal((await post(JSON.stringify({ pad: "x".repeat(20_000) }))).status, 413);
    const r = await fetch(`${relay.url}/v1/devices`, { method: "GET" });
    assert.equal(r.status, 405);
    assert.equal(r.headers.get("allow"), "POST");
    assert.equal((await fetch(`${relay.url}/nope`)).status, 404);
    const pre = await fetch(`${relay.url}/v1/devices`, {
      method: "OPTIONS",
      headers: { origin: "https://evil.example" },
    });
    assert.equal(pre.status, 405);
    assert.equal(pre.headers.get("access-control-allow-origin"), null);
  });

  it("rate-limits registrations to 30 per IP and hour", async () => {
    relay = await startRelay();
    const base = {
      platform: "ios",
      environment: "production",
      bundleId: BUNDLE,
      instance: INSTANCE,
    };
    for (let i = 0; i < 30; i++) {
      assert.equal((await relay.register({ ...base, token: apnsToken() })).status, 201, `#${i}`);
    }
    const r = await relay.register({ ...base, token: apnsToken() });
    assert.equal(r.status, 429);
    assert.ok(Number(r.headers.get("retry-after")) > 0);
  });

  it("uses X-Forwarded-For only behind trusted proxies", async () => {
    relay = await startRelay({ trustProxyHops: 1, limits: { registerPerIpPerHour: 1 } });
    const base = {
      platform: "ios",
      environment: "production",
      bundleId: BUNDLE,
      instance: INSTANCE,
    };
    assert.equal(
      (await relay.register({ ...base, token: apnsToken() }, { "x-forwarded-for": "203.0.113.1" }))
        .status,
      201,
    );
    assert.equal(
      (await relay.register({ ...base, token: apnsToken() }, { "x-forwarded-for": "203.0.113.2" }))
        .status,
      201,
    );
    assert.equal(
      (await relay.register({ ...base, token: apnsToken() }, { "x-forwarded-for": "203.0.113.2" }))
        .status,
      429,
    );
    // A client-supplied entry in front of the proxy's entry is ignored.
    assert.equal(
      (
        await relay.register(
          { ...base, token: apnsToken() },
          { "x-forwarded-for": "1.2.3.4, 203.0.113.2" },
        )
      ).status,
      429,
    );
  });

  it("DELETE /v1/devices/{token} removes the registration and never reveals existence", async () => {
    relay = await startRelay();
    const { relayToken } = await relay.registerIos();
    const del = (t: string) => fetch(`${relay?.url}/v1/devices/${t}`, { method: "DELETE" });
    assert.equal((await del(relayToken)).status, 204);
    assert.equal(relay.store.findByRelayToken(relayToken), null);
    assert.equal((await del(relayToken)).status, 204);
    assert.equal((await del("A".repeat(43))).status, 204);
    assert.equal((await del("bad!token")).status, 400);
  });

  it("refuses registrations for blocked instances", async () => {
    relay = await startRelay();
    relay.store.block(INSTANCE, "abuse");
    const r = await relay.register({
      platform: "ios",
      token: apnsToken(),
      environment: "production",
      bundleId: BUNDLE,
      instance: INSTANCE,
    });
    assert.equal(r.status, 403);
    assert.deepEqual(r.json, { error: "instance_blocked" });
    relay.store.unblock(INSTANCE);
    await relay.registerIos();
  });
});

describe("sending (POST /v1/send)", () => {
  it("delivers an E2E-encrypted alert to APNs and Android to FCM", async () => {
    relay = await startRelay();
    const ios = await relay.registerIos();
    const android = await relay.registerAndroid();
    const p = payload();
    const r = await relay.send([
      alert(ios.relayToken, { payload: p, collapseId: "t1", badge: 2 }),
      alert(android.relayToken, { payload: p }),
    ]);
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { results: [{ status: "ok" }, { status: "ok" }] });
    const call = relay.apnsMock?.calls[0];
    assert.equal(call?.headers[":path"], `/3/device/${ios.deviceToken}`);
    assert.equal(call?.body.fp, p);
    assert.deepEqual((call?.body.aps as Record<string, unknown> | undefined)?.alert, {
      title: "Flowplan",
      body: "New notification",
    });
    const fcm = JSON.parse(relay.fcmMock?.sendCalls[0]?.body ?? "{}");
    assert.equal(fcm.message.token, android.deviceToken);
    assert.equal(fcm.message.data.fp, p);
    // the relay only ever saw ciphertext
    assert.ok(!JSON.stringify(call?.body).includes("There"));
  });

  it("rejects invalid, expired, wrong-instance and replayed signatures", async () => {
    relay = await startRelay();
    const ios = await relay.registerIos();
    const body = JSON.stringify({ messages: [alert(ios.relayToken)] });

    // expired / future timestamps
    assert.deepEqual(
      (await relay.sendRaw(body, { ts: Math.floor(Date.now() / 1000) - 301 })).json,
      { error: "stale_timestamp" },
    );
    assert.equal(
      (await relay.sendRaw(body, { ts: Math.floor(Date.now() / 1000) + 301 })).status,
      401,
    );
    // wrong key with the same kid (forged)
    const forged = generateInstanceKey(relay.instance.kid);
    assert.deepEqual((await relay.sendRaw(body, { key: forged })).json, {
      error: "invalid_signature",
    });
    // unknown kid
    assert.deepEqual((await relay.sendRaw(body, { key: generateInstanceKey("other-kid") })).json, {
      error: "unknown_key",
    });
    // signature over a different body
    const signed = signRequest({
      instance: INSTANCE,
      kid: relay.instance.kid,
      privateKey: relay.instance.privateKey,
      body: "{}",
    });
    const tampered = await fetch(`${relay.url}/v1/send`, {
      method: "POST",
      headers: { "content-type": "application/json", ...signed },
      body,
    });
    assert.equal(tampered.status, 401);
    // malformed header
    const bad = await fetch(`${relay.url}/v1/send`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "flowplan-instance": INSTANCE,
        "flowplan-signature": "kid=x, ts=1",
      },
      body,
    });
    assert.equal(bad.status, 401);
    // non-canonical instance header
    assert.deepEqual((await relay.sendRaw(body, { instance: "https://app.flowplan.org/" })).json, {
      error: "invalid_instance",
    });
    assert.equal(relay.apnsMock?.calls.length, 0);

    // valid → ok, identical replay → 409
    const ts = Math.floor(Date.now() / 1000);
    assert.deepEqual((await relay.sendRaw(body, { ts })).json, { results: [{ status: "ok" }] });
    assert.deepEqual((await relay.sendRaw(body, { ts })).json, { error: "replayed" });
    assert.equal(relay.apnsMock?.calls.length, 1);
  });

  it("a token registered for another instance is forbidden (indistinguishable from unknown)", async () => {
    relay = await startRelay();
    const other = "https://evil.example.com";
    const evilKey = generateInstanceKey();
    relay.instanceKeys.set(other, [evilKey]);
    const victim = await relay.registerIos();
    // the attacker has one device of its own so its keys get fetched
    await relay.register({
      platform: "ios",
      token: apnsToken(),
      environment: "production",
      bundleId: BUNDLE,
      instance: other,
    });
    const r = await relay.send([alert(victim.relayToken), alert("B".repeat(43))], {
      instance: other,
      key: evilKey,
    });
    assert.deepEqual(r.json, { results: [{ status: "forbidden" }, { status: "forbidden" }] });
    assert.equal(relay.apnsMock?.calls.length, 0);
  });

  it("does not fetch keys for origins without registrations", async () => {
    relay = await startRelay();
    const r = await relay.send([alert("C".repeat(43)), { to: "x" }], {
      instance: "https://unknown.example.com",
    });
    assert.deepEqual(r.json, { results: [{ status: "forbidden" }, { status: "invalid" }] });
    assert.deepEqual(relay.fetches, []);
  });

  it("maps APNs gone → deletes the registration", async () => {
    relay = await startRelay();
    const ios = await relay.registerIos();
    relay.apnsMock?.setResponder(() => ({ status: 410, reason: "Unregistered" }));
    assert.deepEqual((await relay.send([alert(ios.relayToken)])).json, {
      results: [{ status: "gone" }],
    });
    assert.equal(relay.store.findByRelayToken(ios.relayToken), null);
    assert.deepEqual((await relay.send([alert(ios.relayToken)])).json, {
      results: [{ status: "forbidden" }],
    });
  });

  it("maps FCM UNREGISTERED → gone", async () => {
    relay = await startRelay();
    const a = await relay.registerAndroid();
    relay.fcmMock?.setResponder(() => ({
      status: 404,
      body: { error: { status: "NOT_FOUND", details: [{ errorCode: "UNREGISTERED" }] } },
    }));
    assert.deepEqual((await relay.send([alert(a.relayToken)])).json, {
      results: [{ status: "gone" }],
    });
    assert.equal(relay.store.findByRelayToken(a.relayToken), null);
  });

  it("validates messages individually and enforces size limits", async () => {
    relay = await startRelay();
    const ios = await relay.registerIos();
    const la = await relay.register({
      platform: "ios-liveactivity",
      token: apnsToken(),
      environment: "production",
      bundleId: BUNDLE,
      instance: INSTANCE,
    });
    const laToken = String(la.json?.relayToken);
    const tooBig = Buffer.alloc(3001, 1);
    const r = await relay.send([
      alert(ios.relayToken),
      alert(ios.relayToken, {
        payload: Buffer.concat([Buffer.from([1]), tooBig]).toString("base64url"),
      }), // > 3000 bytes
      alert(ios.relayToken, {
        payload: Buffer.from([2, ...Buffer.alloc(80)]).toString("base64url"),
      }), // wrong version
      alert(ios.relayToken, { payload: "not base64!" }),
      alert(ios.relayToken, { collapseId: "x".repeat(65) }),
      alert(ios.relayToken, { badge: 10_000 }),
      alert(ios.relayToken, { ttl: 2_419_201 }),
      alert(ios.relayToken, { category: "evil" }),
      {
        to: laToken,
        type: "liveactivity",
        liveActivity: { event: "update", contentState: { big: "x".repeat(2100) } },
      },
      {
        to: laToken,
        type: "liveactivity",
        liveActivity: { event: "update", contentState: { n: 1 } },
      },
      alert(laToken), // alert to a live-activity token
      {
        to: ios.relayToken,
        type: "liveactivity",
        liveActivity: { event: "end", contentState: {} },
      }, // LA to a normal token
    ]);
    assert.deepEqual(
      (r.json?.results as Array<{ status: string }> | undefined)?.map((x) => x.status),
      [
        "ok",
        "invalid",
        "invalid",
        "invalid",
        "invalid",
        "invalid",
        "invalid",
        "invalid",
        "invalid",
        "ok",
        "invalid",
        "invalid",
      ],
    );
    const laCall = relay.apnsMock?.calls.find(
      (c) => c.headers["apns-push-type"] === "liveactivity",
    );
    assert.equal(laCall?.headers["apns-topic"], `${BUNDLE}.push-type.liveactivity`);

    // 0 or > 100 messages → 400
    assert.equal((await relay.send([])).status, 400);
    assert.equal(
      (await relay.send(Array.from({ length: 101 }, () => alert(ios.relayToken)))).status,
      400,
    );
    // > 512 KB body → 413
    const huge = JSON.stringify({ messages: [alert(ios.relayToken)], pad: "x".repeat(520 * 1024) });
    assert.equal((await relay.sendRaw(huge)).status, 413);
    // body must be JSON
    assert.equal((await relay.sendRaw("[1,2")).status, 400);
  });

  it("rate-limits per instance (burst 100, 600/min) with retryAfter", async () => {
    let t = Date.now();
    relay = await startRelay({ now: () => t });
    const ios = await relay.registerIos();
    const batch = () => Array.from({ length: 60 }, () => alert(ios.relayToken));
    const first = (await relay.send(batch())).json?.results as Array<{
      status: string;
      retryAfter?: number;
    }>;
    assert.ok(first.every((x) => x.status === "ok"));
    const second = (await relay.send(batch())).json?.results as Array<{
      status: string;
      retryAfter?: number;
    }>;
    assert.equal(second.filter((x) => x.status === "ok").length, 40);
    const limited = second.filter((x) => x.status === "rate_limited");
    assert.equal(limited.length, 20);
    assert.ok(limited.every((x) => (x.retryAfter ?? 0) >= 1));
    // 10 tokens per second refill
    t += 2000;
    const third = (await relay.send(batch())).json?.results as Array<{ status: string }>;
    assert.equal(third.filter((x) => x.status === "ok").length, 20);
  });

  it("locks out an IP after repeated authentication failures", async () => {
    relay = await startRelay({ limits: { authFailuresPerIpPer10Min: 3 } });
    const ios = await relay.registerIos();
    const body = JSON.stringify({ messages: [alert(ios.relayToken)] });
    const forged = generateInstanceKey(relay.instance.kid);
    for (let i = 0; i < 3; i++)
      assert.equal((await relay.sendRaw(body, { key: forged })).status, 401);
    const r = await relay.sendRaw(body);
    assert.equal(r.status, 429, "even a valid request is refused while locked out");
  });

  it("enforces the blocklist on send", async () => {
    relay = await startRelay();
    const ios = await relay.registerIos();
    relay.store.block(INSTANCE, null);
    const r = await relay.send([alert(ios.relayToken)]);
    assert.equal(r.status, 403);
    assert.deepEqual(r.json, { error: "instance_blocked" });
    relay.store.unblock(INSTANCE);
    assert.deepEqual((await relay.send([alert(ios.relayToken)])).json, {
      results: [{ status: "ok" }],
    });
  });

  it("answers error for a platform that is not configured", async () => {
    relay = await startRelay({ apns: false, fcm: false });
    const ios = await relay.registerIos();
    const a = await relay.registerAndroid();
    assert.deepEqual((await relay.send([alert(ios.relayToken), alert(a.relayToken)])).json, {
      results: [{ status: "error" }, { status: "error" }],
    });
  });

  it("answers 502 when the instance keys cannot be fetched", async () => {
    relay = await startRelay();
    const ios = await relay.registerIos();
    relay.instanceKeys.delete(INSTANCE);
    const r = await relay.send([alert(ios.relayToken)]);
    assert.equal(r.status, 502);
    assert.deepEqual(r.json, { error: "instance_keys_unavailable" });
  });

  it("successful sends extend the expiry", async () => {
    let t = Date.now();
    relay = await startRelay({ now: () => t });
    const ios = await relay.registerIos();
    const before = relay.store.findByRelayToken(ios.relayToken)?.expiresAt ?? 0;
    t += 2 * 3600_000;
    assert.deepEqual((await relay.send([alert(ios.relayToken)])).json, {
      results: [{ status: "ok" }],
    });
    const afterExp = relay.store.findByRelayToken(ios.relayToken)?.expiresAt ?? 0;
    assert.ok(afterExp >= before + 7200);
    // expired registrations are not usable
    t += 181 * 86400_000;
    assert.equal(relay.store.findByRelayToken(ios.relayToken), null);
  });
});

describe("health and metrics", () => {
  it("/healthz is public and reveals nothing", async () => {
    relay = await startRelay();
    const r = await fetch(`${relay.url}/healthz`);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { status: "ok" });
  });

  it("/metrics requires METRICS_TOKEN and is hidden without it", async () => {
    relay = await startRelay();
    assert.equal((await fetch(`${relay.url}/metrics`)).status, 404);
    await relay.close();
    const token = "m".repeat(40);
    relay = await startRelay({ metricsToken: token });
    assert.equal((await fetch(`${relay.url}/metrics`)).status, 401);
    assert.equal(
      (
        await fetch(`${relay.url}/metrics`, {
          headers: { authorization: `Bearer ${"x".repeat(40)}` },
        })
      ).status,
      401,
    );
    const ios = await relay.registerIos();
    await relay.send([alert(ios.relayToken)]);
    const r = await fetch(`${relay.url}/metrics`, {
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(r.status, 200);
    const text = await r.text();
    assert.match(text, /flowplan_push_messages_total\{platform="ios",status="ok"\} 1/);
    assert.match(text, /flowplan_push_registrations_total\{platform="ios"\} 1/);
    assert.ok(!text.includes(ios.relayToken));
  });
});

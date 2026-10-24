import assert from "node:assert/strict";
import { verify } from "node:crypto";
import { after, before, describe, it } from "node:test";
import { encryptPayload, generateDeviceKey } from "../examples/instance.ts";
import type { DeviceRecord } from "../src/db.ts";
import { messageSchema } from "../src/protocol.ts";
import { ApnsClient, buildApnsJwt, mapApnsResponse } from "../src/push/apns.ts";
import { buildApnsRequest, buildFcmMessage } from "../src/push/build.ts";
import { FcmClient, mapFcmResponse, parseFcmError } from "../src/push/fcm.ts";
import {
  apnsTestConfig,
  apnsToken,
  BUNDLE,
  fcmTestConfig,
  fcmToken,
  INSTANCE,
  startMockApns,
  startMockFcm,
} from "./helpers.ts";

const device = generateDeviceKey();
const payload = encryptPayload(device.publicKey, {
  title: "t",
  body: "b",
  url: null,
  id: "1",
  category: null,
  data: null,
  sentAt: 1,
});

function rec(
  platform: DeviceRecord["platform"],
  environment: DeviceRecord["environment"] = "production",
): DeviceRecord {
  return {
    tokenHash: "h",
    instance: INSTANCE,
    platform,
    environment,
    bundleId: BUNDLE,
    deviceTokenEnc: "",
    createdAt: 0,
    lastUsedAt: 0,
    expiresAt: 0,
  };
}

function msg(m: Record<string, unknown>) {
  const r = messageSchema.safeParse({ to: "A".repeat(43), ...m });
  assert.ok(r.success, JSON.stringify(r.error?.issues));
  return r.data;
}

function decodeJwt(jwt: string) {
  const [h, c, s] = jwt.split(".") as [string, string, string];
  return {
    header: JSON.parse(Buffer.from(h, "base64url").toString()),
    claims: JSON.parse(Buffer.from(c, "base64url").toString()),
    input: Buffer.from(`${h}.${c}`),
    sig: Buffer.from(s, "base64url"),
  };
}

describe("APNs request building", () => {
  const now = 1_800_000_000;
  it("alert: placeholder, mutable-content, category, thread-id, badge, fp, headers", () => {
    const b = buildApnsRequest(
      msg({
        type: "alert",
        payload,
        category: "task",
        collapseId: "task-42",
        badge: 3,
        priority: "high",
        ttl: 600,
      }),
      rec("ios"),
      "ab".repeat(32),
      now,
    );
    assert.ok(b.ok);
    assert.deepEqual(b.request.payload, {
      aps: {
        alert: { title: "Flowplan", body: "New notification" },
        "mutable-content": 1,
        sound: "default",
        category: "task",
        "thread-id": "task-42",
        badge: 3,
      },
      fp: payload,
    });
    assert.equal(b.request.topic, BUNDLE);
    assert.equal(b.request.pushType, "alert");
    assert.equal(b.request.priority, 10);
    assert.equal(b.request.expiration, now + 600);
    assert.equal(b.request.collapseId, "task-42");
  });

  it("background: content-available only, priority 5", () => {
    const b = buildApnsRequest(
      msg({ type: "background", payload, priority: "high", ttl: 0 }),
      rec("ios", "sandbox"),
      "ab".repeat(32),
      now,
    );
    assert.ok(b.ok);
    assert.deepEqual(b.request.payload, { aps: { "content-available": 1 }, fp: payload });
    assert.equal(b.request.priority, 5);
    assert.equal(b.request.pushType, "background");
    assert.equal(b.request.expiration, 0);
    assert.equal(b.request.environment, "sandbox");
  });

  it("liveactivity: own topic and aps fields", () => {
    const b = buildApnsRequest(
      msg({
        type: "liveactivity",
        priority: "normal",
        liveActivity: {
          event: "end",
          contentState: { done: 3 },
          staleDate: null,
          dismissalDate: now + 60,
        },
      }),
      rec("ios-liveactivity"),
      "ab".repeat(32),
      now,
    );
    assert.ok(b.ok);
    assert.equal(b.request.topic, `${BUNDLE}.push-type.liveactivity`);
    assert.equal(b.request.pushType, "liveactivity");
    assert.equal(b.request.priority, 5);
    assert.deepEqual(b.request.payload, {
      aps: {
        timestamp: now,
        event: "end",
        "content-state": { done: 3 },
        "dismissal-date": now + 60,
      },
    });
  });

  it("rejects type/platform mismatches", () => {
    assert.equal(
      buildApnsRequest(msg({ type: "alert", payload }), rec("ios-liveactivity"), "x", now).ok,
      false,
    );
    assert.equal(
      buildApnsRequest(
        msg({ type: "liveactivity", liveActivity: { event: "update", contentState: {} } }),
        rec("ios"),
        "x",
        now,
      ).ok,
      false,
    );
  });

  it("builds a valid ES256 provider JWT", () => {
    const { cfg, publicKey } = apnsTestConfig();
    const jwt = decodeJwt(buildApnsJwt(cfg, 1_700_000_000_000));
    assert.deepEqual(jwt.header, { alg: "ES256", kid: cfg.keyId });
    assert.deepEqual(jwt.claims, { iss: cfg.teamId, iat: 1_700_000_000 });
    assert.equal(jwt.sig.length, 64, "JOSE (r||s) signature encoding");
    assert.ok(verify("sha256", jwt.input, { key: publicKey, dsaEncoding: "ieee-p1363" }, jwt.sig));
  });

  it("maps APNs responses", () => {
    assert.equal(mapApnsResponse(200, undefined), "ok");
    assert.equal(mapApnsResponse(410, "Unregistered"), "gone");
    assert.equal(mapApnsResponse(400, "BadDeviceToken"), "gone");
    assert.equal(mapApnsResponse(400, "DeviceTokenNotForTopic"), "gone");
    assert.equal(mapApnsResponse(400, "BadCollapseId"), "invalid");
    assert.equal(mapApnsResponse(413, "PayloadTooLarge"), "invalid");
    assert.equal(mapApnsResponse(403, "ExpiredProviderToken"), "refresh-token");
    assert.equal(mapApnsResponse(403, "BadCertificate"), "error");
    assert.equal(mapApnsResponse(429, "TooManyRequests"), "retry");
    assert.equal(mapApnsResponse(500, "InternalServerError"), "retry");
    assert.equal(mapApnsResponse(503, "ServiceUnavailable"), "retry");
  });
});

describe("APNs client (mock HTTP/2 server)", () => {
  let mock: Awaited<ReturnType<typeof startMockApns>>;
  let sandbox: Awaited<ReturnType<typeof startMockApns>>;
  const { cfg, publicKey } = apnsTestConfig();
  let client: ApnsClient;
  before(async () => {
    mock = await startMockApns();
    sandbox = await startMockApns();
    client = new ApnsClient(cfg, {
      origins: { production: mock.origin, sandbox: sandbox.origin },
      retryBaseMs: 1,
    });
  });
  after(async () => {
    client.close();
    await mock.close();
    await sandbox.close();
  });

  const request = (environment: "production" | "sandbox" = "production") => {
    const b = buildApnsRequest(
      msg({ type: "alert", payload, collapseId: "c1" }),
      rec("ios", environment),
      apnsToken(),
      1_800_000_000,
    );
    assert.ok(b.ok);
    return b.request;
  };

  it("sends with the right path, headers and JWT, reusing one connection", async () => {
    mock.setResponder(() => ({ status: 200 }));
    const r1 = request();
    assert.deepEqual(await client.send(r1), { status: "ok", reason: undefined });
    assert.deepEqual(await client.send(request()), { status: "ok", reason: undefined });
    const call = mock.calls.at(-2);
    assert.ok(call);
    assert.equal(call.headers[":method"], "POST");
    assert.equal(call.headers[":path"], `/3/device/${r1.deviceToken}`);
    assert.equal(call.headers["apns-topic"], BUNDLE);
    assert.equal(call.headers["apns-push-type"], "alert");
    assert.equal(call.headers["apns-priority"], "10");
    assert.equal(call.headers["apns-collapse-id"], "c1");
    assert.equal(call.headers["apns-expiration"], String(1_800_000_000 + 86_400));
    const auth = String(call.headers.authorization);
    assert.match(auth, /^bearer /);
    const jwt = decodeJwt(auth.slice(7));
    assert.ok(verify("sha256", jwt.input, { key: publicKey, dsaEncoding: "ieee-p1363" }, jwt.sig));
    assert.equal(call.body.fp, payload);
    assert.equal(mock.sessions, 1, "HTTP/2 connection is reused");
    assert.equal(mock.calls.at(-1)?.headers.authorization, auth, "JWT is cached");
  });

  it("routes sandbox registrations to the sandbox host", async () => {
    sandbox.setResponder(() => ({ status: 200 }));
    const before = sandbox.calls.length;
    assert.equal((await client.send(request("sandbox"))).status, "ok");
    assert.equal(sandbox.calls.length, before + 1);
  });

  it("410 / BadDeviceToken → gone", async () => {
    mock.setResponder(() => ({ status: 410, reason: "Unregistered" }));
    assert.equal((await client.send(request())).status, "gone");
    mock.setResponder(() => ({ status: 400, reason: "BadDeviceToken" }));
    assert.equal((await client.send(request())).status, "gone");
  });

  it("429/5xx → one retry with backoff, then error", async () => {
    let n = 0;
    mock.setResponder(() =>
      ++n === 1 ? { status: 503, reason: "ServiceUnavailable" } : { status: 200 },
    );
    assert.equal((await client.send(request())).status, "ok");
    assert.equal(n, 2);
    n = 0;
    mock.setResponder(() => {
      n++;
      return { status: 429, reason: "TooManyRequests" };
    });
    assert.equal((await client.send(request())).status, "error");
    assert.equal(n, 2, "exactly one retry");
  });

  it("ExpiredProviderToken → new JWT and retry", async () => {
    const auths: string[] = [];
    mock.setResponder((call) => {
      auths.push(String(call.headers.authorization));
      return auths.length === 1 ? { status: 403, reason: "ExpiredProviderToken" } : { status: 200 };
    });
    // Force a different iat for the refreshed token by advancing the clock.
    let t = Date.now();
    const c = new ApnsClient(cfg, {
      origins: { production: mock.origin },
      retryBaseMs: 1,
      now: () => (t += 1000),
    });
    assert.equal((await c.send(request())).status, "ok");
    assert.equal(auths.length, 2);
    assert.notEqual(auths[0], auths[1]);
    c.close();
  });

  it("other 400 reasons → invalid; oversize payload rejected before sending", async () => {
    mock.setResponder(() => ({ status: 400, reason: "BadCollapseId" }));
    assert.equal((await client.send(request())).status, "invalid");
    const before = mock.calls.length;
    const big = { ...request(), payload: { aps: {}, fp: "x".repeat(5000) } };
    assert.deepEqual(await client.send(big), { status: "invalid", reason: "PayloadTooLarge" });
    assert.equal(mock.calls.length, before);
  });

  it("network failure → error after one retry", async () => {
    const c = new ApnsClient(cfg, {
      origins: { production: "http://127.0.0.1:1" },
      retryBaseMs: 1,
    });
    assert.deepEqual(await c.send(request()), { status: "error", reason: "network" });
    c.close();
  });
});

describe("FCM", () => {
  let mock: Awaited<ReturnType<typeof startMockFcm>>;
  const { cfg, publicKey } = fcmTestConfig();
  before(async () => {
    mock = await startMockFcm();
  });
  after(async () => mock.close());

  const fcmMsg = (m: Record<string, unknown> = {}) => {
    const b = buildFcmMessage(msg({ type: "alert", payload, ...m }), rec("android"), fcmToken());
    assert.ok(b.ok);
    return b.request;
  };

  it("builds data-only messages", () => {
    const b = buildFcmMessage(
      msg({ type: "alert", payload, category: "comment", collapseId: "c", badge: 5, ttl: 60 }),
      rec("android"),
      "tok",
    );
    assert.ok(b.ok);
    assert.deepEqual(b.request, {
      token: "tok",
      data: { fp: payload, type: "alert", category: "comment", collapseId: "c", badge: "5" },
      priority: "high",
      collapseKey: "c",
      ttlSeconds: 60,
    });
    const bg = buildFcmMessage(msg({ type: "background", payload }), rec("android"), "tok");
    assert.ok(bg.ok);
    assert.equal(bg.request.priority, "normal");
    assert.equal(
      buildFcmMessage(
        msg({ type: "liveactivity", liveActivity: { event: "end", contentState: {} } }),
        rec("android"),
        "t",
      ).ok,
      false,
    );
  });

  it("gets an OAuth token with an RS256 service-account JWT, caches it, and sends v1 messages", async () => {
    const client = new FcmClient(cfg, {
      tokenUrl: mock.tokenUrl,
      fcmOrigin: mock.origin,
      retryBaseMs: 1,
    });
    const m = fcmMsg({ collapseId: "k", priority: "normal", ttl: 120 });
    assert.equal((await client.send(m)).status, "ok");
    assert.equal((await client.send(fcmMsg())).status, "ok");
    assert.equal(mock.tokenCalls.length, 1, "access token cached");
    const form = new URLSearchParams(mock.tokenCalls[0]?.body);
    assert.equal(form.get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
    const jwt = decodeJwt(form.get("assertion") ?? "");
    assert.deepEqual(jwt.header, { alg: "RS256", typ: "JWT" });
    assert.equal(jwt.claims.iss, cfg.clientEmail);
    assert.equal(jwt.claims.aud, "https://oauth2.googleapis.com/token");
    assert.equal(jwt.claims.scope, "https://www.googleapis.com/auth/firebase.messaging");
    assert.equal(jwt.claims.exp - jwt.claims.iat, 3600);
    assert.ok(verify("sha256", jwt.input, publicKey, jwt.sig));

    const call = mock.sendCalls[0];
    assert.ok(call);
    assert.equal(call.path, "/v1/projects/flowplan-test/messages:send");
    assert.equal(call.headers.authorization, "Bearer ya29.test-1");
    assert.deepEqual(JSON.parse(call.body), {
      message: {
        token: m.token,
        data: m.data,
        android: { priority: "NORMAL", ttl: "120s", collapse_key: "k" },
      },
    });
  });

  it("maps UNREGISTERED / NOT_FOUND → gone, INVALID_ARGUMENT → invalid", async () => {
    const client = new FcmClient(cfg, {
      tokenUrl: mock.tokenUrl,
      fcmOrigin: mock.origin,
      retryBaseMs: 1,
    });
    mock.setResponder(() => ({
      status: 404,
      body: {
        error: {
          code: 404,
          status: "NOT_FOUND",
          details: [
            {
              "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
              errorCode: "UNREGISTERED",
            },
          ],
        },
      },
    }));
    assert.deepEqual(await client.send(fcmMsg()), { status: "gone", reason: "UNREGISTERED" });
    mock.setResponder(() => ({
      status: 400,
      body: { error: { code: 400, status: "INVALID_ARGUMENT" } },
    }));
    assert.equal((await client.send(fcmMsg())).status, "invalid");
  });

  it("retries 503 once, refreshes the token on 401", async () => {
    const client = new FcmClient(cfg, {
      tokenUrl: mock.tokenUrl,
      fcmOrigin: mock.origin,
      retryBaseMs: 1,
    });
    let n = 0;
    mock.setResponder(() =>
      ++n === 1
        ? { status: 503, body: { error: { status: "UNAVAILABLE" } } }
        : { status: 200, body: {} },
    );
    assert.equal((await client.send(fcmMsg())).status, "ok");
    assert.equal(n, 2);
    n = 0;
    mock.setResponder(() => {
      n++;
      return { status: 500, body: { error: { status: "INTERNAL" } } };
    });
    assert.equal((await client.send(fcmMsg())).status, "error");
    assert.equal(n, 2);
    const tokensBefore = mock.tokenCalls.length;
    n = 0;
    mock.setResponder(() =>
      ++n === 1
        ? { status: 401, body: { error: { status: "UNAUTHENTICATED" } } }
        : { status: 200, body: {} },
    );
    assert.equal((await client.send(fcmMsg())).status, "ok");
    assert.equal(mock.tokenCalls.length, tokensBefore + 1);
  });

  it("parses and maps error codes", () => {
    assert.equal(
      parseFcmError('{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}'),
      "UNREGISTERED",
    );
    assert.equal(parseFcmError("not json"), undefined);
    assert.equal(mapFcmResponse(403, "SENDER_ID_MISMATCH"), "gone");
    assert.equal(mapFcmResponse(429, "QUOTA_EXCEEDED"), "retry");
    assert.equal(mapFcmResponse(403, "THIRD_PARTY_AUTH_ERROR"), "error");
  });
});

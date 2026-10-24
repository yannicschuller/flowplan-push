import { generateKeyPairSync, type KeyObject, randomBytes } from "node:crypto";
import http from "node:http";
import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import { generateInstanceKey, type InstanceKey, signRequest } from "../examples/instance.ts";
import { StorageCipher } from "../src/crypto/storage.ts";
import { Store } from "../src/db.ts";
import { createHttpServer } from "../src/http/server.ts";
import { InstanceKeyResolver, type WellKnownKey } from "../src/instance/keys.ts";
import { silentLogger } from "../src/log.ts";
import { createRelayMetrics } from "../src/metrics.ts";
import { ApnsClient } from "../src/push/apns.ts";
import { FcmClient } from "../src/push/fcm.ts";
import { Relay, type RelayLimits } from "../src/relay.ts";

export const BUNDLE = "app.flowplan.mobile";
export const INSTANCE = "https://app.flowplan.org";

export function randomKey(): Buffer {
  return randomBytes(32);
}

export function apnsToken(): string {
  return randomBytes(32).toString("hex");
}

export function fcmToken(): string {
  return `${randomBytes(11).toString("base64url")}:APA91b${randomBytes(100).toString("base64url")}`;
}

// ---- mock APNs (cleartext HTTP/2) ----------------------------------------

export interface ApnsCall {
  headers: http2.IncomingHttpHeaders;
  body: Record<string, unknown>;
}

export type ApnsResponder = (
  call: ApnsCall,
  n: number,
) => { status: number; reason?: string; headers?: Record<string, string> };

export async function startMockApns(responder: ApnsResponder = () => ({ status: 200 })) {
  const calls: ApnsCall[] = [];
  let respond = responder;
  let sessions = 0;
  const server = http2.createServer();
  server.on("session", () => sessions++);
  server.on("stream", (stream, headers) => {
    const chunks: Buffer[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c));
    stream.on("end", () => {
      const call = { headers, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) };
      calls.push(call);
      const r = respond(call, calls.length);
      stream.respond({ ":status": r.status, "apns-id": "test", ...(r.headers ?? {}) });
      stream.end(r.reason ? JSON.stringify({ reason: r.reason }) : undefined);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    origin,
    calls,
    get sessions() {
      return sessions;
    },
    setResponder(r: ApnsResponder) {
      respond = r;
    },
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

export function apnsTestConfig() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { cfg: { keyId: "ABC123DEFG", teamId: "V7N2K54KJN", privateKey }, publicKey };
}

// ---- mock FCM + OAuth (HTTP/1.1) -------------------------------------------

export interface FcmCall {
  path: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export type FcmResponder = (
  call: FcmCall,
  n: number,
) => { status: number; body?: unknown; headers?: Record<string, string> };

export async function startMockFcm(
  responder: FcmResponder = () => ({ status: 200, body: { name: "projects/p/messages/1" } }),
) {
  const tokenCalls: FcmCall[] = [];
  const sendCalls: FcmCall[] = [];
  let respond = responder;
  let tokenCounter = 0;
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const call = {
        path: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      if (req.url === "/token") {
        tokenCalls.push(call);
        tokenCounter++;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: `ya29.test-${tokenCounter}`,
            expires_in: 3599,
            token_type: "Bearer",
          }),
        );
        return;
      }
      sendCalls.push(call);
      const r = respond(call, sendCalls.length);
      res.writeHead(r.status, { "content-type": "application/json", ...(r.headers ?? {}) });
      res.end(JSON.stringify(r.body ?? {}));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    origin,
    tokenUrl: `${origin}/token`,
    tokenCalls,
    sendCalls,
    setResponder(r: FcmResponder) {
      respond = r;
    },
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

export function fcmTestConfig() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    cfg: {
      projectId: "flowplan-test",
      clientEmail: "relay@flowplan-test.iam.gserviceaccount.com",
      privateKey,
    },
    publicKey,
  };
}

// ---- full relay over HTTP ---------------------------------------------------

export interface TestRelayOptions {
  apns?: boolean;
  fcm?: boolean;
  limits?: Partial<RelayLimits>;
  now?: () => number;
  instanceKeys?: Map<string, InstanceKey[]>;
  allowedBundleIds?: string[];
  metricsToken?: string | null;
  trustProxyHops?: number;
}

export async function startRelay(opts: TestRelayOptions = {}) {
  const now = opts.now ?? Date.now;
  const apnsMock = opts.apns === false ? null : await startMockApns();
  const fcmMock = opts.fcm === false ? null : await startMockFcm();
  const instanceKeys = opts.instanceKeys ?? new Map<string, InstanceKey[]>();
  const fetches: string[] = [];
  const keys = new InstanceKeyResolver({
    now,
    fetchDocument: async (origin): Promise<WellKnownKey[]> => {
      fetches.push(origin);
      const list = instanceKeys.get(origin);
      if (!list) throw new Error("unreachable");
      const { createPublicKey } = await import("node:crypto");
      return list.map((k) => ({ id: k.kid, key: createPublicKey(k.privateKey) as KeyObject }));
    },
  });
  const cipher = new StorageCipher(randomKey());
  const store = new Store(":memory:", cipher, () => Math.floor(now() / 1000));
  const metrics = createRelayMetrics();
  const apns = apnsMock
    ? new ApnsClient(apnsTestConfig().cfg, {
        origins: { production: apnsMock.origin, sandbox: apnsMock.origin },
        retryBaseMs: 1,
      })
    : null;
  const fcm = fcmMock
    ? new FcmClient(fcmTestConfig().cfg, {
        tokenUrl: fcmMock.tokenUrl,
        fcmOrigin: fcmMock.origin,
        retryBaseMs: 1,
      })
    : null;
  const relay = new Relay({
    store,
    keys,
    apns,
    fcm,
    allowedBundleIds: opts.allowedBundleIds ?? [BUNDLE],
    allowPrivateInstances: false,
    metrics,
    logger: silentLogger,
    limits: opts.limits,
    now,
  });
  const server = createHttpServer({
    relay,
    metrics,
    logger: silentLogger,
    metricsToken: opts.metricsToken ?? null,
    trustProxyHops: opts.trustProxyHops ?? 0,
    hsts: true,
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const instance = generateInstanceKey();
  instanceKeys.set(INSTANCE, [instance]);

  async function register(body: Record<string, unknown>, headers: Record<string, string> = {}) {
    const res = await fetch(`${url}/v1/devices`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
    return {
      status: res.status,
      headers: res.headers,
      json: (await res.json().catch(() => null)) as Record<string, unknown> | null,
    };
  }

  async function registerIos(extra: Record<string, unknown> = {}) {
    const token = apnsToken();
    const r = await register({
      platform: "ios",
      token,
      environment: "production",
      bundleId: BUNDLE,
      instance: INSTANCE,
      ...extra,
    });
    if (r.status !== 201) throw new Error(`register failed: ${r.status} ${JSON.stringify(r.json)}`);
    return { deviceToken: token, relayToken: r.json?.relayToken as string };
  }

  async function registerAndroid(extra: Record<string, unknown> = {}) {
    const token = fcmToken();
    const r = await register({
      platform: "android",
      token,
      bundleId: BUNDLE,
      instance: INSTANCE,
      ...extra,
    });
    if (r.status !== 201) throw new Error(`register failed: ${r.status} ${JSON.stringify(r.json)}`);
    return { deviceToken: token, relayToken: r.json?.relayToken as string };
  }

  async function sendRaw(
    body: string,
    o: { instance?: string; key?: InstanceKey; ts?: number; headers?: Record<string, string> } = {},
  ) {
    const key = o.key ?? instance;
    const signed = signRequest({
      instance: o.instance ?? INSTANCE,
      kid: key.kid,
      privateKey: key.privateKey,
      body,
      ts: o.ts ?? Math.floor(now() / 1000),
    });
    const res = await fetch(`${url}/v1/send`, {
      method: "POST",
      headers: { "content-type": "application/json", ...signed, ...(o.headers ?? {}) },
      body,
    });
    return {
      status: res.status,
      headers: res.headers,
      json: (await res.json().catch(() => null)) as Record<string, unknown> | null,
    };
  }

  const send = (messages: unknown[], o: Parameters<typeof sendRaw>[1] = {}) =>
    sendRaw(JSON.stringify({ messages, requestId: randomBytes(8).toString("hex") }), o);

  return {
    url,
    relay,
    store,
    metrics,
    instance,
    instanceKeys,
    fetches,
    apnsMock,
    fcmMock,
    register,
    registerIos,
    registerAndroid,
    send,
    sendRaw,
    async close() {
      await new Promise<void>((r) => server.close(() => r()));
      server.closeAllConnections();
      apns?.close();
      await apnsMock?.close();
      await fcmMock?.close();
      store.close();
    },
  };
}

export type TestRelay = Awaited<ReturnType<typeof startRelay>>;

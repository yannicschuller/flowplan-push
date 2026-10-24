import { type KeyObject, sign } from "node:crypto";
import http2 from "node:http2";
import type { ApnsConfig } from "../config.ts";
import type { Environment } from "../db.ts";
import { type DeliveryResult, retryDelayMs, sleep } from "./types.ts";

/**
 * APNs provider client: token-based auth (ES256 JWT, cached 45 min) over one
 * reused HTTP/2 connection per environment.
 */

export const APNS_ORIGINS: Record<Environment, string> = {
  production: "https://api.push.apple.com",
  sandbox: "https://api.sandbox.push.apple.com",
};

const JWT_MAX_AGE_MS = 45 * 60 * 1000; // Apple: valid ≤ 60 min, refresh at most every 20 min
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 4096;
export const APNS_MAX_PAYLOAD_BYTES = 4096;

export type ApnsPushType = "alert" | "background" | "liveactivity";

export interface ApnsRequest {
  deviceToken: string;
  environment: Environment;
  topic: string;
  pushType: ApnsPushType;
  priority: 5 | 10;
  /** Unix seconds; 0 = deliver once, do not store. */
  expiration: number;
  collapseId?: string | null;
  payload: Record<string, unknown>;
}

export function buildApnsJwt(
  cfg: { keyId: string; teamId: string; privateKey: KeyObject },
  nowMs: number,
): string {
  const header = Buffer.from(JSON.stringify({ alg: "ES256", kid: cfg.keyId })).toString(
    "base64url",
  );
  const claims = Buffer.from(
    JSON.stringify({ iss: cfg.teamId, iat: Math.floor(nowMs / 1000) }),
  ).toString("base64url");
  const input = `${header}.${claims}`;
  const sig = sign("sha256", Buffer.from(input), {
    key: cfg.privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${input}.${sig.toString("base64url")}`;
}

interface RawResponse {
  status: number;
  reason?: string;
  retryAfter?: string;
}

export interface ApnsClientOptions {
  origins?: Partial<Record<Environment, string>>;
  now?: () => number;
  retryBaseMs?: number;
  /** Extra options for http2.connect (tests: custom CA). */
  connectOptions?: http2.SecureClientSessionOptions;
}

export class ApnsClient {
  private readonly sessions = new Map<string, http2.ClientHttp2Session>();
  private jwt: { token: string; issuedAt: number } | null = null;
  private readonly origins: Record<Environment, string>;
  private readonly now: () => number;
  private readonly retryBaseMs: number;
  private closed = false;

  private readonly cfg: ApnsConfig;
  private readonly opts: ApnsClientOptions;

  constructor(cfg: ApnsConfig, opts: ApnsClientOptions = {}) {
    this.cfg = cfg;
    this.opts = opts;
    this.origins = { ...APNS_ORIGINS, ...(opts.origins ?? {}) };
    this.now = opts.now ?? Date.now;
    this.retryBaseMs = opts.retryBaseMs ?? 250;
  }

  private token(): string {
    const now = this.now();
    if (this.jwt && now - this.jwt.issuedAt < JWT_MAX_AGE_MS) return this.jwt.token;
    this.jwt = { token: buildApnsJwt(this.cfg, now), issuedAt: now };
    return this.jwt.token;
  }

  /**
   * Drops the cached JWT after APNs rejected it – but only if it is still the
   * one that was rejected, so concurrent failures cause a single refresh
   * (APNs answers TooManyProviderTokenUpdates to frequent refreshes).
   */
  private invalidateToken(rejected: string): void {
    if (this.jwt?.token === rejected) this.jwt = null;
  }

  private session(env: Environment): http2.ClientHttp2Session {
    const origin = this.origins[env];
    const existing = this.sessions.get(origin);
    if (existing && !existing.closed && !existing.destroyed) return existing;
    const s = http2.connect(origin, { ...(this.opts.connectOptions ?? {}) });
    const drop = () => {
      if (this.sessions.get(origin) === s) this.sessions.delete(origin);
    };
    s.on("error", drop);
    s.on("goaway", drop);
    s.on("close", drop);
    s.setTimeout(10 * 60 * 1000, () => s.close()); // idle connections are closed after 10 min
    s.unref();
    this.sessions.set(origin, s);
    return s;
  }

  private requestOnce(req: ApnsRequest, body: string, jwt: string): Promise<RawResponse> {
    return new Promise((resolve, reject) => {
      let session: http2.ClientHttp2Session;
      try {
        session = this.session(req.environment);
      } catch (err) {
        reject(err);
        return;
      }
      const headers: http2.OutgoingHttpHeaders = {
        ":method": "POST",
        ":path": `/3/device/${req.deviceToken}`,
        authorization: `bearer ${jwt}`,
        "apns-topic": req.topic,
        "apns-push-type": req.pushType,
        "apns-priority": String(req.priority),
        "apns-expiration": String(req.expiration),
        "content-type": "application/json",
      };
      if (req.collapseId) headers["apns-collapse-id"] = req.collapseId;
      const stream = session.request(headers);
      let status = 0;
      let retryAfter: string | undefined;
      const chunks: Buffer[] = [];
      let size = 0;
      stream.setTimeout(REQUEST_TIMEOUT_MS, () => stream.close(http2.constants.NGHTTP2_CANCEL));
      stream.on("response", (h) => {
        status = Number(h[":status"] ?? 0);
        const ra = h["retry-after"];
        retryAfter = typeof ra === "string" ? ra : undefined;
      });
      stream.on("data", (c: Buffer) => {
        size += c.length;
        if (size <= MAX_RESPONSE_BYTES) chunks.push(c);
      });
      stream.on("end", () => {
        let reason: string | undefined;
        if (chunks.length) {
          try {
            const j = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { reason?: unknown };
            if (typeof j.reason === "string") reason = j.reason.slice(0, 64);
          } catch {
            // ignore malformed error bodies
          }
        }
        resolve({ status, reason, retryAfter });
      });
      stream.on("close", () => {
        if (status === 0) reject(new Error("APNs stream closed without response"));
      });
      stream.on("error", reject);
      stream.end(body);
    });
  }

  async send(req: ApnsRequest): Promise<DeliveryResult> {
    if (this.closed) return { status: "error", reason: "closed" };
    const body = JSON.stringify(req.payload);
    if (Buffer.byteLength(body) > APNS_MAX_PAYLOAD_BYTES)
      return { status: "invalid", reason: "PayloadTooLarge" };
    let refreshed = false;
    let retried = false;
    for (;;) {
      let res: RawResponse;
      const jwt = this.token();
      try {
        res = await this.requestOnce(req, body, jwt);
      } catch {
        if (!retried) {
          retried = true;
          await sleep(retryDelayMs(undefined, this.retryBaseMs));
          continue;
        }
        return { status: "error", reason: "network" };
      }
      const mapped = mapApnsResponse(res.status, res.reason);
      if (mapped === "refresh-token") {
        if (!refreshed) {
          refreshed = true;
          this.invalidateToken(jwt);
          continue;
        }
        return { status: "error", reason: res.reason };
      }
      if (mapped === "retry") {
        if (!retried) {
          retried = true;
          await sleep(retryDelayMs(res.retryAfter, this.retryBaseMs));
          continue;
        }
        return { status: "error", reason: res.reason ?? `HTTP ${res.status}` };
      }
      return { status: mapped, reason: res.reason };
    }
  }

  close(): void {
    this.closed = true;
    for (const s of this.sessions.values()) s.close();
    this.sessions.clear();
  }
}

/** Maps an APNs response to a delivery status (or a retry instruction). */
export function mapApnsResponse(
  status: number,
  reason: string | undefined,
): "ok" | "gone" | "invalid" | "error" | "retry" | "refresh-token" {
  if (status === 200) return "ok";
  if (status === 410) return "gone"; // Unregistered / ExpiredToken
  if (status === 400) {
    if (reason === "BadDeviceToken" || reason === "DeviceTokenNotForTopic") return "gone";
    return "invalid";
  }
  if (status === 403) {
    if (reason === "ExpiredProviderToken" || reason === "InvalidProviderToken")
      return "refresh-token";
    return "error";
  }
  if (status === 413) return "invalid";
  if (status === 429 || status >= 500) return "retry";
  return "error";
}

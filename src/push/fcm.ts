import { sign } from "node:crypto";
import type { FcmConfig } from "../config.ts";
import { type DeliveryResult, retryDelayMs, sleep } from "./types.ts";

/**
 * FCM HTTP v1 client. OAuth2 access tokens are obtained with a self-signed
 * service-account JWT (RS256, node:crypto) and cached until shortly before
 * they expire. No firebase-admin SDK.
 */

export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const FCM_ORIGIN = "https://fcm.googleapis.com";
const SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const REQUEST_TIMEOUT_MS = 10_000;
export const FCM_MAX_DATA_BYTES = 4096;

export interface FcmMessage {
  token: string;
  data: Record<string, string>;
  priority: "high" | "normal";
  collapseKey?: string | null;
  ttlSeconds: number;
}

export function buildServiceAccountJwt(cfg: FcmConfig, audience: string, nowMs: number): string {
  const iat = Math.floor(nowMs / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const claims = Buffer.from(
    JSON.stringify({ iss: cfg.clientEmail, scope: SCOPE, aud: audience, iat, exp: iat + 3600 }),
  ).toString("base64url");
  const input = `${header}.${claims}`;
  return `${input}.${sign("sha256", Buffer.from(input), cfg.privateKey).toString("base64url")}`;
}

export function buildFcmRequestBody(msg: FcmMessage): Record<string, unknown> {
  const android: Record<string, unknown> = {
    priority: msg.priority === "high" ? "HIGH" : "NORMAL",
    ttl: `${msg.ttlSeconds}s`,
  };
  if (msg.collapseKey) android.collapse_key = msg.collapseKey;
  return { message: { token: msg.token, data: msg.data, android } };
}

export function fcmDataSize(data: Record<string, string>): number {
  let n = 0;
  for (const [k, v] of Object.entries(data)) n += Buffer.byteLength(k) + Buffer.byteLength(v);
  return n;
}

export interface FcmClientOptions {
  tokenUrl?: string;
  fcmOrigin?: string;
  now?: () => number;
  retryBaseMs?: number;
}

interface FcmErrorBody {
  error?: { status?: string; details?: Array<{ "@type"?: string; errorCode?: string }> };
}

export class FcmClient {
  private access: { token: string; expiresAt: number } | null = null;
  private pending: Promise<string> | null = null;
  private readonly tokenUrl: string;
  private readonly fcmOrigin: string;
  private readonly now: () => number;
  private readonly retryBaseMs: number;

  private readonly cfg: FcmConfig;

  constructor(cfg: FcmConfig, opts: FcmClientOptions = {}) {
    this.cfg = cfg;
    this.tokenUrl = opts.tokenUrl ?? GOOGLE_TOKEN_URL;
    this.fcmOrigin = opts.fcmOrigin ?? FCM_ORIGIN;
    this.now = opts.now ?? Date.now;
    this.retryBaseMs = opts.retryBaseMs ?? 250;
  }

  private async accessToken(): Promise<string> {
    if (this.access && this.now() < this.access.expiresAt) return this.access.token;
    if (this.pending) return this.pending;
    this.pending = (async () => {
      const assertion = buildServiceAccountJwt(this.cfg, GOOGLE_TOKEN_URL, this.now());
      const res = await fetch(this.tokenUrl, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
          assertion,
        }),
        redirect: "error",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`OAuth token request failed: HTTP ${res.status}`);
      const j = (await res.json()) as { access_token?: unknown; expires_in?: unknown };
      if (typeof j.access_token !== "string")
        throw new Error("OAuth token response without access_token");
      const ttl = typeof j.expires_in === "number" ? j.expires_in : 3600;
      // Refresh 5 minutes early (but keep at least 60 s of caching).
      this.access = {
        token: j.access_token,
        expiresAt: this.now() + Math.max(60, ttl - 300) * 1000,
      };
      return j.access_token;
    })().finally(() => {
      this.pending = null;
    });
    return this.pending;
  }

  async send(msg: FcmMessage): Promise<DeliveryResult> {
    if (fcmDataSize(msg.data) > FCM_MAX_DATA_BYTES)
      return { status: "invalid", reason: "PayloadTooLarge" };
    const body = JSON.stringify(buildFcmRequestBody(msg));
    const url = `${this.fcmOrigin}/v1/projects/${encodeURIComponent(this.cfg.projectId)}/messages:send`;
    let refreshed = false;
    let retried = false;
    for (;;) {
      let status: number;
      let errorCode: string | undefined;
      let retryAfter: string | undefined;
      try {
        const token = await this.accessToken();
        const res = await fetch(url, {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json; charset=utf-8",
          },
          body,
          redirect: "error",
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
        status = res.status;
        retryAfter = res.headers.get("retry-after") ?? undefined;
        const text = await res.text();
        if (status !== 200) errorCode = parseFcmError(text.slice(0, 16 * 1024));
      } catch {
        if (!retried) {
          retried = true;
          await sleep(retryDelayMs(undefined, this.retryBaseMs));
          continue;
        }
        return { status: "error", reason: "network" };
      }
      const mapped = mapFcmResponse(status, errorCode);
      if (mapped === "refresh-token") {
        this.access = null;
        if (!refreshed) {
          refreshed = true;
          continue;
        }
        return { status: "error", reason: errorCode ?? "UNAUTHENTICATED" };
      }
      if (mapped === "retry") {
        if (!retried) {
          retried = true;
          await sleep(retryDelayMs(retryAfter, this.retryBaseMs));
          continue;
        }
        return { status: "error", reason: errorCode ?? `HTTP ${status}` };
      }
      return { status: mapped, reason: errorCode };
    }
  }
}

/** Extracts the FCM error code (details[].errorCode, falling back to error.status). */
export function parseFcmError(text: string): string | undefined {
  try {
    const j = JSON.parse(text) as FcmErrorBody;
    const fcm = j.error?.details?.find((d) => typeof d.errorCode === "string")?.errorCode;
    return (fcm ?? j.error?.status)?.slice(0, 64);
  } catch {
    return undefined;
  }
}

export function mapFcmResponse(
  status: number,
  errorCode: string | undefined,
): "ok" | "gone" | "invalid" | "error" | "retry" | "refresh-token" {
  if (status === 200) return "ok";
  if (errorCode === "UNREGISTERED" || status === 404 || errorCode === "NOT_FOUND") return "gone";
  if (errorCode === "SENDER_ID_MISMATCH") return "gone"; // token belongs to another Firebase project
  if (status === 401 || errorCode === "UNAUTHENTICATED") return "refresh-token";
  if (status === 400 || errorCode === "INVALID_ARGUMENT") return "invalid";
  if (status === 429 || errorCode === "QUOTA_EXCEEDED" || status >= 500) return "retry";
  return "error";
}

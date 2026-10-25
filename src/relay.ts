import {
  isTimestampFresh,
  parseSignatureHeader,
  ReplayCache,
  verifySignature,
} from "./auth/signature.ts";
import { hashRelayToken, RELAY_TOKEN_PATTERN } from "./crypto/tokens.ts";
import type { DeviceRecord, Store } from "./db.ts";
import type { InstanceKeyResolver } from "./instance/keys.ts";
import { type Logger, truncateIp } from "./log.ts";
import type { RelayMetrics } from "./metrics.ts";
import { ipInCidrs, rateLimitKeyForIp } from "./net/ip.ts";
import { canonicalOrigin } from "./net/origin.ts";
import {
  type Message,
  type MessageResult,
  messageSchema,
  registerSchema,
  sendBodySchema,
} from "./protocol.ts";
import type { ApnsClient } from "./push/apns.ts";
import { buildApnsRequest, buildFcmMessage } from "./push/build.ts";
import type { FcmClient } from "./push/fcm.ts";
import type { DeliveryResult } from "./push/types.ts";
import { TokenBucketLimiter } from "./ratelimit.ts";
import { noopEventSink, type RelayEventSink, shortDeviceId } from "./stats.ts";

export interface HttpResult {
  status: number;
  body?: unknown;
  headers?: Record<string, string | string[]>;
}

export interface RelayLimits {
  /** PROTOCOL §6.2: 120 registrations per IP (IPv6: /64) and hour. */
  registerPerIpPerHour: number;
  /** PROTOCOL §3: 600 messages per minute per instance, burst 100. */
  instanceMessagesPerMinute: number;
  instanceBurst: number;
  /** Send/delete requests per IP and minute (transport-level flood protection). */
  requestsPerIpPerMinute: number;
  /** Failed authentication attempts per IP before it is locked out for a while. */
  authFailuresPerIpPer10Min: number;
  /** Parallel provider requests per send call. */
  deliveryConcurrency: number;
}

export const DEFAULT_LIMITS: RelayLimits = {
  registerPerIpPerHour: 120,
  instanceMessagesPerMinute: 600,
  instanceBurst: 100,
  requestsPerIpPerMinute: 120,
  authFailuresPerIpPer10Min: 30,
  deliveryConcurrency: 16,
};

export interface RelayDeps {
  store: Store;
  keys: InstanceKeyResolver;
  apns: ApnsClient | null;
  fcm: FcmClient | null;
  allowedBundleIds: string[];
  allowPrivateInstances: boolean;
  metrics: RelayMetrics;
  logger: Logger;
  limits?: Partial<RelayLimits>;
  now?: () => number;
  /** Receives per-instance events for the admin dashboard statistics. */
  events?: RelayEventSink;
}

/** Retry-After (seconds) answered while sending is paused by the operator. */
export const PAUSED_RETRY_AFTER_SECONDS = 300;

const err = (
  status: number,
  error: string,
  extra: Record<string, unknown> = {},
  headers?: Record<string, string>,
) => ({
  status,
  body: { error, ...extra },
  headers,
});

function parseJson(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString("utf8"));
  } catch {
    return undefined;
  }
}

async function pool<T>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) {
      const item = items[next++] as T;
      await fn(item);
    }
  });
  await Promise.all(workers);
}

export class Relay {
  readonly limits: RelayLimits;
  readonly registerLimiter: TokenBucketLimiter;
  readonly requestLimiter: TokenBucketLimiter;
  readonly authFailLimiter: TokenBucketLimiter;
  readonly instanceLimiter: TokenBucketLimiter;
  readonly replay: ReplayCache;
  private readonly now: () => number;
  private readonly allowedBundles: Set<string>;
  private readonly d: RelayDeps;
  private readonly events: RelayEventSink;

  constructor(d: RelayDeps) {
    this.d = d;
    this.events = d.events ?? noopEventSink;
    this.limits = { ...DEFAULT_LIMITS, ...(d.limits ?? {}) };
    this.now = d.now ?? Date.now;
    const l = this.limits;
    this.registerLimiter = new TokenBucketLimiter(
      l.registerPerIpPerHour,
      l.registerPerIpPerHour,
      3_600_000,
      100_000,
      this.now,
    );
    this.requestLimiter = new TokenBucketLimiter(
      l.requestsPerIpPerMinute,
      l.requestsPerIpPerMinute,
      60_000,
      100_000,
      this.now,
    );
    this.authFailLimiter = new TokenBucketLimiter(
      l.authFailuresPerIpPer10Min,
      l.authFailuresPerIpPer10Min,
      600_000,
      100_000,
      this.now,
    );
    this.instanceLimiter = new TokenBucketLimiter(
      l.instanceBurst,
      l.instanceMessagesPerMinute,
      60_000,
      100_000,
      this.now,
    );
    this.replay = new ReplayCache(100_000, this.now);
    this.allowedBundles = new Set(d.allowedBundleIds);
  }

  private rateLimited(
    scope: string,
    retryAfter: number,
    instance: string | null = null,
  ): HttpResult {
    this.d.metrics.rateLimited({ scope });
    this.events.rateLimited({ scope, instance });
    return err(429, "rate_limited", { retryAfter }, { "retry-after": String(retryAfter) });
  }

  // ---- POST /v1/devices ------------------------------------------------

  register(ip: string, body: Buffer): HttpResult {
    const ipKey = rateLimitKeyForIp(ip);
    const rl = this.registerLimiter.tryTake(ipKey);
    if (!rl.ok) return this.rateLimited("register_ip", rl.retryAfter);
    if (this.isIpBlocked(ip)) {
      this.events.refused({ what: "ip_blocked", instance: null });
      return err(403, "ip_blocked");
    }

    const parsed = registerSchema.safeParse(parseJson(body));
    if (!parsed.success) {
      const fields = [
        ...new Set(parsed.error.issues.map((i) => i.path.join(".")).filter(Boolean)),
      ].slice(0, 10);
      return err(400, "invalid_request", { fields });
    }
    const req = parsed.data;
    if (!this.allowedBundles.has(req.bundleId)) return err(403, "bundle_not_allowed");
    const instance = canonicalOrigin(req.instance, this.d.allowPrivateInstances);
    if (!instance) return err(400, "invalid_instance");
    if (this.d.store.isBlocked(instance)) {
      this.events.refused({ what: "instance_blocked", instance });
      return err(403, "instance_blocked");
    }

    const environment =
      req.platform === "android" ? "production" : (req.environment ?? "production");
    const deviceToken = req.platform === "android" ? req.token : req.token.toLowerCase();
    const { relayToken, expiresAt } = this.d.store.register({
      platform: req.platform,
      environment,
      bundleId: req.bundleId,
      instance,
      deviceToken,
    });
    this.d.metrics.registrations({ platform: req.platform });
    this.events.registration({
      instance,
      platform: req.platform,
      deviceId: shortDeviceId(hashRelayToken(relayToken)),
      ip,
    });
    return {
      status: 201,
      body: { relayToken, expiresAt: new Date(expiresAt * 1000).toISOString() },
    };
  }

  /** Registrations from operator-blocked client IP ranges are refused (temporary blocks). */
  private isIpBlocked(ip: string): boolean {
    const ranges = this.d.store.listBlockedIps();
    return (
      ranges.length > 0 &&
      ipInCidrs(
        ip,
        ranges.map((r) => r.cidr),
      )
    );
  }

  // ---- DELETE /v1/devices/{relayToken} -----------------------------------

  unregister(ip: string, relayToken: string): HttpResult {
    const rl = this.requestLimiter.tryTake(rateLimitKeyForIp(ip));
    if (!rl.ok) return this.rateLimited("request_ip", rl.retryAfter);
    if (!RELAY_TOKEN_PATTERN.test(relayToken)) return err(400, "invalid_request");
    // 204 whether or not the token existed: no existence oracle.
    this.d.store.deleteByRelayToken(relayToken);
    return { status: 204 };
  }

  // ---- POST /v1/send -----------------------------------------------------

  private authFailure(
    ip: string,
    reason: string,
    status: number,
    error: string,
    instance: string | null = null,
  ): HttpResult {
    this.authFailLimiter.take(rateLimitKeyForIp(ip), 1);
    this.d.metrics.authFailures({ reason });
    this.events.authFailure({ reason, instance, ip });
    return err(status, error);
  }

  async send(
    ip: string,
    instanceHeader: string | undefined,
    signatureHeader: string | undefined,
    body: Buffer,
  ): Promise<HttpResult> {
    const ipKey = rateLimitKeyForIp(ip);
    const locked = this.authFailLimiter.isExhausted(ipKey);
    if (locked.exhausted) return this.rateLimited("auth_failures_ip", locked.retryAfter);
    const rl = this.requestLimiter.tryTake(ipKey);
    if (!rl.ok) return this.rateLimited("request_ip", rl.retryAfter);

    // Emergency kill switch: refuse every send before doing any work.
    if (this.d.store.getPause()) {
      this.events.refused({ what: "paused", instance: null });
      const retryAfter = PAUSED_RETRY_AFTER_SECONDS;
      return err(503, "relay_paused", { retryAfter }, { "retry-after": String(retryAfter) });
    }

    // The header must already be in canonical form, since it is part of the signed string.
    const instance = canonicalOrigin(instanceHeader, this.d.allowPrivateInstances);
    if (!instance || instance !== instanceHeader) {
      return this.authFailure(ip, "bad_instance", 400, "invalid_instance");
    }
    const sig = parseSignatureHeader(signatureHeader);
    if (!sig) return this.authFailure(ip, "bad_signature_header", 401, "invalid_signature");
    if (!isTimestampFresh(sig.tsNum, this.now())) {
      return this.authFailure(ip, "stale_timestamp", 401, "stale_timestamp");
    }

    const parsedBody = sendBodySchema.safeParse(parseJson(body));
    if (!parsedBody.success) return err(400, "invalid_request");
    const rawMessages = parsedBody.data.messages;

    if (this.d.store.isBlocked(instance)) {
      this.d.metrics.authFailures({ reason: "blocked" });
      this.events.refused({ what: "instance_blocked", instance });
      return err(403, "instance_blocked");
    }

    // An origin without any registration cannot own any of the tokens. Answer
    // without fetching its keys, so unauthenticated requests cannot make the
    // relay contact arbitrary hosts.
    if (!this.d.store.instanceHasDevices(instance)) {
      const results: MessageResult[] = rawMessages.map((m) =>
        messageSchema.safeParse(m).success ? { status: "forbidden" } : { status: "invalid" },
      );
      return { status: 200, body: { results } };
    }

    const key = await this.d.keys.getKey(instance, sig.kid);
    if (!key.ok) {
      if (key.reason === "unreachable") {
        this.d.logger.warn("instance keys unavailable", { instance, detail: key.detail });
        this.d.metrics.authFailures({ reason: "keys_unavailable" });
        this.events.authFailure({ reason: "keys_unavailable", instance, ip });
        return err(502, "instance_keys_unavailable");
      }
      return this.authFailure(ip, "unknown_key", 401, "unknown_key", instance);
    }
    if (!verifySignature(key.key, instance, sig, body)) {
      this.d.logger.warn("invalid signature", { instance, kid: sig.kid, ip: truncateIp(ip) });
      return this.authFailure(ip, "invalid_signature", 401, "invalid_signature", instance);
    }
    // PROTOCOL §6.5: a repeated (instance, requestId) within the window is a
    // replay; an identical signature implies an identical body and is caught
    // by the same check, the signature check stays as a second line.
    const requestKey = `${instance}\n${parsedBody.data.requestId}`;
    if (
      !this.replay.checkAndRemember(requestKey, sig.tsNum) ||
      !this.replay.checkAndRemember(`sig:${sig.sigText}`, sig.tsNum)
    ) {
      return this.authFailure(ip, "replayed", 409, "replayed", instance);
    }

    const results = await this.deliverAll(instance, rawMessages);
    const tally: Record<string, number> = {};
    for (const r of results) tally[r.status] = (tally[r.status] ?? 0) + 1;
    this.events.sendCompleted({ instance, ip, results: tally });
    return { status: 200, body: { results } };
  }

  private async deliverAll(instance: string, rawMessages: unknown[]): Promise<MessageResult[]> {
    const results: MessageResult[] = new Array(rawMessages.length);
    const tasks: Array<{ index: number; msg: Message; rec: DeviceRecord }> = [];
    const counts = new Map<string, number>();
    const count = (platform: string, status: string, reason?: string) => {
      const k = `${platform}|${status}`;
      counts.set(k, (counts.get(k) ?? 0) + 1);
      this.d.metrics.messages({ platform, status });
      this.events.message({ instance, platform, status, reason });
    };

    rawMessages.forEach((raw, index) => {
      const parsed = messageSchema.safeParse(raw);
      if (!parsed.success) {
        results[index] = { status: "invalid" };
        count("unknown", "invalid");
        return;
      }
      const msg = parsed.data;
      const rec = this.d.store.findByRelayToken(msg.to);
      // Unknown, expired or foreign tokens are indistinguishable for the caller.
      if (!rec || rec.instance !== instance || !this.allowedBundles.has(rec.bundleId)) {
        results[index] = { status: "forbidden" };
        count("unknown", "forbidden");
        return;
      }
      const rl = this.instanceLimiter.take(instance, 1);
      if (rl.granted === 0) {
        results[index] = { status: "rate_limited", retryAfter: rl.retryAfter };
        this.d.metrics.rateLimited({ scope: "instance_messages" });
        this.events.rateLimited({ scope: "instance_messages", instance });
        count(rec.platform, "rate_limited");
        return;
      }
      tasks.push({ index, msg, rec });
    });

    await pool(tasks, this.limits.deliveryConcurrency, async ({ index, msg, rec }) => {
      let res: DeliveryResult;
      try {
        res = await this.deliver(msg, rec);
      } catch (e) {
        this.d.logger.error("delivery failed", { platform: rec.platform, error: e });
        res = { status: "error", reason: "exception" };
      }
      if (res.status === "ok") this.d.store.touch(rec);
      if (res.status === "gone") {
        this.d.store.deleteByHash(rec.tokenHash);
        this.events.deviceGone({
          instance,
          platform: rec.platform,
          deviceId: shortDeviceId(rec.tokenHash),
        });
      }
      if (res.status === "error" || res.status === "invalid") {
        this.d.logger.info("delivery not successful", {
          platform: rec.platform,
          status: res.status,
          reason: res.reason,
        });
      }
      results[index] = { status: res.status };
      count(rec.platform, res.status, res.reason);
    });

    try {
      this.d.store.recordDeliveries(counts);
    } catch (e) {
      this.d.logger.warn("could not record stats", { error: e });
    }
    return results;
  }

  private async deliver(msg: Message, rec: DeviceRecord): Promise<DeliveryResult> {
    let deviceToken: string;
    try {
      deviceToken = this.d.store.decryptDeviceToken(rec);
    } catch {
      this.d.logger.error("cannot decrypt device token (storage key missing?)", {
        keyId: rec.deviceTokenEnc.split(".")[1],
      });
      return { status: "error", reason: "decrypt" };
    }
    const nowSeconds = Math.floor(this.now() / 1000);
    if (rec.platform === "android") {
      if (!this.d.fcm) return { status: "error", reason: "fcm_not_configured" };
      const built = buildFcmMessage(msg, rec, deviceToken);
      if (!built.ok) return { status: "invalid", reason: "type_mismatch" };
      return this.d.fcm.send(built.request);
    }
    if (!this.d.apns) return { status: "error", reason: "apns_not_configured" };
    const built = buildApnsRequest(msg, rec, deviceToken, nowSeconds);
    if (!built.ok) return { status: "invalid", reason: "type_mismatch" };
    return this.d.apns.send(built.request);
  }
}

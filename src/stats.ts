import { createHash } from "node:crypto";
import type { Store } from "./db.ts";
import { truncateIp } from "./log.ts";

/**
 * Operational statistics for the admin dashboard.
 *
 * Counters are kept as pending deltas in memory and flushed every few seconds
 * (and on shutdown) into two SQLite tables:
 *   - `stats_minute`: per-minute rows, kept for 2 hours (live view, "last hour")
 *   - `stats_hourly`: per-hour rows, kept for 30 days (24 h / 30 d views)
 * Each delta is written both globally (instance "") and, when the instance is
 * known and authenticated or registered, per instance. So the numbers survive
 * restarts; at most the last flush interval is lost on a crash.
 *
 * Nothing per device is stored here. Recent events (for the instance detail
 * page) live only in memory and carry hashed short device ids, never tokens.
 */

export const MINUTE_RETENTION = 120; // minutes
export const HOURLY_RETENTION = 30 * 24; // hours
const FLUSH_INTERVAL_MS = 10_000;
const MAX_PENDING_KEYS = 20_000;
const MAX_EVENT_INSTANCES = 2_000;
const EVENTS_PER_INSTANCE = 50;

export const MESSAGE_STATUSES = [
  "ok",
  "gone",
  "forbidden",
  "invalid",
  "rate_limited",
  "error",
] as const;

/** Stable, non-reversible short id for a registration (derived from the relay-token hash). */
export function shortDeviceId(tokenHash: string): string {
  return createHash("sha256")
    .update(`flowplan-push/admin-device-id/v1:${tokenHash}`)
    .digest("hex")
    .slice(0, 10);
}

export interface InstanceEvent {
  at: number; // unix ms
  kind: "registration" | "send" | "auth_failure" | "gone" | "blocked";
  /** Human-readable, anonymized detail (no tokens, payloads or device ids). */
  detail: string;
  device?: string;
  ip?: string;
}

export interface ProviderHealth {
  configured: boolean;
  lastOkAt: number | null;
  lastErrorAt: number | null;
  lastErrorReason: string | null;
}

/** Events the relay reports. All methods must be cheap and must never throw. */
export interface RelayEventSink {
  message(e: { instance: string; platform: string; status: string; reason?: string }): void;
  registration(e: { instance: string; platform: string; deviceId: string; ip: string }): void;
  authFailure(e: { reason: string; instance: string | null; ip: string }): void;
  rateLimited(e: { scope: string; instance: string | null }): void;
  sendCompleted(e: { instance: string; ip: string; results: Record<string, number> }): void;
  deviceGone(e: { instance: string; platform: string; deviceId: string }): void;
  refused(e: { what: "ip_blocked" | "instance_blocked" | "paused"; instance: string | null }): void;
}

export const noopEventSink: RelayEventSink = {
  message() {},
  registration() {},
  authFailure() {},
  rateLimited() {},
  sendCompleted() {},
  deviceGone() {},
  refused() {},
};

type Row = { key: string; n: number };

export class StatsCollector implements RelayEventSink {
  private pending = new Map<string, number>();
  private readonly events = new Map<string, InstanceEvent[]>();
  readonly providers: { apns: ProviderHealth; fcm: ProviderHealth };
  private readonly store: Store;
  private readonly nowMs: () => number;
  private timer: NodeJS.Timeout | null = null;
  private lastPrune = 0;

  constructor(
    store: Store,
    opts: { apns: boolean; fcm: boolean; now?: () => number; autoFlush?: boolean } = {
      apns: false,
      fcm: false,
    },
  ) {
    this.store = store;
    this.nowMs = opts.now ?? Date.now;
    const p = (configured: boolean): ProviderHealth => ({
      configured,
      lastOkAt: null,
      lastErrorAt: null,
      lastErrorReason: null,
    });
    this.providers = { apns: p(opts.apns), fcm: p(opts.fcm) };
    if (opts.autoFlush !== false) {
      this.timer = setInterval(() => this.safeFlush(), FLUSH_INTERVAL_MS);
      this.timer.unref();
    }
  }

  close(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.safeFlush();
  }

  private minuteNow(): number {
    return Math.floor(this.nowMs() / 60_000);
  }

  /** Adds `n` to a counter, globally and (if given) for one instance. */
  count(kind: string, key: string, instance: string | null, n = 1): void {
    const minute = this.minuteNow();
    const add = (inst: string) => {
      const k = `${minute}\t${inst}\t${kind}\t${key}`;
      this.pending.set(k, (this.pending.get(k) ?? 0) + n);
    };
    add("");
    if (instance) add(instance);
    if (this.pending.size >= MAX_PENDING_KEYS) this.safeFlush();
  }

  private safeFlush(): void {
    try {
      this.flush();
    } catch {
      // Statistics must never break the relay; deltas stay pending for the next try.
    }
  }

  /** Writes pending deltas to SQLite and prunes old rows (at most every 10 minutes). */
  flush(): void {
    if (this.pending.size > 0) {
      const batch = this.pending;
      this.pending = new Map();
      const db = this.store.db;
      const upMinute = db.prepare(
        `INSERT INTO stats_minute (minute, instance, kind, key, count) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(minute, instance, kind, key) DO UPDATE SET count = count + excluded.count`,
      );
      const upHour = db.prepare(
        `INSERT INTO stats_hourly (hour, instance, kind, key, count) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(hour, instance, kind, key) DO UPDATE SET count = count + excluded.count`,
      );
      try {
        this.store.tx(() => {
          for (const [k, n] of batch) {
            const [m, inst, kind, key] = k.split("\t") as [string, string, string, string];
            const minute = Number(m);
            upMinute.run(minute, inst, kind, key, n);
            upHour.run(Math.floor(minute / 60), inst, kind, key, n);
          }
        });
      } catch (e) {
        // Put the deltas back so nothing is lost.
        for (const [k, n] of batch) this.pending.set(k, (this.pending.get(k) ?? 0) + n);
        throw e;
      }
    }
    const now = this.nowMs();
    if (now - this.lastPrune >= 600_000) {
      this.lastPrune = now;
      this.prune();
    }
  }

  prune(): void {
    const minute = this.minuteNow();
    this.store.db
      .prepare("DELETE FROM stats_minute WHERE minute < ?")
      .run(minute - MINUTE_RETENTION);
    this.store.db
      .prepare("DELETE FROM stats_hourly WHERE hour < ?")
      .run(Math.floor(minute / 60) - HOURLY_RETENTION);
  }

  private addEvent(instance: string, ev: Omit<InstanceEvent, "at">): void {
    let list = this.events.get(instance);
    if (list) {
      this.events.delete(instance); // re-insert: most recently active last
    } else {
      list = [];
      if (this.events.size >= MAX_EVENT_INSTANCES) {
        const oldest = this.events.keys().next().value;
        if (oldest !== undefined) this.events.delete(oldest);
      }
    }
    list.push({ at: this.nowMs(), ...ev });
    if (list.length > EVENTS_PER_INSTANCE) list.splice(0, list.length - EVENTS_PER_INSTANCE);
    this.events.set(instance, list);
  }

  recentEvents(instance: string): InstanceEvent[] {
    return [...(this.events.get(instance) ?? [])].reverse();
  }

  // ---- RelayEventSink ------------------------------------------------------

  message(e: { instance: string; platform: string; status: string; reason?: string }): void {
    this.count("msg", e.status, e.instance);
    this.count("msgp", `${e.platform}:${e.status}`, null);
    const provider =
      e.platform === "android"
        ? this.providers.fcm
        : e.platform.startsWith("ios")
          ? this.providers.apns
          : null;
    if (!provider) return;
    if (e.status === "ok") provider.lastOkAt = this.nowMs();
    if (e.status === "error") {
      provider.lastErrorAt = this.nowMs();
      provider.lastErrorReason = (e.reason ?? "unknown").slice(0, 80);
    }
  }

  registration(e: { instance: string; platform: string; deviceId: string; ip: string }): void {
    this.count("reg", e.platform, e.instance);
    this.addEvent(e.instance, {
      kind: "registration",
      detail: `registered ${e.platform} device`,
      device: e.deviceId,
      ip: truncateIp(e.ip),
    });
  }

  authFailure(e: { reason: string; instance: string | null; ip: string }): void {
    this.count("auth", e.reason, e.instance);
    if (e.instance) {
      this.addEvent(e.instance, {
        kind: "auth_failure",
        detail: `send rejected: ${e.reason}`,
        ip: truncateIp(e.ip),
      });
    }
  }

  rateLimited(e: { scope: string; instance: string | null }): void {
    this.count("rl", e.scope, e.instance);
  }

  sendCompleted(e: { instance: string; ip: string; results: Record<string, number> }): void {
    const parts = Object.entries(e.results)
      .filter(([, n]) => n > 0)
      .map(([s, n]) => `${n} ${s}`);
    this.addEvent(e.instance, {
      kind: "send",
      detail: `send: ${parts.join(", ") || "no messages"}`,
      ip: truncateIp(e.ip),
    });
  }

  deviceGone(e: { instance: string; platform: string; deviceId: string }): void {
    this.addEvent(e.instance, {
      kind: "gone",
      detail: `${e.platform} device unregistered by provider (gone)`,
      device: e.deviceId,
    });
  }

  refused(e: {
    what: "ip_blocked" | "instance_blocked" | "paused";
    instance: string | null;
  }): void {
    this.count("refused", e.what, e.instance);
    if (e.instance && e.what === "instance_blocked") {
      this.addEvent(e.instance, { kind: "blocked", detail: "request refused: instance blocked" });
    }
  }

  // ---- queries (flush first so the database is complete) -----------------

  /** Per-minute counts of the last `minutes` minutes (oldest first), summed over `keys`. */
  minuteSeries(kind: string, keys: string[] | null, instance = "", minutes = 60): number[] {
    this.safeFlush();
    const now = this.minuteNow();
    const from = now - minutes + 1;
    const rows = this.store.db
      .prepare(
        "SELECT minute, key, count FROM stats_minute WHERE instance = ? AND kind = ? AND minute >= ?",
      )
      .all(instance, kind, from) as Array<{ minute: number; key: string; count: number }>;
    const out = new Array<number>(minutes).fill(0);
    for (const r of rows) {
      if (keys && !keys.includes(r.key)) continue;
      const i = r.minute - from;
      if (i >= 0 && i < minutes) out[i] = (out[i] ?? 0) + r.count;
    }
    return out;
  }

  /** Per-hour counts of the last `hours` hours (oldest first). */
  hourSeries(kind: string, keys: string[] | null, instance = "", hours = 24): number[] {
    this.safeFlush();
    const now = Math.floor(this.minuteNow() / 60);
    const from = now - hours + 1;
    const rows = this.store.db
      .prepare(
        "SELECT hour, key, count FROM stats_hourly WHERE instance = ? AND kind = ? AND hour >= ?",
      )
      .all(instance, kind, from) as Array<{ hour: number; key: string; count: number }>;
    const out = new Array<number>(hours).fill(0);
    for (const r of rows) {
      if (keys && !keys.includes(r.key)) continue;
      const i = r.hour - from;
      if (i >= 0 && i < hours) out[i] = (out[i] ?? 0) + r.count;
    }
    return out;
  }

  /** Totals by key over the last `minutes` minutes (≤ 120). */
  lastMinutes(kind: string, instance = "", minutes = 60): Record<string, number> {
    this.safeFlush();
    const rows = this.store.db
      .prepare(
        "SELECT key, SUM(count) AS n FROM stats_minute WHERE instance = ? AND kind = ? AND minute > ? GROUP BY key",
      )
      .all(instance, kind, this.minuteNow() - minutes) as Row[];
    return Object.fromEntries(rows.map((r) => [r.key, r.n]));
  }

  /** Totals by key over the last `hours` hours (current hour included). */
  lastHours(kind: string, instance = "", hours = 24): Record<string, number> {
    this.safeFlush();
    const rows = this.store.db
      .prepare(
        "SELECT key, SUM(count) AS n FROM stats_hourly WHERE instance = ? AND kind = ? AND hour > ? GROUP BY key",
      )
      .all(instance, kind, Math.floor(this.minuteNow() / 60) - hours) as Row[];
    return Object.fromEntries(rows.map((r) => [r.key, r.n]));
  }

  /**
   * Instances ranked by messages in the last 24 h, then by registrations.
   * Includes instances that only have registrations.
   */
  topInstances(limit = 25): Array<{
    instance: string;
    messages1h: number;
    messages24h: number;
    errors24h: number;
    devices: number;
    lastSeen: number | null;
  }> {
    this.safeFlush();
    const db = this.store.db;
    const minute = this.minuteNow();
    const hour = Math.floor(minute / 60);
    const h24 = db
      .prepare(
        `SELECT instance, SUM(count) AS n, SUM(CASE WHEN key = 'error' THEN count ELSE 0 END) AS e,
                MAX(hour) AS last
         FROM stats_hourly WHERE instance != '' AND kind = 'msg' AND hour > ?
         GROUP BY instance ORDER BY n DESC LIMIT ?`,
      )
      .all(hour - 24, limit) as Array<{ instance: string; n: number; e: number; last: number }>;
    const devices = db
      .prepare(
        "SELECT instance, COUNT(*) AS n, MAX(last_used_at) AS used FROM devices GROUP BY instance ORDER BY n DESC LIMIT ?",
      )
      .all(limit) as Array<{ instance: string; n: number; used: number }>;
    const names = [...new Set([...h24.map((r) => r.instance), ...devices.map((r) => r.instance)])];
    const m1 = db.prepare(
      "SELECT SUM(count) AS n, MAX(minute) AS last FROM stats_minute WHERE instance = ? AND kind = 'msg' AND minute > ?",
    );
    const devCount = db.prepare(
      "SELECT COUNT(*) AS n, MAX(last_used_at) AS used FROM devices WHERE instance = ?",
    );
    const lastHourly = db.prepare(
      "SELECT MAX(hour) AS last FROM stats_hourly WHERE instance = ? AND kind IN ('msg','reg')",
    );
    const out = names.map((instance) => {
      const d = h24.find((r) => r.instance === instance);
      const recent = m1.get(instance, minute - 60) as { n: number | null; last: number | null };
      const dc = devCount.get(instance) as { n: number; used: number | null };
      const lh = lastHourly.get(instance) as { last: number | null };
      const candidates = [
        recent.last !== null ? (recent.last + 1) * 60 : null,
        lh.last !== null ? Math.min((lh.last + 1) * 3600, Math.floor(this.nowMs() / 1000)) : null,
        dc.used,
      ].filter((x): x is number => typeof x === "number");
      return {
        instance,
        messages1h: recent.n ?? 0,
        messages24h: d?.n ?? 0,
        errors24h: d?.e ?? 0,
        devices: dc.n,
        lastSeen: candidates.length ? Math.max(...candidates) : null,
      };
    });
    out.sort(
      (a, b) =>
        b.messages24h - a.messages24h ||
        b.devices - a.devices ||
        a.instance.localeCompare(b.instance),
    );
    return out.slice(0, limit);
  }
}

import type { Store } from "../db.ts";
import { MESSAGE_STATUSES, type ProviderHealth, type StatsCollector } from "../stats.ts";
import type { AdminActions, AuditEntry } from "./actions.ts";

export interface DashboardDeps {
  store: Store;
  stats: StatsCollector;
  actions: AdminActions;
  version: string;
  commit: string | null;
  startedAt: number;
  now?: () => number;
}

export interface Summary {
  generatedAt: number;
  version: string;
  commit: string | null;
  uptimeSeconds: number;
  dbOk: boolean;
  paused: { since: number; by: string; reason: string } | null;
  providers: { apns: ProviderHealth; fcm: ProviderHealth };
  devices: { total: number; byPlatform: Record<string, number>; new24h: number; instances: number };
  registrations: { lastHour: number; last24h: number };
  messages: {
    /** All statuses per minute, last 60 minutes (oldest first). */
    perMinute: number[];
    byStatusPerMinute: Record<string, number[]>;
    lastHour: Record<string, number>;
    last24h: Record<string, number>;
  };
  authFailures: { perMinute: number[]; lastHour: Record<string, number> };
  rateLimited: { perMinute: number[]; lastHour: Record<string, number> };
  refused: { lastHour: Record<string, number> };
  top: ReturnType<StatsCollector["topInstances"]>;
  blocked: ReturnType<Store["listBlocked"]>;
  blockedIps: ReturnType<Store["listBlockedIps"]>;
  audit: AuditEntry[];
}

function sum(r: Record<string, number>): number {
  return Object.values(r).reduce((a, b) => a + b, 0);
}

export function buildSummary(d: DashboardDeps): Summary {
  const now = (d.now ?? Date.now)();
  const { store, stats } = d;
  let dbOk = true;
  try {
    store.db.prepare("SELECT 1").get();
  } catch {
    dbOk = false;
  }
  const nowS = store.nowSeconds();
  const byPlatform = Object.fromEntries(
    (
      store.db
        .prepare("SELECT platform, COUNT(*) AS n FROM devices GROUP BY platform")
        .all() as Array<{
        platform: string;
        n: number;
      }>
    ).map((r) => [r.platform, r.n]),
  );
  const new24h = (
    store.db
      .prepare("SELECT COUNT(*) AS n FROM devices WHERE created_at > ?")
      .get(nowS - 86400) as {
      n: number;
    }
  ).n;
  const instances = (
    store.db.prepare("SELECT COUNT(DISTINCT instance) AS n FROM devices").get() as { n: number }
  ).n;
  const byStatusPerMinute: Record<string, number[]> = {};
  for (const s of MESSAGE_STATUSES) byStatusPerMinute[s] = stats.minuteSeries("msg", [s]);
  return {
    generatedAt: now,
    version: d.version,
    commit: d.commit,
    uptimeSeconds: Math.max(0, Math.floor((now - d.startedAt) / 1000)),
    dbOk,
    paused: store.getPause(),
    providers: {
      apns: { ...stats.providers.apns },
      fcm: { ...stats.providers.fcm },
    },
    devices: {
      total: sum(byPlatform),
      byPlatform,
      new24h,
      instances,
    },
    registrations: {
      lastHour: sum(stats.lastMinutes("reg")),
      last24h: sum(stats.lastHours("reg")),
    },
    messages: {
      perMinute: stats.minuteSeries("msg", null),
      byStatusPerMinute,
      lastHour: stats.lastMinutes("msg"),
      last24h: stats.lastHours("msg"),
    },
    authFailures: {
      perMinute: stats.minuteSeries("auth", null),
      lastHour: stats.lastMinutes("auth"),
    },
    rateLimited: {
      perMinute: stats.minuteSeries("rl", null),
      lastHour: stats.lastMinutes("rl"),
    },
    refused: { lastHour: stats.lastMinutes("refused") },
    top: stats.topInstances(25),
    blocked: store.listBlocked(),
    blockedIps: store.listBlockedIps(),
    audit: d.actions.listAudit(10),
  };
}

export interface InstanceDetail {
  instance: string;
  generatedAt: number;
  blocked: ReturnType<Store["listBlocked"]>[number] | null;
  devices: {
    total: number;
    byPlatform: Record<string, number>;
    byEnvironment: Record<string, number>;
    firstRegistered: number | null;
    lastRegistered: number | null;
    lastUsed: number | null;
  };
  messages: {
    lastHour: Record<string, number>;
    last24h: Record<string, number>;
    last30d: Record<string, number>;
    perMinute: number[];
    perHour: number[];
    errorsPerHour: number[];
  };
  registrations24h: number;
  authFailures24h: Record<string, number>;
  rateLimited24h: Record<string, number>;
  events: ReturnType<StatsCollector["recentEvents"]>;
}

export function buildInstanceDetail(d: DashboardDeps, instance: string): InstanceDetail {
  const { store, stats } = d;
  const group = (col: "platform" | "environment") =>
    Object.fromEntries(
      (
        store.db
          .prepare(
            `SELECT ${col} AS k, COUNT(*) AS n FROM devices WHERE instance = ? GROUP BY ${col}`,
          )
          .all(instance) as Array<{ k: string; n: number }>
      ).map((r) => [r.k, r.n]),
    );
  const agg = store.db
    .prepare(
      "SELECT COUNT(*) AS n, MIN(created_at) AS first, MAX(created_at) AS last, MAX(last_used_at) AS used FROM devices WHERE instance = ?",
    )
    .get(instance) as { n: number; first: number | null; last: number | null; used: number | null };
  return {
    instance,
    generatedAt: (d.now ?? Date.now)(),
    blocked: store.listBlocked().find((b) => b.origin === instance) ?? null,
    devices: {
      total: agg.n,
      byPlatform: group("platform"),
      byEnvironment: group("environment"),
      firstRegistered: agg.first,
      lastRegistered: agg.last,
      lastUsed: agg.used,
    },
    messages: {
      lastHour: stats.lastMinutes("msg", instance),
      last24h: stats.lastHours("msg", instance, 24),
      last30d: stats.lastHours("msg", instance, 30 * 24),
      perMinute: stats.minuteSeries("msg", null, instance),
      perHour: stats.hourSeries("msg", null, instance, 24),
      errorsPerHour: stats.hourSeries("msg", ["error"], instance, 24),
    },
    registrations24h: sum(stats.lastHours("reg", instance, 24)),
    authFailures24h: stats.lastHours("auth", instance, 24),
    rateLimited24h: stats.lastHours("rl", instance, 24),
    events: stats.recentEvents(instance),
  };
}

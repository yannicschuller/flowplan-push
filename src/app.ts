import type http from "node:http";
import { AdminActions } from "./admin/actions.ts";
import { AdminHandler } from "./admin/handler.ts";
import { OidcClient, type OidcClientOptions } from "./admin/oidc.ts";
import { AdminSessions } from "./admin/sessions.ts";
import type { Config } from "./config.ts";
import { StorageCipher } from "./crypto/storage.ts";
import { Store } from "./db.ts";
import { createHttpServer } from "./http/server.ts";
import { InstanceKeyResolver } from "./instance/keys.ts";
import { createLogger, type Logger } from "./log.ts";
import { createRelayMetrics, type RelayMetrics } from "./metrics.ts";
import { ApnsClient } from "./push/apns.ts";
import { FcmClient } from "./push/fcm.ts";
import { Relay } from "./relay.ts";
import { StatsCollector } from "./stats.ts";
import { relayVersion } from "./version.ts";

export interface App {
  server: http.Server;
  relay: Relay;
  store: Store;
  metrics: RelayMetrics;
  logger: Logger;
  stats: StatsCollector;
  actions: AdminActions;
  admin: AdminHandler | null;
  close(): Promise<void>;
}

export interface AppOverrides {
  logger?: Logger;
  /** Tests: options for the OIDC client (e.g. an http mock identity provider). */
  oidc?: OidcClientOptions;
}

export function createApp(config: Config, overrides: AppOverrides = {}): App {
  const startedAt = Date.now();
  const logger = overrides.logger ?? createLogger(config.logLevel);
  const metrics = createRelayMetrics();
  const cipher = new StorageCipher(config.storageKey, config.oldStorageKeys);
  const store = new Store(config.dataDir, cipher);
  const keys = new InstanceKeyResolver({
    fetchOptions: { allowPrivate: config.allowPrivateInstances },
    onFetch: (_origin, outcome) => metrics.wellKnownFetches({ outcome }),
  });
  const apns = config.apns ? new ApnsClient(config.apns) : null;
  const fcm = config.fcm ? new FcmClient(config.fcm) : null;
  const stats = new StatsCollector(store, { apns: !!apns, fcm: !!fcm });
  const actions = new AdminActions(store, logger);
  const relay = new Relay({
    store,
    keys,
    apns,
    fcm,
    allowedBundleIds: config.allowedBundleIds,
    allowPrivateInstances: config.allowPrivateInstances,
    metrics,
    logger,
    events: stats,
  });
  metrics.registry.gauge("flowplan_push_devices", "Registered devices (all platforms)", () =>
    store.deviceCount(),
  );
  metrics.registry.gauge(
    "flowplan_push_replay_cache_entries",
    "Signatures in the replay cache",
    () => relay.replay.size,
  );

  metrics.registry.gauge(
    "flowplan_push_sending_paused",
    "1 while sending is paused by the operator (kill switch)",
    () => (store.getPause() ? 1 : 0),
  );

  let admin: AdminHandler | null = null;
  let sessions: AdminSessions | null = null;
  if (config.admin) {
    sessions = new AdminSessions(store, config.admin);
    admin = new AdminHandler({
      config: config.admin,
      oidc: new OidcClient(config.admin, overrides.oidc),
      sessions,
      actions,
      logger,
      dashboard: {
        store,
        stats,
        actions,
        version: relayVersion(),
        commit: config.commit,
        startedAt,
      },
    });
  }

  const server = createHttpServer({
    relay,
    metrics,
    logger,
    metricsToken: config.metricsToken,
    trustProxyHops: config.trustProxyHops,
    hsts: config.publicUrl.startsWith("https://"),
    admin,
    healthCheck: () => {
      try {
        store.db.prepare("SELECT 1").get();
        return true;
      } catch {
        return false;
      }
    },
  });

  const purge = () => {
    try {
      const n = store.purgeExpired();
      if (n > 0) logger.info("purged expired registrations", { count: n });
      sessions?.purge();
    } catch (e) {
      logger.error("purge failed", { error: e });
    }
  };
  const purgeTimer = setInterval(purge, 3_600_000);
  purgeTimer.unref();
  purge();

  const keyStats = store.stats(0).devicesByKeyId;
  const stale = Object.entries(keyStats).filter(([id]) => id !== cipher.currentKeyId);
  if (stale.length > 0) {
    logger.warn("registrations encrypted with an old storage key exist; run `admin rotate-keys`", {
      keyIds: stale.map(([id, n]) => `${id}:${n}`),
    });
  }

  return {
    server,
    relay,
    store,
    metrics,
    logger,
    stats,
    actions,
    admin,
    async close() {
      clearInterval(purgeTimer);
      stats.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      server.closeAllConnections?.();
      apns?.close();
      store.close();
    },
  };
}

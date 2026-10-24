import { createApp } from "./app.ts";
import { ConfigError, loadConfig } from "./config.ts";
import { StorageKeyError } from "./crypto/storage.ts";
import { createLogger } from "./log.ts";

// Files created at runtime (database, WAL) are private to the relay user.
process.umask(0o077);

let config: ReturnType<typeof loadConfig>;
try {
  config = loadConfig();
} catch (e) {
  if (e instanceof ConfigError || e instanceof StorageKeyError) {
    process.stderr.write(`flowplan-push: configuration error: ${e.message}\n`);
    process.exit(78); // EX_CONFIG
  }
  throw e;
}

const app = createApp(config, { logger: createLogger(config.logLevel) });
const { logger } = app;

if (!config.apns) logger.warn('APNs is not configured: iOS messages will return status "error"');
if (!config.fcm) logger.warn('FCM is not configured: Android messages will return status "error"');
if (config.allowPrivateInstances)
  logger.warn("ALLOW_PRIVATE_INSTANCES is enabled: do not use this on a public relay");

app.server.listen(config.port, config.host, () => {
  logger.info("flowplan-push relay listening", {
    port: config.port,
    publicUrl: config.publicUrl,
    apns: !!config.apns,
    fcm: !!config.fcm,
    fcmProject: config.fcm?.projectId,
    bundles: config.allowedBundleIds,
    trustProxyHops: config.trustProxyHops,
    metrics: !!config.metricsToken,
  });
});

let stopping = false;
const shutdown = (signal: string) => {
  if (stopping) return;
  stopping = true;
  logger.info("shutting down", { signal });
  const force = setTimeout(() => process.exit(1), 10_000);
  force.unref();
  app
    .close()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
};
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("unhandledRejection", (e) => logger.error("unhandled rejection", { error: e }));

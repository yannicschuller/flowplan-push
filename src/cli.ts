import { randomBytes } from "node:crypto";
import { ConfigError, loadConfig } from "./config.ts";
import { StorageCipher, StorageKeyError } from "./crypto/storage.ts";
import { Store } from "./db.ts";
import { canonicalOrigin } from "./net/origin.ts";

/**
 * Admin CLI (no web admin UI). Runs against the same DATA_DIR as the server;
 * changes take effect immediately (the blocklist is read per request).
 *
 *   docker exec <container> node dist/src/cli.js <command>
 */

const USAGE = `Usage: flowplan-push-admin <command>

Commands:
  block <origin> [reason…]   Block an instance origin (registrations and sends are refused)
  unblock <origin>           Remove an origin from the blocklist
  blocked                    List blocked origins
  delete-instance <origin>   Delete all registrations of an origin
  stats [days] [--json]      Registrations and delivery counters (default: 7 days)
  purge                      Delete expired registrations now
  rotate-keys                Re-encrypt all device tokens with the current RELAY_STORAGE_KEY
  generate-key               Print a new random RELAY_STORAGE_KEY
`;

function out(line = ""): void {
  process.stdout.write(`${line}\n`);
}

function fail(msg: string, code = 1): never {
  process.stderr.write(`${msg}\n`);
  process.exit(code);
}

function main(argv: string[]): void {
  const [cmd, ...args] = argv;
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    out(USAGE);
    return;
  }
  if (cmd === "generate-key") {
    out(randomBytes(32).toString("base64"));
    return;
  }

  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig();
  } catch (e) {
    if (e instanceof ConfigError || e instanceof StorageKeyError)
      fail(`configuration error: ${e.message}`, 78);
    throw e;
  }
  const store = new Store(
    config.dataDir,
    new StorageCipher(config.storageKey, config.oldStorageKeys),
  );
  const originArg = () => {
    const o = canonicalOrigin(args[0], true);
    if (!o) fail("expected an origin like https://flowplan.example.com");
    return o;
  };

  try {
    switch (cmd) {
      case "block": {
        const origin = originArg();
        const reason = args.slice(1).join(" ").slice(0, 500) || null;
        store.block(origin, reason);
        out(`blocked ${origin}`);
        break;
      }
      case "unblock": {
        const origin = originArg();
        out(store.unblock(origin) ? `unblocked ${origin}` : `${origin} was not blocked`);
        break;
      }
      case "blocked": {
        const rows = store.listBlocked();
        if (rows.length === 0) out("no blocked instances");
        for (const r of rows) {
          out(`${r.origin}\t${new Date(r.createdAt * 1000).toISOString()}\t${r.reason ?? ""}`);
        }
        break;
      }
      case "delete-instance": {
        const origin = originArg();
        out(`deleted ${store.deleteInstanceDevices(origin)} registrations of ${origin}`);
        break;
      }
      case "stats": {
        const days = Number(args.find((a) => /^\d+$/.test(a)) ?? 7);
        const s = store.stats(days);
        if (args.includes("--json")) {
          out(JSON.stringify(s, null, 2));
          break;
        }
        out("Registrations by platform:");
        for (const [p, n] of Object.entries(s.devicesByPlatform)) out(`  ${p.padEnd(18)} ${n}`);
        out(`Instances with registrations: ${s.instances}`);
        out(`Blocked instances: ${s.blocked}`);
        out("Registrations by storage key id:");
        const currentKeyId = new StorageCipher(config.storageKey).currentKeyId;
        for (const [k, n] of Object.entries(s.devicesByKeyId)) {
          out(
            `  ${k.padEnd(14)} ${String(n).padStart(7)}${k === currentKeyId ? "  (current)" : "  (old: run rotate-keys)"}`,
          );
        }
        out("Top instances:");
        for (const t of s.topInstances) out(`  ${String(t.devices).padStart(7)}  ${t.instance}`);
        out(`Deliveries (last ${days} days):`);
        for (const d of s.daily)
          out(`  ${d.day}  ${d.platform.padEnd(18)} ${d.status.padEnd(13)} ${d.count}`);
        break;
      }
      case "purge":
        out(`purged ${store.purgeExpired()} expired registrations`);
        break;
      case "rotate-keys": {
        const r = store.reencryptAll();
        out(`re-encrypted ${r.reencrypted} registrations, ${r.failed} failed`);
        if (r.failed > 0) {
          out(
            "Failed records were encrypted with a key that is not configured; they cannot be recovered.",
          );
          process.exitCode = 2;
        } else {
          out("All registrations use the current key. You can now remove RELAY_STORAGE_KEYS_OLD.");
        }
        break;
      }
      default:
        out(USAGE);
        process.exitCode = 64;
    }
  } finally {
    store.close();
  }
}

main(process.argv.slice(2));

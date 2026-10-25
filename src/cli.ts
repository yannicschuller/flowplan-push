import { randomBytes } from "node:crypto";
import {
  ActionError,
  AdminActions,
  CLI_ACTOR,
  parseDuration,
  parseIpRange,
} from "./admin/actions.ts";
import { ConfigError, loadConfig } from "./config.ts";
import { StorageCipher, StorageKeyError } from "./crypto/storage.ts";
import { Store } from "./db.ts";
import { createLogger } from "./log.ts";
import { canonicalOrigin } from "./net/origin.ts";

/**
 * Admin CLI. Runs against the same DATA_DIR as the server; changes take effect
 * immediately (blocklists and the pause switch are read per request). Uses the
 * same actions as the web dashboard; every change is written to the audit log
 * with actor "cli".
 *
 *   docker exec <container> node dist/src/cli.js <command>
 */

const USAGE = `Usage: flowplan-push-admin <command>

Commands:
  block <origin> [reason…]   Block an instance origin (registrations and sends are refused)
  block <origin> --for <1h|24h|7d|30d> [reason…]   Block temporarily
  unblock <origin>           Remove an origin from the blocklist
  blocked                    List blocked origins
  delete-instance <origin>   Delete all registrations of an origin
  block-ip <ip|cidr> <1h|24h|7d|30d> [reason…]   Refuse registrations from an IP range
  unblock-ip <ip|cidr>       Remove an IP range block
  blocked-ips                List blocked IP ranges
  pause <reason…>            Emergency: refuse every send (503 relay_paused) until resumed
  resume                     End the pause
  status                     Show whether sending is paused
  audit [n]                  Show the last n admin audit entries (default 30)
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

function iso(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toISOString();
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
  const actions = new AdminActions(store, createLogger("silent"));
  const originArg = () => {
    const o = canonicalOrigin(args[0], true);
    if (!o) fail("expected an origin like https://flowplan.example.com");
    return o;
  };

  try {
    switch (cmd) {
      case "block": {
        const origin = originArg();
        let rest = args.slice(1);
        let duration: number | null = null;
        if (rest[0] === "--for") {
          duration = parseDuration(rest[1], false);
          rest = rest.slice(2);
        }
        const reason = rest.join(" ").slice(0, 500) || null;
        actions.blockInstance(CLI_ACTOR, origin, reason, duration);
        out(`blocked ${origin}${duration ? ` until ${iso(store.nowSeconds() + duration)}` : ""}`);
        break;
      }
      case "unblock": {
        const origin = originArg();
        const r = actions.unblockInstance(CLI_ACTOR, origin, null);
        out(r.was ? `unblocked ${origin}` : `${origin} was not blocked`);
        break;
      }
      case "blocked": {
        const rows = store.listBlocked();
        if (rows.length === 0) out("no blocked instances");
        for (const r of rows) {
          out(
            `${r.origin}\t${iso(r.createdAt)}\t${r.reason ?? ""}\t${r.expiresAt ? `until ${iso(r.expiresAt)}` : "permanent"}\t${r.createdBy ?? ""}`,
          );
        }
        break;
      }
      case "delete-instance": {
        const origin = originArg();
        const r = actions.deleteInstance(CLI_ACTOR, origin, null);
        out(`deleted ${r.deleted} registrations of ${origin}`);
        break;
      }
      case "block-ip": {
        const cidr = parseIpRange(args[0]);
        const duration = parseDuration(args[1], false) as number;
        const reason = args.slice(2).join(" ").slice(0, 500) || null;
        actions.blockIp(CLI_ACTOR, cidr, reason, duration);
        out(`blocked ${cidr} for registrations until ${iso(store.nowSeconds() + duration)}`);
        break;
      }
      case "unblock-ip": {
        const cidr = parseIpRange(args[0]);
        out(
          actions.unblockIp(CLI_ACTOR, cidr, null).was
            ? `unblocked ${cidr}`
            : `${cidr} was not blocked`,
        );
        break;
      }
      case "blocked-ips": {
        const rows = store.listBlockedIps();
        if (rows.length === 0) out("no blocked IP ranges");
        for (const r of rows)
          out(`${r.cidr}\tuntil ${iso(r.expiresAt)}\t${r.reason ?? ""}\t${r.createdBy ?? ""}`);
        break;
      }
      case "pause": {
        const reason = args.join(" ").slice(0, 500);
        if (reason.length < 3) fail("a reason is required: pause <reason…>");
        actions.pauseSending(CLI_ACTOR, reason);
        out("sending paused: every send request now gets 503 relay_paused");
        break;
      }
      case "resume": {
        const r = actions.resumeSending(CLI_ACTOR, args.join(" ").slice(0, 500) || null);
        out(r.was ? "sending resumed" : "sending was not paused");
        break;
      }
      case "status": {
        const p = store.getPause();
        out(p ? `sending PAUSED since ${iso(p.since)} by ${p.by}: ${p.reason}` : "sending enabled");
        break;
      }
      case "audit": {
        const n = Math.min(1000, Number(args[0] ?? 30) || 30);
        for (const e of actions.listAudit(n)) {
          out(
            `${e.id}\t${iso(e.at)}\t${e.actor}\t${e.action}\t${e.target ?? ""}\t${e.reason ?? ""}\t${e.ip ?? ""}`,
          );
        }
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
        out(`purged ${actions.purgeExpired(CLI_ACTOR, null).purged} expired registrations`);
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
  } catch (e) {
    if (e instanceof ActionError) fail(e.message, 64);
    throw e;
  } finally {
    store.close();
  }
}

main(process.argv.slice(2));

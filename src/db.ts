import { chmodSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { StorageCipher } from "./crypto/storage.ts";
import { generateRelayToken, hashRelayToken } from "./crypto/tokens.ts";

/**
 * SQLite storage (node:sqlite). What is stored:
 *   - relay tokens: only SHA-256 hashes
 *   - device tokens: AES-256-GCM ciphertext bound to the record (AAD), plus
 *     an HMAC lookup hash to find an existing registration for the same token
 *   - instance origin, platform, environment, bundle id, timestamps
 *   - blocked instance origins
 *   - daily delivery counters (no per-device data)
 */

export type Platform = "ios" | "ios-liveactivity" | "android";
export type Environment = "production" | "sandbox";

export const TOKEN_LIFETIME_SECONDS = 180 * 24 * 3600;
/** Expiry is extended on use, but written at most once per hour per record. */
const TOUCH_INTERVAL_SECONDS = 3600;

export interface DeviceRecord {
  tokenHash: string;
  instance: string;
  platform: Platform;
  environment: Environment;
  bundleId: string;
  deviceTokenEnc: string;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
}

export interface RegisterInput {
  platform: Platform;
  environment: Environment;
  bundleId: string;
  instance: string;
  deviceToken: string;
}

interface DeviceRow {
  token_hash: string;
  instance: string;
  platform: string;
  environment: string;
  bundle_id: string;
  device_token_enc: string;
  created_at: number;
  last_used_at: number;
  expires_at: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS devices (
  token_hash        TEXT PRIMARY KEY,
  instance          TEXT NOT NULL,
  platform          TEXT NOT NULL CHECK (platform IN ('ios','ios-liveactivity','android')),
  environment       TEXT NOT NULL CHECK (environment IN ('production','sandbox')),
  bundle_id         TEXT NOT NULL,
  device_token_enc  TEXT NOT NULL,
  device_lookup     TEXT NOT NULL,
  key_id            TEXT NOT NULL,
  created_at        INTEGER NOT NULL,
  last_used_at      INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS devices_lookup ON devices (device_lookup, instance);
CREATE INDEX IF NOT EXISTS devices_instance ON devices (instance);
CREATE INDEX IF NOT EXISTS devices_expires ON devices (expires_at);
CREATE INDEX IF NOT EXISTS devices_key ON devices (key_id);
CREATE TABLE IF NOT EXISTS blocked_instances (
  origin      TEXT PRIMARY KEY,
  reason      TEXT,
  created_at  INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS stats_daily (
  day       TEXT NOT NULL,
  platform  TEXT NOT NULL,
  status    TEXT NOT NULL,
  count     INTEGER NOT NULL,
  PRIMARY KEY (day, platform, status)
) STRICT;
`;

function aadFor(tokenHash: string): string {
  return `flowplan-push/device-token/v1|${tokenHash}`;
}

function lookupInput(platform: Platform, deviceToken: string): string {
  return `${platform}|${deviceToken}`;
}

export class Store {
  readonly db: DatabaseSync;
  private readonly cipher: StorageCipher;
  private readonly now: () => number;

  constructor(
    dataDir: string,
    cipher: StorageCipher,
    now: () => number = () => Math.floor(Date.now() / 1000),
  ) {
    this.cipher = cipher;
    this.now = now;
    let file = ":memory:";
    if (dataDir !== ":memory:") {
      if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true, mode: 0o700 });
      file = path.join(dataDir, "relay.db");
    }
    this.db = new DatabaseSync(file);
    if (file !== ":memory:") {
      try {
        chmodSync(file, 0o600);
      } catch {
        // best effort (e.g. volume without chmod support)
      }
    }
    this.db.exec(
      "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;",
    );
    this.db.exec("PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;");
    this.db.exec(SCHEMA);
    this.db.prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1')").run();
  }

  close(): void {
    this.db.close();
  }

  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  /** Creates a registration; replaces an existing one for the same (device token, instance). */
  register(input: RegisterInput): { relayToken: string; expiresAt: number; replaced: number } {
    const now = this.now();
    const relayToken = generateRelayToken();
    const tokenHash = hashRelayToken(relayToken);
    const lookups = this.cipher.lookupHashesAllKeys(lookupInput(input.platform, input.deviceToken));
    const enc = this.cipher.encrypt(input.deviceToken, aadFor(tokenHash));
    const expiresAt = now + TOKEN_LIFETIME_SECONDS;
    const replaced = this.tx(() => {
      const placeholders = lookups.map(() => "?").join(",");
      const del = this.db
        .prepare(`DELETE FROM devices WHERE instance = ? AND device_lookup IN (${placeholders})`)
        .run(input.instance, ...lookups);
      this.db
        .prepare(
          `INSERT INTO devices (token_hash, instance, platform, environment, bundle_id, device_token_enc,
             device_lookup, key_id, created_at, last_used_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          tokenHash,
          input.instance,
          input.platform,
          input.environment,
          input.bundleId,
          enc,
          lookups[0] as string,
          this.cipher.currentKeyId,
          now,
          now,
          expiresAt,
        );
      return Number(del.changes);
    });
    return { relayToken, expiresAt, replaced };
  }

  /** Returns the live (non-expired) record for a relay token, or null. */
  findByRelayToken(relayToken: string): DeviceRecord | null {
    const row = this.db
      .prepare("SELECT * FROM devices WHERE token_hash = ? AND expires_at > ?")
      .get(hashRelayToken(relayToken), this.now()) as DeviceRow | undefined;
    if (!row) return null;
    return {
      tokenHash: row.token_hash,
      instance: row.instance,
      platform: row.platform as Platform,
      environment: row.environment as Environment,
      bundleId: row.bundle_id,
      deviceTokenEnc: row.device_token_enc,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      expiresAt: row.expires_at,
    };
  }

  decryptDeviceToken(rec: DeviceRecord): string {
    return this.cipher.decrypt(rec.deviceTokenEnc, aadFor(rec.tokenHash));
  }

  deleteByRelayToken(relayToken: string): boolean {
    return this.deleteByHash(hashRelayToken(relayToken));
  }

  deleteByHash(tokenHash: string): boolean {
    return (
      Number(this.db.prepare("DELETE FROM devices WHERE token_hash = ?").run(tokenHash).changes) > 0
    );
  }

  /** Extends the expiry after a successful send (throttled to one write per hour). */
  touch(rec: DeviceRecord): void {
    const now = this.now();
    if (now - rec.lastUsedAt < TOUCH_INTERVAL_SECONDS) return;
    this.db
      .prepare("UPDATE devices SET last_used_at = ?, expires_at = ? WHERE token_hash = ?")
      .run(now, now + TOKEN_LIFETIME_SECONDS, rec.tokenHash);
  }

  instanceHasDevices(origin: string): boolean {
    return !!this.db.prepare("SELECT 1 FROM devices WHERE instance = ? LIMIT 1").get(origin);
  }

  purgeExpired(): number {
    return Number(
      this.db.prepare("DELETE FROM devices WHERE expires_at <= ?").run(this.now()).changes,
    );
  }

  // ---- blocklist -------------------------------------------------------

  isBlocked(origin: string): boolean {
    return !!this.db.prepare("SELECT 1 FROM blocked_instances WHERE origin = ?").get(origin);
  }

  block(origin: string, reason: string | null): void {
    this.db
      .prepare(
        "INSERT INTO blocked_instances (origin, reason, created_at) VALUES (?, ?, ?) ON CONFLICT(origin) DO UPDATE SET reason = excluded.reason",
      )
      .run(origin, reason, this.now());
  }

  unblock(origin: string): boolean {
    return (
      Number(
        this.db.prepare("DELETE FROM blocked_instances WHERE origin = ?").run(origin).changes,
      ) > 0
    );
  }

  listBlocked(): Array<{ origin: string; reason: string | null; createdAt: number }> {
    return (
      this.db
        .prepare("SELECT origin, reason, created_at FROM blocked_instances ORDER BY origin")
        .all() as Array<{
        origin: string;
        reason: string | null;
        created_at: number;
      }>
    ).map((r) => ({ origin: r.origin, reason: r.reason, createdAt: r.created_at }));
  }

  deleteInstanceDevices(origin: string): number {
    return Number(this.db.prepare("DELETE FROM devices WHERE instance = ?").run(origin).changes);
  }

  // ---- stats -----------------------------------------------------------

  recordDeliveries(counts: Map<string, number>): void {
    if (counts.size === 0) return;
    const day = new Date(this.now() * 1000).toISOString().slice(0, 10);
    const stmt = this.db.prepare(
      `INSERT INTO stats_daily (day, platform, status, count) VALUES (?, ?, ?, ?)
       ON CONFLICT(day, platform, status) DO UPDATE SET count = count + excluded.count`,
    );
    this.tx(() => {
      for (const [k, n] of counts) {
        const [platform, status] = k.split("|");
        stmt.run(day, platform ?? "unknown", status ?? "unknown", n);
      }
    });
  }

  stats(days = 7): {
    devicesByPlatform: Record<string, number>;
    instances: number;
    topInstances: Array<{ instance: string; devices: number }>;
    blocked: number;
    devicesByKeyId: Record<string, number>;
    daily: Array<{ day: string; platform: string; status: string; count: number }>;
  } {
    const byPlatform = this.db
      .prepare("SELECT platform, COUNT(*) AS n FROM devices GROUP BY platform")
      .all() as Array<{ platform: string; n: number }>;
    const byKey = this.db
      .prepare("SELECT key_id, COUNT(*) AS n FROM devices GROUP BY key_id")
      .all() as Array<{
      key_id: string;
      n: number;
    }>;
    const instances = this.db
      .prepare("SELECT COUNT(DISTINCT instance) AS n FROM devices")
      .get() as { n: number };
    const top = this.db
      .prepare(
        "SELECT instance, COUNT(*) AS n FROM devices GROUP BY instance ORDER BY n DESC LIMIT 20",
      )
      .all() as Array<{ instance: string; n: number }>;
    const blocked = this.db.prepare("SELECT COUNT(*) AS n FROM blocked_instances").get() as {
      n: number;
    };
    const since = new Date((this.now() - days * 86400) * 1000).toISOString().slice(0, 10);
    const daily = this.db
      .prepare(
        "SELECT day, platform, status, count FROM stats_daily WHERE day >= ? ORDER BY day, platform, status",
      )
      .all(since) as Array<{ day: string; platform: string; status: string; count: number }>;
    return {
      devicesByPlatform: Object.fromEntries(byPlatform.map((r) => [r.platform, r.n])),
      instances: instances.n,
      topInstances: top.map((r) => ({ instance: r.instance, devices: r.n })),
      blocked: blocked.n,
      devicesByKeyId: Object.fromEntries(byKey.map((r) => [r.key_id, r.n])),
      daily,
    };
  }

  deviceCount(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM devices").get() as { n: number }).n;
  }

  /**
   * Re-encrypts every record not yet using the current storage key (after a
   * rotation). Afterwards the old key can be removed from RELAY_STORAGE_KEYS_OLD.
   */
  reencryptAll(): { reencrypted: number; failed: number } {
    const rows = this.db
      .prepare("SELECT token_hash, platform, device_token_enc FROM devices WHERE key_id != ?")
      .all(this.cipher.currentKeyId) as Array<{
      token_hash: string;
      platform: string;
      device_token_enc: string;
    }>;
    let reencrypted = 0;
    let failed = 0;
    const update = this.db.prepare(
      "UPDATE devices SET device_token_enc = ?, device_lookup = ?, key_id = ? WHERE token_hash = ?",
    );
    this.tx(() => {
      for (const r of rows) {
        try {
          const plain = this.cipher.decrypt(r.device_token_enc, aadFor(r.token_hash));
          update.run(
            this.cipher.encrypt(plain, aadFor(r.token_hash)),
            this.cipher.lookupHash(lookupInput(r.platform as Platform, plain)),
            this.cipher.currentKeyId,
            r.token_hash,
          );
          reencrypted++;
        } catch {
          failed++;
        }
      }
    });
    return { reencrypted, failed };
  }
}

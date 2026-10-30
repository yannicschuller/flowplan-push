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
 *   - blocked instance origins and (temporarily) blocked client IP ranges
 *   - daily delivery counters and per-minute/per-hour aggregates (no per-device data)
 *   - operator settings (emergency pause), admin sessions (hashed ids) and the
 *     append-only admin audit log
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
CREATE TABLE IF NOT EXISTS blocked_ips (
  cidr        TEXT PRIMARY KEY,
  reason      TEXT,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  created_by  TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS settings (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  updated_at  INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS stats_minute (
  minute    INTEGER NOT NULL,
  instance  TEXT NOT NULL,
  kind      TEXT NOT NULL,
  key       TEXT NOT NULL,
  count     INTEGER NOT NULL,
  PRIMARY KEY (minute, instance, kind, key)
) STRICT, WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS stats_hourly (
  hour      INTEGER NOT NULL,
  instance  TEXT NOT NULL,
  kind      TEXT NOT NULL,
  key       TEXT NOT NULL,
  count     INTEGER NOT NULL,
  PRIMARY KEY (hour, instance, kind, key)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS stats_hourly_instance ON stats_hourly (instance, hour);
CREATE INDEX IF NOT EXISTS stats_minute_instance ON stats_minute (instance, minute);
CREATE TABLE IF NOT EXISTS admin_sessions (
  id_hash       TEXT PRIMARY KEY,
  sub           TEXT NOT NULL,
  email         TEXT,
  name          TEXT,
  csrf          TEXT NOT NULL,
  config_fp     TEXT NOT NULL,
  ip            TEXT,
  created_at    INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS admin_login_states (
  state_hash    TEXT PRIMARY KEY,
  binding_hash  TEXT NOT NULL,
  nonce         TEXT NOT NULL,
  verifier      TEXT NOT NULL,
  created_at    INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS admin_audit (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  at         INTEGER NOT NULL,
  actor      TEXT NOT NULL,
  actor_sub  TEXT,
  action     TEXT NOT NULL,
  target     TEXT,
  reason     TEXT,
  ip         TEXT,
  details    TEXT
) STRICT;
CREATE TRIGGER IF NOT EXISTS admin_audit_no_update BEFORE UPDATE ON admin_audit
  BEGIN SELECT RAISE(ABORT, 'admin_audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS admin_audit_no_delete BEFORE DELETE ON admin_audit
  BEGIN SELECT RAISE(ABORT, 'admin_audit is append-only'); END;
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
    this.migrate();
    this.db.prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '2')").run();
  }

  /** Additive migrations for databases created by older versions. */
  private migrate(): void {
    const cols = new Set(
      (
        this.db.prepare("PRAGMA table_info(blocked_instances)").all() as Array<{ name: string }>
      ).map((c) => c.name),
    );
    if (!cols.has("expires_at"))
      this.db.exec("ALTER TABLE blocked_instances ADD COLUMN expires_at INTEGER");
    if (!cols.has("created_by"))
      this.db.exec("ALTER TABLE blocked_instances ADD COLUMN created_by TEXT");
    this.db.prepare("UPDATE meta SET value = '2' WHERE key = 'schema_version'").run();
  }

  /** Current time in Unix seconds (the store's clock; injectable in tests). */
  nowSeconds(): number {
    return this.now();
  }

  close(): void {
    this.db.close();
  }

  tx<T>(fn: () => T): T {
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
    const now = this.now();
    // Expired temporary blocks are housekeeping, not registrations: not counted.
    this.db.prepare("DELETE FROM blocked_ips WHERE expires_at <= ?").run(now);
    this.db
      .prepare("DELETE FROM blocked_instances WHERE expires_at IS NOT NULL AND expires_at <= ?")
      .run(now);
    return Number(this.db.prepare("DELETE FROM devices WHERE expires_at <= ?").run(now).changes);
  }

  // ---- blocklist -------------------------------------------------------

  isBlocked(origin: string): boolean {
    return !!this.db
      .prepare(
        "SELECT 1 FROM blocked_instances WHERE origin = ? AND (expires_at IS NULL OR expires_at > ?)",
      )
      .get(origin, this.now());
  }

  /**
   * Blocks an origin. `expiresAt` (Unix seconds) makes the block temporary;
   * `by` records who blocked it (admin e-mail/subject or "cli").
   */
  block(
    origin: string,
    reason: string | null,
    opts: { expiresAt?: number | null; by?: string | null } = {},
  ): void {
    this.db
      .prepare(
        `INSERT INTO blocked_instances (origin, reason, created_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(origin) DO UPDATE SET reason = excluded.reason, created_at = excluded.created_at,
           expires_at = excluded.expires_at, created_by = excluded.created_by`,
      )
      .run(origin, reason, this.now(), opts.expiresAt ?? null, opts.by ?? null);
  }

  unblock(origin: string): boolean {
    return (
      Number(
        this.db.prepare("DELETE FROM blocked_instances WHERE origin = ?").run(origin).changes,
      ) > 0
    );
  }

  listBlocked(): Array<{
    origin: string;
    reason: string | null;
    createdAt: number;
    expiresAt: number | null;
    createdBy: string | null;
  }> {
    return (
      this.db
        .prepare(
          `SELECT origin, reason, created_at, expires_at, created_by FROM blocked_instances
           WHERE expires_at IS NULL OR expires_at > ? ORDER BY origin`,
        )
        .all(this.now()) as Array<{
        origin: string;
        reason: string | null;
        created_at: number;
        expires_at: number | null;
        created_by: string | null;
      }>
    ).map((r) => ({
      origin: r.origin,
      reason: r.reason,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      createdBy: r.created_by,
    }));
  }

  // ---- blocked client IP ranges (registrations only) -------------------

  blockIp(cidr: string, reason: string | null, expiresAt: number, by: string | null): void {
    this.db
      .prepare(
        `INSERT INTO blocked_ips (cidr, reason, created_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(cidr) DO UPDATE SET reason = excluded.reason, created_at = excluded.created_at,
           expires_at = excluded.expires_at, created_by = excluded.created_by`,
      )
      .run(cidr, reason, this.now(), expiresAt, by);
  }

  unblockIp(cidr: string): boolean {
    return Number(this.db.prepare("DELETE FROM blocked_ips WHERE cidr = ?").run(cidr).changes) > 0;
  }

  listBlockedIps(): Array<{
    cidr: string;
    reason: string | null;
    createdAt: number;
    expiresAt: number;
    createdBy: string | null;
  }> {
    return (
      this.db
        .prepare(
          "SELECT cidr, reason, created_at, expires_at, created_by FROM blocked_ips WHERE expires_at > ? ORDER BY cidr",
        )
        .all(this.now()) as Array<{
        cidr: string;
        reason: string | null;
        created_at: number;
        expires_at: number;
        created_by: string | null;
      }>
    ).map((r) => ({
      cidr: r.cidr,
      reason: r.reason,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      createdBy: r.created_by,
    }));
  }

  // ---- operator settings ------------------------------------------------

  getSetting(key: string): string | null {
    const row = this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as
      | { value: string }
      | undefined;
    return row?.value ?? null;
  }

  setSetting(key: string, value: string | null): void {
    if (value === null) {
      this.db.prepare("DELETE FROM settings WHERE key = ?").run(key);
      return;
    }
    this.db
      .prepare(
        `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      )
      .run(key, value, this.now());
  }

  /** Emergency pause of all sending (kill switch); null when sending is enabled. */
  getPause(): { since: number; by: string; reason: string } | null {
    const raw = this.getSetting("sending_paused");
    if (!raw) return null;
    try {
      const v = JSON.parse(raw) as { since: number; by: string; reason: string };
      return { since: Number(v.since), by: String(v.by), reason: String(v.reason) };
    } catch {
      // A corrupt value fails closed: sending stays paused until resumed.
      return { since: 0, by: "unknown", reason: "unreadable pause state" };
    }
  }

  setPause(p: { by: string; reason: string } | null): void {
    this.setSetting(
      "sending_paused",
      p ? JSON.stringify({ since: this.now(), by: p.by, reason: p.reason }) : null,
    );
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
    const blocked = this.db
      .prepare(
        "SELECT COUNT(*) AS n FROM blocked_instances WHERE expires_at IS NULL OR expires_at > ?",
      )
      .get(this.now()) as { n: number };
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

  /** Instances with at least one registered device. */
  instanceCount(): number {
    return (
      this.db.prepare("SELECT COUNT(DISTINCT instance) AS n FROM devices").get() as { n: number }
    ).n;
  }

  /**
   * Instances that sent notifications within the last `hours` (from the hourly
   * statistics; deltas of the current minute may not be written yet).
   */
  activeInstanceCount(hours: number): number {
    const since = Math.floor(this.now() / 3600) - hours + 1;
    return (
      this.db
        .prepare(
          "SELECT COUNT(DISTINCT instance) AS n FROM stats_hourly WHERE hour >= ? AND instance != '' AND kind = 'msg'",
        )
        .get(since) as { n: number }
    ).n;
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

import { randomBytes } from "node:crypto";
import type { AdminConfig } from "../config.ts";
import { safeEqual, sha256Hex } from "../crypto/encoding.ts";
import type { Store } from "../db.ts";

/**
 * Server-side admin sessions in SQLite (`admin_sessions`).
 *
 * - The cookie carries a random 256-bit id; the database stores only its
 *   SHA-256, so a database leak does not yield usable sessions.
 * - Idle timeout (30 min) and absolute lifetime (8 h); the live-refresh API
 *   does not count as activity.
 * - Every session records the admin-config fingerprint; when the admin
 *   configuration changes (issuer, client, allow lists…) all sessions die.
 * - Login state (state, nonce, PKCE verifier) is also server-side, bound to
 *   the browser by a separate short-lived cookie, valid for 10 minutes, single use.
 */

export const SESSION_COOKIE = "__Host-fp_admin";
export const LOGIN_COOKIE = "__Host-fp_admin_login";
export const LOGIN_STATE_TTL_SECONDS = 600;
const MAX_LOGIN_STATES = 500;
const LAST_SEEN_WRITE_INTERVAL = 15;

export interface AdminSession {
  idHash: string;
  sub: string;
  email: string | null;
  name: string | null;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
}

interface SessionRow {
  id_hash: string;
  sub: string;
  email: string | null;
  name: string | null;
  csrf: string;
  config_fp: string;
  created_at: number;
  last_seen_at: number;
}

const hashId = (id: string) => sha256Hex(`flowplan-push/admin-session/v1:${id}`);
const hashState = (s: string) => sha256Hex(`flowplan-push/admin-login/v1:${s}`);

export class AdminSessions {
  private readonly store: Store;
  private readonly cfg: AdminConfig;

  constructor(store: Store, cfg: AdminConfig) {
    this.store = store;
    this.cfg = cfg;
    this.purge();
  }

  private now(): number {
    return this.store.nowSeconds();
  }

  /** Deletes expired sessions/login states and sessions from another admin configuration. */
  purge(): number {
    const now = this.now();
    const r = this.store.db
      .prepare(
        "DELETE FROM admin_sessions WHERE config_fp != ? OR last_seen_at <= ? OR created_at <= ?",
      )
      .run(
        this.cfg.fingerprint,
        now - this.cfg.sessionIdleSeconds,
        now - this.cfg.sessionAbsoluteSeconds,
      );
    this.store.db
      .prepare("DELETE FROM admin_login_states WHERE created_at <= ?")
      .run(now - LOGIN_STATE_TTL_SECONDS);
    return Number(r.changes);
  }

  // ---- login state -----------------------------------------------------

  saveLoginState(p: { state: string; binding: string; nonce: string; verifier: string }): void {
    const db = this.store.db;
    this.store.tx(() => {
      db.prepare("DELETE FROM admin_login_states WHERE created_at <= ?").run(
        this.now() - LOGIN_STATE_TTL_SECONDS,
      );
      const n = (db.prepare("SELECT COUNT(*) AS n FROM admin_login_states").get() as { n: number })
        .n;
      if (n >= MAX_LOGIN_STATES) {
        db.prepare(
          "DELETE FROM admin_login_states WHERE state_hash IN (SELECT state_hash FROM admin_login_states ORDER BY created_at LIMIT ?)",
        ).run(n - MAX_LOGIN_STATES + 1);
      }
      db.prepare(
        "INSERT INTO admin_login_states (state_hash, binding_hash, nonce, verifier, created_at) VALUES (?, ?, ?, ?, ?)",
      ).run(hashState(p.state), sha256Hex(p.binding), p.nonce, p.verifier, this.now());
    });
  }

  /** Single use: the state row is deleted whether or not it matches. */
  consumeLoginState(
    state: string,
    binding: string | null,
  ): { nonce: string; verifier: string } | null {
    const h = hashState(state);
    const row = this.store.db
      .prepare(
        "SELECT binding_hash, nonce, verifier, created_at FROM admin_login_states WHERE state_hash = ?",
      )
      .get(h) as
      | { binding_hash: string; nonce: string; verifier: string; created_at: number }
      | undefined;
    if (!row) return null;
    this.store.db.prepare("DELETE FROM admin_login_states WHERE state_hash = ?").run(h);
    if (!binding || !safeEqual(row.binding_hash, sha256Hex(binding))) return null;
    if (row.created_at <= this.now() - LOGIN_STATE_TTL_SECONDS) return null;
    return { nonce: row.nonce, verifier: row.verifier };
  }

  // ---- sessions ----------------------------------------------------------

  /** Creates a fresh session (new id and CSRF token on every login). */
  create(
    user: { sub: string; email: string | null; name: string | null },
    ip: string,
  ): {
    id: string;
    session: AdminSession;
  } {
    const id = randomBytes(32).toString("base64url");
    const csrf = randomBytes(32).toString("base64url");
    const now = this.now();
    this.store.db
      .prepare(
        `INSERT INTO admin_sessions (id_hash, sub, email, name, csrf, config_fp, ip, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(hashId(id), user.sub, user.email, user.name, csrf, this.cfg.fingerprint, ip, now, now);
    return {
      id,
      session: {
        idHash: hashId(id),
        sub: user.sub,
        email: user.email,
        name: user.name,
        csrf,
        createdAt: now,
        lastSeenAt: now,
      },
    };
  }

  /** Looks up a session; `touch` extends the idle timeout (user activity). */
  get(id: string | null, touch: boolean): AdminSession | null {
    if (!id || !/^[A-Za-z0-9_-]{43}$/.test(id)) return null;
    const h = hashId(id);
    const row = this.store.db.prepare("SELECT * FROM admin_sessions WHERE id_hash = ?").get(h) as
      | SessionRow
      | undefined;
    if (!row) return null;
    const now = this.now();
    if (
      row.config_fp !== this.cfg.fingerprint ||
      now - row.last_seen_at >= this.cfg.sessionIdleSeconds ||
      now - row.created_at >= this.cfg.sessionAbsoluteSeconds
    ) {
      this.store.db.prepare("DELETE FROM admin_sessions WHERE id_hash = ?").run(h);
      return null;
    }
    if (touch && now - row.last_seen_at >= LAST_SEEN_WRITE_INTERVAL) {
      this.store.db
        .prepare("UPDATE admin_sessions SET last_seen_at = ? WHERE id_hash = ?")
        .run(now, h);
      row.last_seen_at = now;
    }
    return {
      idHash: row.id_hash,
      sub: row.sub,
      email: row.email,
      name: row.name,
      csrf: row.csrf,
      createdAt: row.created_at,
      lastSeenAt: row.last_seen_at,
    };
  }

  destroy(id: string | null): void {
    if (!id) return;
    this.store.db.prepare("DELETE FROM admin_sessions WHERE id_hash = ?").run(hashId(id));
  }

  count(): number {
    return (
      this.store.db.prepare("SELECT COUNT(*) AS n FROM admin_sessions").get() as { n: number }
    ).n;
  }
}

/** Parses a Cookie header. Duplicate names make the value ambiguous → treated as absent. */
export function readCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  let found: string | null = null;
  let seen = 0;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() !== name) continue;
    seen++;
    found = part.slice(i + 1).trim();
  }
  return seen === 1 ? found : null;
}

export function sessionCookie(value: string, maxAgeSeconds: number): string {
  return `${SESSION_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}

/** The login-binding cookie must survive the top-level redirect back from the IdP: SameSite=Lax. */
export function loginCookie(value: string): string {
  return `${LOGIN_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${LOGIN_STATE_TTL_SECONDS}`;
}

export function clearCookie(name: string): string {
  const sameSite = name === LOGIN_COOKIE ? "Lax" : "Strict";
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=0`;
}

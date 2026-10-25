import type { Store } from "../db.ts";
import type { Logger } from "../log.ts";
import { parseCidr } from "../net/ip.ts";
import { canonicalOrigin } from "../net/origin.ts";

/**
 * Operator actions shared by the web dashboard and the CLI. Every action
 * appends a row to the append-only `admin_audit` table (SQLite triggers
 * refuse UPDATE and DELETE) and is logged.
 */

export interface Actor {
  /** Display identity: admin e-mail, else subject; "cli" for the command line. */
  id: string;
  sub: string | null;
  /** Client IP (full address, operator-visible only); null for the CLI. */
  ip: string | null;
}

export const CLI_ACTOR: Actor = { id: "cli", sub: null, ip: null };

export class ActionError extends Error {}

export interface AuditEntry {
  id: number;
  at: number;
  actor: string;
  actorSub: string | null;
  action: string;
  target: string | null;
  reason: string | null;
  ip: string | null;
  details: Record<string, unknown> | null;
}

/** Durations offered for temporary blocks (seconds); null = until unblocked. */
export const DURATIONS: Record<string, number | null> = {
  "1h": 3600,
  "24h": 86400,
  "7d": 7 * 86400,
  "30d": 30 * 86400,
  permanent: null,
};

export const MAX_REASON_LENGTH = 500;

export function parseDuration(raw: string | undefined, allowPermanent: boolean): number | null {
  const key = (raw ?? "").trim();
  if (!(key in DURATIONS)) throw new ActionError("invalid duration");
  const v = DURATIONS[key] ?? null;
  if (v === null && !allowPermanent) throw new ActionError("a duration is required");
  return v;
}

export function cleanReason(raw: string | undefined | null, required: boolean): string | null {
  const r = (raw ?? "")
    // biome-ignore lint/suspicious/noControlCharactersInRegex: strip control characters on purpose
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .trim()
    .slice(0, MAX_REASON_LENGTH);
  if (required && r.length < 3)
    throw new ActionError("a reason (at least 3 characters) is required");
  return r || null;
}

export function parseOrigin(raw: string | undefined): string {
  // Blocking must also work for origins that would not be accepted for new
  // registrations today, so private addresses are allowed here.
  const o = canonicalOrigin(raw, true);
  if (!o) throw new ActionError("expected an origin like https://flowplan.example.com");
  return o;
}

export function parseIpRange(raw: string | undefined): string {
  const c = parseCidr(raw ?? "");
  if (!c) throw new ActionError("expected an IP address or CIDR like 203.0.113.0/24");
  // Refuse ranges so wide that they would block (nearly) everyone by accident.
  if ((c.family === "ipv4" && c.prefix < 8) || (c.family === "ipv6" && c.prefix < 16)) {
    throw new ActionError("range too wide (minimum /8 for IPv4, /16 for IPv6)");
  }
  return c.text;
}

export class AdminActions {
  readonly store: Store;
  private readonly logger: Logger;

  constructor(store: Store, logger: Logger) {
    this.store = store;
    this.logger = logger;
  }

  audit(
    actor: Actor,
    action: string,
    target: string | null,
    reason: string | null,
    details: Record<string, unknown> | null = null,
  ): number {
    const r = this.store.db
      .prepare(
        "INSERT INTO admin_audit (at, actor, actor_sub, action, target, reason, ip, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        this.store.nowSeconds(),
        actor.id.slice(0, 254),
        actor.sub,
        action,
        target,
        reason,
        actor.ip,
        details ? JSON.stringify(details) : null,
      );
    this.logger.warn("admin action", {
      action,
      actor: actor.id,
      target,
      reason,
      ...(details ?? {}),
    });
    return Number(r.lastInsertRowid);
  }

  listAudit(limit = 50, beforeId?: number): AuditEntry[] {
    const rows = this.store.db
      .prepare(
        `SELECT * FROM admin_audit ${beforeId ? "WHERE id < ?" : ""} ORDER BY id DESC LIMIT ?`,
      )
      .all(...(beforeId ? [beforeId, limit] : [limit])) as Array<{
      id: number;
      at: number;
      actor: string;
      actor_sub: string | null;
      action: string;
      target: string | null;
      reason: string | null;
      ip: string | null;
      details: string | null;
    }>;
    return rows.map((r) => {
      let details: Record<string, unknown> | null = null;
      try {
        details = r.details ? (JSON.parse(r.details) as Record<string, unknown>) : null;
      } catch {
        details = null;
      }
      return {
        id: r.id,
        at: r.at,
        actor: r.actor,
        actorSub: r.actor_sub,
        action: r.action,
        target: r.target,
        reason: r.reason,
        ip: r.ip,
        details,
      };
    });
  }

  blockInstance(
    actor: Actor,
    origin: string,
    reason: string | null,
    durationSeconds: number | null,
  ) {
    const expiresAt = durationSeconds === null ? null : this.store.nowSeconds() + durationSeconds;
    this.store.block(origin, reason, { expiresAt, by: actor.id });
    return this.audit(actor, "block_instance", origin, reason, { expiresAt });
  }

  unblockInstance(actor: Actor, origin: string, reason: string | null) {
    const was = this.store.unblock(origin);
    return {
      auditId: this.audit(actor, "unblock_instance", origin, reason, { wasBlocked: was }),
      was,
    };
  }

  deleteInstance(actor: Actor, origin: string, reason: string | null) {
    const deleted = this.store.deleteInstanceDevices(origin);
    return { auditId: this.audit(actor, "delete_instance", origin, reason, { deleted }), deleted };
  }

  blockIp(actor: Actor, cidr: string, reason: string | null, durationSeconds: number) {
    const expiresAt = this.store.nowSeconds() + durationSeconds;
    this.store.blockIp(cidr, reason, expiresAt, actor.id);
    return this.audit(actor, "block_ip", cidr, reason, { expiresAt });
  }

  unblockIp(actor: Actor, cidr: string, reason: string | null) {
    const was = this.store.unblockIp(cidr);
    return { auditId: this.audit(actor, "unblock_ip", cidr, reason, { wasBlocked: was }), was };
  }

  pauseSending(actor: Actor, reason: string) {
    this.store.setPause({ by: actor.id, reason });
    return this.audit(actor, "pause_sending", null, reason);
  }

  resumeSending(actor: Actor, reason: string | null) {
    const was = this.store.getPause() !== null;
    this.store.setPause(null);
    return { auditId: this.audit(actor, "resume_sending", null, reason, { wasPaused: was }), was };
  }

  purgeExpired(actor: Actor, reason: string | null) {
    const purged = this.store.purgeExpired();
    return { auditId: this.audit(actor, "purge_expired", null, reason, { purged }), purged };
  }
}

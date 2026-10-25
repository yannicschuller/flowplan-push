import { createHmac, randomBytes } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { AdminConfig } from "../config.ts";
import { safeEqual } from "../crypto/encoding.ts";
import type { Logger } from "../log.ts";
import { cidrMatcher, rateLimitKeyForIp } from "../net/ip.ts";
import { canonicalOrigin } from "../net/origin.ts";
import { TokenBucketLimiter } from "../ratelimit.ts";
import type { HttpResult } from "../relay.ts";
import {
  ActionError,
  type Actor,
  type AdminActions,
  cleanReason,
  parseDuration,
  parseIpRange,
  parseOrigin,
} from "./actions.ts";
import { ADMIN_CSS, ADMIN_JS } from "./assets.ts";
import { authorize } from "./authz.ts";
import { newAuthRequestSecrets, type OidcClient, OidcError } from "./oidc.ts";
import {
  type AdminSession,
  type AdminSessions,
  clearCookie,
  LOGIN_COOKIE,
  loginCookie,
  readCookie,
  SESSION_COOKIE,
  sessionCookie,
} from "./sessions.ts";
import { buildInstanceDetail, buildSummary, type DashboardDeps } from "./summary.ts";
import {
  auditPage,
  type ConfirmView,
  confirmPage,
  continuePage,
  dashboardPage,
  instancePage,
  loginPage,
  messagePage,
} from "./views.ts";

/**
 * /admin: OIDC-protected operator dashboard. Disabled (404) unless
 * ADMIN_OIDC_ISSUER and at least one admin rule are configured.
 *
 * Protection layers, in order:
 *   1. optional IP allow list (ADMIN_ALLOWED_IPS) → 404 for everyone else
 *   2. login/callback rate limit per IP
 *   3. server-side session (cookie __Host-fp_admin: Secure, HttpOnly, SameSite=Strict)
 *   4. every POST: exact Origin match, Sec-Fetch-Site same-origin (if sent),
 *      form content type, per-session CSRF token
 *   5. actions: two steps (review → confirm) with an HMAC-bound confirmation
 *      token (5 min), reason required, append-only audit log
 * Responses: strict CSP (self only, no inline code), DENY framing, no-store.
 */

export interface AdminHandlerDeps {
  config: AdminConfig;
  oidc: OidcClient;
  sessions: AdminSessions;
  actions: AdminActions;
  dashboard: DashboardDeps;
  logger: Logger;
  /** Login attempts per IP (default: burst 10, refill 10 per 10 minutes). */
  loginLimiter?: TokenBucketLimiter;
}

const MAX_FORM_BYTES = 8 * 1024;

/**
 * "same-origin" instead of the relay's usual "no-referrer": with no-referrer,
 * browsers send `Origin: null` on same-origin form POSTs, which would defeat
 * the exact Origin check. same-origin still sends no referrer to any other
 * origin (identity provider, links), so nothing leaks.
 */
const ADMIN_REFERRER_POLICY = "same-origin";
const CONFIRM_TTL_SECONDS = 300;

class Reject extends Error {
  readonly result: HttpResult;
  constructor(result: HttpResult) {
    super("reject");
    this.result = result;
  }
}

function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  return new Promise((resolve, reject) => {
    const ctype = String(req.headers["content-type"] ?? "").toLowerCase();
    if (!/^application\/x-www-form-urlencoded\s*(;\s*charset=utf-8\s*)?$/.test(ctype)) {
      reject(new Reject({ status: 415, body: { error: "unsupported_media_type" } }));
      return;
    }
    const declared = req.headers["content-length"];
    if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > MAX_FORM_BYTES)) {
      reject(new Reject({ status: 413, body: { error: "payload_too_large" } }));
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on("data", (c: Buffer) => {
      if (done) return;
      size += c.length;
      if (size > MAX_FORM_BYTES) {
        done = true;
        reject(new Reject({ status: 413, body: { error: "payload_too_large" } }));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      resolve(new URLSearchParams(Buffer.concat(chunks).toString("utf8")));
    });
    req.on("error", () => {
      if (done) return;
      done = true;
      reject(new Reject({ status: 400, body: { error: "bad_request" } }));
    });
  });
}

interface ActionSpec {
  title: string;
  danger: boolean;
  /** Validates the posted form; returns the normalised fields shown and signed. */
  validate(f: URLSearchParams): Record<string, string>;
  describe(v: Record<string, string>): { description: string; consequences: string[] };
  run(a: AdminActions, actor: Actor, v: Record<string, string>): { id: number; text: string };
}

const req = (r: string | null): string => {
  if (!r) throw new ActionError("a reason is required");
  return r;
};

export const ACTIONS: Record<string, ActionSpec> = {
  block_instance: {
    title: "Block instance",
    danger: true,
    validate: (f) => {
      const origin = parseOrigin(f.get("origin") ?? undefined);
      const duration = f.get("duration") ?? "permanent";
      parseDuration(duration, true);
      return { origin, duration, reason: req(cleanReason(f.get("reason"), true)) };
    },
    describe: (v) => ({
      description: `Block ${v.origin} ${v.duration === "permanent" ? "until it is unblocked" : `for ${v.duration}`}.`,
      consequences: [
        "Its send requests get 403 instance_blocked immediately.",
        "Apps can no longer register for it.",
        "Existing registrations are kept, so unblocking restores delivery.",
      ],
    }),
    run: (a, actor, v) => ({
      id: a.blockInstance(
        actor,
        v.origin as string,
        v.reason ?? null,
        parseDuration(v.duration, true),
      ),
      text: `blocked ${v.origin}`,
    }),
  },
  unblock_instance: {
    title: "Unblock instance",
    danger: false,
    validate: (f) => ({
      origin: parseOrigin(f.get("origin") ?? undefined),
      reason: req(cleanReason(f.get("reason"), true)),
    }),
    describe: (v) => ({
      description: `Remove the block of ${v.origin}.`,
      consequences: ["Sends and registrations are accepted again."],
    }),
    run: (a, actor, v) => {
      const r = a.unblockInstance(actor, v.origin as string, v.reason ?? null);
      return {
        id: r.auditId,
        text: r.was ? `unblocked ${v.origin}` : `${v.origin} was not blocked`,
      };
    },
  },
  delete_instance: {
    title: "Delete all registrations",
    danger: true,
    validate: (f) => ({
      origin: parseOrigin(f.get("origin") ?? undefined),
      reason: req(cleanReason(f.get("reason"), true)),
    }),
    describe: (v) => ({
      description: `Delete every device registration of ${v.origin}.`,
      consequences: [
        "Its relay tokens stop working at once (sends answer forbidden).",
        "This cannot be undone; apps re-register by themselves later unless the instance is blocked.",
      ],
    }),
    run: (a, actor, v) => {
      const r = a.deleteInstance(actor, v.origin as string, v.reason ?? null);
      return { id: r.auditId, text: `deleted ${r.deleted} registrations of ${v.origin}` };
    },
  },
  block_ip: {
    title: "Block IP range for registrations",
    danger: true,
    validate: (f) => {
      const cidr = parseIpRange(f.get("cidr") ?? undefined);
      const duration = f.get("duration") ?? "24h";
      parseDuration(duration, false);
      return { cidr, duration, reason: req(cleanReason(f.get("reason"), true)) };
    },
    describe: (v) => ({
      description: `Refuse new registrations from ${v.cidr} for ${v.duration}.`,
      consequences: [
        "Registrations from this range get 403 ip_blocked.",
        "Sends are not affected (instances authenticate with signatures).",
        "The block expires automatically.",
      ],
    }),
    run: (a, actor, v) => ({
      id: a.blockIp(
        actor,
        v.cidr as string,
        v.reason ?? null,
        parseDuration(v.duration, false) as number,
      ),
      text: `blocked ${v.cidr} for registrations`,
    }),
  },
  unblock_ip: {
    title: "Unblock IP range",
    danger: false,
    validate: (f) => ({
      cidr: parseIpRange(f.get("cidr") ?? undefined),
      reason: req(cleanReason(f.get("reason"), true)),
    }),
    describe: (v) => ({
      description: `Remove the registration block of ${v.cidr}.`,
      consequences: ["Registrations from this range are accepted again."],
    }),
    run: (a, actor, v) => {
      const r = a.unblockIp(actor, v.cidr as string, v.reason ?? null);
      return { id: r.auditId, text: r.was ? `unblocked ${v.cidr}` : `${v.cidr} was not blocked` };
    },
  },
  pause_sending: {
    title: "Pause all sending",
    danger: true,
    validate: (f) => ({ reason: req(cleanReason(f.get("reason"), true)) }),
    describe: () => ({
      description: "Emergency stop: the relay refuses every send request.",
      consequences: [
        "POST /v1/send answers 503 relay_paused with Retry-After: 300 for every instance.",
        "Notifications sent while paused are not delivered (instances may retry later).",
        "Registrations keep working. The pause survives restarts until you resume.",
      ],
    }),
    run: (a, actor, v) => ({
      id: a.pauseSending(actor, v.reason as string),
      text: "sending paused",
    }),
  },
  resume_sending: {
    title: "Resume sending",
    danger: false,
    validate: (f) => ({ reason: req(cleanReason(f.get("reason"), true)) }),
    describe: () => ({
      description: "End the emergency pause.",
      consequences: ["Send requests are processed normally again."],
    }),
    run: (a, actor, v) => {
      const r = a.resumeSending(actor, v.reason ?? null);
      return { id: r.auditId, text: r.was ? "sending resumed" : "sending was not paused" };
    },
  },
  purge_expired: {
    title: "Purge expired registrations",
    danger: false,
    validate: (f) => ({ reason: req(cleanReason(f.get("reason"), true)) }),
    describe: () => ({
      description: "Delete registrations whose 180-day lifetime has ended, and expired blocks.",
      consequences: ["Only expired data is removed. This also runs every hour automatically."],
    }),
    run: (a, actor, v) => {
      const r = a.purgeExpired(actor, v.reason ?? null);
      return { id: r.auditId, text: `purged ${r.purged} expired registrations` };
    },
  },
};

export class AdminHandler {
  private readonly d: AdminHandlerDeps;
  private readonly ipAllowed: ((ip: string) => boolean) | null;
  private readonly loginLimiter: TokenBucketLimiter;

  constructor(d: AdminHandlerDeps) {
    this.d = d;
    this.ipAllowed = d.config.allowedIps ? cidrMatcher(d.config.allowedIps) : null;
    this.loginLimiter = d.loginLimiter ?? new TokenBucketLimiter(10, 10, 600_000, 10_000);
  }

  private csp(): string {
    const formAction = ["'self'"];
    const ep = this.d.oidc.cachedMetadata()?.end_session_endpoint;
    if (ep && this.d.config.rpLogout) formAction.push(new URL(ep).origin);
    return [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self'",
      "connect-src 'self'",
      `form-action ${formAction.join(" ")}`,
      "frame-ancestors 'none'",
      "base-uri 'none'",
    ].join("; ");
  }

  private htmlResult(
    status: number,
    body: string,
    extra: Record<string, string | string[]> = {},
  ): HttpResult {
    return {
      status,
      body,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": this.csp(),
        "cache-control": "no-store",
        "referrer-policy": ADMIN_REFERRER_POLICY,
        pragma: "no-cache",
        ...extra,
      },
    };
  }

  private redirect(location: string, extra: Record<string, string | string[]> = {}): HttpResult {
    return {
      status: 303,
      headers: {
        location,
        "content-security-policy": this.csp(),
        "cache-control": "no-store",
        "referrer-policy": ADMIN_REFERRER_POLICY,
        ...extra,
      },
    };
  }

  private actor(s: AdminSession, ip: string): Actor {
    return { id: s.email ?? s.sub, sub: s.sub, ip };
  }

  private session(
    req: IncomingMessage,
    touch: boolean,
  ): { id: string | null; s: AdminSession | null } {
    const id = readCookie(req.headers.cookie, SESSION_COOKIE);
    return { id, s: this.d.sessions.get(id, touch) };
  }

  async handle(req: IncomingMessage, method: string, url: URL, ip: string): Promise<HttpResult> {
    if (this.ipAllowed && !this.ipAllowed(ip)) {
      req.resume();
      return { status: 404, body: { error: "not_found" } };
    }
    try {
      return await this.route(req, method, url, ip);
    } catch (e) {
      if (e instanceof Reject) {
        req.resume();
        return e.result;
      }
      throw e;
    }
  }

  private async route(
    req: IncomingMessage,
    method: string,
    url: URL,
    ip: string,
  ): Promise<HttpResult> {
    const path = url.pathname;
    const get = method === "GET" || method === "HEAD";
    if (get) req.resume();

    if (path === "/admin/assets/admin.css" && get) {
      return {
        status: 200,
        body: ADMIN_CSS,
        headers: { "content-type": "text/css; charset=utf-8" },
      };
    }
    if (path === "/admin/assets/admin.js" && get) {
      return {
        status: 200,
        body: ADMIN_JS,
        headers: { "content-type": "text/javascript; charset=utf-8" },
      };
    }
    if (path === "/admin/login" && get) return this.login(req, ip);
    if (path === "/admin/callback" && get) return this.callback(req, url, ip);
    if (path === "/admin/logout" && method === "POST") return this.logout(req, ip);
    if (path === "/admin/action" && method === "POST") return this.action(req, ip);

    if (path === "/admin/api/summary" && get) {
      const { s } = this.session(req, false);
      if (!s) return { status: 401, body: { error: "unauthorized" } };
      return { status: 200, body: buildSummary(this.d.dashboard) };
    }
    if (path === "/admin/api/instance" && get) {
      const { s } = this.session(req, false);
      if (!s) return { status: 401, body: { error: "unauthorized" } };
      const origin = canonicalOrigin(url.searchParams.get("origin") ?? "", true);
      if (!origin) return { status: 400, body: { error: "invalid_instance" } };
      return { status: 200, body: buildInstanceDetail(this.d.dashboard, origin) };
    }

    if ((path === "/admin" || path === "/admin/") && get) {
      const { s } = this.session(req, true);
      if (!s) return this.htmlResult(200, loginPage(this.issuerHost()));
      let done: { id: number; text: string } | undefined;
      const doneId = Number(url.searchParams.get("done"));
      if (Number.isInteger(doneId) && doneId > 0) {
        const e = this.d.actions.listAudit(1, doneId + 1)[0];
        if (e && e.id === doneId && e.actorSub === s.sub)
          done = { id: e.id, text: `${e.action}${e.target ? ` ${e.target}` : ""}` };
      }
      return this.htmlResult(200, dashboardPage(s, buildSummary(this.d.dashboard), done));
    }
    if (path === "/admin/instance" && get) {
      const { s } = this.session(req, true);
      if (!s) return this.redirect("/admin");
      const origin = canonicalOrigin(url.searchParams.get("origin") ?? "", true);
      if (!origin)
        return this.htmlResult(
          400,
          messagePage("Invalid instance", "That is not a valid instance origin."),
        );
      return this.htmlResult(200, instancePage(s, buildInstanceDetail(this.d.dashboard, origin)));
    }
    if (path === "/admin/audit" && get) {
      const { s } = this.session(req, true);
      if (!s) return this.redirect("/admin");
      const before = Number(url.searchParams.get("before"));
      const entries = this.d.actions.listAudit(
        100,
        Number.isInteger(before) && before > 0 ? before : undefined,
      );
      const last = entries[entries.length - 1];
      return this.htmlResult(
        200,
        auditPage(s, entries, entries.length === 100 && last ? last.id : null),
      );
    }

    req.resume();
    if (
      [
        "/admin",
        "/admin/",
        "/admin/login",
        "/admin/callback",
        "/admin/logout",
        "/admin/action",
      ].includes(path) ||
      path.startsWith("/admin/api/") ||
      path === "/admin/instance" ||
      path === "/admin/audit"
    ) {
      return { status: 405, body: { error: "method_not_allowed" } };
    }
    return { status: 404, body: { error: "not_found" } };
  }

  private issuerHost(): string {
    try {
      return new URL(this.d.config.issuer).host;
    } catch {
      return "identity provider";
    }
  }

  private limited(ip: string): HttpResult | null {
    const r = this.loginLimiter.tryTake(rateLimitKeyForIp(ip));
    if (r.ok) return null;
    return this.htmlResult(
      429,
      messagePage(
        "Too many attempts",
        "Too many sign-in attempts from your address. Try again later.",
      ),
      { "retry-after": String(r.retryAfter) },
    );
  }

  private async login(req: IncomingMessage, ip: string): Promise<HttpResult> {
    req.resume();
    const lim = this.limited(ip);
    if (lim) return lim;
    if (this.session(req, false).s) return this.redirect("/admin");
    const sec = newAuthRequestSecrets();
    const binding = randomBytes(32).toString("base64url");
    let location: string;
    try {
      location = await this.d.oidc.authorizationUrl(sec);
    } catch (e) {
      this.d.logger.error("admin login: identity provider unavailable", {
        code: e instanceof OidcError ? e.code : "error",
      });
      return this.htmlResult(
        502,
        messagePage(
          "Identity provider unavailable",
          "The sign-in service could not be reached. Try again shortly.",
        ),
      );
    }
    this.d.sessions.saveLoginState({
      state: sec.state,
      binding,
      nonce: sec.nonce,
      verifier: sec.verifier,
    });
    return {
      status: 302,
      headers: {
        location,
        "set-cookie": loginCookie(binding),
        "cache-control": "no-store",
        "referrer-policy": ADMIN_REFERRER_POLICY,
        "content-security-policy": this.csp(),
      },
    };
  }

  private async callback(req: IncomingMessage, url: URL, ip: string): Promise<HttpResult> {
    req.resume();
    const clear = { "set-cookie": clearCookie(LOGIN_COOKIE) };
    const lim = this.limited(ip);
    if (lim) return lim;
    const q = url.searchParams;
    const fail = (status: number, title: string, msg: string) =>
      this.htmlResult(status, messagePage(title, msg, "Start again"), clear);

    const state = q.get("state");
    if (!state || state.length > 200)
      return fail(400, "Sign-in failed", "The sign-in response is incomplete.");
    const binding = readCookie(req.headers.cookie, LOGIN_COOKIE);
    const saved = this.d.sessions.consumeLoginState(state, binding);
    if (!saved) {
      this.d.logger.warn("admin login: unknown, expired or foreign state");
      return fail(
        400,
        "Sign-in expired",
        "This sign-in attempt is unknown or has expired. Please start again.",
      );
    }
    const error = q.get("error");
    if (error) {
      const code = /^[A-Za-z0-9_.-]{1,64}$/.test(error) ? error : "error";
      this.d.logger.warn("admin login: identity provider returned an error", { code });
      return fail(403, "Sign-in refused", `The identity provider refused the sign-in (${code}).`);
    }
    const code = q.get("code");
    if (!code || code.length > 2048)
      return fail(400, "Sign-in failed", "The sign-in response is incomplete.");

    let claims: Awaited<ReturnType<OidcClient["completeLogin"]>>;
    try {
      claims = await this.d.oidc.completeLogin({
        code,
        verifier: saved.verifier,
        nonce: saved.nonce,
        iss: q.get("iss"),
      });
    } catch (e) {
      const c = e instanceof OidcError ? e.code : "error";
      this.d.logger.warn("admin login failed", {
        code: c,
        detail: e instanceof OidcError ? e.message : undefined,
      });
      return fail(403, "Sign-in failed", "The identity provider's response could not be verified.");
    }
    const authz = authorize(claims, this.d.config);
    if (!authz.ok) {
      const who = typeof claims.email === "string" ? claims.email : claims.sub;
      this.d.actions.audit({ id: who, sub: claims.sub, ip }, "login_denied", null, authz.reason);
      return fail(
        403,
        "Not authorized",
        "Your account signed in successfully but is not an administrator of this relay.",
      );
    }
    // Rotate: any previous session of this browser ends; the new id is fresh.
    this.d.sessions.destroy(readCookie(req.headers.cookie, SESSION_COOKIE));
    const { id, session } = this.d.sessions.create(
      { sub: claims.sub, email: authz.email, name: authz.name },
      ip,
    );
    this.d.actions.audit(this.actor(session, ip), "login", null, null, { via: authz.via });
    return this.htmlResult(200, continuePage(), {
      "set-cookie": [
        sessionCookie(id, this.d.config.sessionAbsoluteSeconds),
        clearCookie(LOGIN_COOKIE),
      ],
    });
  }

  /** Origin, fetch-metadata, content type, session and CSRF checks for every POST. */
  private async verifyPost(
    req: IncomingMessage,
  ): Promise<{ form: URLSearchParams; s: AdminSession; id: string }> {
    const origin = req.headers.origin;
    if (origin !== this.d.config.publicOrigin) {
      throw new Reject(
        this.htmlResult(403, messagePage("Request refused", "Cross-origin request refused.")),
      );
    }
    const site = req.headers["sec-fetch-site"];
    if (site !== undefined && site !== "same-origin") {
      throw new Reject(
        this.htmlResult(403, messagePage("Request refused", "Cross-site request refused.")),
      );
    }
    const form = await readForm(req);
    const { id, s } = this.session(req, true);
    if (!s || !id) {
      throw new Reject(
        this.htmlResult(
          401,
          messagePage(
            "Session expired",
            "Your session has expired. Please sign in again.",
            "Sign in",
          ),
        ),
      );
    }
    const csrf = form.get("csrf") ?? "";
    if (!safeEqual(csrf, s.csrf)) {
      throw new Reject(
        this.htmlResult(
          403,
          messagePage(
            "Request refused",
            "Invalid or missing CSRF token. Reload the page and try again.",
          ),
        ),
      );
    }
    return { form, s, id };
  }

  private async logout(req: IncomingMessage, ip: string): Promise<HttpResult> {
    let verified: Awaited<ReturnType<AdminHandler["verifyPost"]>>;
    try {
      verified = await this.verifyPost(req);
    } catch (e) {
      if (e instanceof Reject && e.result.status === 401) {
        return this.redirect("/admin", { "set-cookie": clearCookie(SESSION_COOKIE) });
      }
      throw e;
    }
    const { s, id } = verified;
    this.d.actions.audit(this.actor(s, ip), "logout", null, null);
    this.d.sessions.destroy(id);
    const target = this.d.oidc.endSessionUrl() ?? "/admin";
    return this.redirect(target, { "set-cookie": clearCookie(SESSION_COOKIE) });
  }

  private confirmToken(
    s: AdminSession,
    action: string,
    v: Record<string, string>,
    exp: number,
  ): string {
    const fields = Object.keys(v)
      .sort()
      .map((k) => [k, v[k]]);
    const mac = createHmac("sha256", s.csrf)
      .update(JSON.stringify(["flowplan-push/admin-confirm/v1", s.idHash, action, fields, exp]))
      .digest("base64url");
    return `${exp}.${mac}`;
  }

  private async action(req: IncomingMessage, ip: string): Promise<HttpResult> {
    const { form, s } = await this.verifyPost(req);
    const name = form.get("action") ?? "";
    const spec = Object.hasOwn(ACTIONS, name) ? ACTIONS[name] : undefined;
    if (!spec)
      return this.htmlResult(400, messagePage("Unknown action", "That action does not exist."));
    let v: Record<string, string>;
    try {
      v = spec.validate(form);
    } catch (e) {
      if (e instanceof ActionError)
        return this.htmlResult(400, messagePage("Invalid input", e.message));
      throw e;
    }
    const now = this.d.dashboard.store.nowSeconds();
    const step = form.get("step");
    if (step !== "execute") {
      const view: ConfirmView = {
        action: name,
        title: spec.title,
        ...spec.describe(v),
        fields: v,
        token: this.confirmToken(s, name, v, now + CONFIRM_TTL_SECONDS),
        danger: spec.danger,
      };
      return this.htmlResult(200, confirmPage(s, view));
    }
    const token = form.get("confirm") ?? "";
    const exp = Number(token.split(".")[0]);
    if (
      !Number.isInteger(exp) ||
      exp < now ||
      exp > now + CONFIRM_TTL_SECONDS ||
      !safeEqual(token, this.confirmToken(s, name, v, exp))
    ) {
      return this.htmlResult(
        400,
        messagePage(
          "Confirmation expired",
          "The confirmation is invalid or has expired. Please start the action again.",
        ),
      );
    }
    let r: { id: number; text: string };
    try {
      r = spec.run(this.d.actions, this.actor(s, ip), v);
    } catch (e) {
      if (e instanceof ActionError)
        return this.htmlResult(400, messagePage("Invalid input", e.message));
      throw e;
    }
    return this.redirect(`/admin?done=${r.id}`);
  }
}

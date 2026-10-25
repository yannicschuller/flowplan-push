import { MESSAGE_STATUSES } from "../stats.ts";
import type { AuditEntry } from "./actions.ts";
import { assetUrl, PRELOAD_FONT } from "./assets.ts";
import type { AuthzDiagnostics } from "./authz.ts";
import {
  fmtAgo,
  fmtDuration,
  fmtNum,
  fmtPct,
  fmtTime,
  html,
  type SafeHtml,
  sparkline,
} from "./html.ts";
import { brandMark, type IconName, icon } from "./icons.ts";
import type { AdminSession } from "./sessions.ts";
import type { InstanceDetail, Summary } from "./summary.ts";

const ASSET_CSS = assetUrl("admin.css") ?? "/admin/assets/admin.css";
const ASSET_JS = assetUrl("admin.js") ?? "/admin/assets/admin.js";
const ICON = assetUrl("icon.svg");

type Crumb = [label: string, href?: string];

interface PageOpts {
  title: string;
  session?: AdminSession | null;
  /** JSON endpoint the client script polls for live values. */
  api?: string;
  nav?: "dashboard" | "audit" | "instance";
  /** Trail in the top bar (signed-in pages). */
  crumbs?: Crumb[];
  /** Extra <head> markup (meta refresh on the post-login page). */
  head?: SafeHtml;
}

function htmlDocument(o: PageOpts, body: SafeHtml): string {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<title>${o.title} · Flowplan push relay</title>
${ICON ? html`<link rel="icon" href="${ICON}" type="image/svg+xml">` : ""}
${PRELOAD_FONT ? html`<link rel="preload" href="${PRELOAD_FONT}" as="font" type="font/woff2" crossorigin>` : ""}
<link rel="stylesheet" href="${ASSET_CSS}">
${o.head ?? ""}
<script src="${ASSET_JS}" defer></script>
</head>
${body}
</html>`.value;
}

function initial(s: AdminSession): string {
  const who = s.email ?? s.name ?? s.sub;
  return (who.match(/[\p{L}\p{N}]/u)?.[0] ?? "?").toUpperCase();
}

/** Signed-in pages: the app's shell with sidebar, top bar and content column. */
export function page(o: PageOpts, body: SafeHtml): string {
  const s = o.session;
  if (!s) return entryPage(o, body);
  const who = s.email ?? s.name ?? s.sub;
  const crumbs: Crumb[] = o.crumbs ?? [[o.title]];
  const navLink = (href: string, key: PageOpts["nav"], name: IconName, label: string) =>
    html`<a href="${href}"${o.nav === key ? html` aria-current="page"` : ""}>${icon(name, 18)}${label}</a>`;
  return htmlDocument(
    o,
    html`<body>
<a class="skip" href="#main">Skip to content</a>
<div class="app">
<aside class="sidebar">
  <div class="sidebar-top"><a class="brand" href="/admin" aria-label="Flowplan push relay, dashboard">${brandMark(28)}<span>flowplan</span><small>push relay</small></a></div>
  <p class="sidebar-label" id="nav-label">Administration</p>
  <nav class="main-nav" aria-labelledby="nav-label">
    ${navLink("/admin", "dashboard", "squaresFour", "Dashboard")}
    ${navLink("/admin/audit", "audit", "clockCounterClockwise", "Audit log")}
  </nav>
  <form method="post" action="/admin/logout" class="sidebar-user">
    <input type="hidden" name="csrf" value="${s.csrf}">
    <span class="avatar" aria-hidden="true">${initial(s)}</span>
    <span class="who" title="${s.sub}"><strong>${who}</strong><small>Relay administrator</small></span>
    <button type="submit" class="icon-button" title="Sign out" aria-label="Sign out">${icon("signOut", 18)}</button>
  </form>
</aside>
<div class="content">
  <header class="topbar">
    <nav class="breadcrumb" aria-label="Breadcrumb"><span>Push relay</span>${crumbs.map(
      ([label, href], i) =>
        html`<span class="sep" aria-hidden="true">/</span>${
          i === crumbs.length - 1
            ? html`<span aria-current="page">${label}</span>`
            : html`<a href="${href ?? "/admin"}">${label}</a>`
        }`,
    )}</nav>
    <span class="topbar-note">Every action is audited</span>
  </header>
  <main id="main" class="page"${o.api ? html` data-api="${o.api}"` : ""}>
<p id="live-status" class="live-toast" role="status" hidden></p>
${body}
  </main>
</div>
</div>
</body>`,
  );
}

/** Signed-out pages: the app's sign-in screen (brand top left, one centred card). */
function entryPage(o: PageOpts, card: SafeHtml, wide = false): string {
  return htmlDocument(
    o,
    html`<body>
<main class="login" id="main">
  <a class="login-brand" href="/admin">${brandMark(32)}flowplan <span class="muted">· push relay</span></a>
  <section class="login-card${wide ? " wide" : ""}">
    <div class="login-mark">${brandMark(48)}</div>
${card}
  </section>
</main>
</body>`,
  );
}

function liveBadge(): SafeHtml {
  return html`<span class="live-badge live" id="live-badge"><span data-live-text>Live</span><span class="muted">· every 5 s</span></span>`;
}

function pageHead(
  name: IconName,
  title: string,
  description: SafeHtml | string,
  actions: SafeHtml | "" = "",
  tone = "",
): SafeHtml {
  return html`<div class="page-head">
  <span class="head-icon${tone ? ` ${tone}` : ""}" aria-hidden="true">${icon(name, 24)}</span>
  <div><h1 class="break">${title}</h1><p>${description}</p></div>
  ${actions ? html`<div class="head-actions">${actions}</div>` : ""}
</div>`;
}

function cardHead(title: string, description?: SafeHtml | string, extra?: SafeHtml): SafeHtml {
  return html`<header class="card-head"><div><h2>${title}</h2>${description ? html`<p>${description}</p>` : ""}</div>${extra ?? ""}</header>`;
}

function empty(title: string, text: string, name: IconName = "tray"): SafeHtml {
  return html`<div class="empty"><span class="tone-icon" aria-hidden="true">${icon(name, 18)}</span><div><strong>${title}</strong><p>${text}</p></div></div>`;
}

export function loginPage(issuerHost: string, notice?: string): string {
  return entryPage(
    { title: "Sign in" },
    html`<h1>Push relay<br>administration</h1>
  <p>Sign in with your organisation's identity provider (${issuerHost}).</p>
  ${notice ? html`<p class="callout error" role="alert">${icon("warningCircleBold", 18)}<span class="notice">${notice}</span></p>` : ""}
  <a class="button primary wide" href="/admin/login">${icon("signIn", 17)}Sign in with SSO</a>
  <p class="fine">Access is limited to configured administrators. Every action is audited.</p>`,
  );
}

export function messagePage(title: string, message: string, linkText = "Back"): string {
  return entryPage(
    { title },
    html`<h1>${title}</h1>
  <p>${message}</p>
  <a class="button wide" href="/admin">${linkText}</a>`,
  );
}

/**
 * Signed in at the provider, but no admin rule matched: shows what the
 * provider sent about this person (their own data only), so the ADMIN_*
 * variables can be set to match.
 */
export function deniedPage(d: AuthzDiagnostics, groupsConfigured: boolean): string {
  const groups = !d.groupsPresent
    ? html`<p>The token has no <code>${d.groupsClaim}</code> claim.${
        groupsConfigured
          ? html` Many providers only send groups for the <code>groups</code> scope (add it to <code>ADMIN_OIDC_SCOPES</code>) or need a groups mapper; Keycloak and Zitadel may use another claim name (<code>ADMIN_GROUPS_CLAIM</code>).`
          : ""
      }</p>`
    : d.groups.length === 0
      ? html`<p>The <code>${d.groupsClaim}</code> claim is empty.</p>`
      : html`<p>Groups in <code>${d.groupsClaim}</code>:</p><ul>${d.groups.map((g) => html`<li><code>${g}</code></li>`)}</ul>`;
  return entryPage(
    { title: "Not authorized" },
    html`<h1>Not authorized</h1>
  <p>Your account signed in successfully but is not an administrator of this relay. No admin rule matched what the identity provider sent:</p>
  <ul>
    <li>Subject (<code>ADMIN_SUBJECTS</code>): <code>${d.sub}</code></li>
    <li>E-mail (<code>ADMIN_EMAILS</code>): ${d.email ? html`<code>${d.email}</code>${d.emailVerified === false ? " – not verified, so it does not count" : ""}` : "none"}</li>
  </ul>
  ${groups}
  <p>Group names match regardless of case and of a leading slash.</p>
  <a class="button" href="/admin">Start again</a>`,
    true,
  );
}

/**
 * After the callback: a same-site navigation to /admin, so the SameSite=Strict
 * session cookie is sent (it is withheld on the cross-site redirect chain from the IdP).
 */
export function continuePage(): string {
  return entryPage(
    { title: "Signed in", head: html`<meta http-equiv="refresh" content="0;url=/admin">` },
    html`<h1>Signed in</h1>
  <p>Opening the dashboard …</p>
  <a class="button primary wide" href="/admin">Continue to the dashboard${icon("arrowRight", 17)}</a>`,
  );
}

const STATUS_LABEL: Record<string, string> = {
  ok: "ok",
  gone: "gone",
  forbidden: "forbidden",
  invalid: "invalid",
  rate_limited: "rate limited",
  error: "error",
};

/** Badge tone of a delivery result (the app's status badges). */
const STATUS_TONE: Record<string, string> = {
  ok: "ok",
  gone: "",
  forbidden: "",
  invalid: "",
  rate_limited: "warn",
  error: "error",
};

function kv(obj: Record<string, number>, path: string, empty = "none"): SafeHtml {
  const entries = Object.entries(obj).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return html`<p class="muted small" data-kv="${path}">${empty}</p>`;
  return html`<dl class="kv" data-kv="${path}">${entries.map(
    ([k, v]) => html`<dt>${k}</dt><dd>${fmtNum(v)}</dd>`,
  )}</dl>`;
}

function sum(r: Record<string, number>): number {
  return Object.values(r).reduce((a, b) => a + b, 0);
}

type ProviderState = "off" | "bad" | "good" | "idle";

function providerState(p: Summary["providers"]["apns"]): ProviderState {
  return !p.configured
    ? "off"
    : p.lastErrorAt && (!p.lastOkAt || p.lastErrorAt > p.lastOkAt)
      ? "bad"
      : p.lastOkAt
        ? "good"
        : "idle";
}

const PROVIDER_TONE: Record<ProviderState, string> = {
  off: "",
  bad: "error",
  good: "ok",
  idle: "info",
};

function providerTile(
  name: string,
  key: "apns" | "fcm",
  logo: IconName,
  p: Summary["providers"]["apns"],
  now: number,
) {
  const state = providerState(p);
  const label = {
    off: "not configured",
    bad: "last delivery failed",
    good: "delivering",
    idle: "no traffic yet",
  }[state];
  return html`<div class="health-tile ${PROVIDER_TONE[state]}" data-health="${key}">
  <span class="tone-icon" aria-hidden="true">${icon(logo, 17)}</span>
  <div class="tile-text"><strong>${name}</strong><small>${label}</small>
  <small>last ok <span data-k="providers.${key}.lastOkAt" data-fmt="agoms">${p.lastOkAt ? fmtAgo(p.lastOkAt / 1000, now) : "never"}</span> · last error <span data-k="providers.${key}.lastErrorAt" data-fmt="agoms">${p.lastErrorAt ? fmtAgo(p.lastErrorAt / 1000, now) : "never"}</span>
  <span class="mono" data-k="providers.${key}.lastErrorReason">${p.lastErrorReason ?? ""}</span></small></div>
</div>`;
}

function csrfField(s: AdminSession): SafeHtml {
  return html`<input type="hidden" name="csrf" value="${s.csrf}">`;
}

function reasonField(placeholder = "Reason (required, kept in the audit log)"): SafeHtml {
  return html`<input name="reason" required minlength="3" maxlength="500" placeholder="${placeholder}" aria-label="Reason (kept in the audit log)" autocomplete="off">`;
}

function durationSelect(allowPermanent: boolean): SafeHtml {
  return html`<select name="duration" aria-label="Duration">
  ${allowPermanent ? html`<option value="permanent">until unblocked</option>` : ""}
  <option value="1h">1 hour</option>
  <option value="24h"${allowPermanent ? "" : html` selected`}>24 hours</option>
  <option value="7d">7 days</option>
  <option value="30d">30 days</option>
</select>`;
}

function auditTable(entries: AuditEntry[], withIp: boolean): SafeHtml {
  if (entries.length === 0)
    return html`<div class="card-body">${empty("No admin actions yet", "Sign-ins, sign-outs and every action appear here.", "clockCounterClockwise")}</div>`;
  return html`<div class="table-scroll"><table class="audit">
<thead><tr><th>#</th><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Reason</th>${withIp ? html`<th>IP</th><th>Details</th>` : ""}</tr></thead>
<tbody>${entries.map(
    (e) => html`<tr>
  <td class="mono">${e.id}</td><td class="nowrap">${fmtTime(e.at)}</td><td>${e.actor}</td>
  <td><span class="tag">${e.action}</span></td><td class="mono break">${e.target ?? ""}</td><td>${e.reason ?? ""}</td>
  ${withIp ? html`<td class="mono">${e.ip ?? ""}</td><td class="mono small break">${e.details ? JSON.stringify(e.details) : ""}</td>` : ""}
</tr>`,
  )}</tbody></table></div>`;
}

function topRows(top: Summary["top"], now: number, blocked: Set<string>): SafeHtml {
  if (top.length === 0) return html`<tr><td colspan="6" class="empty">No instances yet.</td></tr>`;
  return html`${top.map(
    (t) => html`<tr>
  <td class="break"><a href="/admin/instance?origin=${encodeURIComponent(t.instance)}">${t.instance}</a>${blocked.has(t.instance) ? html`<span class="badge error">blocked</span>` : ""}</td>
  <td class="num">${fmtNum(t.messages1h)}</td><td class="num">${fmtNum(t.messages24h)}</td>
  <td class="num">${fmtNum(t.devices)}</td><td class="num">${fmtPct(t.errors24h, t.messages24h)}</td>
  <td class="nowrap">${t.lastSeen ? fmtAgo(t.lastSeen, now) : "–"}</td>
</tr>`,
  )}`;
}

/** One line on the state of the relay, as the app's live strip says it. */
function relayState(d: Summary): { tone: string; icon: IconName; text: string } {
  const problems: string[] = [];
  if (d.paused) problems.push("Sending is paused");
  if (!d.dbOk) problems.push("Database unavailable");
  if (providerState(d.providers.apns) === "bad") problems.push("APNs: last delivery failed");
  if (providerState(d.providers.fcm) === "bad") problems.push("FCM: last delivery failed");
  if (problems.length) return { tone: "error", icon: "xCircleBold", text: problems.join(" · ") };
  if (!d.providers.apns.configured && !d.providers.fcm.configured)
    return { tone: "warn", icon: "warningCircleBold", text: "No push provider configured" };
  return { tone: "ok", icon: "checkCircleBold", text: "All fine" };
}

export function dashboardPage(
  s: AdminSession,
  d: Summary,
  done?: { id: number; text: string },
): string {
  const now = d.generatedAt;
  const m = d.messages;
  const hourTotal = sum(m.lastHour);
  const blockedSet = new Set(d.blocked.map((b) => b.origin));
  const state = relayState(d);
  return page(
    {
      title: "Dashboard",
      session: s,
      api: "/admin/api/summary",
      nav: "dashboard",
      crumbs: [["Dashboard"]],
    },
    html`
${pageHead("paperPlaneTilt", "Push relay", "Deliveries, registrations and abuse controls of this relay.", liveBadge())}
${done ? html`<p class="callout ok" role="status">${icon("checkCircleBold", 18)}<span>Done (audit #${done.id}): ${done.text}</span></p>` : ""}
<div id="paused-banner" class="callout error" role="alert"${d.paused ? "" : html` hidden`}>
  ${icon("pauseCircle", 20)}
  <p class="break"><strong>Sending is paused.</strong> Every <code>POST /v1/send</code> answers
  <code>503 relay_paused</code>.
  <span data-k="paused.reason">${d.paused?.reason ?? ""}</span> (by <span data-k="paused.by">${d.paused?.by ?? ""}</span>)</p>
</div>

<section class="live-strip" aria-label="State of the relay">
  <div class="live-strip-state">
    <div class="state-head ${state.tone}">
      <span class="tone-icon" aria-hidden="true">${icon(state.icon, 20)}</span>
      <div><strong>${state.text}</strong>
      <small>v${d.version}${d.commit ? html` · <span class="mono">${d.commit.slice(0, 12)}</span>` : ""} · running for <span data-k="uptimeSeconds" data-fmt="dur">${fmtDuration(d.uptimeSeconds)}</span></small></div>
    </div>
    <div class="kpi-grid">
      <div class="kpi"><strong data-k="@msgHour">${fmtNum(hourTotal)}</strong><span>Messages, last hour</span></div>
      <div class="kpi"><strong data-k="@errHour">${fmtPct(m.lastHour.error ?? 0, hourTotal)}</strong><span>Error rate (1 h)</span></div>
      <div class="kpi"><strong data-k="devices.total" data-fmt="num">${fmtNum(d.devices.total)}</strong><span>Registered devices</span></div>
      <div class="kpi"><strong data-k="devices.instances" data-fmt="num">${fmtNum(d.devices.instances)}</strong><span>Instances</span></div>
    </div>
  </div>
  <div class="live-strip-chart">
    <header><h2>Messages per minute</h2><span class="muted small">last 60 minutes</span></header>
    <div class="chart">
      <span class="chart-max">max <span id="max-msg">${fmtNum(Math.max(0, ...m.perMinute))}</span>/min</span>
      ${sparkline(m.perMinute, "s-all", "messages per minute, last 60 minutes", "messages.perMinute", { tall: true, maxId: "max-msg" })}
      <div class="chart-axis" aria-hidden="true"><span>60 min ago</span><span>30 min</span><span>now</span></div>
    </div>
  </div>
</section>

<h2 class="group-title">Delivery</h2>
<section class="health-tiles" aria-label="Health">
  ${providerTile("APNs (iOS)", "apns", "appleLogo", d.providers.apns, now)}
  ${providerTile("FCM (Android)", "fcm", "androidLogo", d.providers.fcm, now)}
  <div class="health-tile ${d.dbOk ? "ok" : "error"}"><span class="tone-icon" aria-hidden="true">${icon("database", 17)}</span>
    <div class="tile-text"><strong>Database</strong><small>${d.dbOk ? "ok" : "unavailable"}</small></div></div>
  <div class="health-tile info"><span class="tone-icon" aria-hidden="true">${icon("clock", 17)}</span>
    <div class="tile-text"><strong>Uptime</strong><small><span data-k="uptimeSeconds" data-fmt="dur">${fmtDuration(d.uptimeSeconds)}</span> · <span class="mono">${d.version}${d.commit ? html` · ${d.commit.slice(0, 12)}` : ""}</span></small></div></div>
</section>

<section class="card">
  ${cardHead("Delivery results", "Per minute over the last 60 minutes, with the last hour and the last 24 hours.")}
  <div class="card-body"><div class="kpi-grid statuses">
  ${MESSAGE_STATUSES.map(
    (st) => html`<div class="kpi">
    <span class="badge ${STATUS_TONE[st] ?? ""}">${STATUS_LABEL[st]}</span>
    <div class="value"><span data-k="messages.lastHour.${st}" data-fmt="num">${fmtNum(m.lastHour[st] ?? 0)}</span> <small>/ h</small></div>
    ${sparkline(m.byStatusPerMinute[st] ?? [], `st-${st}`, `${st} per minute`, `messages.byStatusPerMinute.${st}`)}
    <small>24 h: <span data-k="messages.last24h.${st}" data-fmt="num">${fmtNum(m.last24h[st] ?? 0)}</span></small>
  </div>`,
  )}
  </div></div>
</section>

<h2 class="group-title">Traffic</h2>
<section class="kpi-grid cards">
  <div class="kpi"><strong data-k="devices.new24h" data-fmt="num">${fmtNum(d.devices.new24h)}</strong><span>New registrations, 24 h</span>
    <small><span data-k="devices.total" data-fmt="num">${fmtNum(d.devices.total)}</span> devices in all</small>
    ${kv(d.devices.byPlatform, "devices.byPlatform")}</div>
  <div class="kpi"><strong data-k="@authHour">${fmtNum(sum(d.authFailures.lastHour))}</strong><span>Auth failures, last hour</span>
    ${sparkline(d.authFailures.perMinute, "s-bad", "auth failures per minute", "authFailures.perMinute")}${kv(d.authFailures.lastHour, "authFailures.lastHour")}</div>
  <div class="kpi"><strong data-k="@rlHour">${fmtNum(sum(d.rateLimited.lastHour))}</strong><span>Rate-limit hits, last hour</span>
    ${sparkline(d.rateLimited.perMinute, "s-warn", "rate-limit hits per minute", "rateLimited.perMinute")}${kv(d.rateLimited.lastHour, "rateLimited.lastHour")}</div>
  <div class="kpi"><strong>${fmtNum(sum(d.refused.lastHour))}</strong><span>Refused, last hour</span>
    <small>blocked instances and IP ranges</small>${kv(d.refused.lastHour, "refused.lastHour")}</div>
</section>

<section class="card">
  ${cardHead("Top instances", "By messages in the last 24 hours.")}
  <div class="table-scroll"><table>
    <thead><tr><th>Instance</th><th class="num">Msgs 1 h</th><th class="num">Msgs 24 h</th><th class="num">Devices</th><th class="num">Errors 24 h</th><th>Last seen</th></tr></thead>
    <tbody data-table="top">${topRows(d.top, now, blockedSet)}</tbody>
  </table></div>
</section>

<h2 class="group-title">Controls</h2>
<section class="grid2">
  <div class="card danger-zone">
    ${cardHead("Emergency", "Stops every delivery at once. Registrations keep working.")}
    <div class="card-body">
    <div class="control">${
      d.paused
        ? html`<h3>Resume sending</h3><p>Sending has been paused since ${fmtTime(d.paused.since)} by ${d.paused.by}.</p>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="resume_sending"><input type="hidden" name="step" value="review">
      ${reasonField()}<button class="button primary">${icon("playCircle", 17)}Resume sending…</button></form>`
        : html`<h3>Kill switch</h3><p>Every send request is refused with <code>503 relay_paused</code>
      (Retry-After 300 s) until resumed. Use it if credentials leak or the relay is abused at scale.</p>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="pause_sending"><input type="hidden" name="step" value="review">
      ${reasonField()}<button class="button danger">${icon("pauseCircle", 17)}Pause all sending…</button></form>`
    }</div>
    <div class="control"><h3>Maintenance</h3><p>Deletes registrations whose expiry has passed, and expired blocks.</p>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="purge_expired"><input type="hidden" name="step" value="review">
      ${reasonField()}<button class="button">${icon("broom", 17)}Purge expired registrations…</button></form></div>
    </div>
  </div>
  <div class="card">
    ${cardHead("Block", "Refuse an instance, or registrations from an IP range. Every step is confirmed and audited.")}
    <div class="card-body">
    <div class="control"><h3>Block an instance</h3>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="block_instance"><input type="hidden" name="step" value="review">
      <input name="origin" required placeholder="https://instance.example.com" aria-label="Instance origin" autocomplete="off" maxlength="255">
      ${durationSelect(true)}${reasonField()}<button class="button danger">${icon("prohibit", 17)}Block…</button></form></div>
    <div class="control"><h3>Block an IP range for registrations</h3>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="block_ip"><input type="hidden" name="step" value="review">
      <input name="cidr" required placeholder="203.0.113.7 or 203.0.113.0/24" aria-label="IP address or range" autocomplete="off" maxlength="64">
      ${durationSelect(false)}${reasonField()}<button class="button danger">${icon("prohibit", 17)}Block…</button></form></div>
    </div>
  </div>
</section>

<section class="card">
  ${cardHead("Blocked instances", "Their send requests are refused.")}
  ${
    d.blocked.length === 0
      ? html`<div class="card-body">${empty("No blocked instances", "Every instance may send.", "shieldCheck")}</div>`
      : html`<div class="table-scroll"><table><thead><tr><th>Instance</th><th>Since</th><th>Until</th><th>By</th><th>Reason</th><th><span class="sr-only">Unblock</span></th></tr></thead><tbody>
    ${d.blocked.map(
      (
        b,
      ) => html`<tr><td class="break"><a href="/admin/instance?origin=${encodeURIComponent(b.origin)}">${b.origin}</a></td>
      <td class="nowrap">${fmtTime(b.createdAt)}</td><td class="nowrap">${b.expiresAt ? fmtTime(b.expiresAt) : "permanent"}</td>
      <td>${b.createdBy ?? "–"}</td><td>${b.reason ?? ""}</td>
      <td><form method="post" action="/admin/action" class="row-form">${csrfField(s)}
        <input type="hidden" name="action" value="unblock_instance"><input type="hidden" name="step" value="review">
        <input type="hidden" name="origin" value="${b.origin}">${reasonField("Reason")}<button class="button compact">Unblock…</button></form></td></tr>`,
    )}</tbody></table></div>`
  }
</section>
<section class="card">
  ${cardHead("Blocked IP ranges", "Registrations only.")}
  ${
    d.blockedIps.length === 0
      ? html`<div class="card-body">${empty("No blocked IP ranges", "Registrations are accepted from every address.", "shieldCheck")}</div>`
      : html`<div class="table-scroll"><table><thead><tr><th>Range</th><th>Until</th><th>By</th><th>Reason</th><th><span class="sr-only">Unblock</span></th></tr></thead><tbody>
    ${d.blockedIps.map(
      (
        b,
      ) => html`<tr><td class="mono">${b.cidr}</td><td class="nowrap">${fmtTime(b.expiresAt)}</td><td>${b.createdBy ?? "–"}</td><td>${b.reason ?? ""}</td>
      <td><form method="post" action="/admin/action" class="row-form">${csrfField(s)}
        <input type="hidden" name="action" value="unblock_ip"><input type="hidden" name="step" value="review">
        <input type="hidden" name="cidr" value="${b.cidr}">${reasonField("Reason")}<button class="button compact">Unblock…</button></form></td></tr>`,
    )}</tbody></table></div>`
  }
</section>

<section class="card">
  ${cardHead("Recent admin actions", undefined, html`<a class="fix-link" href="/admin/audit">Full audit log${icon("arrowRight", 14)}</a>`)}
  ${auditTable(d.audit, false)}
</section>
<p class="fine">Live values refresh every 5 s. Updated <span data-k="generatedAt" data-fmt="clock">${new Date(now).toISOString().slice(11, 19)} UTC</span>.</p>
`,
  );
}

export function instancePage(s: AdminSession, d: InstanceDetail): string {
  const now = d.generatedAt;
  const t24 = sum(d.messages.last24h);
  const enc = encodeURIComponent(d.instance);
  return page(
    {
      title: d.instance,
      session: s,
      api: `/admin/api/instance?origin=${enc}`,
      nav: "instance",
      crumbs: [["Dashboard", "/admin"], ["Instance"]],
    },
    html`
<nav class="crumbs" aria-label="Breadcrumb"><a href="/admin">Dashboard</a>${icon("caretRight", 12)}<span>Instance</span></nav>
${pageHead("globe", d.instance, "Registrations, deliveries and recent events of this Flowplan instance.", liveBadge())}
${
  d.blocked
    ? html`<p class="callout error" role="alert">${icon("prohibit", 18)}<span><strong>Blocked</strong> since ${fmtTime(d.blocked.createdAt)} ${d.blocked.expiresAt ? html`until ${fmtTime(d.blocked.expiresAt)}` : "until unblocked"}, by ${d.blocked.createdBy ?? "–"}: ${d.blocked.reason ?? ""}</span></p>`
    : ""
}
<section class="kpi-grid cards">
  <div class="kpi"><strong data-k="devices.total" data-fmt="num">${fmtNum(d.devices.total)}</strong><span>Devices</span>
    ${kv(d.devices.byPlatform, "devices.byPlatform")}${kv(d.devices.byEnvironment, "devices.byEnvironment")}</div>
  <div class="kpi"><strong>${fmtNum(t24)}</strong><span>Messages, 24 h</span>
    ${sparkline(d.messages.perHour, "s-all", "messages per hour", "messages.perHour")}<small>per hour · errors ${fmtPct(d.messages.last24h.error ?? 0, t24)}</small></div>
  <div class="kpi"><strong data-k="@msgHour">${fmtNum(sum(d.messages.lastHour))}</strong><span>Messages, last hour</span>
    ${sparkline(d.messages.perMinute, "s-all", "messages per minute", "messages.perMinute")}${kv(d.messages.lastHour, "messages.lastHour")}</div>
  <div class="kpi"><strong>${fmtNum(d.registrations24h)}</strong><span>Registrations, 24 h</span>
    <dl class="kv"><dt>first</dt><dd>${fmtTime(d.devices.firstRegistered)}</dd><dt>latest</dt><dd>${fmtTime(d.devices.lastRegistered)}</dd><dt>last used</dt><dd>${fmtAgo(d.devices.lastUsed, now)}</dd></dl></div>
</section>
<section class="grid2">
  <div class="card">${cardHead("Results", "Deliveries by result.")}
    <div class="table-scroll"><table><thead><tr><th>Status</th><th class="num">1 h</th><th class="num">24 h</th><th class="num">30 d</th></tr></thead><tbody>
    ${MESSAGE_STATUSES.map(
      (
        st,
      ) => html`<tr><td><span class="badge ${STATUS_TONE[st] ?? ""}">${STATUS_LABEL[st]}</span></td><td class="num">${fmtNum(d.messages.lastHour[st] ?? 0)}</td>
      <td class="num">${fmtNum(d.messages.last24h[st] ?? 0)}</td><td class="num">${fmtNum(d.messages.last30d[st] ?? 0)}</td></tr>`,
    )}</tbody></table></div>
    <div class="card-body"><div class="control"><h3>Auth failures, 24 h</h3>${kv(d.authFailures24h, "authFailures24h")}</div>
    <div class="control"><h3>Rate-limit hits, 24 h</h3>${kv(d.rateLimited24h, "rateLimited24h")}</div></div>
  </div>
  <div class="card danger-zone">${cardHead("Actions", "Confirmed on the next page and kept in the audit log.")}
    <div class="card-body">
    <div class="control">${
      d.blocked
        ? html`<h3>Unblock</h3><form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="unblock_instance"><input type="hidden" name="step" value="review">
      <input type="hidden" name="origin" value="${d.instance}">${reasonField()}<button class="button primary">Unblock…</button></form>`
        : html`<h3>Block this instance</h3><form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="block_instance"><input type="hidden" name="step" value="review">
      <input type="hidden" name="origin" value="${d.instance}">${durationSelect(true)}${reasonField()}<button class="button danger">${icon("prohibit", 17)}Block instance…</button></form>`
    }</div>
    <div class="control"><h3>Delete registrations</h3><form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="delete_instance"><input type="hidden" name="step" value="review">
      <input type="hidden" name="origin" value="${d.instance}">${reasonField()}<button class="button danger">${icon("trash", 17)}Delete all ${fmtNum(d.devices.total)} registrations…</button></form></div>
    </div>
  </div>
</section>
<section class="card">${cardHead("Recent events", "In memory since the start, anonymized: hashed short device ids, truncated IPs.")}
  <div class="table-scroll"><table><thead><tr><th>When</th><th>Event</th><th>Detail</th><th>Device</th><th>IP</th></tr></thead>
  <tbody data-table="events">${
    d.events.length === 0
      ? html`<tr><td colspan="5" class="empty">No events since the relay started.</td></tr>`
      : d.events.map(
          (e) =>
            html`<tr><td class="nowrap">${fmtAgo(e.at / 1000, now)}</td><td><span class="tag">${e.kind}</span></td><td>${e.detail}</td><td class="mono">${e.device ?? ""}</td><td class="mono">${e.ip ?? ""}</td></tr>`,
        )
  }</tbody></table></div>
</section>`,
  );
}

export function auditPage(
  s: AdminSession,
  entries: AuditEntry[],
  nextBefore: number | null,
): string {
  return page(
    { title: "Audit log", session: s, nav: "audit", crumbs: [["Audit log"]] },
    html`${pageHead("clockCounterClockwise", "Audit log", "Append-only: the database refuses updates and deletes of audit rows. Sign-ins, sign-outs and every action are recorded.")}
<section class="card">${auditTable(entries, true)}
${nextBefore ? html`<div class="card-body actions"><a class="button compact" href="/admin/audit?before=${nextBefore}">Older entries${icon("arrowRight", 15)}</a></div>` : ""}
</section>`,
  );
}

export interface ConfirmView {
  action: string;
  title: string;
  description: string;
  consequences: string[];
  fields: Record<string, string>;
  token: string;
  danger: boolean;
}

export function confirmPage(s: AdminSession, c: ConfirmView): string {
  return page(
    { title: `Confirm: ${c.title}`, session: s, crumbs: [["Dashboard", "/admin"], ["Confirm"]] },
    html`<nav class="crumbs" aria-label="Breadcrumb"><a href="/admin">Dashboard</a>${icon("caretRight", 12)}<span>Confirm</span></nav>
${pageHead(c.danger ? "warning" : "shieldCheck", c.title, c.description, "", c.danger ? "danger" : "")}
<section class="card${c.danger ? " danger-zone" : ""} confirm">
  ${cardHead("What happens")}
  <div class="card-body">
  <ul>${c.consequences.map((x) => html`<li>${x}</li>`)}</ul>
  <dl class="kv wide">${Object.entries(c.fields).map(([k, v]) => html`<dt>${k}</dt><dd class="break">${v}</dd>`)}</dl>
  <form method="post" action="/admin/action" class="actions">
    ${csrfField(s)}
    <input type="hidden" name="action" value="${c.action}">
    <input type="hidden" name="step" value="execute">
    <input type="hidden" name="confirm" value="${c.token}">
    ${Object.entries(c.fields).map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}
    <button type="submit" class="button ${c.danger ? "danger-solid" : "primary"}">Confirm: ${c.title}</button>
    <a class="button" href="/admin">Cancel</a>
  </form>
  <p class="fine">This confirmation expires in 5 minutes.</p>
  </div>
</section>`,
  );
}

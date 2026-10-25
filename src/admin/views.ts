import { MESSAGE_STATUSES } from "../stats.ts";
import type { AuditEntry } from "./actions.ts";
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
import type { AdminSession } from "./sessions.ts";
import type { InstanceDetail, Summary } from "./summary.ts";

export const ASSET_CSS = "/admin/assets/admin.css";
export const ASSET_JS = "/admin/assets/admin.js";

interface PageOpts {
  title: string;
  session?: AdminSession | null;
  /** JSON endpoint the client script polls for live values. */
  api?: string;
  nav?: "dashboard" | "audit" | "instance";
  /** Extra <head> markup (meta refresh on the post-login page). */
  head?: SafeHtml;
}

export function page(o: PageOpts, body: SafeHtml): string {
  const s = o.session;
  const who = s ? (s.email ?? s.name ?? s.sub) : null;
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${o.title} · Flowplan push admin</title>
<link rel="stylesheet" href="${ASSET_CSS}">
${o.head ?? ""}
<script src="${ASSET_JS}" defer></script>
</head>
<body>
<header class="top">
  <a class="brand" href="/admin"><span class="dot"></span>Flowplan push <span class="muted">admin</span></a>
  ${
    s
      ? html`<nav>
    <a href="/admin" class="${o.nav === "dashboard" ? "active" : ""}">Dashboard</a>
    <a href="/admin/audit" class="${o.nav === "audit" ? "active" : ""}">Audit log</a>
  </nav>
  <form method="post" action="/admin/logout" class="logout">
    <input type="hidden" name="csrf" value="${s.csrf}">
    <span class="who" title="${s.sub}">${who}</span>
    <button type="submit" class="btn small ghost">Sign out</button>
  </form>`
      : ""
  }
</header>
<main${o.api ? html` data-api="${o.api}"` : ""}>
<p id="live-status" class="live" hidden></p>
${body}
</main>
</body>
</html>`.value;
}

export function loginPage(issuerHost: string, notice?: string): string {
  return page(
    { title: "Sign in" },
    html`<section class="card narrow center">
  <h1>Push relay administration</h1>
  <p class="muted">Sign in with your organisation's identity provider (${issuerHost}).</p>
  ${notice ? html`<p class="notice">${notice}</p>` : ""}
  <p><a class="btn primary" href="/admin/login">Sign in with SSO</a></p>
  <p class="fine">Access is limited to configured administrators. Every action is audited.</p>
</section>`,
  );
}

export function messagePage(title: string, message: string, linkText = "Back"): string {
  return page(
    { title },
    html`<section class="card narrow center">
  <h1>${title}</h1>
  <p>${message}</p>
  <p><a class="btn" href="/admin">${linkText}</a></p>
</section>`,
  );
}

/**
 * After the callback: a same-site navigation to /admin, so the SameSite=Strict
 * session cookie is sent (it is withheld on the cross-site redirect chain from the IdP).
 */
export function continuePage(): string {
  return page(
    { title: "Signed in", head: html`<meta http-equiv="refresh" content="0;url=/admin">` },
    html`<section class="card narrow center">
  <h1>Signed in</h1>
  <p><a class="btn primary" href="/admin">Continue to the dashboard</a></p>
</section>`,
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

function kv(obj: Record<string, number>, path: string, empty = "none"): SafeHtml {
  const entries = Object.entries(obj).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return html`<p class="muted small" data-kv="${path}">${empty}</p>`;
  return html`<dl class="kv" data-kv="${path}">${entries.map(
    ([k, v]) => html`<dt>${k}</dt><dd>${fmtNum(v)}</dd>`,
  )}</dl>`;
}

function providerCard(
  name: string,
  key: "apns" | "fcm",
  p: Summary["providers"]["apns"],
  now: number,
) {
  const state = !p.configured
    ? "off"
    : p.lastErrorAt && (!p.lastOkAt || p.lastErrorAt > p.lastOkAt)
      ? "bad"
      : p.lastOkAt
        ? "good"
        : "idle";
  const label = {
    off: "not configured",
    bad: "last delivery failed",
    good: "delivering",
    idle: "no traffic yet",
  }[state];
  return html`<div class="health ${state}" data-health="${key}">
  <div class="health-name"><span class="pill ${state}">${label}</span> ${name}</div>
  <div class="small muted">last ok: <span data-k="providers.${key}.lastOkAt" data-fmt="agoms">${p.lastOkAt ? fmtAgo(p.lastOkAt / 1000, now) : "never"}</span></div>
  <div class="small muted">last error: <span data-k="providers.${key}.lastErrorAt" data-fmt="agoms">${p.lastErrorAt ? fmtAgo(p.lastErrorAt / 1000, now) : "never"}</span>
  <span class="mono" data-k="providers.${key}.lastErrorReason">${p.lastErrorReason ?? ""}</span></div>
</div>`;
}

function csrfField(s: AdminSession): SafeHtml {
  return html`<input type="hidden" name="csrf" value="${s.csrf}">`;
}

function reasonField(placeholder = "Reason (required, kept in the audit log)"): SafeHtml {
  return html`<input name="reason" required minlength="3" maxlength="500" placeholder="${placeholder}" autocomplete="off">`;
}

function durationSelect(allowPermanent: boolean): SafeHtml {
  return html`<select name="duration">
  ${allowPermanent ? html`<option value="permanent">until unblocked</option>` : ""}
  <option value="1h">1 hour</option>
  <option value="24h"${allowPermanent ? "" : html` selected`}>24 hours</option>
  <option value="7d">7 days</option>
  <option value="30d">30 days</option>
</select>`;
}

function auditTable(entries: AuditEntry[], withIp: boolean): SafeHtml {
  if (entries.length === 0) return html`<p class="muted small">No admin actions yet.</p>`;
  return html`<div class="table-wrap"><table class="audit">
<thead><tr><th>#</th><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Reason</th>${withIp ? html`<th>IP</th><th>Details</th>` : ""}</tr></thead>
<tbody>${entries.map(
    (e) => html`<tr>
  <td class="mono">${e.id}</td><td class="nowrap">${fmtTime(e.at)}</td><td>${e.actor}</td>
  <td><span class="tag">${e.action}</span></td><td class="mono break">${e.target ?? ""}</td><td>${e.reason ?? ""}</td>
  ${withIp ? html`<td class="mono">${e.ip ?? ""}</td><td class="mono small">${e.details ? JSON.stringify(e.details) : ""}</td>` : ""}
</tr>`,
  )}</tbody></table></div>`;
}

function topRows(top: Summary["top"], now: number, blocked: Set<string>): SafeHtml {
  if (top.length === 0) return html`<tr><td colspan="6" class="muted">No instances yet.</td></tr>`;
  return html`${top.map(
    (t) => html`<tr>
  <td class="break"><a href="/admin/instance?origin=${encodeURIComponent(t.instance)}">${t.instance}</a>${blocked.has(t.instance) ? html`<span class="pill blocked">blocked</span>` : ""}</td>
  <td class="num">${fmtNum(t.messages1h)}</td><td class="num">${fmtNum(t.messages24h)}</td>
  <td class="num">${fmtNum(t.devices)}</td><td class="num">${fmtPct(t.errors24h, t.messages24h)}</td>
  <td class="nowrap">${t.lastSeen ? fmtAgo(t.lastSeen, now) : "–"}</td>
</tr>`,
  )}`;
}

export function dashboardPage(
  s: AdminSession,
  d: Summary,
  done?: { id: number; text: string },
): string {
  const now = d.generatedAt;
  const m = d.messages;
  const hourTotal = Object.values(m.lastHour).reduce((a, b) => a + b, 0);
  const blockedSet = new Set(d.blocked.map((b) => b.origin));
  return page(
    { title: "Dashboard", session: s, api: "/admin/api/summary", nav: "dashboard" },
    html`
${done ? html`<p class="flash">Done (audit #${done.id}): ${done.text}</p>` : ""}
<p id="paused-banner" class="banner danger"${d.paused ? "" : html` hidden`}>
  <strong>Sending is paused.</strong> Every <span class="mono">POST /v1/send</span> answers
  <span class="mono">503 relay_paused</span>.
  <span data-k="paused.reason">${d.paused?.reason ?? ""}</span> (by <span data-k="paused.by">${d.paused?.by ?? ""}</span>)
</p>

<section class="grid4">
  <div class="card stat"><div class="label">Messages, last hour</div><div class="value" data-k="@msgHour">${fmtNum(hourTotal)}</div>
    ${sparkline(m.perMinute, "s-all", "messages per minute", "messages.perMinute")}<div class="small muted">per minute, 60 min</div></div>
  <div class="card stat"><div class="label">Registrations</div><div class="value" data-k="devices.total" data-fmt="num">${fmtNum(d.devices.total)}</div>
    <div class="small muted"><span data-k="devices.new24h" data-fmt="num">${fmtNum(d.devices.new24h)}</span> new in 24 h · <span data-k="devices.instances" data-fmt="num">${fmtNum(d.devices.instances)}</span> instances</div>
    ${kv(d.devices.byPlatform, "devices.byPlatform")}</div>
  <div class="card stat"><div class="label">Auth failures, last hour</div><div class="value" data-k="@authHour">${fmtNum(Object.values(d.authFailures.lastHour).reduce((a, b) => a + b, 0))}</div>
    ${sparkline(d.authFailures.perMinute, "s-bad", "auth failures per minute", "authFailures.perMinute")}${kv(d.authFailures.lastHour, "authFailures.lastHour")}</div>
  <div class="card stat"><div class="label">Rate-limit hits, last hour</div><div class="value" data-k="@rlHour">${fmtNum(Object.values(d.rateLimited.lastHour).reduce((a, b) => a + b, 0))}</div>
    ${sparkline(d.rateLimited.perMinute, "s-warn", "rate-limit hits per minute", "rateLimited.perMinute")}${kv(d.rateLimited.lastHour, "rateLimited.lastHour")}</div>
</section>

<section class="card">
  <h2>Delivery results <span class="muted small">per minute, last 60 minutes</span></h2>
  <div class="statuses">
  ${MESSAGE_STATUSES.map(
    (st) => html`<div class="status-cell">
    <div class="label"><span class="pill st-${st}">${STATUS_LABEL[st]}</span></div>
    <div class="value small-value"><span data-k="messages.lastHour.${st}" data-fmt="num">${fmtNum(m.lastHour[st] ?? 0)}</span> <span class="muted small">/ h</span></div>
    ${sparkline(m.byStatusPerMinute[st] ?? [], `st-${st}`, `${st} per minute`, `messages.byStatusPerMinute.${st}`)}
    <div class="small muted">24 h: <span data-k="messages.last24h.${st}" data-fmt="num">${fmtNum(m.last24h[st] ?? 0)}</span></div>
  </div>`,
  )}
  </div>
</section>

<section class="grid2">
  <div class="card">
    <h2>Health</h2>
    <div class="healths">
      ${providerCard("APNs (iOS)", "apns", d.providers.apns, now)}
      ${providerCard("FCM (Android)", "fcm", d.providers.fcm, now)}
    </div>
    <dl class="kv wide">
      <dt>Database</dt><dd>${d.dbOk ? "ok" : "unavailable"}</dd>
      <dt>Uptime</dt><dd data-k="uptimeSeconds" data-fmt="dur">${fmtDuration(d.uptimeSeconds)}</dd>
      <dt>Version</dt><dd class="mono">${d.version}${d.commit ? html` · ${d.commit.slice(0, 12)}` : ""}</dd>
      <dt>Refused (1 h)</dt><dd>${kv(d.refused.lastHour, "refused.lastHour")}</dd>
    </dl>
  </div>
  <div class="card danger-zone">
    <h2>Emergency</h2>
    ${
      d.paused
        ? html`<p>Sending has been paused since ${fmtTime(d.paused.since)} by ${d.paused.by}.</p>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="resume_sending"><input type="hidden" name="step" value="review">
      ${reasonField()}<button class="btn primary">Resume sending…</button></form>`
        : html`<p class="small">Kill switch: every send request is refused with <span class="mono">503 relay_paused</span>
      (Retry-After 300 s) until resumed. Registrations keep working. Use it if credentials leak or the relay is abused at scale.</p>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="pause_sending"><input type="hidden" name="step" value="review">
      ${reasonField()}<button class="btn danger">Pause all sending…</button></form>`
    }
    <h3>Block an instance</h3>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="block_instance"><input type="hidden" name="step" value="review">
      <input name="origin" required placeholder="https://instance.example.com" autocomplete="off" maxlength="255">
      ${durationSelect(true)}${reasonField()}<button class="btn danger">Block…</button></form>
    <h3>Block an IP range for registrations</h3>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="block_ip"><input type="hidden" name="step" value="review">
      <input name="cidr" required placeholder="203.0.113.7 or 203.0.113.0/24" autocomplete="off" maxlength="64">
      ${durationSelect(false)}${reasonField()}<button class="btn danger">Block…</button></form>
    <h3>Maintenance</h3>
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="purge_expired"><input type="hidden" name="step" value="review">
      ${reasonField()}<button class="btn">Purge expired registrations…</button></form>
  </div>
</section>

<section class="card">
  <h2>Top instances <span class="muted small">by messages in the last 24 h</span></h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Instance</th><th class="num">Msgs 1 h</th><th class="num">Msgs 24 h</th><th class="num">Devices</th><th class="num">Errors 24 h</th><th>Last seen</th></tr></thead>
    <tbody data-table="top">${topRows(d.top, now, blockedSet)}</tbody>
  </table></div>
</section>

<section>
  <div class="card">
    <h2>Blocked instances</h2>
    ${
      d.blocked.length === 0
        ? html`<p class="muted small">None.</p>`
        : html`<div class="table-wrap"><table><thead><tr><th>Instance</th><th>Since</th><th>Until</th><th>By</th><th>Reason</th><th></th></tr></thead><tbody>
      ${d.blocked.map(
        (
          b,
        ) => html`<tr><td class="break"><a href="/admin/instance?origin=${encodeURIComponent(b.origin)}">${b.origin}</a></td>
        <td class="nowrap">${fmtTime(b.createdAt)}</td><td class="nowrap">${b.expiresAt ? fmtTime(b.expiresAt) : "permanent"}</td>
        <td>${b.createdBy ?? "–"}</td><td>${b.reason ?? ""}</td>
        <td><form method="post" action="/admin/action" class="row-form">${csrfField(s)}
          <input type="hidden" name="action" value="unblock_instance"><input type="hidden" name="step" value="review">
          <input type="hidden" name="origin" value="${b.origin}">${reasonField("Reason")}<button class="btn small">Unblock…</button></form></td></tr>`,
      )}</tbody></table></div>`
    }
  </div>
</section>
<section>
  <div class="card">
    <h2>Blocked IP ranges <span class="muted small">registrations only</span></h2>
    ${
      d.blockedIps.length === 0
        ? html`<p class="muted small">None.</p>`
        : html`<div class="table-wrap"><table><thead><tr><th>Range</th><th>Until</th><th>By</th><th>Reason</th><th></th></tr></thead><tbody>
      ${d.blockedIps.map(
        (
          b,
        ) => html`<tr><td class="mono">${b.cidr}</td><td class="nowrap">${fmtTime(b.expiresAt)}</td><td>${b.createdBy ?? "–"}</td><td>${b.reason ?? ""}</td>
        <td><form method="post" action="/admin/action" class="row-form">${csrfField(s)}
          <input type="hidden" name="action" value="unblock_ip"><input type="hidden" name="step" value="review">
          <input type="hidden" name="cidr" value="${b.cidr}">${reasonField("Reason")}<button class="btn small">Unblock…</button></form></td></tr>`,
      )}</tbody></table></div>`
    }
  </div>
</section>

<section class="card">
  <h2>Recent admin actions <a class="small" href="/admin/audit">full audit log</a></h2>
  ${auditTable(d.audit, false)}
</section>
<p class="fine">Live values refresh every 5 s. Updated <span data-k="generatedAt" data-fmt="clock">${new Date(now).toISOString().slice(11, 19)} UTC</span>.</p>
`,
  );
}

export function instancePage(s: AdminSession, d: InstanceDetail): string {
  const now = d.generatedAt;
  const t24 = Object.values(d.messages.last24h).reduce((a, b) => a + b, 0);
  const enc = encodeURIComponent(d.instance);
  return page(
    {
      title: d.instance,
      session: s,
      api: `/admin/api/instance?origin=${enc}`,
      nav: "instance",
    },
    html`
<p class="crumbs"><a href="/admin">Dashboard</a> › instance</p>
<h1 class="break">${d.instance}</h1>
${
  d.blocked
    ? html`<p class="banner danger"><strong>Blocked</strong> since ${fmtTime(d.blocked.createdAt)} ${d.blocked.expiresAt ? html`until ${fmtTime(d.blocked.expiresAt)}` : "until unblocked"}, by ${d.blocked.createdBy ?? "–"}: ${d.blocked.reason ?? ""}</p>`
    : ""
}
<section class="grid4">
  <div class="card stat"><div class="label">Devices</div><div class="value" data-k="devices.total" data-fmt="num">${fmtNum(d.devices.total)}</div>
    ${kv(d.devices.byPlatform, "devices.byPlatform")}${kv(d.devices.byEnvironment, "devices.byEnvironment")}</div>
  <div class="card stat"><div class="label">Messages, 24 h</div><div class="value">${fmtNum(t24)}</div>
    ${sparkline(d.messages.perHour, "s-all", "messages per hour", "messages.perHour")}<div class="small muted">per hour, 24 h · errors ${fmtPct(d.messages.last24h.error ?? 0, t24)}</div></div>
  <div class="card stat"><div class="label">Messages, last hour</div><div class="value" data-k="@msgHour">${fmtNum(Object.values(d.messages.lastHour).reduce((a, b) => a + b, 0))}</div>
    ${sparkline(d.messages.perMinute, "s-all", "messages per minute", "messages.perMinute")}${kv(d.messages.lastHour, "messages.lastHour")}</div>
  <div class="card stat"><div class="label">Registrations, 24 h</div><div class="value">${fmtNum(d.registrations24h)}</div>
    <div class="small muted">first ${fmtTime(d.devices.firstRegistered)}<br>latest ${fmtTime(d.devices.lastRegistered)}<br>last used ${fmtAgo(d.devices.lastUsed, now)}</div></div>
</section>
<section class="grid2">
  <div class="card"><h2>Results</h2>
    <div class="table-wrap"><table><thead><tr><th>Status</th><th class="num">1 h</th><th class="num">24 h</th><th class="num">30 d</th></tr></thead><tbody>
    ${MESSAGE_STATUSES.map(
      (
        st,
      ) => html`<tr><td><span class="pill st-${st}">${STATUS_LABEL[st]}</span></td><td class="num">${fmtNum(d.messages.lastHour[st] ?? 0)}</td>
      <td class="num">${fmtNum(d.messages.last24h[st] ?? 0)}</td><td class="num">${fmtNum(d.messages.last30d[st] ?? 0)}</td></tr>`,
    )}</tbody></table></div>
    <h3>Auth failures, 24 h</h3>${kv(d.authFailures24h, "authFailures24h")}
    <h3>Rate-limit hits, 24 h</h3>${kv(d.rateLimited24h, "rateLimited24h")}
  </div>
  <div class="card danger-zone"><h2>Actions</h2>
    ${
      d.blocked
        ? html`<form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="unblock_instance"><input type="hidden" name="step" value="review">
      <input type="hidden" name="origin" value="${d.instance}">${reasonField()}<button class="btn primary">Unblock…</button></form>`
        : html`<form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="block_instance"><input type="hidden" name="step" value="review">
      <input type="hidden" name="origin" value="${d.instance}">${durationSelect(true)}${reasonField()}<button class="btn danger">Block instance…</button></form>`
    }
    <form method="post" action="/admin/action" class="inline-form">${csrfField(s)}
      <input type="hidden" name="action" value="delete_instance"><input type="hidden" name="step" value="review">
      <input type="hidden" name="origin" value="${d.instance}">${reasonField()}<button class="btn danger">Delete all ${fmtNum(d.devices.total)} registrations…</button></form>
  </div>
</section>
<section class="card"><h2>Recent events <span class="muted small">in memory since start, anonymized: hashed short device ids, truncated IPs</span></h2>
  <div class="table-wrap"><table><thead><tr><th>When</th><th>Event</th><th>Detail</th><th>Device</th><th>IP</th></tr></thead>
  <tbody data-table="events">${
    d.events.length === 0
      ? html`<tr><td colspan="5" class="muted">No events since the relay started.</td></tr>`
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
    { title: "Audit log", session: s, nav: "audit" },
    html`<h1>Audit log</h1>
<p class="muted small">Append-only: the database refuses updates and deletes of audit rows. Logins, logouts and every action are recorded.</p>
<section class="card">${auditTable(entries, true)}
${nextBefore ? html`<p><a class="btn small" href="/admin/audit?before=${nextBefore}">Older entries</a></p>` : ""}
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
    { title: `Confirm: ${c.title}`, session: s },
    html`<section class="card narrow">
  <p class="crumbs"><a href="/admin">Dashboard</a> › confirm</p>
  <h1>${c.title}</h1>
  <p>${c.description}</p>
  <ul>${c.consequences.map((x) => html`<li>${x}</li>`)}</ul>
  <dl class="kv wide">${Object.entries(c.fields).map(([k, v]) => html`<dt>${k}</dt><dd class="break">${v}</dd>`)}</dl>
  <form method="post" action="/admin/action" class="confirm-form">
    ${csrfField(s)}
    <input type="hidden" name="action" value="${c.action}">
    <input type="hidden" name="step" value="execute">
    <input type="hidden" name="confirm" value="${c.token}">
    ${Object.entries(c.fields).map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}
    <button type="submit" class="btn ${c.danger ? "danger" : "primary"}">Confirm: ${c.title}</button>
    <a class="btn ghost" href="/admin">Cancel</a>
  </form>
  <p class="fine">This confirmation expires in 5 minutes.</p>
</section>`,
  );
}

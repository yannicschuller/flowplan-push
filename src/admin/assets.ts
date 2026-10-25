/**
 * Static assets of the admin dashboard, embedded so the build needs no copy
 * step and nothing is loaded from third parties (CSP: 'self' only).
 */

export const ADMIN_CSS = `
:root{--bg:#f6f7f9;--card:#fff;--fg:#17202a;--muted:#5d6b7a;--line:#e3e7ec;--accent:#2563eb;
--on-accent:#fff;--good:#15803d;--bad:#b91c1c;--warn:#b45309;--idle:#64748b;--tag:#eef2f7;--danger-bg:#fef2f2;--flash:#ecfdf5}
@media (prefers-color-scheme:dark){:root{--bg:#0f1419;--card:#171d24;--fg:#e6edf3;--muted:#93a1b0;--line:#2a333d;
--accent:#60a5fa;--on-accent:#0b1220;--good:#4ade80;--bad:#f87171;--warn:#fbbf24;--idle:#94a3b8;--tag:#222b35;--danger-bg:#2a1414;--flash:#0f2a1d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header.top{display:flex;align-items:center;gap:20px;padding:10px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
.brand{font-weight:650;color:var(--fg);display:flex;align-items:center;gap:8px}.brand .dot{width:10px;height:10px;border-radius:50%;background:var(--accent)}
header nav{display:flex;gap:4px}header nav a{padding:6px 10px;border-radius:6px;color:var(--muted)}header nav a.active{background:var(--tag);color:var(--fg)}
.logout{margin-left:auto;display:flex;align-items:center;gap:10px}.who{color:var(--muted);font-size:13px}
main{max-width:1280px;margin:0 auto;padding:20px 16px 40px}
h1{font-size:22px;margin:4px 0 16px}h2{font-size:15px;margin:0 0 12px}h3{font-size:13px;margin:16px 0 6px;color:var(--muted);font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px;min-width:0}
.narrow{max-width:560px;margin:40px auto}.center{text-align:center}
.grid4{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.grid4 .card{margin-bottom:0}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:16px}.grid2 .card{margin-bottom:0}
section.grid4,section.grid2{margin-bottom:16px}
@media (max-width:1000px){.grid4{grid-template-columns:repeat(2,minmax(0,1fr))}.grid2{grid-template-columns:1fr}}
@media (max-width:560px){.grid4{grid-template-columns:1fr}}
.stat .label,.status-cell .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.stat .value{font-size:28px;font-weight:650;font-variant-numeric:tabular-nums;margin:2px 0 6px}
.small-value{font-size:18px;font-weight:600;font-variant-numeric:tabular-nums}
.statuses{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:14px}
@media (max-width:1000px){.statuses{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:560px){.statuses{grid-template-columns:repeat(2,minmax(0,1fr))}}
svg.spark{width:100%;height:32px;display:block;margin:4px 0}
svg.spark polyline{fill:none;stroke:var(--accent);stroke-width:1.5;vector-effect:non-scaling-stroke;stroke-linejoin:round}
svg.spark.s-bad polyline,svg.spark.st-error polyline{stroke:var(--bad)}svg.spark.s-warn polyline,svg.spark.st-rate_limited polyline{stroke:var(--warn)}
svg.spark.st-ok polyline{stroke:var(--good)}svg.spark.st-gone polyline,svg.spark.st-forbidden polyline,svg.spark.st-invalid polyline{stroke:var(--idle)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;background:var(--tag);color:var(--muted);text-transform:none;letter-spacing:0}
.pill.good,.pill.st-ok{background:color-mix(in srgb,var(--good) 15%,transparent);color:var(--good)}
.pill.bad,.pill.st-error{background:color-mix(in srgb,var(--bad) 15%,transparent);color:var(--bad)}
.pill.blocked{background:color-mix(in srgb,var(--bad) 15%,transparent);color:var(--bad);margin-left:6px}
.pill.st-rate_limited{background:color-mix(in srgb,var(--warn) 15%,transparent);color:var(--warn)}
.tag{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:var(--tag);padding:1px 6px;border-radius:4px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:2px 12px;margin:6px 0 0;font-size:13px}.kv dt{color:var(--muted)}.kv dd{margin:0;font-variant-numeric:tabular-nums}
.kv.wide{grid-template-columns:140px 1fr;margin-top:12px}
.healths{display:grid;grid-template-columns:1fr 1fr;gap:12px}.health{border:1px solid var(--line);border-radius:8px;padding:10px}.health-name{font-weight:600;margin-bottom:4px}
.muted{color:var(--muted)}.small{font-size:12px}.fine{font-size:12px;color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.nowrap{white-space:nowrap}.break{overflow-wrap:anywhere}.num{text-align:right;font-variant-numeric:tabular-nums}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted);font-weight:600;font-size:12px;border-bottom:1px solid var(--line);padding:6px 8px}
td{border-bottom:1px solid var(--line);padding:6px 8px;vertical-align:top}tr:last-child td{border-bottom:0}
.btn{display:inline-block;border:1px solid var(--line);background:var(--card);color:var(--fg);padding:7px 12px;border-radius:7px;font:inherit;cursor:pointer;white-space:nowrap}
.btn:hover{text-decoration:none;border-color:var(--muted)}.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.btn.danger{background:var(--bad);border-color:var(--bad);color:var(--on-accent)}.btn.small{padding:3px 8px;font-size:12px}.btn.ghost{background:transparent}
input,select{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:6px 8px;min-width:0}
.inline-form{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0}.inline-form input[name=origin],.inline-form input[name=cidr]{flex:1 1 220px}
.inline-form input[name=reason]{flex:2 1 200px}.row-form{display:flex;gap:6px}.row-form input{width:110px;padding:3px 6px;font-size:12px}
.confirm-form{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
.danger-zone{border-color:color-mix(in srgb,var(--bad) 35%,var(--line))}
.banner{padding:10px 14px;border-radius:8px;margin:0 0 16px}.banner.danger{background:var(--danger-bg);border:1px solid var(--bad)}
.flash{background:var(--flash);border:1px solid var(--good);padding:10px 14px;border-radius:8px}
.notice{color:var(--bad)}.crumbs{font-size:12px;color:var(--muted);margin:0 0 4px}
.live{position:fixed;right:16px;bottom:16px;background:var(--card);border:1px solid var(--bad);color:var(--bad);padding:8px 12px;border-radius:8px;margin:0}
`;

export const ADMIN_JS = `"use strict";
(function () {
  var main = document.querySelector("main[data-api]");
  if (!main) return;
  var api = main.getAttribute("data-api");
  var status = document.getElementById("live-status");
  var stopped = false;

  function get(o, path) {
    var parts = path.split(".");
    for (var i = 0; i < parts.length; i++) {
      if (o === null || o === undefined) return undefined;
      o = o[parts[i]];
    }
    return o;
  }
  function sum(o) { var s = 0; for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) s += o[k]; return s; }
  function num(n) { return (n || 0).toLocaleString("en-US"); }
  function ago(sec, nowMs) {
    if (!sec) return "never";
    var s = Math.max(0, Math.floor(nowMs / 1000 - sec));
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago";
    return Math.floor(s / 86400) + " d ago";
  }
  function dur(s) {
    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d > 0) return d + "d " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    return m + "m";
  }
  function pct(part, total) {
    if (!total) return "\\u2013";
    var p = (part / total) * 100;
    return (p < 10 ? p.toFixed(1) : Math.round(p)) + "%";
  }
  var computed = {
    "@msgHour": function (d) { return num(sum(get(d, "messages.lastHour") || {})); },
    "@authHour": function (d) { return num(sum(get(d, "authFailures.lastHour") || {})); },
    "@rlHour": function (d) { return num(sum(get(d, "rateLimited.lastHour") || {})); }
  };
  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function setSpark(svg, values) {
    var line = svg.querySelector("polyline");
    if (!line || !values || !values.length) return;
    var w = 120, h = 28, max = Math.max.apply(null, [1].concat(values)), n = Math.max(1, values.length - 1);
    var pts = values.map(function (v, i) {
      return ((i / n) * w).toFixed(1) + "," + (h - 1 - (v / max) * (h - 3)).toFixed(1);
    });
    line.setAttribute("points", pts.join(" "));
  }
  function setKv(node, obj) {
    var entries = Object.keys(obj || {}).map(function (k) { return [k, obj[k]]; })
      .sort(function (a, b) { return b[1] - a[1]; });
    var path = node.getAttribute("data-kv");
    var repl;
    if (!entries.length) {
      repl = el("p", { "class": "muted small", "data-kv": path }, "none");
    } else {
      repl = el("dl", { "class": "kv", "data-kv": path });
      entries.forEach(function (e) { repl.appendChild(el("dt", null, e[0])); repl.appendChild(el("dd", null, num(e[1]))); });
    }
    node.replaceWith(repl);
  }
  function td(text, cls) { return el("td", cls ? { "class": cls } : null, text); }
  var blocked = {};
  function renderTop(tbody, rows, now) {
    var frag = document.createDocumentFragment();
    if (!rows.length) { var tr0 = el("tr"); var c = td("No instances yet.", "muted"); c.setAttribute("colspan", "6"); tr0.appendChild(c); frag.appendChild(tr0); }
    rows.forEach(function (t) {
      var tr = el("tr");
      var cell = td(undefined, "break");
      var a = el("a", { href: "/admin/instance?origin=" + encodeURIComponent(t.instance) }, t.instance);
      cell.appendChild(a);
      if (blocked[t.instance]) cell.appendChild(el("span", { "class": "pill blocked" }, "blocked"));
      tr.appendChild(cell);
      tr.appendChild(td(num(t.messages1h), "num"));
      tr.appendChild(td(num(t.messages24h), "num"));
      tr.appendChild(td(num(t.devices), "num"));
      tr.appendChild(td(pct(t.errors24h, t.messages24h), "num"));
      tr.appendChild(td(t.lastSeen ? ago(t.lastSeen, now) : "\\u2013", "nowrap"));
      frag.appendChild(tr);
    });
    tbody.replaceChildren(frag);
  }
  function renderEvents(tbody, events, now) {
    var frag = document.createDocumentFragment();
    if (!events.length) { var tr0 = el("tr"); var c = td("No events since the relay started.", "muted"); c.setAttribute("colspan", "5"); tr0.appendChild(c); frag.appendChild(tr0); }
    events.forEach(function (e) {
      var tr = el("tr");
      tr.appendChild(td(ago(e.at / 1000, now), "nowrap"));
      var k = td(); k.appendChild(el("span", { "class": "tag" }, e.kind)); tr.appendChild(k);
      tr.appendChild(td(e.detail));
      tr.appendChild(td(e.device || "", "mono"));
      tr.appendChild(td(e.ip || "", "mono"));
      frag.appendChild(tr);
    });
    tbody.replaceChildren(frag);
  }
  function update(d) {
    var now = d.generatedAt || Date.now();
    document.querySelectorAll("[data-k]").forEach(function (n) {
      var key = n.getAttribute("data-k");
      if (computed[key]) { n.textContent = computed[key](d); return; }
      var v = get(d, key), f = n.getAttribute("data-fmt");
      if (v === undefined) return;
      if (f === "num") n.textContent = num(v);
      else if (f === "dur") n.textContent = dur(v);
      else if (f === "agoms") n.textContent = v ? ago(v / 1000, now) : "never";
      else if (f === "clock") n.textContent = new Date(v).toISOString().slice(11, 19) + " UTC";
      else n.textContent = v === null ? "" : String(v);
    });
    document.querySelectorAll("svg[data-s]").forEach(function (s) { setSpark(s, get(d, s.getAttribute("data-s"))); });
    document.querySelectorAll("[data-kv]").forEach(function (n) {
      var v = get(d, n.getAttribute("data-kv"));
      if (v && typeof v === "object") setKv(n, v);
    });
    var top = document.querySelector("tbody[data-table=top]");
    if (d.blocked) { blocked = {}; d.blocked.forEach(function (b) { blocked[b.origin] = true; }); }
    if (top && d.top) renderTop(top, d.top, now);
    var ev = document.querySelector("tbody[data-table=events]");
    if (ev && d.events) renderEvents(ev, d.events, now);
    var banner = document.getElementById("paused-banner");
    if (banner && "paused" in d) banner.hidden = !d.paused;
  }
  function show(msg) { if (status) { status.textContent = msg; status.hidden = !msg; } }
  function poll() {
    if (stopped || document.hidden) return;
    fetch(api, { credentials: "same-origin", headers: { accept: "application/json" }, cache: "no-store" })
      .then(function (r) {
        if (r.status === 401 || r.status === 403 || r.status === 404) {
          stopped = true;
          show("Session expired. Reload the page to sign in again.");
          return null;
        }
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (d) { if (d) { update(d); show(""); } })
      .catch(function () { show("Connection lost, retrying\\u2026"); });
  }
  setInterval(poll, 5000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) poll(); });
})();
`;

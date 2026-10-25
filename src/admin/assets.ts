/**
 * Static assets of the admin dashboard. Stylesheet and script are embedded,
 * so the build needs no copy step; the logo and the fonts (Flowplan's own
 * type, SIL Open Font License 1.1, see assets/fonts/LICENSE-*.txt) are read
 * once from assets/ next to src/ or dist/. Nothing is loaded from third
 * parties (CSP: 'self' only). Every URL carries a content hash (?v=…), so a
 * matching request is cached for a year as immutable.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const ASSET_PREFIX = "/admin/assets/";
const IMMUTABLE = "public, max-age=31536000, immutable";

/** assets/ of the repository: ../../assets from src/admin, ../../../assets from dist/src/admin. */
function assetDir(): string | null {
  for (const rel of ["../../assets/", "../../../assets/"]) {
    const dir = fileURLToPath(new URL(rel, import.meta.url));
    if (existsSync(`${dir}fonts`)) return dir;
  }
  return null;
}

interface Asset {
  body: string | Buffer;
  type: string;
  hash: string;
}

const hashOf = (b: string | Buffer) => createHash("sha256").update(b).digest("hex").slice(0, 12);

const FILES: Record<string, [file: string, type: string]> = {
  "icon.svg": ["icon.svg", "image/svg+xml"],
  "fonts/instrument-sans-latin.woff2": [
    "fonts/instrument-sans-latin-standard-normal.woff2",
    "font/woff2",
  ],
  "fonts/instrument-sans-latin-ext.woff2": [
    "fonts/instrument-sans-latin-ext-standard-normal.woff2",
    "font/woff2",
  ],
  "fonts/instrument-serif-latin.woff2": [
    "fonts/instrument-serif-latin-400-normal.woff2",
    "font/woff2",
  ],
  "fonts/instrument-serif-latin-ext.woff2": [
    "fonts/instrument-serif-latin-ext-400-normal.woff2",
    "font/woff2",
  ],
  "fonts/jetbrains-mono-latin.woff2": [
    "fonts/jetbrains-mono-latin-wght-normal.woff2",
    "font/woff2",
  ],
  "fonts/jetbrains-mono-latin-ext.woff2": [
    "fonts/jetbrains-mono-latin-ext-wght-normal.woff2",
    "font/woff2",
  ],
};

const assets = new Map<string, Asset>();
const dir = assetDir();
for (const [name, [file, type]] of Object.entries(FILES)) {
  if (!dir || !existsSync(dir + file)) continue;
  const body = readFileSync(dir + file);
  assets.set(name, { body, type, hash: hashOf(body) });
}

/** URL of an asset with its content hash; null when the file is not installed. */
export function assetUrl(name: string): string | null {
  const a = assets.get(name);
  return a ? `${ASSET_PREFIX}${name}?v=${a.hash}` : null;
}

const LATIN =
  "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD";
const LATIN_EXT =
  "U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF";

/** The app's public/fonts.css, upright styles only (the dashboard uses no italics). */
function fontFaces(): string {
  const faces: Array<[family: string, weight: string, base: string]> = [
    ["Instrument Sans", "400 700", "instrument-sans"],
    ["Instrument Serif", "400", "instrument-serif"],
    ["JetBrains Mono", "100 800", "jetbrains-mono"],
  ];
  let css = "";
  for (const [family, weight, base] of faces) {
    for (const [suffix, range] of [
      ["latin", LATIN],
      ["latin-ext", LATIN_EXT],
    ] as const) {
      const url = assetUrl(`fonts/${base}-${suffix}.woff2`);
      if (url) {
        css += `@font-face{font-family:"${family}";font-style:normal;font-display:swap;font-weight:${weight};src:url("${url}") format("woff2");unicode-range:${range}}\n`;
      }
    }
  }
  return css;
}

/** The font the first paint needs; preloaded by every page. */
export const PRELOAD_FONT = assetUrl("fonts/instrument-sans-latin.woff2");

const STYLES = `
/* Flowplan's design tokens (app/globals.css of the app): paper and ink,
   warm neutrals, one ultramarine accent. Dark values as in the app's dark theme. */
:root{
--bg:#fcfbf8;--surface:#f6f4ef;--sidebar:#f3f1eb;--hover:#ebe8e0;--border:#e4e0d6;
--text:#1d1c22;--muted:#6f6b78;--secondary:#5e5a66;
--blue:#3b3fd8;--blue-light:#ecebfc;--accent-strong:#2c2fb5;--on-accent:#fff;--signal:#f0663a;
--shadow:0 12px 40px #1d1a1414;--tile-shadow:0 1px 2px #1724390a;--radius:10px;
--field-focus:#8ab4f4;--field-ring:#3b3fd81a;
--chart-1:#3b3fd8;--chart-2:#eb6834;--chart-3:#1baf7a;--chart-4:#eda100;--chart-5:#e87ba4;
--chart-other:#a29fab;--chart-grid:#ebe8e0;--chart-text:#6f6b78;--chart-wash:.12;
--ok:#3f6d52;--ok-bg:#e8f3ec;--warn:#6f5b22;--warn-bg:#fbf1dc;--err:#a43c3f;--err-bg:#fbecec;
--info:#3f6aa8;--info-bg:#e9f0fc;--neutral:#636873;--neutral-bg:#eff0f3;
--danger:#b02f38;--danger-solid:#b8432b;--live:#1f9d55;
--font-ui:"Instrument Sans",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
--font-display:"Instrument Serif","Iowan Old Style",Georgia,serif;
--font-mono:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,monospace;
color-scheme:light;font-family:var(--font-ui);font-feature-settings:"ss01","cv05";
-webkit-text-size-adjust:100%;text-size-adjust:100%}
@media (prefers-color-scheme:dark){:root{
--bg:#16151b;--surface:#1d1c23;--sidebar:#121117;--hover:#29272f;--border:#2e2c35;
--text:#ecebf1;--muted:#8e8a98;--secondary:#b3afbd;
--blue:#959bff;--blue-light:#2a2a55;--accent-strong:#b9bcff;--on-accent:#121117;--signal:#ff8a5c;
--shadow:0 12px 50px #0007;--tile-shadow:none;--field-focus:#6f75e8;--field-ring:#959bff33;
--chart-1:#7a80f5;--chart-2:#d95926;--chart-3:#199e70;--chart-4:#c98500;--chart-5:#d55181;
--chart-other:#6d6a77;--chart-grid:#2e2c35;--chart-text:#aeaab8;--chart-wash:.2;
--ok:#a8d8b9;--ok-bg:rgba(90,170,120,.18);--warn:#f2c27a;--warn-bg:#3a2c14;--err:#f3b0b0;--err-bg:rgba(235,110,110,.18);
--info:#b4c6f5;--info-bg:rgba(110,140,240,.2);--neutral:#c3c7d1;--neutral-bg:rgba(170,175,190,.18);
--danger:#f3b0b0;color-scheme:dark}}

/* ---------- Base ---------- */
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;color:var(--text);background:var(--bg);font-size:14px;line-height:1.5}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline;text-underline-offset:3px}
p{margin:0 0 16px}
h1,h2,h3{line-height:1.3;letter-spacing:-.025em;margin:0 0 16px}
h1{font-size:26px;line-height:1.2}h2{font-size:15px}h3{font-size:13.5px;font-weight:600;margin:0 0 4px}
ul{margin:0 0 16px;padding-left:20px}li{margin:3px 0}
code,.mono,.tag{font-family:var(--font-mono);font-size:12px}
code,.tag{padding:1px 6px;border:1px solid var(--border);border-radius:5px;background:var(--surface);overflow-wrap:anywhere}
.tag{white-space:nowrap;overflow-wrap:normal}
small,.small{font-size:12.5px}
.muted{color:var(--muted)}.secondary{color:var(--secondary)}
.fine{font-size:12px;color:var(--muted)}
.nowrap{white-space:nowrap}.break{overflow-wrap:anywhere}
.num{text-align:right;font-variant-numeric:tabular-nums}
.icon{display:inline-block;flex-shrink:0;vertical-align:-.2em}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.skip{position:absolute;left:12px;top:-60px;z-index:20;padding:8px 12px;border-radius:8px;background:var(--blue);color:var(--on-accent)}
.skip:focus{top:12px}
:focus-visible{outline:2px solid var(--blue);outline-offset:3px}

/* ---------- Buttons, fields ---------- */
.button{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:38px;padding:8px 14px;
border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font:inherit;font-weight:500;
line-height:1.4;white-space:nowrap;cursor:pointer;text-decoration:none;-webkit-tap-highlight-color:transparent}
.button:hover{background:var(--hover);text-decoration:none}
.button .icon{width:17px;height:17px}
.button.primary{background:var(--blue);border-color:var(--blue);color:var(--on-accent)}
.button.primary:hover{background:var(--accent-strong);border-color:var(--accent-strong)}
.button.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 40%,var(--border))}
.button.danger:hover{background:color-mix(in srgb,var(--danger) 8%,var(--bg))}
.button.danger-solid{background:var(--danger-solid);border-color:var(--danger-solid);color:#fff}
.button.danger-solid:hover{filter:brightness(.94)}
.button.compact{min-height:32px;padding:5px 10px;font-size:13px}
.button.wide{width:100%}
.icon-button{display:inline-grid;place-items:center;width:34px;height:34px;padding:0;border:0;border-radius:6px;
background:none;color:var(--secondary);cursor:pointer}
.icon-button:hover{background:var(--hover);color:var(--text)}
input,select{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--border);border-radius:6px;
min-height:38px;padding:7px 11px;min-width:0;outline:none}
select{padding-right:8px}
input::placeholder{color:var(--muted)}
input:focus,select:focus{border-color:var(--field-focus);box-shadow:0 0 0 3px var(--field-ring)}

/* ---------- Shell: sidebar and top bar as in the app ---------- */
.app{display:grid;grid-template-columns:246px minmax(0,1fr);min-height:100dvh;background:linear-gradient(to right,var(--sidebar) 245px,var(--border) 245px 246px,transparent 246px)}
.sidebar{position:sticky;top:0;display:flex;flex-direction:column;height:100dvh;background:var(--sidebar);border-right:1px solid var(--border)}
.sidebar-top{display:flex;align-items:center;height:57px;padding:0 19px}
.brand{display:flex;align-items:center;gap:10px;color:var(--text);font-size:21px;font-weight:620;letter-spacing:-.035em;min-width:0}
.brand:hover{text-decoration:none}
.brand small{align-self:flex-end;margin-bottom:3px;color:var(--muted);font-size:12px;font-weight:500;letter-spacing:0;white-space:nowrap}
.brand-mark{display:block;flex-shrink:0;border-radius:28%;box-shadow:0 1px 2px #1d1a4a26,0 4px 12px -4px #4146e659}
.main-nav{display:grid;gap:2px;padding:10px 10px 8px}
.main-nav a{display:flex;align-items:center;gap:10px;padding:7px 10px;border-radius:6px;color:var(--secondary);font-size:13.5px}
.main-nav a:hover{background:var(--hover);color:var(--text);text-decoration:none}
.main-nav a[aria-current="page"]{background:var(--blue-light);color:var(--blue);font-weight:600}
.sidebar-label{margin:14px 20px 4px;color:var(--muted);font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase}
.sidebar-user{display:flex;align-items:center;gap:9px;margin:auto 0 0;padding:12px 12px 12px 16px;border-top:1px solid var(--border)}
.avatar{display:inline-grid;place-items:center;flex-shrink:0;width:30px;height:30px;border-radius:50%;background:var(--blue-light);color:var(--blue);font-size:13px;font-weight:600;text-transform:uppercase}
.who{display:grid;min-width:0;flex:1;line-height:1.3}
.who strong{overflow:hidden;font-size:13px;font-weight:600;text-overflow:ellipsis;white-space:nowrap}
.who small{color:var(--muted);font-size:11.5px}
.content{min-width:0;display:flex;flex-direction:column}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:15px;height:57px;padding:0 27px;border-bottom:1px solid var(--border)}
.breadcrumb{display:flex;align-items:center;gap:10px;min-width:0;font-size:12px;white-space:nowrap;overflow:hidden}
.breadcrumb a,.breadcrumb span{color:var(--muted)}
.breadcrumb [aria-current]{color:var(--text);overflow:hidden;text-overflow:ellipsis}
.breadcrumb .sep{color:var(--border)}
.topbar-note{display:flex;align-items:center;gap:7px;color:var(--secondary);font-size:12px;white-space:nowrap}
.topbar-note::before{content:"";width:5px;height:5px;border-radius:50%;background:var(--live)}
main.page{width:100%;max-width:1276px;margin:0 auto;padding:44px 48px 64px}

/* ---------- Page head (settings shell of the app) ---------- */
.page-head{display:flex;align-items:center;gap:16px;margin-bottom:22px}
.page-head h1{margin:0 0 2px}
.page-head p{margin:0;color:var(--secondary)}
.page-head>div:not(.head-actions){flex:1 1 0;min-width:0}
.head-icon{display:grid;place-items:center;flex-shrink:0;width:48px;height:48px;border-radius:14px;background:var(--blue-light);color:var(--blue)}
.head-icon.danger{background:var(--err-bg);color:var(--err)}
.head-actions{margin-left:auto;display:flex;align-items:center;gap:8px}
.crumbs{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:0 0 14px;color:var(--muted);font-size:13px}
.crumbs a{color:var(--secondary)}.crumbs .icon{color:var(--muted)}
.group-title{margin:28px 2px 10px;color:var(--muted);font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase}

/* ---------- Live badge, callouts, badges ---------- */
.live-badge{display:inline-flex;align-items:center;gap:6px;color:var(--secondary);font-size:12.5px;white-space:nowrap}
.live-badge::before{content:"";width:8px;height:8px;border-radius:50%;background:#9a96a3}
.live-badge.live::before{background:var(--live);box-shadow:0 0 0 3px color-mix(in srgb,var(--live) 25%,transparent);animation:live-breathe 2s ease-in-out infinite}
.live-badge.error::before{background:#c43a3a}
@keyframes live-breathe{50%{box-shadow:0 0 0 6px transparent}}
.callout{display:flex;align-items:flex-start;gap:10px;margin:0 0 16px;padding:13px 16px;border-radius:10px;background:var(--blue-light);color:var(--text);font-size:13.5px}
.callout>.icon{margin-top:1px;color:var(--blue)}
.callout p{margin:0}
.callout.ok{background:var(--ok-bg)}.callout.ok>.icon{color:var(--ok)}
.callout.error{background:var(--err-bg);border:1px solid color-mix(in srgb,var(--err) 30%,transparent)}.callout.error>.icon{color:var(--err)}
.badge{display:inline-flex;align-items:center;gap:6px;min-height:22px;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:550;
white-space:nowrap;background:var(--neutral-bg);color:var(--neutral);vertical-align:middle}
.badge::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.badge.ok{background:var(--ok-bg);color:var(--ok)}.badge.warn{background:var(--warn-bg);color:var(--warn)}
.badge.error{background:var(--err-bg);color:var(--err)}.badge.info{background:var(--info-bg);color:var(--info)}
td .badge{margin-left:8px}

/* ---------- Cards (the app's setting groups and tiles) ---------- */
.card{min-width:0;margin:0 0 16px;border:1px solid var(--border);border-radius:14px;background:var(--bg);box-shadow:var(--tile-shadow)}
.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:18px 22px 14px}
.card-head h2{margin:0;font-size:15px}
.card-head p{max-width:68ch;margin:4px 0 0;color:var(--secondary);font-size:13px}
.card-body{padding:0 22px 20px}
.card-body>:last-child{margin-bottom:0}
.table-scroll+.card-body{padding-top:16px;border-top:1px solid var(--border)}
.card.danger-zone{border-color:color-mix(in srgb,#c43a3a 35%,var(--border))}
.card.danger-zone .card-head h2{color:var(--err)}
.fix-link{display:inline-flex;align-items:center;gap:4px;font-size:13px;font-weight:500;white-space:nowrap}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;align-items:start;margin-bottom:16px}
.grid2>.card{margin:0}

/* Live strip: state and four numbers left, the requests chart right. */
.live-strip{display:grid;grid-template-columns:minmax(0,360px) minmax(0,1fr);margin-bottom:16px;border:1px solid var(--border);border-radius:14px;background:var(--bg);box-shadow:var(--tile-shadow)}
.live-strip-state{display:grid;align-content:start;gap:18px;padding:18px 20px;border-right:1px solid var(--border)}
.state-head{display:flex;align-items:flex-start;gap:12px}
.state-head strong{display:block;font-size:15.5px;font-weight:620}
.state-head small{color:var(--muted)}
.tone-icon{display:grid;place-items:center;flex:none;width:36px;height:36px;border-radius:10px;background:var(--neutral-bg);color:var(--neutral)}
.ok>.tone-icon,.tone-icon.ok{background:var(--ok-bg);color:var(--ok)}
.warn>.tone-icon,.tone-icon.warn{background:var(--warn-bg);color:var(--warn)}
.error>.tone-icon,.tone-icon.error{background:var(--err-bg);color:var(--err)}
.info>.tone-icon,.tone-icon.info{background:var(--info-bg);color:var(--blue)}
.live-strip-chart{min-width:0;padding:16px 20px 14px}
.live-strip-chart header{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:6px 12px;margin-bottom:10px}
.live-strip-chart h2{margin:0;font-size:14.5px}
.chart{position:relative}
.chart-axis{display:flex;justify-content:space-between;margin-top:6px;color:var(--chart-text);font-size:11px;font-variant-numeric:tabular-nums}
.chart-max{position:absolute;top:-2px;left:0;color:var(--chart-text);font-size:11px;font-variant-numeric:tabular-nums}
.kpi-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 16px}
.kpi{display:grid;align-content:start;gap:1px;min-width:0}
.kpi strong,.kpi .value{font-size:24px;font-weight:620;letter-spacing:-.02em;line-height:1.15;font-variant-numeric:tabular-nums}
.kpi>span:not(.badge){color:var(--secondary);font-size:12.5px}
.kpi small{color:var(--muted);font-size:12px;line-height:1.35}
.kpi-grid.cards{grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:16px}
.kpi-grid.cards .kpi{padding:14px 16px 12px;border:1px solid var(--border);border-radius:12px;background:var(--bg);box-shadow:var(--tile-shadow)}
.kpi-grid.statuses{grid-template-columns:repeat(6,minmax(0,1fr));gap:18px}
.kpi .badge{justify-self:start;margin-bottom:6px}
.kpi .spark{margin:8px 0 4px}
.kpi .kv{margin-top:8px}

/* Health tiles (monitoring page of the app). */
.health-tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:16px}
.health-tile{display:flex;align-items:flex-start;gap:10px;min-width:0;min-height:62px;padding:11px 12px;border:1px solid var(--border);border-radius:12px;background:var(--bg);box-shadow:var(--tile-shadow)}
.health-tile.error{border-color:color-mix(in srgb,#c43a3a 45%,var(--border))}
.health-tile .tone-icon{width:30px;height:30px;border-radius:9px}
.tile-text{display:grid;gap:1px;min-width:0}
.tile-text strong{font-size:13.5px;font-weight:600}
.tile-text small{color:var(--secondary);font-size:12px;line-height:1.35;overflow-wrap:anywhere}

/* Sparklines: the app's trend style (line plus a light wash). */
svg.spark{display:block;width:100%;height:32px;overflow:visible}
svg.spark.tall{height:150px}
svg.spark .line{fill:none;stroke:var(--chart-1);stroke-width:1.75;stroke-linejoin:round;stroke-linecap:round;vector-effect:non-scaling-stroke}
svg.spark .area{fill:var(--chart-1);fill-opacity:var(--chart-wash);stroke:none}
svg.spark .grid{stroke:var(--chart-grid);stroke-width:1;vector-effect:non-scaling-stroke}
svg.spark.s-bad .line,svg.spark.st-error .line{stroke:var(--chart-2)}svg.spark.s-bad .area,svg.spark.st-error .area{fill:var(--chart-2)}
svg.spark.s-warn .line,svg.spark.st-rate_limited .line{stroke:var(--chart-4)}svg.spark.s-warn .area,svg.spark.st-rate_limited .area{fill:var(--chart-4)}
svg.spark.st-ok .line{stroke:var(--chart-3)}svg.spark.st-ok .area{fill:var(--chart-3)}
svg.spark:is(.st-gone,.st-forbidden,.st-invalid) .line{stroke:var(--chart-other)}svg.spark:is(.st-gone,.st-forbidden,.st-invalid) .area{fill:var(--chart-other)}

/* Key/value lists */
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;margin:0;font-size:13px}
.kv dt{color:var(--secondary)}.kv dd{margin:0;font-variant-numeric:tabular-nums}
.kv.wide{grid-template-columns:minmax(110px,max-content) minmax(0,1fr);gap:8px 18px;font-size:13.5px}

/* ---------- Tables (the app's admin lists) ---------- */
.table-scroll{position:relative;overflow-x:auto;border-top:1px solid var(--border);-webkit-overflow-scrolling:touch}
.card>.table-scroll:last-child{border-radius:0 0 14px 14px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{padding:9px 12px;border-bottom:1px solid var(--border);background:var(--surface);color:var(--secondary);font-size:12px;font-weight:550;text-align:left;white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:color-mix(in srgb,var(--surface) 60%,transparent)}
:is(th,td):first-child{padding-left:22px}:is(th,td):last-child{padding-right:22px}
th.num{text-align:right}
td.mono{color:var(--secondary)}
td.empty{padding:22px;color:var(--muted);text-align:center}

/* Empty states (settings-empty of the app) */
.empty{display:flex;align-items:center;gap:12px;margin:0;padding:14px 16px;border:1px dashed var(--border);border-radius:12px;color:var(--secondary)}
.empty .tone-icon{background:var(--surface);color:var(--muted)}
.empty strong{color:var(--text);font-weight:550}
.empty p{margin:2px 0 0;font-size:13px}

/* ---------- Forms of the controls ---------- */
.control{padding:16px 0;border-top:1px solid var(--border)}
.control:first-child{padding-top:0;border-top:0}
.control p{margin:0 0 10px;color:var(--secondary);font-size:13px}
.inline-form{display:flex;flex-wrap:wrap;gap:8px;margin:0}
.inline-form input[name=origin],.inline-form input[name=cidr]{flex:1 1 220px}
.inline-form input[name=reason]{flex:2 1 220px}
.inline-form select{flex:0 0 auto}
.row-form{display:flex;justify-content:flex-end;gap:6px}
.row-form input{width:130px;min-height:32px;padding:4px 9px;font-size:13px}
.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px}
.actions+.fine{margin-top:12px}

/* ---------- Sign-in and message pages (the app's login) ---------- */
.login{display:flex;flex-direction:column;align-items:center;min-height:100dvh;
padding:max(24px,env(safe-area-inset-top)) max(32px,env(safe-area-inset-right)) max(24px,env(safe-area-inset-bottom)) max(32px,env(safe-area-inset-left));
background:radial-gradient(60rem 30rem at 85% -10%,var(--blue-light),transparent 70%),var(--surface)}
.login-brand{align-self:flex-start;display:flex;align-items:center;gap:10px;color:var(--text);font-size:23px;font-weight:620;letter-spacing:-.035em}
.login-brand:hover{text-decoration:none}
.login-brand .muted{font-weight:500;letter-spacing:-.01em}
.login-card{width:440px;max-width:100%;margin:auto;padding:32px 36px 28px;border:1px solid var(--border);border-radius:17px;background:var(--bg);text-align:center;box-shadow:0 10px 60px #273e6207}
.login-card.wide{width:600px;text-align:left}
.login-mark{display:flex;justify-content:center;margin:0 0 16px}
.login-card.wide .login-mark{justify-content:flex-start}
.login-card h1{margin:0 0 10px;font-family:var(--font-display);font-size:34px;font-weight:400;letter-spacing:-.01em;line-height:1.05}
.login-card>p,.login-card li{color:var(--secondary);line-height:1.55}
.login-card>p{margin-bottom:20px}
.login-card .callout{text-align:left}
.login-card .fine{margin:16px 0 0}
.notice{color:var(--err)}

/* Connection notice of the live refresh */
.live-toast{position:fixed;right:max(16px,env(safe-area-inset-right));bottom:max(16px,env(safe-area-inset-bottom));z-index:10;margin:0;padding:10px 14px;
border:1px solid color-mix(in srgb,var(--err) 35%,var(--border));border-radius:10px;background:var(--bg);color:var(--err);box-shadow:var(--shadow);font-size:13px}

/* ---------- Narrower screens ---------- */
@media (max-width:1180px){
.kpi-grid.statuses{grid-template-columns:repeat(3,minmax(0,1fr))}
.health-tiles,.kpi-grid.cards{grid-template-columns:repeat(2,minmax(0,1fr))}
.live-strip{grid-template-columns:minmax(0,1fr)}
.live-strip-state{border-right:0;border-bottom:1px solid var(--border)}
}
@media (max-width:860px){
.app{display:block}
.sidebar{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;border-right:0;border-bottom:1px solid var(--border);
padding:max(0px,env(safe-area-inset-top)) env(safe-area-inset-right) 0 env(safe-area-inset-left)}
.sidebar-top{flex:1;height:56px;padding:0 16px}
.sidebar-label{display:none}
.sidebar-user{order:2;margin:0;padding:0 12px 0 0;border:0}
.sidebar-user .who{display:none}
.app{background:none}
.table-scroll>table{min-width:600px}.table-scroll>table.audit{min-width:860px}
.main-nav{order:3;display:flex;width:100%;gap:4px;padding:0 12px 10px;overflow-x:auto}
.main-nav a{flex:0 0 auto;min-height:40px}
.topbar{display:none}
main.page{padding:22px max(16px,env(safe-area-inset-right)) max(48px,env(safe-area-inset-bottom)) max(16px,env(safe-area-inset-left))}
.page-head{flex-wrap:wrap;gap:12px 14px}
.page-head h1{font-size:22px}
.head-icon{width:40px;height:40px;border-radius:12px}
.head-actions{margin-left:0;width:100%}
.grid2{grid-template-columns:minmax(0,1fr)}
.card-head{padding:16px 16px 12px}.card-body{padding:0 16px 16px}
:is(th,td):first-child{padding-left:16px}:is(th,td):last-child{padding-right:16px}
.button,input,select{min-height:44px}
.button.compact,.row-form input{min-height:40px}
.login-card{padding:30px 22px}
.login-card h1{font-size:30px}
}
@media (max-width:560px){
.health-tiles,.kpi-grid.cards{grid-template-columns:minmax(0,1fr)}
.kpi-grid.statuses{grid-template-columns:repeat(2,minmax(0,1fr))}
.brand small{display:none}
.login{padding-left:max(16px,env(safe-area-inset-left));padding-right:max(16px,env(safe-area-inset-right))}
.login-brand{align-self:center;margin-bottom:22px}
.login-card{margin:0 auto auto}
}
@media (prefers-reduced-motion:reduce){.live-badge.live::before{animation:none}}
@media print{.sidebar,.topbar,.live-toast,form{display:none!important}.app{display:block}}
`;

export const ADMIN_CSS = fontFaces() + STYLES;

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
    "@rlHour": function (d) { return num(sum(get(d, "rateLimited.lastHour") || {})); },
    "@errHour": function (d) { var h = get(d, "messages.lastHour") || {}; return pct(h.error || 0, sum(h)); }
  };
  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function setSpark(svg, values) {
    var line = svg.querySelector(".line");
    if (!line || !values || !values.length) return;
    var w = 120, h = 28, max = Math.max.apply(null, [1].concat(values)), n = Math.max(1, values.length - 1);
    var pts = values.map(function (v, i) {
      return ((i / n) * w).toFixed(1) + "," + (h - 1 - (v / max) * (h - 3)).toFixed(1);
    }).join(" ");
    line.setAttribute("points", pts);
    var area = svg.querySelector(".area");
    if (area) area.setAttribute("points", "0," + h + " " + pts + " " + w + "," + h);
    var label = svg.getAttribute("data-max") ? document.getElementById(svg.getAttribute("data-max")) : null;
    if (label) label.textContent = num(Math.max.apply(null, [0].concat(values)));
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
    if (!rows.length) { var tr0 = el("tr"); var c = td("No instances yet.", "empty"); c.setAttribute("colspan", "6"); tr0.appendChild(c); frag.appendChild(tr0); }
    rows.forEach(function (t) {
      var tr = el("tr");
      var cell = td(undefined, "break");
      var a = el("a", { href: "/admin/instance?origin=" + encodeURIComponent(t.instance) }, t.instance);
      cell.appendChild(a);
      if (blocked[t.instance]) cell.appendChild(el("span", { "class": "badge error" }, "blocked"));
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
    if (!events.length) { var tr0 = el("tr"); var c = td("No events since the relay started.", "empty"); c.setAttribute("colspan", "5"); tr0.appendChild(c); frag.appendChild(tr0); }
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
  var badge = document.getElementById("live-badge");
  function show(msg) {
    if (status) { status.textContent = msg; status.hidden = !msg; }
    if (badge) {
      badge.className = "live-badge " + (stopped ? "paused" : msg ? "error" : "live");
      var label = badge.querySelector("[data-live-text]");
      if (label) label.textContent = stopped ? "Paused" : msg ? "Connection lost" : "Live";
    }
  }
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

assets.set("admin.css", {
  body: ADMIN_CSS,
  type: "text/css; charset=utf-8",
  hash: hashOf(ADMIN_CSS),
});
assets.set("admin.js", {
  body: ADMIN_JS,
  type: "text/javascript; charset=utf-8",
  hash: hashOf(ADMIN_JS),
});

export interface AssetResponse {
  status: number;
  body: string | Buffer;
  headers: Record<string, string>;
}

/**
 * GET/HEAD of /admin/assets/<name>: immutable for a year when ?v= names the
 * current content, otherwise revalidated on every use. Unknown names: null.
 */
export function serveAsset(pathname: string, version: string | null): AssetResponse | null {
  if (!pathname.startsWith(ASSET_PREFIX)) return null;
  const a = assets.get(pathname.slice(ASSET_PREFIX.length));
  if (!a) return null;
  return {
    status: 200,
    body: a.body,
    headers: {
      "content-type": a.type,
      "cache-control": version === a.hash ? IMMUTABLE : "no-cache",
      etag: `"${a.hash}"`,
    },
  };
}

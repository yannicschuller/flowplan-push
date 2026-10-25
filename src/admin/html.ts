/**
 * Tiny auto-escaping HTML template helper. Every interpolated value is
 * escaped unless it is itself the result of `html` (or `raw`, used only for
 * markup produced in this module tree, never for request or database data).
 */

export class SafeHtml {
  readonly value: string;
  constructor(value: string) {
    this.value = value;
  }
  toString(): string {
    return this.value;
  }
}

const ESC: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "`": "&#96;",
};

export function esc(s: string): string {
  return s.replace(/[&<>"'`]/g, (c) => ESC[c] ?? c);
}

function render(v: unknown): string {
  if (v instanceof SafeHtml) return v.value;
  if (Array.isArray(v)) return v.map(render).join("");
  if (v === null || v === undefined || v === false) return "";
  return esc(String(v));
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHtml {
  let out = strings[0] ?? "";
  for (let i = 0; i < values.length; i++) out += render(values[i]) + (strings[i + 1] ?? "");
  return new SafeHtml(out);
}

export function raw(s: string): SafeHtml {
  return new SafeHtml(s);
}

// ---- formatting (mirrored in the client script) ----------------------------

export function fmtNum(n: number | null | undefined): string {
  return (n ?? 0).toLocaleString("en-US");
}

export function fmtTime(unixSeconds: number | null | undefined): string {
  if (!unixSeconds) return "–";
  return `${new Date(unixSeconds * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function fmtAgo(unixSeconds: number | null | undefined, nowMs: number): string {
  if (!unixSeconds) return "never";
  const s = Math.max(0, Math.floor(nowMs / 1000 - unixSeconds));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function fmtDuration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function fmtPct(part: number, total: number): string {
  if (!total) return "–";
  const p = (part / total) * 100;
  return `${p < 10 ? p.toFixed(1) : Math.round(p)}%`;
}

/** Inline SVG sparkline (no inline styles; colours come from CSS classes). */
export function sparkline(values: number[], cls = "", label = "", path = ""): SafeHtml {
  const w = 120;
  const h = 28;
  const max = Math.max(1, ...values);
  const n = Math.max(1, values.length - 1);
  const pts = values
    .map((v, i) => `${((i / n) * w).toFixed(1)},${(h - 1 - (v / max) * (h - 3)).toFixed(1)}`)
    .join(" ");
  return html`<svg class="spark ${cls}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="${label}"${path ? html` data-s="${path}"` : ""}><polyline points="${pts}"/></svg>`;
}

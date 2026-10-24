/** Tiny Prometheus text-format registry (counters and gauges, low-cardinality labels only). */

type Labels = Record<string, string>;

function labelKey(labels: Labels): string {
  const keys = Object.keys(labels).sort();
  if (keys.length === 0) return "";
  return `{${keys.map((k) => `${k}="${String(labels[k]).replace(/["\\\n]/g, "_")}"`).join(",")}}`;
}

interface Family {
  type: "counter" | "gauge";
  help: string;
  values: Map<string, number>;
  collect?: () => number;
}

export class Metrics {
  private readonly families = new Map<string, Family>();

  counter(name: string, help: string): (labels?: Labels, by?: number) => void {
    const fam: Family = { type: "counter", help, values: new Map() };
    this.families.set(name, fam);
    return (labels = {}, by = 1) => {
      const k = labelKey(labels);
      fam.values.set(k, (fam.values.get(k) ?? 0) + by);
    };
  }

  gauge(name: string, help: string, collect: () => number): void {
    this.families.set(name, { type: "gauge", help, values: new Map(), collect });
  }

  render(): string {
    const lines: string[] = [];
    for (const [name, fam] of this.families) {
      lines.push(`# HELP ${name} ${fam.help}`, `# TYPE ${name} ${fam.type}`);
      if (fam.collect) {
        let v = Number.NaN;
        try {
          v = fam.collect();
        } catch {
          // keep NaN
        }
        lines.push(`${name} ${v}`);
      }
      for (const [k, v] of fam.values) lines.push(`${name}${k} ${v}`);
    }
    return `${lines.join("\n")}\n`;
  }
}

export interface RelayMetrics {
  registry: Metrics;
  httpRequests: (labels: { route: string; status: string }) => void;
  messages: (labels: { platform: string; status: string }) => void;
  registrations: (labels: { platform: string }) => void;
  wellKnownFetches: (labels: { outcome: string }) => void;
  authFailures: (labels: { reason: string }) => void;
  rateLimited: (labels: { scope: string }) => void;
}

export function createRelayMetrics(): RelayMetrics {
  const registry = new Metrics();
  const startedAt = Date.now();
  registry.gauge("flowplan_push_uptime_seconds", "Seconds since the relay started", () =>
    Math.floor((Date.now() - startedAt) / 1000),
  );
  return {
    registry,
    httpRequests: registry.counter(
      "flowplan_push_http_requests_total",
      "HTTP requests by route and status",
    ),
    messages: registry.counter(
      "flowplan_push_messages_total",
      "Messages by platform and result status",
    ),
    registrations: registry.counter(
      "flowplan_push_registrations_total",
      "Device registrations by platform",
    ),
    wellKnownFetches: registry.counter(
      "flowplan_push_wellknown_fetches_total",
      "Fetches of instance /.well-known/flowplan-push by outcome",
    ),
    authFailures: registry.counter(
      "flowplan_push_auth_failures_total",
      "Rejected send requests by reason",
    ),
    rateLimited: registry.counter(
      "flowplan_push_rate_limited_total",
      "Rate-limited requests or messages by scope",
    ),
  };
}

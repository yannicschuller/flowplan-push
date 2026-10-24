/**
 * Minimal structured JSON logger with redaction.
 *
 * Rules: never pass device tokens, relay tokens, payloads, signatures or keys
 * to the logger. As a second line of defence every field whose name looks
 * sensitive is replaced by "[redacted]" and long strings are truncated.
 */

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const LEVELS: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };

const SENSITIVE_KEY =
  /token|payload|signature|^sig$|authorization|secret|password|private|key|cookie|content-?state|body/i;
/** Field names that match SENSITIVE_KEY but are known to be harmless. */
const SAFE_KEYS = new Set(["kid", "keyId", "keyCount", "bodyBytes", "tokenCount"]);

const MAX_STRING = 300;

function sanitize(value: unknown, depth: number): unknown {
  if (depth > 4) return "[depth]";
  if (typeof value === "string") {
    return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  }
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (value === undefined) return undefined;
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Error) {
    return { name: value.name, message: sanitize(value.message, depth + 1) };
  }
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => sanitize(v, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = !SAFE_KEYS.has(k) && SENSITIVE_KEY.test(k) ? "[redacted]" : sanitize(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

export interface Logger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

export function createLogger(
  level: LogLevel = "info",
  write: (line: string) => void = (l) => process.stdout.write(`${l}\n`),
): Logger {
  const min = LEVELS[level];
  const emit = (
    lvl: Exclude<LogLevel, "silent">,
    msg: string,
    fields?: Record<string, unknown>,
  ) => {
    if (LEVELS[lvl] < min) return;
    const entry = {
      time: new Date().toISOString(),
      level: lvl,
      msg,
      ...(fields ? (sanitize(fields, 0) as Record<string, unknown>) : {}),
    };
    try {
      write(JSON.stringify(entry));
    } catch {
      // logging must never throw
    }
  };
  return {
    debug: (m, f) => emit("debug", m, f),
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
  };
}

export const silentLogger: Logger = createLogger("silent");

/** Truncates an IP address for logs (IPv4 → /24, IPv6 → /48) to avoid storing personal data. */
export function truncateIp(ip: string): string {
  if (ip.includes(".") && !ip.includes(":")) {
    const parts = ip.split(".");
    return `${parts.slice(0, 3).join(".")}.0`;
  }
  const v4 = /::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (v4?.[1]) return truncateIp(v4[1]);
  return `${ip.split(":").slice(0, 3).join(":")}::`;
}

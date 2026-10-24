import { createPrivateKey, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { parseStorageKey } from "./crypto/storage.ts";
import type { LogLevel } from "./log.ts";

/** All configuration comes from environment variables; see README "Configuration". */

export class ConfigError extends Error {}

export interface ApnsConfig {
  keyId: string;
  teamId: string;
  privateKey: KeyObject;
}

export interface FcmConfig {
  projectId: string;
  clientEmail: string;
  privateKey: KeyObject;
}

export interface Config {
  publicUrl: string;
  host: string;
  port: number;
  dataDir: string;
  storageKey: Buffer;
  oldStorageKeys: Buffer[];
  apns: ApnsConfig | null;
  fcm: FcmConfig | null;
  allowedBundleIds: string[];
  allowPrivateInstances: boolean;
  trustProxyHops: number;
  metricsToken: string | null;
  logLevel: LogLevel;
}

type Env = Record<string, string | undefined>;

function bool(env: Env, name: string, def: boolean): boolean {
  const v = env[name]?.trim().toLowerCase();
  if (v === undefined || v === "") return def;
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  throw new ConfigError(`${name} must be true or false`);
}

/** Reads `NAME` or the file named by `NAME_FILE` (Docker/Coolify secrets). */
function valueOrFile(env: Env, name: string): string | undefined {
  const direct = env[name];
  const file = env[`${name}_FILE`];
  if (direct && file) throw new ConfigError(`Set either ${name} or ${name}_FILE, not both`);
  if (file) {
    try {
      return readFileSync(file, "utf8");
    } catch {
      throw new ConfigError(`${name}_FILE cannot be read`);
    }
  }
  return direct && direct.trim() !== "" ? direct : undefined;
}

/** Accepts a PEM, a PEM with literal "\n" sequences (single-line env vars), or base64 of a PEM. */
export function normalizePem(raw: string): string {
  let s = raw.trim();
  if (!s.includes("-----BEGIN")) {
    const decoded = Buffer.from(s, "base64").toString("utf8");
    if (decoded.includes("-----BEGIN")) s = decoded.trim();
  }
  return s.replace(/\\n/g, "\n");
}

function parseApns(env: Env): ApnsConfig | null {
  const keyRaw = valueOrFile(env, "APNS_KEY");
  const keyId = env.APNS_KEY_ID?.trim();
  if (!keyRaw && !keyId) return null;
  if (!keyRaw || !keyId)
    throw new ConfigError("APNs needs both APNS_KEY (or APNS_KEY_FILE) and APNS_KEY_ID");
  if (!/^[A-Z0-9]{10}$/.test(keyId))
    throw new ConfigError("APNS_KEY_ID must be the 10-character key id");
  const teamId = (env.APNS_TEAM_ID ?? "V7N2K54KJN").trim();
  if (!/^[A-Z0-9]{10}$/.test(teamId))
    throw new ConfigError("APNS_TEAM_ID must be the 10-character team id");
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({ key: normalizePem(keyRaw), format: "pem" });
  } catch {
    throw new ConfigError("APNS_KEY is not a valid PEM private key (.p8 file contents)");
  }
  if (
    privateKey.asymmetricKeyType !== "ec" ||
    privateKey.asymmetricKeyDetails?.namedCurve !== "prime256v1"
  ) {
    throw new ConfigError("APNS_KEY must be an EC P-256 key (.p8 from Apple)");
  }
  return { keyId, teamId, privateKey };
}

function parseFcm(env: Env): FcmConfig | null {
  const raw = valueOrFile(env, "FCM_SERVICE_ACCOUNT");
  if (!raw) {
    if (env.FCM_PROJECT_ID)
      throw new ConfigError("FCM_PROJECT_ID is set but FCM_SERVICE_ACCOUNT is missing");
    return null;
  }
  let json: Record<string, unknown>;
  try {
    const text = raw.trim().startsWith("{") ? raw : Buffer.from(raw, "base64").toString("utf8");
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new ConfigError(
      "FCM_SERVICE_ACCOUNT is not valid JSON (paste the service account key file)",
    );
  }
  if (json.type !== "service_account")
    throw new ConfigError("FCM_SERVICE_ACCOUNT must be a service account key");
  const clientEmail = json.client_email;
  const pem = json.private_key;
  if (typeof clientEmail !== "string" || typeof pem !== "string") {
    throw new ConfigError("FCM_SERVICE_ACCOUNT lacks client_email/private_key");
  }
  const projectId = (
    env.FCM_PROJECT_ID ?? (typeof json.project_id === "string" ? json.project_id : "")
  ).trim();
  if (!/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/.test(projectId))
    throw new ConfigError("FCM_PROJECT_ID is missing or invalid");
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({ key: normalizePem(pem), format: "pem" });
  } catch {
    throw new ConfigError("FCM_SERVICE_ACCOUNT private_key is not a valid PEM key");
  }
  if (privateKey.asymmetricKeyType !== "rsa")
    throw new ConfigError("FCM service account key must be RSA");
  return { projectId, clientEmail, privateKey };
}

export function loadConfig(env: Env = process.env): Config {
  const storageKey = parseStorageKey(env.RELAY_STORAGE_KEY);
  const oldStorageKeys = (env.RELAY_STORAGE_KEYS_OLD ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((k, i) => parseStorageKey(k, `RELAY_STORAGE_KEYS_OLD[${i}]`));
  if (oldStorageKeys.some((k) => k.equals(storageKey))) {
    throw new ConfigError("RELAY_STORAGE_KEYS_OLD must not contain the current RELAY_STORAGE_KEY");
  }

  const publicUrl = (env.RELAY_PUBLIC_URL ?? "https://push.flowplan.org").replace(/\/+$/, "");
  try {
    const u = new URL(publicUrl);
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error();
  } catch {
    throw new ConfigError("RELAY_PUBLIC_URL must be an http(s) URL");
  }

  const port = Number(env.PORT ?? "8080");
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new ConfigError("PORT must be 1–65535");

  const trustRaw = (env.TRUST_PROXY ?? "false").trim().toLowerCase();
  let trustProxyHops: number;
  if (["false", "0", "no", "off", ""].includes(trustRaw)) trustProxyHops = 0;
  else if (["true", "yes", "on"].includes(trustRaw)) trustProxyHops = 1;
  else if (/^[1-9]$/.test(trustRaw)) trustProxyHops = Number(trustRaw);
  else
    throw new ConfigError(
      "TRUST_PROXY must be false, true (= 1 hop) or the number of proxy hops (1–9)",
    );

  const metricsToken = env.METRICS_TOKEN?.trim() || null;
  if (metricsToken && metricsToken.length < 32) {
    throw new ConfigError("METRICS_TOKEN must be at least 32 characters (openssl rand -hex 32)");
  }

  const logLevel = (env.LOG_LEVEL ?? "info").trim().toLowerCase() as LogLevel;
  if (!["debug", "info", "warn", "error", "silent"].includes(logLevel)) {
    throw new ConfigError("LOG_LEVEL must be debug, info, warn, error or silent");
  }

  const allowedBundleIds = (env.ALLOWED_BUNDLE_IDS ?? "app.flowplan.mobile")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const b of allowedBundleIds) {
    if (!/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(b) || b.length > 155) {
      throw new ConfigError(`ALLOWED_BUNDLE_IDS contains an invalid bundle id: ${b}`);
    }
  }
  if (allowedBundleIds.length === 0) throw new ConfigError("ALLOWED_BUNDLE_IDS must not be empty");

  return {
    publicUrl,
    host: env.HOST?.trim() || "0.0.0.0",
    port,
    dataDir: path.resolve(env.DATA_DIR ?? "./data"),
    storageKey,
    oldStorageKeys,
    apns: parseApns(env),
    fcm: parseFcm(env),
    allowedBundleIds,
    allowPrivateInstances: bool(env, "ALLOW_PRIVATE_INSTANCES", false),
    trustProxyHops,
    metricsToken,
    logLevel,
  };
}

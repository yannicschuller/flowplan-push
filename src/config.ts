import { createHash, createPrivateKey, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { parseStorageKey } from "./crypto/storage.ts";
import type { LogLevel } from "./log.ts";
import { parseCidr } from "./net/ip.ts";
import { isLocalhostName } from "./net/origin.ts";

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

/** Optional OIDC-protected admin dashboard (README "Admin dashboard (OIDC)"). */
export interface AdminConfig {
  issuer: string;
  clientId: string;
  clientSecret: string | null;
  scopes: string[];
  /** `${RELAY_PUBLIC_URL}/admin/callback` */
  redirectUri: string;
  /** `${RELAY_PUBLIC_URL}/admin` (RP-initiated logout target). */
  postLogoutRedirectUri: string;
  /** Origin of RELAY_PUBLIC_URL; admin POSTs must carry exactly this Origin. */
  publicOrigin: string;
  emails: string[];
  subjects: string[];
  groups: string[];
  groupsClaim: string;
  /** CIDRs allowed to reach /admin at all; null = no IP restriction. */
  allowedIps: string[] | null;
  /** Redirect to the IdP's end_session_endpoint on logout (if it has one). */
  rpLogout: boolean;
  sessionIdleSeconds: number;
  sessionAbsoluteSeconds: number;
  /** Hash of everything that decides who is an admin; sessions from another config are invalid. */
  fingerprint: string;
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
  admin: AdminConfig | null;
  /** Build commit (image label), shown on the admin dashboard. */
  commit: string | null;
}

type Env = Record<string, string | undefined>;

function bool(env: Env, name: string, def: boolean): boolean {
  const v = env[name]?.trim().toLowerCase();
  if (v === undefined || v === "") return def;
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  throw new ConfigError(`${name} must be true or false`);
}

/** Reads `NAME` or the file named by `NAME_FILE` (Docker/Kubernetes secrets, mounted files). */
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
  const teamId = (env.APNS_TEAM_ID ?? "").trim();
  if (!teamId)
    throw new ConfigError(
      "APNs needs APNS_TEAM_ID: your 10-character Apple Team ID (developer.apple.com → Account → Membership details)",
    );
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

function list(env: Env, name: string): string[] {
  return (env[name] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export const ADMIN_SESSION_IDLE_SECONDS = 30 * 60;
export const ADMIN_SESSION_ABSOLUTE_SECONDS = 8 * 3600;

/** A whole number between `min` and `max` from the environment, else the default. */
function boundedInt(env: Env, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  if (!/^\d+$/.test(raw)) throw new ConfigError(`${name} must be a whole number`);
  const n = Number(raw);
  if (n < min || n > max) throw new ConfigError(`${name} must be between ${min} and ${max}`);
  return n;
}

export function parseAdmin(env: Env, publicUrl: string): AdminConfig | null {
  const issuerRaw = env.ADMIN_OIDC_ISSUER?.trim();
  const anyAdminVar = Object.keys(env).some(
    (k) => k.startsWith("ADMIN_") && (env[k] ?? "").trim() !== "",
  );
  if (!issuerRaw) {
    if (anyAdminVar)
      throw new ConfigError("ADMIN_* variables are set but ADMIN_OIDC_ISSUER is missing");
    return null;
  }
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuerRaw);
  } catch {
    throw new ConfigError("ADMIN_OIDC_ISSUER must be an https URL");
  }
  if (issuerUrl.protocol !== "https:" || issuerUrl.username || issuerUrl.password) {
    throw new ConfigError("ADMIN_OIDC_ISSUER must be an https URL without credentials");
  }
  if (issuerUrl.search || issuerUrl.hash)
    throw new ConfigError("ADMIN_OIDC_ISSUER must not contain a query or fragment");

  const pub = new URL(publicUrl);
  if (pub.protocol !== "https:" && !isLocalhostName(pub.hostname)) {
    throw new ConfigError(
      "The admin dashboard needs an https RELAY_PUBLIC_URL (secure cookies); http is only allowed for localhost",
    );
  }
  if (pub.pathname !== "/" && pub.pathname !== "") {
    throw new ConfigError("The admin dashboard needs RELAY_PUBLIC_URL without a path");
  }

  const clientId = env.ADMIN_OIDC_CLIENT_ID?.trim();
  if (!clientId || clientId.length > 255)
    throw new ConfigError("ADMIN_OIDC_CLIENT_ID is required for the admin dashboard");
  const clientSecret = valueOrFile(env, "ADMIN_OIDC_CLIENT_SECRET")?.trim() || null;

  const scopes = (env.ADMIN_OIDC_SCOPES ?? "openid email profile")
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (!scopes.includes("openid")) throw new ConfigError("ADMIN_OIDC_SCOPES must include openid");
  if (scopes.some((s) => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(s)))
    throw new ConfigError("ADMIN_OIDC_SCOPES contains an invalid scope");

  const emails = list(env, "ADMIN_EMAILS").map((e) => e.toLowerCase());
  for (const e of emails) {
    if (!/^[^\s@]+@[^\s@]+$/.test(e) || e.length > 254)
      throw new ConfigError(`ADMIN_EMAILS contains an invalid address: ${e}`);
  }
  const subjects = list(env, "ADMIN_SUBJECTS");
  const groups = list(env, "ADMIN_GROUPS");
  const groupsClaim = (env.ADMIN_GROUPS_CLAIM ?? "groups").trim() || "groups";
  if (!/^[A-Za-z0-9_:/.-]{1,200}$/.test(groupsClaim))
    throw new ConfigError("ADMIN_GROUPS_CLAIM must be a claim name (dots for nested claims)");
  if (emails.length === 0 && subjects.length === 0 && groups.length === 0) {
    throw new ConfigError(
      "The admin dashboard needs at least one of ADMIN_EMAILS, ADMIN_SUBJECTS or ADMIN_GROUPS; refusing to enable it for every account of the identity provider",
    );
  }

  let allowedIps: string[] | null = null;
  const ipList = list(env, "ADMIN_ALLOWED_IPS");
  if (ipList.length > 0) {
    allowedIps = ipList.map((c) => {
      const p = parseCidr(c);
      if (!p) throw new ConfigError(`ADMIN_ALLOWED_IPS contains an invalid address or CIDR: ${c}`);
      return p.text;
    });
  }

  const origin = pub.origin;
  const fingerprint = createHash("sha256")
    .update(
      JSON.stringify({
        v: 1,
        issuer: issuerRaw,
        clientId,
        secret: clientSecret ? createHash("sha256").update(clientSecret).digest("hex") : null,
        emails: [...emails].sort(),
        subjects: [...subjects].sort(),
        groups: [...groups].sort(),
        groupsClaim,
        origin,
      }),
    )
    .digest("hex");

  return {
    issuer: issuerRaw,
    clientId,
    clientSecret,
    scopes,
    redirectUri: `${origin}/admin/callback`,
    postLogoutRedirectUri: `${origin}/admin`,
    publicOrigin: origin,
    emails,
    subjects,
    groups,
    groupsClaim,
    allowedIps,
    rpLogout: bool(env, "ADMIN_OIDC_RP_LOGOUT", true),
    // How long a dashboard session lasts without activity, and at most.
    sessionIdleSeconds:
      boundedInt(env, "ADMIN_SESSION_IDLE_MINUTES", ADMIN_SESSION_IDLE_SECONDS / 60, 5, 24 * 60) *
      60,
    sessionAbsoluteSeconds:
      boundedInt(env, "ADMIN_SESSION_MAX_HOURS", ADMIN_SESSION_ABSOLUTE_SECONDS / 3600, 1, 7 * 24) *
      3600,
    fingerprint,
  };
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
    admin: parseAdmin(env, publicUrl),
    commit: (env.RELAY_COMMIT ?? "").trim().slice(0, 40) || null,
  };
}

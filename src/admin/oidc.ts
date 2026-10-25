import { createHash, randomBytes } from "node:crypto";
import {
  createRemoteJWKSet,
  customFetch,
  type JWTPayload,
  type JWTVerifyGetKey,
  jwtVerify,
} from "jose";
import type { AdminConfig } from "../config.ts";
import { safeEqual } from "../crypto/encoding.ts";

/**
 * OpenID Connect relying party for the admin dashboard: Authorization Code
 * flow with PKCE (S256), state and nonce, discovery, and ID token validation
 * with `jose` (signature against the provider's JWKS with key rotation and
 * caching, iss, aud, azp, exp/nbf/iat with 60 s skew, nonce).
 *
 * Every request to the identity provider goes through `boundedFetch`: https
 * only, no redirects, 5 s timeout, 256 KB response limit, no cookies.
 */

export class OidcError extends Error {
  readonly code: string;
  constructor(code: string, message?: string) {
    super(message ?? code);
    this.code = code;
  }
}

export interface OidcMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
  id_token_signing_alg_values_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  scopes_supported?: string[];
}

/** Asymmetric JWS algorithms accepted for ID tokens (no HS*, never "none"). */
export const ACCEPTED_ID_TOKEN_ALGS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "Ed25519",
];

export const CLOCK_SKEW_SECONDS = 60;
/** ID tokens must have been issued within this many seconds (iat). */
export const MAX_ID_TOKEN_AGE_SECONDS = 600;
const FETCH_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 256 * 1024;
const METADATA_TTL_MS = 3_600_000;

export interface OidcClientOptions {
  /** Tests only: allow http:// issuer and endpoints (never settable from the environment). */
  allowInsecureHttp?: boolean;
  fetchImpl?: typeof fetch;
  now?: () => number;
  /** Minimum time between JWKS refetches on an unknown key id (default 30 s). */
  jwksCooldownMs?: number;
}

export interface IdTokenClaims extends JWTPayload {
  sub: string;
  email?: unknown;
  email_verified?: unknown;
  name?: unknown;
  preferred_username?: unknown;
}

/** RFC 7636 code verifier/challenge and fresh state and nonce values. */
export function newAuthRequestSecrets(): {
  state: string;
  nonce: string;
  verifier: string;
  challenge: string;
} {
  const verifier = randomBytes(32).toString("base64url");
  return {
    state: randomBytes(32).toString("base64url"),
    nonce: randomBytes(32).toString("base64url"),
    verifier,
    challenge: createHash("sha256").update(verifier).digest("base64url"),
  };
}

function stripSlash(s: string): string {
  return s.replace(/\/+$/, "");
}

export class OidcClient {
  private readonly cfg: AdminConfig;
  private readonly opts: OidcClientOptions;
  private meta: { value: OidcMetadata; fetchedAt: number } | null = null;
  private jwks: { uri: string; get: JWTVerifyGetKey } | null = null;
  private inflight: Promise<OidcMetadata> | null = null;

  constructor(cfg: AdminConfig, opts: OidcClientOptions = {}) {
    this.cfg = cfg;
    this.opts = opts;
  }

  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  private checkUrl(raw: unknown, what: string): string {
    if (typeof raw !== "string") throw new OidcError("bad_metadata", `${what} missing`);
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      throw new OidcError("bad_metadata", `${what} is not a URL`);
    }
    const okScheme =
      u.protocol === "https:" || (this.opts.allowInsecureHttp && u.protocol === "http:");
    if (!okScheme || u.username || u.password)
      throw new OidcError("bad_metadata", `${what} must be https`);
    return u.toString();
  }

  /** GET/POST with https-only, timeout, size limit and no redirects. */
  async boundedFetch(
    url: string,
    init: {
      method: "GET" | "POST";
      headers?: Headers | Record<string, string>;
      body?: string;
      signal?: AbortSignal;
    },
  ): Promise<Response> {
    this.checkUrl(url, "endpoint");
    const timeout = AbortSignal.timeout(FETCH_TIMEOUT_MS);
    const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    const doFetch = this.opts.fetchImpl ?? fetch;
    let res: Response;
    try {
      res = await doFetch(url, {
        method: init.method,
        headers: init.headers,
        body: init.body,
        redirect: "manual",
        credentials: "omit",
        signal,
      });
    } catch {
      throw new OidcError(timeout.aborted ? "idp_timeout" : "idp_unreachable");
    }
    if (res.status >= 300 && res.status < 400) {
      await res.body?.cancel().catch(() => {});
      throw new OidcError("idp_redirect", "identity provider answered with a redirect");
    }
    const declared = Number(res.headers.get("content-length") ?? "0");
    if (declared > MAX_RESPONSE_BYTES) {
      await res.body?.cancel().catch(() => {});
      throw new OidcError("idp_response_too_large");
    }
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (res.body) {
      const reader = res.body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > MAX_RESPONSE_BYTES) {
            await reader.cancel().catch(() => {});
            throw new OidcError("idp_response_too_large");
          }
          chunks.push(value);
        }
      } catch (e) {
        if (e instanceof OidcError) throw e;
        throw new OidcError(timeout.aborted ? "idp_timeout" : "idp_unreachable");
      }
    }
    return new Response(Buffer.concat(chunks), { status: res.status, headers: res.headers });
  }

  private async fetchJson(
    url: string,
    init: Parameters<OidcClient["boundedFetch"]>[1],
  ): Promise<{ status: number; json: Record<string, unknown> | null }> {
    const res = await this.boundedFetch(url, init);
    let json: unknown = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    return {
      status: res.status,
      json:
        json && typeof json === "object" && !Array.isArray(json)
          ? (json as Record<string, unknown>)
          : null,
    };
  }

  /** Provider metadata from `${issuer}/.well-known/openid-configuration` (cached 1 h). */
  async metadata(): Promise<OidcMetadata> {
    if (this.meta && this.now() - this.meta.fetchedAt < METADATA_TTL_MS) return this.meta.value;
    if (this.inflight) return this.inflight;
    this.inflight = this.discover()
      .then((m) => {
        this.meta = { value: m, fetchedAt: this.now() };
        return m;
      })
      .catch((e) => {
        // Keep using the last good metadata if the provider is briefly unreachable.
        if (this.meta) return this.meta.value;
        throw e;
      })
      .finally(() => {
        this.inflight = null;
      });
    return this.inflight;
  }

  /** Cached metadata if discovery already happened (no network). */
  cachedMetadata(): OidcMetadata | null {
    return this.meta?.value ?? null;
  }

  private async discover(): Promise<OidcMetadata> {
    const url = `${stripSlash(this.cfg.issuer)}/.well-known/openid-configuration`;
    const { status, json } = await this.fetchJson(url, {
      method: "GET",
      headers: { accept: "application/json" },
    });
    if (status !== 200 || !json) throw new OidcError("discovery_failed", `HTTP ${status}`);
    const issuer = json.issuer;
    // OIDC Discovery §4.3: the issuer must match the configured one (a trailing
    // slash difference in the configuration is tolerated, the discovered value wins).
    if (typeof issuer !== "string" || stripSlash(issuer) !== stripSlash(this.cfg.issuer)) {
      throw new OidcError("issuer_mismatch", "discovered issuer does not match ADMIN_OIDC_ISSUER");
    }
    const strings = (v: unknown) =>
      Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : undefined;
    const m: OidcMetadata = {
      issuer,
      authorization_endpoint: this.checkUrl(json.authorization_endpoint, "authorization_endpoint"),
      token_endpoint: this.checkUrl(json.token_endpoint, "token_endpoint"),
      jwks_uri: this.checkUrl(json.jwks_uri, "jwks_uri"),
      id_token_signing_alg_values_supported: strings(json.id_token_signing_alg_values_supported),
      token_endpoint_auth_methods_supported: strings(json.token_endpoint_auth_methods_supported),
      scopes_supported: strings(json.scopes_supported),
    };
    if (json.userinfo_endpoint !== undefined)
      m.userinfo_endpoint = this.checkUrl(json.userinfo_endpoint, "userinfo_endpoint");
    if (json.end_session_endpoint !== undefined)
      m.end_session_endpoint = this.checkUrl(json.end_session_endpoint, "end_session_endpoint");
    return m;
  }

  private keySet(meta: OidcMetadata): JWTVerifyGetKey {
    if (this.jwks?.uri === meta.jwks_uri) return this.jwks.get;
    const get = createRemoteJWKSet(new URL(meta.jwks_uri), {
      timeoutDuration: FETCH_TIMEOUT_MS,
      // Unknown "kid" → refetch (key rotation), but at most every 30 s.
      cooldownDuration: this.opts.jwksCooldownMs ?? 30_000,
      cacheMaxAge: 600_000,
      [customFetch]: (url, init) =>
        this.boundedFetch(url, { method: "GET", headers: init.headers, signal: init.signal }),
    });
    this.jwks = { uri: meta.jwks_uri, get };
    return get;
  }

  async authorizationUrl(p: { state: string; nonce: string; challenge: string }): Promise<string> {
    const meta = await this.metadata();
    const u = new URL(meta.authorization_endpoint);
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", this.cfg.clientId);
    u.searchParams.set("redirect_uri", this.cfg.redirectUri);
    u.searchParams.set("scope", requestedScopes(this.cfg, meta).join(" "));
    u.searchParams.set("state", p.state);
    u.searchParams.set("nonce", p.nonce);
    u.searchParams.set("code_challenge", p.challenge);
    u.searchParams.set("code_challenge_method", "S256");
    return u.toString();
  }

  /** Exchanges the code and returns the validated ID token claims (plus userinfo if needed). */
  async completeLogin(p: {
    code: string;
    verifier: string;
    nonce: string;
    iss?: string | null;
  }): Promise<IdTokenClaims> {
    const meta = await this.metadata();
    // RFC 9207: if the provider sends "iss" with the response, it must be ours (mix-up defence).
    if (p.iss !== undefined && p.iss !== null && p.iss !== meta.issuer) {
      throw new OidcError("issuer_mismatch", "authorization response iss does not match");
    }
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: p.code,
      redirect_uri: this.cfg.redirectUri,
      code_verifier: p.verifier,
    });
    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    };
    if (this.cfg.clientSecret) {
      const methods = meta.token_endpoint_auth_methods_supported;
      const usePost =
        methods !== undefined &&
        !methods.includes("client_secret_basic") &&
        methods.includes("client_secret_post");
      if (usePost) {
        body.set("client_id", this.cfg.clientId);
        body.set("client_secret", this.cfg.clientSecret);
      } else {
        // RFC 6749 §2.3.1: form-encode both parts before base64.
        const enc = (s: string) => encodeURIComponent(s).replace(/%20/g, "+");
        headers.authorization = `Basic ${Buffer.from(
          `${enc(this.cfg.clientId)}:${enc(this.cfg.clientSecret)}`,
        ).toString("base64")}`;
      }
    } else {
      body.set("client_id", this.cfg.clientId);
    }
    const { status, json } = await this.fetchJson(meta.token_endpoint, {
      method: "POST",
      headers,
      body: body.toString(),
    });
    if (status !== 200 || !json) throw new OidcError("token_exchange_failed", `HTTP ${status}`);
    if (typeof json.token_type !== "string" || json.token_type.toLowerCase() !== "bearer") {
      throw new OidcError("token_exchange_failed", "unexpected token_type");
    }
    if (typeof json.id_token !== "string")
      throw new OidcError("token_exchange_failed", "no id_token in the token response");
    const claims = await this.validateIdToken(json.id_token, p.nonce);
    const accessToken = typeof json.access_token === "string" ? json.access_token : null;
    return this.withUserinfo(meta, claims, accessToken);
  }

  async validateIdToken(idToken: string, nonce: string): Promise<IdTokenClaims> {
    const meta = await this.metadata();
    let algorithms = ACCEPTED_ID_TOKEN_ALGS;
    if (meta.id_token_signing_alg_values_supported) {
      algorithms = algorithms.filter((a) =>
        meta.id_token_signing_alg_values_supported?.includes(a),
      );
      if (algorithms.length === 0) {
        throw new OidcError(
          "unsupported_alg",
          "the provider signs ID tokens only with symmetric algorithms; configure an RS256/ES256 signing key",
        );
      }
    }
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(idToken, this.keySet(meta), {
        issuer: meta.issuer,
        audience: this.cfg.clientId,
        algorithms,
        clockTolerance: CLOCK_SKEW_SECONDS,
        maxTokenAge: MAX_ID_TOKEN_AGE_SECONDS,
        requiredClaims: ["iss", "aud", "exp", "iat", "sub", "nonce"],
        currentDate: new Date(this.now()),
      }));
    } catch (e) {
      const code = (e as { code?: string }).code ?? "invalid";
      throw new OidcError("invalid_id_token", code);
    }
    // OIDC Core §3.1.3.7: azp must be our client id when present, and must be
    // present when the token has several audiences.
    const aud = payload.aud;
    if (Array.isArray(aud) && aud.length > 1 && payload.azp === undefined) {
      throw new OidcError("invalid_id_token", "azp missing for multiple audiences");
    }
    if (payload.azp !== undefined && payload.azp !== this.cfg.clientId) {
      throw new OidcError("invalid_id_token", "azp mismatch");
    }
    if (typeof payload.nonce !== "string" || !safeEqual(payload.nonce, nonce)) {
      throw new OidcError("invalid_id_token", "nonce mismatch");
    }
    if (typeof payload.sub !== "string" || payload.sub.length === 0 || payload.sub.length > 255) {
      throw new OidcError("invalid_id_token", "invalid sub");
    }
    return payload as IdTokenClaims;
  }

  /**
   * Some providers put e-mail or groups only into the userinfo response. If a
   * claim needed for authorization is missing from the ID token, fetch userinfo
   * (sub must match, OIDC Core §5.3.2) and fill in only the missing claims.
   */
  private async withUserinfo(
    meta: OidcMetadata,
    claims: IdTokenClaims,
    accessToken: string | null,
  ): Promise<IdTokenClaims> {
    const needEmail = this.cfg.emails.length > 0 && claims.email === undefined;
    const needGroups =
      this.cfg.groups.length > 0 && getClaim(claims, this.cfg.groupsClaim) === undefined;
    if ((!needEmail && !needGroups) || !accessToken || !meta.userinfo_endpoint) return claims;
    let info: Record<string, unknown> | null = null;
    try {
      const r = await this.fetchJson(meta.userinfo_endpoint, {
        method: "GET",
        headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
      });
      if (r.status === 200) info = r.json;
    } catch {
      info = null;
    }
    if (!info || info.sub !== claims.sub) return claims;
    const merged: IdTokenClaims = { ...claims };
    if (needEmail) {
      if (info.email !== undefined) merged.email = info.email;
      if (info.email_verified !== undefined) merged.email_verified = info.email_verified;
    }
    if (needGroups) {
      const root =
        this.cfg.groupsClaim in info ? this.cfg.groupsClaim : this.cfg.groupsClaim.split(".")[0];
      if (root && info[root] !== undefined && merged[root] === undefined) merged[root] = info[root];
    }
    return merged;
  }

  /** RP-initiated logout URL, or null if the provider has none. */
  endSessionUrl(): string | null {
    const ep = this.meta?.value.end_session_endpoint;
    if (!ep || !this.cfg.rpLogout) return null;
    const u = new URL(ep);
    u.searchParams.set("client_id", this.cfg.clientId);
    u.searchParams.set("post_logout_redirect_uri", this.cfg.postLogoutRedirectUri);
    return u.toString();
  }
}

/** Claim lookup: exact name first (e.g. "urn:…:roles"), then a dotted path ("realm_access.roles"). */
/**
 * The configured scopes, plus "groups" when admins are matched by group, the
 * provider offers that scope and it isn't requested yet (Pocket ID, Zitadel
 * and others only put the groups claim into tokens for this scope).
 */
export function requestedScopes(
  cfg: Pick<AdminConfig, "scopes" | "groups">,
  meta: Pick<OidcMetadata, "scopes_supported">,
): string[] {
  const scopes = [...cfg.scopes];
  if (
    cfg.groups.length > 0 &&
    !scopes.includes("groups") &&
    meta.scopes_supported?.includes("groups")
  )
    scopes.push("groups");
  return scopes;
}

export function getClaim(claims: Record<string, unknown>, name: string): unknown {
  if (name in claims) return claims[name];
  let cur: unknown = claims;
  for (const part of name.split(".")) {
    if (!cur || typeof cur !== "object" || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

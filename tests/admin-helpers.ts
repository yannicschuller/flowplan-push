import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, type JWTPayload, SignJWT } from "jose";
import type { OidcClientOptions } from "../src/admin/oidc.ts";
import { type App, createApp } from "../src/app.ts";
import { type AdminConfig, type Config, loadConfig, parseAdmin } from "../src/config.ts";
import { silentLogger } from "../src/log.ts";

// ---- mock OpenID provider -------------------------------------------------

type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;

export interface PendingCode {
  nonce: string;
  challenge: string;
  /** Claims merged into (or removed from, with undefined) the default ID token claims. */
  claims?: Record<string, unknown>;
  /** Sign with this key instead of the published one (bad signature tests). */
  signWith?: KeyPair;
  kid?: string;
  alg?: string;
  /** Raw JWT to return instead of a generated one. */
  rawIdToken?: string;
  userinfo?: Record<string, unknown>;
}

export async function startMockIdp(opts: {
  clientId: string;
  clientSecret: string | null;
  redirectUri?: string;
  /** Screenshots/demo only: /authorize immediately redirects back with a code. */
  autoApprove?: boolean;
}) {
  let key = await generateKeyPair("RS256");
  let kid = "k1";
  const codes = new Map<string, PendingCode>();
  const tokenRequests: Array<{ headers: http.IncomingHttpHeaders; body: URLSearchParams }> = [];
  let jwksFetches = 0;
  let discoveryOverride: Record<string, unknown> | null = null;
  let userinfoCalls = 0;

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      const url = new URL(req.url ?? "/", issuer);
      const json = (status: number, body: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      };
      if (url.pathname === "/.well-known/openid-configuration") {
        return json(200, {
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          userinfo_endpoint: `${issuer}/userinfo`,
          end_session_endpoint: `${issuer}/logout`,
          id_token_signing_alg_values_supported: ["RS256", "ES256"],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          ...(discoveryOverride ?? {}),
        });
      }
      if (url.pathname === "/authorize" && opts.autoApprove) {
        const code = `auto-${codes.size}-${Date.now()}`;
        codes.set(code, {
          nonce: url.searchParams.get("nonce") ?? "",
          challenge: url.searchParams.get("code_challenge") ?? "",
        });
        const back = new URL(url.searchParams.get("redirect_uri") ?? "");
        back.searchParams.set("state", url.searchParams.get("state") ?? "");
        back.searchParams.set("code", code);
        res.writeHead(302, { location: back.toString() });
        res.end();
        return;
      }
      if (url.pathname === "/jwks") {
        jwksFetches++;
        const jwk = await exportJWK(key.publicKey);
        return json(200, { keys: [{ ...jwk, kid, alg: "RS256", use: "sig" }] });
      }
      if (url.pathname === "/userinfo") {
        userinfoCalls++;
        const auth = String(req.headers.authorization ?? "");
        const code = auth.replace(/^Bearer at-/, "");
        const p = codes.get(`used:${code}`);
        if (!p) return json(401, { error: "invalid_token" });
        return json(200, p.userinfo ?? { sub: "admin-sub" });
      }
      if (url.pathname === "/token" && req.method === "POST") {
        const body = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        tokenRequests.push({ headers: req.headers, body });
        const code = body.get("code") ?? "";
        const p = codes.get(code);
        if (!p) return json(400, { error: "invalid_grant" });
        codes.delete(code);
        codes.set(`used:${code}`, p);
        if (opts.clientSecret) {
          const expected = `Basic ${Buffer.from(`${opts.clientId}:${opts.clientSecret}`).toString("base64")}`;
          if (req.headers.authorization !== expected) return json(401, { error: "invalid_client" });
        }
        if (
          body.get("redirect_uri") !==
          (opts.redirectUri ?? "https://push.example.com/admin/callback")
        )
          return json(400, { error: "invalid_grant", detail: "redirect_uri" });
        const verifier = body.get("code_verifier") ?? "";
        if (createHash("sha256").update(verifier).digest("base64url") !== p.challenge)
          return json(400, { error: "invalid_grant", detail: "pkce" });
        const now = Math.floor(Date.now() / 1000);
        const claims: Record<string, unknown> = {
          iss: issuer,
          aud: opts.clientId,
          sub: "admin-sub",
          email: "admin@example.com",
          email_verified: true,
          name: "Ada Admin",
          nonce: p.nonce,
          iat: now,
          exp: now + 300,
          ...(p.claims ?? {}),
        };
        for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
        const signer = p.signWith ?? key;
        const idToken =
          p.rawIdToken ??
          (await new SignJWT(claims as JWTPayload)
            .setProtectedHeader({ alg: p.alg ?? "RS256", kid: p.kid ?? kid })
            .sign(signer.privateKey));
        return json(200, {
          access_token: `at-${code}`,
          token_type: "Bearer",
          expires_in: 300,
          id_token: idToken,
        });
      }
      json(404, { error: "not_found" });
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    issuer,
    codes,
    tokenRequests,
    get jwksFetches() {
      return jwksFetches;
    },
    get userinfoCalls() {
      return userinfoCalls;
    },
    get key() {
      return key;
    },
    async rotateKey(newKid: string) {
      key = await generateKeyPair("RS256");
      kid = newKid;
    },
    setDiscovery(o: Record<string, unknown> | null) {
      discoveryOverride = o;
    },
    close: () =>
      new Promise<void>((r) => {
        server.close(() => r());
        server.closeAllConnections();
      }),
  };
}

export type MockIdp = Awaited<ReturnType<typeof startMockIdp>>;

// ---- relay app with the admin dashboard -----------------------------------------

export const PUBLIC_URL = "https://push.example.com";
export const CLIENT_ID = "flowplan-push-admin";
export const CLIENT_SECRET = "s3cr3t-client-secret-value-0123456789";

export function adminEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    RELAY_STORAGE_KEY: randomBytes(32).toString("base64"),
    RELAY_PUBLIC_URL: PUBLIC_URL,
    LOG_LEVEL: "silent",
    ADMIN_OIDC_ISSUER: "https://idp.placeholder.example",
    ADMIN_OIDC_CLIENT_ID: CLIENT_ID,
    ADMIN_OIDC_CLIENT_SECRET: CLIENT_SECRET,
    ADMIN_EMAILS: "admin@example.com",
    ...extra,
  };
}

export interface AdminAppOptions {
  env?: Record<string, string>;
  /** Set false to start the relay without the admin dashboard. */
  admin?: boolean;
  configure?: (c: Config) => void;
  oidc?: Omit<OidcClientOptions, "allowInsecureHttp">;
}

export async function startAdminApp(o: AdminAppOptions = {}) {
  const env = adminEnv(o.env);
  if (o.admin === false) {
    for (const k of Object.keys(env)) if (k.startsWith("ADMIN_")) delete env[k];
  }
  const idp = await startMockIdp({
    clientId: env.ADMIN_OIDC_CLIENT_ID ?? CLIENT_ID,
    clientSecret: env.ADMIN_OIDC_CLIENT_SECRET ?? null,
  });
  const config = loadConfig(env);
  config.dataDir = ":memory:";
  if (config.admin) config.admin = { ...config.admin, issuer: idp.issuer };
  o.configure?.(config);
  const app: App = createApp(config, {
    logger: silentLogger,
    oidc: { allowInsecureHttp: true, ...(o.oidc ?? {}) },
  });
  await new Promise<void>((r) => app.server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;

  async function req(
    path: string,
    init: {
      method?: string;
      cookie?: string | null;
      headers?: Record<string, string>;
      form?: Record<string, string>;
    } = {},
  ) {
    const headers: Record<string, string> = { ...(init.headers ?? {}) };
    if (init.cookie) headers.cookie = init.cookie;
    let body: string | undefined;
    if (init.form) {
      body = new URLSearchParams(init.form).toString();
      headers["content-type"] ??= "application/x-www-form-urlencoded";
      headers.origin ??= PUBLIC_URL;
    }
    const res = await fetch(`${url}${path}`, {
      method: init.method ?? (init.form ? "POST" : "GET"),
      headers,
      body,
      redirect: "manual",
    });
    const text = await res.text();
    return { status: res.status, headers: res.headers, text, cookies: res.headers.getSetCookie() };
  }

  /** Runs the full login; returns the session cookie header value ("__Host-fp_admin=…"). */
  async function login(p: Omit<PendingCode, "nonce" | "challenge"> & { code?: string } = {}) {
    const r = await startLogin();
    const code = p.code ?? randomBytes(8).toString("hex");
    idp.codes.set(code, { nonce: r.nonce, challenge: r.challenge, ...p });
    const cb = await req(`/admin/callback?state=${encodeURIComponent(r.state)}&code=${code}`, {
      cookie: r.loginCookie,
    });
    const session = cb.cookies.find((c) => c.startsWith("__Host-fp_admin="));
    return {
      callback: cb,
      session,
      cookie: session ? session.split(";")[0] : null,
      state: r.state,
      code,
    };
  }

  async function startLogin(headers: Record<string, string> = {}) {
    const r = await req("/admin/login", { headers });
    if (r.status !== 302) throw new Error(`login start failed: ${r.status} ${r.text}`);
    const loc = new URL(r.headers.get("location") ?? "");
    const bind = r.cookies.find((c) => c.startsWith("__Host-fp_admin_login="));
    return {
      response: r,
      location: loc,
      state: loc.searchParams.get("state") ?? "",
      nonce: loc.searchParams.get("nonce") ?? "",
      challenge: loc.searchParams.get("code_challenge") ?? "",
      loginCookie: bind ? (bind.split(";")[0] as string) : "",
      loginSetCookie: bind ?? "",
    };
  }

  /** Extracts the CSRF token from a rendered page. */
  function csrfOf(html: string): string {
    const m = /name="csrf" value="([^"]+)"/.exec(html);
    if (!m?.[1]) throw new Error("no csrf token on page");
    return m[1];
  }

  /** Review + confirm of an action; returns the final response. */
  async function act(cookie: string, action: string, fields: Record<string, string>) {
    const dash = await req("/admin", { cookie });
    const csrf = csrfOf(dash.text);
    const review = await req("/admin/action", {
      cookie,
      form: { csrf, action, step: "review", ...fields },
    });
    if (review.status !== 200) return { review, final: review };
    const token = /name="confirm" value="([^"]+)"/.exec(review.text)?.[1] ?? "";
    const hidden: Record<string, string> = {};
    for (const m of review.text.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
      hidden[m[1] as string] = (m[2] as string)
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">");
    }
    const final = await req("/admin/action", {
      cookie,
      form: { ...hidden, confirm: token, step: "execute", csrf },
    });
    return { review, final };
  }

  return {
    app,
    url,
    idp,
    config,
    admin: config.admin as AdminConfig,
    req,
    login,
    startLogin,
    csrfOf,
    act,
    async close() {
      await app.close();
      await idp.close();
    },
  };
}

export type AdminApp = Awaited<ReturnType<typeof startAdminApp>>;

export { parseAdmin };

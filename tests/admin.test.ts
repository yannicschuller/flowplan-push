import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { generateKeyPair, SignJWT } from "jose";
import { authorize } from "../src/admin/authz.ts";
import { AdminSessions, readCookie } from "../src/admin/sessions.ts";
import { ConfigError, loadConfig, parseAdmin } from "../src/config.ts";
import { StorageCipher } from "../src/crypto/storage.ts";
import { Store } from "../src/db.ts";
import {
  type AdminApp,
  adminEnv,
  CLIENT_ID,
  CLIENT_SECRET,
  PUBLIC_URL,
  startAdminApp,
} from "./admin-helpers.ts";
import { apnsToken, BUNDLE, randomKey } from "./helpers.ts";

let t: AdminApp | null = null;
afterEach(async () => {
  await t?.close();
  t = null;
});

describe("admin configuration", () => {
  const base = () => adminEnv({ ADMIN_OIDC_ISSUER: "https://idp.example.com/application/o/push/" });

  it("is disabled without ADMIN_OIDC_ISSUER", () => {
    const env = { RELAY_STORAGE_KEY: randomKey().toString("base64") };
    assert.equal(loadConfig(env).admin, null);
  });

  it("refuses to enable without any admin rule", () => {
    const env = base();
    delete (env as Record<string, string | undefined>).ADMIN_EMAILS;
    assert.throws(() => loadConfig(env), /ADMIN_EMAILS, ADMIN_SUBJECTS or ADMIN_GROUPS/);
  });

  it("validates the issuer, public URL, scopes and allow lists", () => {
    assert.throws(
      () => loadConfig({ ...base(), ADMIN_OIDC_ISSUER: "http://idp.example.com" }),
      ConfigError,
    );
    assert.throws(
      () => loadConfig({ ...base(), ADMIN_OIDC_ISSUER: "https://u:p@idp.example.com" }),
      ConfigError,
    );
    assert.throws(
      () => loadConfig({ ...base(), RELAY_PUBLIC_URL: "http://push.example.com" }),
      /https RELAY_PUBLIC_URL/,
    );
    assert.ok(loadConfig({ ...base(), RELAY_PUBLIC_URL: "http://localhost:8080" }).admin);
    assert.throws(() => loadConfig({ ...base(), ADMIN_OIDC_SCOPES: "email profile" }), /openid/);
    assert.throws(
      () => loadConfig({ ...base(), ADMIN_ALLOWED_IPS: "10.0.0.0/33" }),
      /ADMIN_ALLOWED_IPS/,
    );
    assert.throws(() => loadConfig({ ...base(), ADMIN_EMAILS: "not-an-email" }), /ADMIN_EMAILS/);
    const { ADMIN_OIDC_CLIENT_ID: _drop, ...noClient } = base();
    assert.throws(() => loadConfig(noClient), /ADMIN_OIDC_CLIENT_ID/);
    const { ADMIN_OIDC_ISSUER: _i, ...noIssuer } = base();
    assert.throws(() => loadConfig(noIssuer), /ADMIN_OIDC_ISSUER is missing/);
  });

  it("parses lists, defaults and a stable fingerprint", () => {
    const c = loadConfig({
      ...base(),
      ADMIN_EMAILS: "Admin@Example.com, ops@example.com",
      ADMIN_GROUPS: "push-admins",
      ADMIN_ALLOWED_IPS: "203.0.113.7, 2001:db8::/32",
    }).admin;
    assert.ok(c);
    assert.deepEqual(c.emails, ["admin@example.com", "ops@example.com"]);
    assert.deepEqual(c.scopes, ["openid", "email", "profile"]);
    assert.equal(c.groupsClaim, "groups");
    assert.equal(c.redirectUri, "https://push.example.com/admin/callback");
    assert.deepEqual(c.allowedIps, ["203.0.113.7/32", "2001:db8::/32"]);
    assert.equal(c.sessionIdleSeconds, 1800);
    assert.equal(c.sessionAbsoluteSeconds, 8 * 3600);
    const again = parseAdmin(
      {
        ...base(),
        ADMIN_EMAILS: "ops@example.com,admin@example.com",
        ADMIN_GROUPS: "push-admins",
        ADMIN_ALLOWED_IPS: "203.0.113.7",
      },
      PUBLIC_URL,
    );
    assert.equal(again?.fingerprint, c.fingerprint, "order and IP list do not matter");
    const changed = parseAdmin({ ...base(), ADMIN_EMAILS: "admin@example.com" }, PUBLIC_URL);
    assert.notEqual(changed?.fingerprint, c.fingerprint);
  });
});

describe("admin disabled", () => {
  it("answers 404 for every /admin path when not configured", async () => {
    t = await startAdminApp({ admin: false });
    for (const p of [
      "/admin",
      "/admin/",
      "/admin/login",
      "/admin/callback?state=x&code=y",
      "/admin/assets/admin.js",
      "/admin/api/summary",
    ]) {
      const r = await t.req(p);
      assert.equal(r.status, 404, p);
    }
    assert.equal((await t.req("/admin/action", { form: { a: "b" } })).status, 404);
  });
});

describe("OIDC login", () => {
  it("logs in with code + PKCE + state + nonce and sets a strict session cookie", async () => {
    t = await startAdminApp();
    const start = await t.startLogin();
    assert.equal(start.location.origin + start.location.pathname, `${t.idp.issuer}/authorize`);
    const q = start.location.searchParams;
    assert.equal(q.get("response_type"), "code");
    assert.equal(q.get("client_id"), CLIENT_ID);
    assert.equal(q.get("redirect_uri"), "https://push.example.com/admin/callback");
    assert.equal(q.get("scope"), "openid email profile");
    assert.equal(q.get("code_challenge_method"), "S256");
    assert.match(start.state, /^[A-Za-z0-9_-]{43}$/);
    assert.match(start.nonce, /^[A-Za-z0-9_-]{43}$/);
    assert.match(
      start.loginSetCookie,
      /^__Host-fp_admin_login=[^;]+; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$/,
    );

    const r = await t.login();
    assert.equal(r.callback.status, 200);
    assert.ok(r.session);
    assert.match(
      r.session,
      /^__Host-fp_admin=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800$/,
    );
    assert.ok(!/Domain=/i.test(r.session));
    assert.ok(r.callback.cookies.some((c) => /^__Host-fp_admin_login=; .*Max-Age=0/.test(c)));
    assert.match(r.callback.text, /http-equiv="refresh" content="0;url=\/admin"/);
    // Client authentication, PKCE and redirect_uri were checked by the mock token endpoint.
    assert.equal(t.idp.tokenRequests.length, 1);

    const dash = await t.req("/admin", { cookie: r.cookie });
    assert.equal(dash.status, 200);
    assert.match(dash.text, /Top instances/);
    assert.match(dash.text, /admin@example.com/);
    const csp = dash.headers.get("content-security-policy") ?? "";
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /style-src 'self'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.ok(!csp.includes("unsafe-inline"));
    assert.equal(dash.headers.get("x-frame-options"), "DENY");
    assert.equal(dash.headers.get("cache-control"), "no-store");
    assert.equal(dash.headers.get("referrer-policy"), "same-origin", "Origin must survive on POST");
    assert.equal(dash.headers.get("x-content-type-options"), "nosniff");
    assert.ok(
      !/<script>|style="|onclick=|\son\w+=/i.test(dash.text),
      "no inline script/style/handlers",
    );

    const audit = t.app.actions.listAudit(5);
    assert.equal(audit[0]?.action, "login");
    assert.equal(audit[0]?.actor, "admin@example.com");
    assert.deepEqual(audit[0]?.details, { via: "email" });
  });

  it("shows the sign-in page without a session and protects pages and the API", async () => {
    t = await startAdminApp();
    const r = await t.req("/admin");
    assert.equal(r.status, 200);
    assert.match(r.text, /Sign in with SSO/);
    assert.equal((await t.req("/admin/api/summary")).status, 401);
    assert.equal((await t.req("/admin/audit")).status, 303);
    assert.equal((await t.req("/admin/instance?origin=https%3A%2F%2Fa.example.com")).status, 303);
    assert.equal(
      (
        await t.req("/admin/api/summary", {
          cookie: "__Host-fp_admin=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        })
      ).status,
      401,
    );
    assert.equal((await t.req("/admin/nope")).status, 404);
    assert.equal((await t.req("/admin/login", { method: "POST" })).status, 405);
  });

  it("serves the self-hosted script and stylesheet", async () => {
    t = await startAdminApp();
    const js = await t.req("/admin/assets/admin.js");
    assert.equal(js.status, 200);
    assert.match(js.headers.get("content-type") ?? "", /text\/javascript/);
    assert.match(js.text, /setInterval\(poll, 5000\)/);
    assert.ok(!/innerHTML|eval\(|new Function/.test(js.text));
    const css = await t.req("/admin/assets/admin.css");
    assert.match(css.headers.get("content-type") ?? "", /text\/css/);
    assert.ok(!/https?:\/\//.test(css.text), "no external resources");
  });

  it("rejects unknown, reused and unbound state", async () => {
    t = await startAdminApp();
    const unknown = await t.req("/admin/callback?state=nope&code=x");
    assert.equal(unknown.status, 400);

    // Correct state but without the browser-binding cookie (login CSRF / injected response).
    const s1 = await t.startLogin();
    t.idp.codes.set("c-unbound", { nonce: s1.nonce, challenge: s1.challenge });
    const unbound = await t.req(`/admin/callback?state=${s1.state}&code=c-unbound`);
    assert.equal(unbound.status, 400);
    // The state was consumed by that attempt: even the right browser cannot reuse it.
    const reuse = await t.req(`/admin/callback?state=${s1.state}&code=c-unbound`, {
      cookie: s1.loginCookie,
    });
    assert.equal(reuse.status, 400);

    const ok = await t.login();
    assert.equal(ok.callback.status, 200);
    const replay = await t.req(`/admin/callback?state=${ok.state}&code=${ok.code}`, {
      cookie: ok.callback.cookies.join("; "),
    });
    assert.equal(replay.status, 400, "a state is single-use");
    assert.equal(t.idp.tokenRequests.length, 1, "no token request for rejected callbacks");
  });

  it("handles an error response from the provider", async () => {
    t = await startAdminApp();
    const s = await t.startLogin();
    const r = await t.req(`/admin/callback?state=${s.state}&error=access_denied`, {
      cookie: s.loginCookie,
    });
    assert.equal(r.status, 403);
    assert.match(r.text, /access_denied/);
    const s2 = await t.startLogin();
    const r2 = await t.req(`/admin/callback?state=${s2.state}&error=%3Cscript%3E`, {
      cookie: s2.loginCookie,
    });
    assert.ok(!r2.text.includes("<script>"));
  });

  for (const [name, p] of [
    ["wrong nonce", { claims: { nonce: "other" } }],
    ["missing nonce", { claims: { nonce: undefined } }],
    ["wrong audience", { claims: { aud: "someone-else" } }],
    ["wrong issuer", { claims: { iss: "https://evil.example.com" } }],
    [
      "expired token",
      {
        claims: {
          exp: Math.floor(Date.now() / 1000) - 3600,
          iat: Math.floor(Date.now() / 1000) - 3700,
        },
      },
    ],
    ["not yet valid (nbf)", { claims: { nbf: Math.floor(Date.now() / 1000) + 3600 } }],
    ["issued too long ago", { claims: { iat: Math.floor(Date.now() / 1000) - 3600 } }],
    [
      "iat in the future",
      {
        claims: {
          iat: Math.floor(Date.now() / 1000) + 3600,
          exp: Math.floor(Date.now() / 1000) + 7200,
        },
      },
    ],
    ["foreign azp", { claims: { azp: "other-client" } }],
    ["several audiences without azp", { claims: { aud: [CLIENT_ID, "other"] } }],
    ["unsigned token (alg none)", { rawIdToken: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." }],
  ] as const) {
    it(`rejects an ID token with ${name}`, async () => {
      t = await startAdminApp();
      const r = await t.login(p as Parameters<AdminApp["login"]>[0]);
      assert.equal(r.callback.status, 403, name);
      assert.equal(r.session, undefined);
      assert.match(r.callback.text, /could not be verified/);
    });
  }

  it("rejects a token signed with a key that is not in the JWKS", async () => {
    t = await startAdminApp();
    const other = await generateKeyPair("RS256");
    const r = await t.login({ signWith: other });
    assert.equal(r.callback.status, 403);
    // Same kid, foreign key; and an unknown kid.
    const r2 = await t.login({ signWith: other, kid: "unknown-kid" });
    assert.equal(r2.callback.status, 403);
  });

  it("rejects symmetric (HS256) ID tokens even if signed with the client secret", async () => {
    t = await startAdminApp();
    const now = Math.floor(Date.now() / 1000);
    const s = await t.startLogin();
    const token = await new SignJWT({
      nonce: s.nonce,
      sub: "admin-sub",
      email: "admin@example.com",
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(t.idp.issuer)
      .setAudience(CLIENT_ID)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(new TextEncoder().encode(CLIENT_SECRET));
    t.idp.codes.set("hs", { nonce: s.nonce, challenge: s.challenge, rawIdToken: token });
    const r = await t.req(`/admin/callback?state=${s.state}&code=hs`, { cookie: s.loginCookie });
    assert.equal(r.status, 403);
  });

  it("follows signing key rotation (unknown kid → JWKS refetch) and caches the JWKS", async () => {
    t = await startAdminApp({ oidc: { jwksCooldownMs: 0 } });
    assert.equal((await t.login()).callback.status, 200);
    assert.equal((await t.login()).callback.status, 200);
    assert.equal(t.idp.jwksFetches, 1, "JWKS cached between logins");
    await t.idp.rotateKey("k2");
    assert.equal((await t.login()).callback.status, 200, "new key picked up");
    assert.equal(t.idp.jwksFetches, 2);
  });

  it("does not hammer the JWKS endpoint for unknown key ids (cooldown)", async () => {
    t = await startAdminApp();
    assert.equal((await t.login()).callback.status, 200);
    await t.idp.rotateKey("k2");
    assert.equal((await t.login()).callback.status, 403, "within the 30 s cooldown");
    assert.equal(t.idp.jwksFetches, 1);
  });

  it("checks the RFC 9207 iss response parameter", async () => {
    t = await startAdminApp();
    const s = await t.startLogin();
    t.idp.codes.set("c", { nonce: s.nonce, challenge: s.challenge });
    const r = await t.req(
      `/admin/callback?state=${s.state}&code=c&iss=${encodeURIComponent("https://evil.example.com")}`,
      {
        cookie: s.loginCookie,
      },
    );
    assert.equal(r.status, 403);
  });

  it("refuses a provider whose discovered issuer does not match", async () => {
    t = await startAdminApp();
    t.idp.setDiscovery({ issuer: "https://other-issuer.example.com" });
    const r = await t.req("/admin/login");
    assert.equal(r.status, 502);
  });

  it("refuses http endpoints in discovery unless explicitly allowed for tests", async () => {
    const { OidcClient } = await import("../src/admin/oidc.ts");
    t = await startAdminApp();
    const client = new OidcClient(t.admin);
    await assert.rejects(() => client.metadata(), /must be https/);
  });

  it("denies accounts that are not admins and audits the attempt", async () => {
    t = await startAdminApp();
    const r = await t.login({ claims: { email: "mallory@example.com", sub: "mallory" } });
    assert.equal(r.callback.status, 403);
    assert.equal(r.session, undefined);
    assert.match(r.callback.text, /not an administrator/);
    const a = t.app.actions.listAudit(1)[0];
    assert.equal(a?.action, "login_denied");
    assert.equal(a?.actor, "mallory@example.com");
    assert.equal(a?.reason, "not_an_admin");
  });

  it("requires email_verified when the claim is present", async () => {
    t = await startAdminApp();
    const r = await t.login({ claims: { email_verified: false } });
    assert.equal(r.callback.status, 403);
    assert.equal(t.app.actions.listAudit(1)[0]?.reason, "email_not_verified");
    const absent = await t.login({ claims: { email_verified: undefined } });
    assert.equal(absent.callback.status, 200, "absent claim is accepted");
    const str = await t.login({ claims: { email_verified: "true" } });
    assert.equal(str.callback.status, 200);
  });

  it("authorizes by group claim, nested role claim and subject", async () => {
    t = await startAdminApp({ env: { ADMIN_EMAILS: "", ADMIN_GROUPS: "push-admins" } });
    assert.equal(
      (await t.login({ claims: { email: "x@example.com", groups: ["staff", "push-admins"] } }))
        .callback.status,
      200,
    );
    assert.equal(
      (await t.login({ claims: { email: "x@example.com", groups: ["staff"] } })).callback.status,
      403,
    );
    await t.close();

    t = await startAdminApp({
      env: {
        ADMIN_EMAILS: "",
        ADMIN_GROUPS: "relay-admin",
        ADMIN_GROUPS_CLAIM: "realm_access.roles",
      },
    });
    assert.equal(
      (await t.login({ claims: { realm_access: { roles: ["relay-admin"] } } })).callback.status,
      200,
    );
    await t.close();

    t = await startAdminApp({ env: { ADMIN_EMAILS: "", ADMIN_SUBJECTS: "sub-123" } });
    assert.equal(
      (await t.login({ claims: { sub: "sub-123", email: undefined } })).callback.status,
      200,
    );
    assert.equal((await t.login({ claims: { sub: "sub-456" } })).callback.status, 403);
  });

  it("fetches userinfo when the ID token lacks the needed claims", async () => {
    t = await startAdminApp({ env: { ADMIN_EMAILS: "", ADMIN_GROUPS: "push-admins" } });
    const r = await t.login({
      claims: { groups: undefined },
      userinfo: { sub: "admin-sub", groups: ["push-admins"] },
    });
    assert.equal(r.callback.status, 200);
    assert.equal(t.idp.userinfoCalls, 1);
    // userinfo for another subject is ignored.
    const r2 = await t.login({
      claims: { groups: undefined },
      userinfo: { sub: "someone-else", groups: ["push-admins"] },
    });
    assert.equal(r2.callback.status, 403);
  });

  it("rate-limits login attempts per IP", async () => {
    t = await startAdminApp();
    let last = 0;
    for (let i = 0; i < 11; i++) last = (await t.req("/admin/login")).status;
    assert.equal(last, 429);
  });

  it("logs out locally and at the provider (RP-initiated logout)", async () => {
    t = await startAdminApp();
    const { cookie } = await t.login();
    assert.ok(cookie);
    const dash = await t.req("/admin", { cookie });
    const csrf = t.csrfOf(dash.text);
    assert.match(
      dash.headers.get("content-security-policy") ?? "",
      new RegExp(`form-action 'self' ${t.idp.issuer.replace(/[.]/g, "\\.")}`),
    );
    const out = await t.req("/admin/logout", { cookie, form: { csrf } });
    assert.equal(out.status, 303);
    const loc = new URL(out.headers.get("location") ?? "");
    assert.equal(`${loc.origin}${loc.pathname}`, `${t.idp.issuer}/logout`);
    assert.equal(loc.searchParams.get("client_id"), CLIENT_ID);
    assert.equal(loc.searchParams.get("post_logout_redirect_uri"), `${PUBLIC_URL}/admin`);
    assert.ok(out.cookies.some((c) => /^__Host-fp_admin=; .*Max-Age=0/.test(c)));
    assert.equal((await t.req("/admin/api/summary", { cookie })).status, 401, "session is gone");
    assert.equal(t.app.actions.listAudit(1)[0]?.action, "logout");
  });

  it("logs out locally only with ADMIN_OIDC_RP_LOGOUT=false", async () => {
    t = await startAdminApp({ env: { ADMIN_OIDC_RP_LOGOUT: "false" } });
    const { cookie } = await t.login();
    const csrf = t.csrfOf((await t.req("/admin", { cookie })).text);
    const out = await t.req("/admin/logout", { cookie, form: { csrf } });
    assert.equal(out.headers.get("location"), "/admin");
  });

  it("rotates the session id on every login", async () => {
    t = await startAdminApp();
    const a = await t.login();
    const s = await t.startLogin();
    t.idp.codes.set("again", { nonce: s.nonce, challenge: s.challenge });
    const b = await t.req(`/admin/callback?state=${s.state}&code=again`, {
      cookie: `${s.loginCookie}; ${a.cookie}`,
    });
    const newCookie = b.cookies.find((c) => c.startsWith("__Host-fp_admin="))?.split(";")[0];
    assert.ok(newCookie && newCookie !== a.cookie);
    assert.equal(
      (await t.req("/admin/api/summary", { cookie: a.cookie })).status,
      401,
      "old session ended",
    );
    assert.equal((await t.req("/admin/api/summary", { cookie: newCookie })).status, 200);
  });
});

describe("admin sessions", () => {
  function setup() {
    let now = 1_800_000_000;
    const store = new Store(":memory:", new StorageCipher(randomKey()), () => now);
    const cfg = loadConfig(adminEnv()).admin;
    assert.ok(cfg);
    return {
      store,
      cfg,
      sessions: new AdminSessions(store, cfg),
      advance: (s: number) => {
        now += s;
      },
    };
  }

  it("expires after 30 minutes idle; reads without touch do not extend", () => {
    const { sessions, advance } = setup();
    const { id } = sessions.create({ sub: "s", email: "a@example.com", name: null }, "127.0.0.1");
    advance(29 * 60);
    assert.ok(sessions.get(id, false), "still valid");
    advance(2 * 60);
    assert.equal(sessions.get(id, true), null, "idle timeout although polled");
  });

  it("activity extends the idle timeout but not past 8 hours", () => {
    const { sessions, advance } = setup();
    const { id } = sessions.create({ sub: "s", email: null, name: null }, "127.0.0.1");
    for (let i = 0; i < 15; i++) {
      advance(29 * 60);
      assert.ok(sessions.get(id, true), `active at step ${i}`);
    }
    advance(20 * 60); // 15*29 + 20 = 455 min < 480
    assert.ok(sessions.get(id, true));
    advance(26 * 60); // 481 min
    assert.equal(sessions.get(id, true), null, "absolute lifetime");
  });

  it("invalidates sessions when the admin configuration changes", () => {
    const { store, cfg, sessions } = setup();
    const { id } = sessions.create({ sub: "s", email: null, name: null }, "127.0.0.1");
    const other = new AdminSessions(store, { ...cfg, fingerprint: "changed" });
    assert.equal(other.get(id, true), null);
    assert.equal(other.count(), 0, "purged at start");
  });

  it("stores only hashes of session ids and single-use login states", () => {
    const { store, sessions, advance } = setup();
    const { id } = sessions.create({ sub: "s", email: null, name: null }, "127.0.0.1");
    const dump = JSON.stringify(store.db.prepare("SELECT * FROM admin_sessions").all());
    assert.ok(!dump.includes(id));
    sessions.saveLoginState({ state: "st", binding: "b", nonce: "n", verifier: "v" });
    assert.equal(sessions.consumeLoginState("st", "wrong"), null);
    sessions.saveLoginState({ state: "st2", binding: "b", nonce: "n", verifier: "v" });
    advance(601);
    assert.equal(sessions.consumeLoginState("st2", "b"), null, "expired after 10 minutes");
    sessions.saveLoginState({ state: "st3", binding: "b", nonce: "n", verifier: "v" });
    assert.deepEqual(sessions.consumeLoginState("st3", "b"), { nonce: "n", verifier: "v" });
    assert.equal(sessions.consumeLoginState("st3", "b"), null);
  });

  it("ignores ambiguous (duplicated) cookies", () => {
    assert.equal(readCookie("a=1; __Host-fp_admin=x", "__Host-fp_admin"), "x");
    assert.equal(readCookie("__Host-fp_admin=x; __Host-fp_admin=y", "__Host-fp_admin"), null);
  });
});

describe("authorization rules", () => {
  const cfg = () => {
    const c = loadConfig(
      adminEnv({ ADMIN_GROUPS: "a,b", ADMIN_GROUPS_CLAIM: "urn:zitadel:iam:org:project:roles" }),
    ).admin;
    assert.ok(c);
    return c;
  };
  it("accepts object-valued role claims (Zitadel) and case-insensitive e-mail", () => {
    assert.equal(
      authorize({ sub: "x", "urn:zitadel:iam:org:project:roles": { b: {} } }, cfg()).ok,
      true,
    );
    assert.equal(authorize({ sub: "x", email: "ADMIN@example.com" }, cfg()).ok, true);
    assert.equal(
      authorize({ sub: "x", email: "admin@example.com", email_verified: "false" }, cfg()).ok,
      false,
    );
  });
});

describe("admin request protection", () => {
  it("rejects POSTs without CSRF token, with a foreign Origin or wrong content type", async () => {
    t = await startAdminApp();
    const { cookie } = await t.login();
    assert.ok(cookie);
    const csrf = t.csrfOf((await t.req("/admin", { cookie })).text);
    const form = { action: "pause_sending", step: "review", reason: "testing" };
    assert.equal((await t.req("/admin/action", { cookie, form })).status, 403, "no csrf");
    assert.equal(
      (await t.req("/admin/action", { cookie, form: { ...form, csrf: `${csrf}x` } })).status,
      403,
      "bad csrf",
    );
    assert.equal(
      (
        await t.req("/admin/action", {
          cookie,
          form: { ...form, csrf },
          headers: { origin: "https://evil.example.com" },
        })
      ).status,
      403,
      "foreign origin",
    );
    assert.equal(
      (
        await t.req("/admin/action", {
          cookie,
          form: { ...form, csrf },
          headers: { origin: "null" },
        })
      ).status,
      403,
      "opaque origin",
    );
    const noOrigin = await fetch(`${t.url}/admin/action`, {
      method: "POST",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ ...form, csrf }).toString(),
    });
    assert.equal(noOrigin.status, 403, "missing origin");
    assert.equal(
      (
        await t.req("/admin/action", {
          cookie,
          form: { ...form, csrf },
          headers: { "sec-fetch-site": "cross-site" },
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await t.req("/admin/action", {
          cookie,
          form: { ...form, csrf },
          headers: { "content-type": "application/json" },
        })
      ).status,
      415,
    );
    assert.equal(
      (await t.req("/admin/action", { form: { ...form, csrf } })).status,
      401,
      "no session",
    );
    assert.equal(t.app.store.getPause(), null, "nothing happened");
    assert.equal(
      (await t.req("/admin/action", { cookie, form: { ...form, csrf } })).status,
      200,
      "valid review",
    );
  });

  it("restricts /admin to ADMIN_ALLOWED_IPS (404 for others) using the trusted client IP", async () => {
    t = await startAdminApp({ env: { ADMIN_ALLOWED_IPS: "203.0.113.0/24", TRUST_PROXY: "1" } });
    assert.equal((await t.req("/admin")).status, 404);
    assert.equal((await t.req("/admin/login")).status, 404);
    assert.equal(
      (await t.req("/admin", { headers: { "x-forwarded-for": "203.0.113.9" } })).status,
      200,
    );
    // A spoofed leftmost entry is not trusted with one proxy hop.
    assert.equal(
      (await t.req("/admin", { headers: { "x-forwarded-for": "203.0.113.9, 198.51.100.1" } }))
        .status,
      404,
    );
    // The relay API is not affected.
    assert.equal((await t.req("/healthz")).status, 200);
  });
});

describe("admin actions", () => {
  const ORIGIN = "https://abuse.example.com";

  it("blocks and unblocks an instance with confirmation, reason and audit entry", async () => {
    t = await startAdminApp();
    const { cookie } = await t.login();
    assert.ok(cookie);
    const { review, final } = await t.act(cookie, "block_instance", {
      origin: "https://Abuse.Example.com/",
      duration: "24h",
      reason: "spam wave",
    });
    assert.equal(review.status, 200);
    assert.match(review.text, /Confirm: Block instance/);
    assert.match(review.text, /https:\/\/abuse\.example\.com/, "normalised origin shown");
    assert.equal(final.status, 303);
    assert.match(final.headers.get("location") ?? "", /^\/admin\?done=\d+$/);
    assert.equal(t.app.store.isBlocked(ORIGIN), true);
    const b = t.app.store.listBlocked()[0];
    assert.equal(b?.createdBy, "admin@example.com");
    assert.equal(b?.reason, "spam wave");
    assert.ok(b?.expiresAt && b.expiresAt > Date.now() / 1000 + 86000);
    const e = t.app.actions.listAudit(1)[0];
    assert.equal(e?.action, "block_instance");
    assert.equal(e?.target, ORIGIN);
    assert.equal(e?.reason, "spam wave");
    assert.equal(e?.actor, "admin@example.com");
    assert.equal(e?.actorSub, "admin-sub");
    assert.equal(e?.ip, "127.0.0.1");

    const done = await t.req(final.headers.get("location") ?? "", { cookie });
    assert.match(done.text, /Done \(audit #\d+\): block_instance https:\/\/abuse\.example\.com/);
    assert.match(done.text, /spam wave/);

    const un = await t.act(cookie, "unblock_instance", { origin: ORIGIN, reason: "resolved" });
    assert.equal(un.final.status, 303);
    assert.equal(t.app.store.isBlocked(ORIGIN), false);
    assert.equal(t.app.actions.listAudit(1)[0]?.action, "unblock_instance");
  });

  it("requires a reason and valid input", async () => {
    t = await startAdminApp();
    const { cookie } = await t.login();
    assert.ok(cookie);
    assert.equal(
      (await t.act(cookie, "block_instance", { origin: ORIGIN, duration: "permanent", reason: "" }))
        .review.status,
      400,
    );
    assert.equal(
      (await t.act(cookie, "block_instance", { origin: "javascript:alert(1)", reason: "xx bad" }))
        .review.status,
      400,
    );
    assert.equal(
      (await t.act(cookie, "block_instance", { origin: ORIGIN, duration: "99y", reason: "spam" }))
        .review.status,
      400,
    );
    assert.equal(
      (await t.act(cookie, "block_ip", { cidr: "0.0.0.0/0", duration: "1h", reason: "everyone" }))
        .review.status,
      400,
    );
    assert.equal(
      (
        await t.act(cookie, "block_ip", {
          cidr: "203.0.113.0/24",
          duration: "permanent",
          reason: "spam",
        })
      ).review.status,
      400,
    );
    assert.equal((await t.act(cookie, "drop_database", { reason: "nope" })).review.status, 400);
    assert.equal((await t.act(cookie, "__proto__", { reason: "nope" })).review.status, 400);
  });

  it("refuses tampered or expired confirmations", async () => {
    t = await startAdminApp();
    const { cookie } = await t.login();
    assert.ok(cookie);
    const csrf = t.csrfOf((await t.req("/admin", { cookie })).text);
    const review = await t.req("/admin/action", {
      cookie,
      form: {
        csrf,
        action: "block_instance",
        step: "review",
        origin: ORIGIN,
        duration: "1h",
        reason: "spam",
      },
    });
    const token = /name="confirm" value="([^"]+)"/.exec(review.text)?.[1] ?? "";
    const exec = (f: Record<string, string>) =>
      t?.req("/admin/action", {
        cookie,
        form: { csrf, action: "block_instance", step: "execute", ...f },
      });
    assert.equal(
      (
        await exec({
          confirm: token,
          origin: "https://other.example.com",
          duration: "1h",
          reason: "spam",
        })
      )?.status,
      400,
    );
    assert.equal(
      (await exec({ confirm: token, origin: ORIGIN, duration: "permanent", reason: "spam" }))
        ?.status,
      400,
    );
    assert.equal(
      (await exec({ origin: ORIGIN, duration: "1h", reason: "spam" }))?.status,
      400,
      "no token",
    );
    const expired = `${Math.floor(Date.now() / 1000) - 1}.${token.split(".")[1]}`;
    assert.equal(
      (await exec({ confirm: expired, origin: ORIGIN, duration: "1h", reason: "spam" }))?.status,
      400,
    );
    assert.equal(t.app.store.isBlocked(ORIGIN), false);
    assert.equal(
      (await exec({ confirm: token, origin: ORIGIN, duration: "1h", reason: "spam" }))?.status,
      303,
    );
    assert.equal(t.app.store.isBlocked(ORIGIN), true);
  });

  it("deletes all registrations of an instance", async () => {
    t = await startAdminApp();
    const { cookie } = await t.login();
    assert.ok(cookie);
    for (let i = 0; i < 3; i++) {
      t.app.store.register({
        platform: "ios",
        environment: "production",
        bundleId: BUNDLE,
        instance: ORIGIN,
        deviceToken: apnsToken(),
      });
    }
    t.app.store.register({
      platform: "ios",
      environment: "production",
      bundleId: BUNDLE,
      instance: "https://keep.example.com",
      deviceToken: apnsToken(),
    });
    const r = await t.act(cookie, "delete_instance", { origin: ORIGIN, reason: "abuse" });
    assert.equal(r.final.status, 303);
    assert.equal(t.app.store.instanceHasDevices(ORIGIN), false);
    assert.equal(t.app.store.deviceCount(), 1);
    const e = t.app.actions.listAudit(1)[0];
    assert.equal(e?.action, "delete_instance");
    assert.deepEqual(e?.details, { deleted: 3 });
  });

  it("blocks an IP range for registrations (temporary) and unblocks it", async () => {
    t = await startAdminApp();
    const { cookie } = await t.login();
    assert.ok(cookie);
    const r = await t.act(cookie, "block_ip", {
      cidr: "127.0.0.1",
      duration: "1h",
      reason: "registration flood",
    });
    assert.equal(r.final.status, 303);
    const blocked = t.app.store.listBlockedIps()[0];
    assert.equal(blocked?.cidr, "127.0.0.1/32");
    assert.ok(blocked && blocked.expiresAt <= Date.now() / 1000 + 3601);
    const reg = await fetch(`${t.url}/v1/devices`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        platform: "ios",
        token: apnsToken(),
        environment: "production",
        bundleId: BUNDLE,
        instance: "https://app.example.com",
      }),
    });
    assert.equal(reg.status, 403);
    assert.deepEqual(await reg.json(), { error: "ip_blocked" });
    assert.equal(t.app.actions.listAudit(1)[0]?.action, "block_ip");
    const un = await t.act(cookie, "unblock_ip", { cidr: "127.0.0.1/32", reason: "flood over" });
    assert.equal(un.final.status, 303);
    assert.equal(t.app.store.listBlockedIps().length, 0);
  });

  it("pauses and resumes all sending (kill switch)", async () => {
    t = await startAdminApp();
    const { cookie } = await t.login();
    assert.ok(cookie);
    const send = () =>
      fetch(`${t?.url}/v1/send`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "flowplan-instance": "https://app.example.com",
          "flowplan-signature": "x",
        },
        body: "{}",
      });
    assert.notEqual((await send()).status, 503);
    const p = await t.act(cookie, "pause_sending", { reason: "APNs key leaked" });
    assert.equal(p.final.status, 303);
    const r = await send();
    assert.equal(r.status, 503);
    assert.equal(r.headers.get("retry-after"), "300");
    assert.deepEqual(await r.json(), { error: "relay_paused", retryAfter: 300 });
    const dash = await t.req("/admin", { cookie });
    assert.match(dash.text, /Sending is paused/);
    assert.match(dash.text, /APNs key leaked/);
    const metrics = t.app.metrics.registry.render();
    assert.match(metrics, /flowplan_push_sending_paused 1/);
    const res = await t.act(cookie, "resume_sending", { reason: "key rotated" });
    assert.equal(res.final.status, 303);
    assert.notEqual((await send()).status, 503);
    const actions = t.app.actions.listAudit(3).map((e) => e.action);
    assert.deepEqual(actions.slice(0, 2), ["resume_sending", "pause_sending"]);
  });

  it("purges expired registrations now", async () => {
    t = await startAdminApp();
    const { cookie } = await t.login();
    assert.ok(cookie);
    t.app.store.register({
      platform: "ios",
      environment: "production",
      bundleId: BUNDLE,
      instance: ORIGIN,
      deviceToken: apnsToken(),
    });
    t.app.store.db.prepare("UPDATE devices SET expires_at = 1").run();
    const r = await t.act(cookie, "purge_expired", { reason: "cleanup" });
    assert.equal(r.final.status, 303);
    assert.equal(t.app.store.deviceCount(), 0);
    assert.deepEqual(t.app.actions.listAudit(1)[0]?.details, { purged: 1 });
  });

  it("keeps the audit log append-only", async () => {
    t = await startAdminApp();
    t.app.actions.audit({ id: "x", sub: null, ip: null }, "test", null, null);
    assert.throws(
      () => t?.app.store.db.prepare("UPDATE admin_audit SET actor = 'y'").run(),
      /append-only/,
    );
    assert.throws(() => t?.app.store.db.prepare("DELETE FROM admin_audit").run(), /append-only/);
    const page = await t.login().then((l) => t?.req("/admin/audit", { cookie: l.cookie }));
    assert.equal(page?.status, 200);
    assert.match(page?.text ?? "", /<span class="tag">test<\/span>/);
  });
});

describe("dashboard content", () => {
  it("shows live data and never renders secrets, tokens or device ids", async () => {
    t = await startAdminApp();
    const deviceTokens: string[] = [];
    const relayTokens: string[] = [];
    for (let i = 0; i < 5; i++) {
      const dt = apnsToken();
      deviceTokens.push(dt);
      const r = t.app.store.register({
        platform: "ios",
        environment: "production",
        bundleId: BUNDLE,
        instance: "https://app.example.com",
        deviceToken: dt,
      });
      relayTokens.push(r.relayToken);
      t.app.stats.registration({
        instance: "https://app.example.com",
        platform: "ios",
        deviceId: "abcdef0123",
        ip: "198.51.100.23",
      });
    }
    t.app.stats.message({ instance: "https://app.example.com", platform: "ios", status: "ok" });
    t.app.stats.message({
      instance: "https://app.example.com",
      platform: "android",
      status: "error",
      reason: "UNAVAILABLE",
    });
    t.app.stats.authFailure({
      reason: "invalid_signature",
      instance: "https://app.example.com",
      ip: "198.51.100.23",
    });
    t.app.stats.rateLimited({ scope: "register_ip", instance: null });
    t.app.store.block("https://bad.example.com", "spam", { by: "ops@example.com" });

    const login = await t.login();
    const cookie = login.cookie;
    assert.ok(cookie);
    const sessionId = cookie.split("=")[1] ?? "";
    const pages = [
      await t.req("/admin", { cookie }),
      await t.req(`/admin/instance?origin=${encodeURIComponent("https://app.example.com")}`, {
        cookie,
      }),
      await t.req("/admin/api/summary", { cookie }),
      await t.req(`/admin/api/instance?origin=${encodeURIComponent("https://app.example.com")}`, {
        cookie,
      }),
      await t.req("/admin/audit", { cookie }),
    ];
    for (const p of pages) assert.equal(p.status, 200);
    const all = pages.map((p) => p.text).join("\n");
    const secrets = [
      ...deviceTokens,
      ...relayTokens,
      CLIENT_SECRET,
      t.config.storageKey.toString("base64"),
      sessionId,
      login.code,
      "198.51.100.23", // full client IPs of relay users are never shown (truncated)
    ];
    for (const s of secrets) assert.ok(!all.includes(s), `leaked: ${s.slice(0, 12)}…`);
    assert.ok(!all.includes("eyJ"), "no JWTs");

    const [dash, inst, api] = pages;
    assert.match(dash?.text ?? "", /https:\/\/app\.example\.com/);
    assert.match(dash?.text ?? "", /https:\/\/bad\.example\.com/);
    assert.match(dash?.text ?? "", /ops@example\.com/);
    assert.match(dash?.text ?? "", /invalid_signature/);
    assert.match(dash?.text ?? "", /<svg class="spark/);
    assert.match(inst?.text ?? "", /198\.51\.100\.0/, "truncated IP in events");
    assert.match(inst?.text ?? "", /abcdef0123/, "hashed short device id");
    const j = JSON.parse(api?.text ?? "{}");
    assert.equal(j.devices.total, 5);
    assert.equal(j.messages.lastHour.ok, 1);
    assert.equal(j.messages.lastHour.error, 1);
    assert.equal(j.messages.perMinute.length, 60);
    assert.equal(j.authFailures.lastHour.invalid_signature, 1);
    assert.equal(j.providers.fcm.lastErrorReason, "UNAVAILABLE");
    assert.equal(j.top[0].instance, "https://app.example.com");
    assert.equal(j.top[0].devices, 5);
    assert.equal(api?.headers.get("cache-control"), "no-store");
  });

  it("escapes attacker-influenced values (instance origins, reasons)", async () => {
    t = await startAdminApp();
    t.app.store.block("https://x.example.com", `<img src=x onerror=alert(1)>"'`, {
      by: "<b>me</b>",
    });
    const { cookie } = await t.login();
    const dash = await t.req("/admin", { cookie });
    assert.ok(!dash.text.includes("<img src=x"));
    assert.ok(!dash.text.includes("<b>me</b>"));
    assert.match(dash.text, /&lt;img src=x onerror=alert\(1\)&gt;&quot;&#39;/);
  });
});

describe("admin CLI shares the actions", () => {
  it("block/pause/resume/audit through the CLI write audit entries", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "fp-cli-"));
    try {
      const env = {
        ...process.env,
        RELAY_STORAGE_KEY: randomKey().toString("base64"),
        DATA_DIR: dir,
        LOG_LEVEL: "silent",
      };
      const run = (...args: string[]) =>
        execFileSync(
          process.execPath,
          ["--disable-warning=ExperimentalWarning", "src/cli.ts", ...args],
          {
            env,
            encoding: "utf8",
          },
        );
      assert.match(
        run("block", "https://abuse.example.com", "sent", "spam"),
        /blocked https:\/\/abuse\.example\.com/,
      );
      assert.match(run("blocked"), /abuse\.example\.com\t.*\tsent spam/);
      assert.match(run("block-ip", "203.0.113.0/24", "24h", "flood"), /blocked 203\.0\.113\.0\/24/);
      assert.match(run("blocked-ips"), /203\.0\.113\.0\/24/);
      assert.match(run("pause", "incident"), /paused/);
      assert.match(run("status"), /PAUSED/);
      assert.match(run("resume"), /resumed/);
      const audit = run("audit");
      for (const a of ["block_instance", "block_ip", "pause_sending", "resume_sending"])
        assert.match(audit, new RegExp(a));
      assert.match(audit, /\bcli\b/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

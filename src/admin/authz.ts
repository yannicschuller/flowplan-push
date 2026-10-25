import type { AdminConfig } from "../config.ts";
import { getClaim, type IdTokenClaims } from "./oidc.ts";

/** What the provider sent, for the denial page: only the person's own sign-in. */
export type AuthzDiagnostics = {
  sub: string;
  email: string | null;
  emailVerified: boolean | null;
  groupsClaim: string;
  groupsPresent: boolean;
  groups: string[];
};

export type AuthzResult =
  | { ok: true; via: "email" | "subject" | "group"; email: string | null; name: string | null }
  | { ok: false; reason: string; diagnostics: AuthzDiagnostics };

/** Normalises a groups/roles claim: array of strings, a single string, or an object keyed by role. */
export function claimValues(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  if (value && typeof value === "object") return Object.keys(value);
  return [];
}

/**
 * A group from the token matches a configured one regardless of case and of
 * a leading slash (Keycloak sends group paths like "/admins").
 */
export function groupMatches(found: string, wanted: string): boolean {
  const norm = (g: string) => g.trim().replace(/^\/+/, "").toLowerCase();
  const w = norm(wanted);
  return w !== "" && norm(found) === w;
}

function emailVerified(claims: IdTokenClaims): boolean {
  if (!("email_verified" in claims) || claims.email_verified === undefined) return true;
  return claims.email_verified === true || claims.email_verified === "true";
}

/**
 * A user is an admin if ANY configured rule matches:
 *   - ADMIN_SUBJECTS contains `sub` (most robust: subjects never change)
 *   - ADMIN_EMAILS contains `email` (case-insensitive) and `email_verified`
 *     is true or absent (if the claim is present and not true, e-mail does not count)
 *   - the ADMIN_GROUPS_CLAIM claim contains one of ADMIN_GROUPS
 */
export function authorize(claims: IdTokenClaims, cfg: AdminConfig): AuthzResult {
  const email = typeof claims.email === "string" ? claims.email.toLowerCase().slice(0, 254) : null;
  const nameClaim = claims.name ?? claims.preferred_username;
  const name = typeof nameClaim === "string" ? nameClaim.slice(0, 120) : null;

  if (cfg.subjects.includes(claims.sub)) return { ok: true, via: "subject", email, name };
  if (email && cfg.emails.includes(email)) {
    if (emailVerified(claims)) return { ok: true, via: "email", email, name };
  }
  if (cfg.groups.length > 0) {
    const groups = claimValues(getClaim(claims, cfg.groupsClaim));
    if (groups.some((g) => cfg.groups.some((w) => groupMatches(g, w))))
      return { ok: true, via: "group", email, name };
  }
  const raw = getClaim(claims, cfg.groupsClaim);
  const diagnostics: AuthzDiagnostics = {
    sub: String(claims.sub).slice(0, 255),
    email,
    emailVerified: "email_verified" in claims ? emailVerified(claims) : null,
    groupsClaim: cfg.groupsClaim,
    groupsPresent: raw !== undefined,
    groups: claimValues(raw)
      .slice(0, 20)
      .map((g) => g.slice(0, 80)),
  };
  if (email && cfg.emails.includes(email))
    return { ok: false, reason: "email_not_verified", diagnostics };
  return { ok: false, reason: "not_an_admin", diagnostics };
}

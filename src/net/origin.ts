import { isIP } from "node:net";
import { isAllowedAddress } from "./ip.ts";

const MAX_ORIGIN_LENGTH = 255;

export function isLocalhostName(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h.endsWith(".localhost") || h === "127.0.0.1" || h === "::1";
}

/**
 * Validates an instance origin and returns its canonical form
 * (`scheme://host[:port]`, lower-case host, default port removed), or null.
 *
 * - https only; http only for localhost names when private instances are allowed
 * - no credentials, path, query or fragment (a single trailing "/" is tolerated)
 * - IP literals must pass the SSRF address policy
 * - host names need at least one dot (except localhost in development)
 */
export function canonicalOrigin(input: unknown, allowPrivate: boolean): string | null {
  if (typeof input !== "string" || input.length === 0 || input.length > MAX_ORIGIN_LENGTH)
    return null;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters on purpose
  if (/[\s\u0000-\u001f\u007f\\]/.test(input)) return null;
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.username || url.password || url.search || url.hash) return null;
  if (url.pathname !== "/" || /[?#]/.test(input)) return null;
  // Reject inputs that only become an origin through normalisation tricks
  // (e.g. "https:example.com"); the canonical output is what is used anyway.
  if (!/^https?:\/\/[^/]/i.test(input)) return null;

  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (url.protocol === "http:") {
    if (!(allowPrivate && isLocalhostName(host))) return null;
  } else if (url.protocol !== "https:") {
    return null;
  }

  if (isIP(host)) {
    if (!isAllowedAddress(host, allowPrivate)) return null;
  } else {
    if (!/^[a-z0-9.-]+$/.test(host)) return null; // URL() already punycodes IDNs
    if (host.startsWith(".") || host.endsWith(".") || host.includes("..")) return null;
    if (!host.includes(".") && !(allowPrivate && isLocalhostName(host))) return null;
    if (
      !allowPrivate &&
      (isLocalhostName(host) || host.endsWith(".local") || host.endsWith(".internal"))
    ) {
      return null;
    }
  }
  return url.origin;
}

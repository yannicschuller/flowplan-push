import { lookup as dnsLookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { isAllowedAddress } from "./ip.ts";
import { isLocalhostName } from "./origin.ts";

/**
 * SSRF-safe HTTP GET used to fetch `/.well-known/flowplan-push`.
 *
 * - https only (http only for localhost names when private instances are allowed)
 * - the host name is resolved once; every returned address must pass the
 *   address policy, and the connection is pinned to that address (no second
 *   DNS lookup → no DNS rebinding between check and connect)
 * - redirects are followed only within the same origin (max 3)
 * - overall timeout (default 5 s) and response size limit (default 16 KB)
 * - no cookies, no credentials, no connection reuse
 */

export type SafeFetchErrorCode =
  | "bad_url"
  | "scheme_not_allowed"
  | "address_not_allowed"
  | "dns_failed"
  | "cross_origin_redirect"
  | "too_many_redirects"
  | "too_large"
  | "timeout"
  | "network";

export class SafeFetchError extends Error {
  readonly code: SafeFetchErrorCode;
  constructor(code: SafeFetchErrorCode, message?: string) {
    super(message ?? code);
    this.code = code;
  }
}

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export type Resolver = (hostname: string) => Promise<ResolvedAddress[]>;

export const systemResolver: Resolver = async (hostname) => {
  const res = await dnsLookup(hostname, { all: true, verbatim: true });
  return res.map((r) => ({ address: r.address, family: r.family === 6 ? 6 : 4 }));
};

export interface SafeFetchOptions {
  allowPrivate: boolean;
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  resolver?: Resolver;
  /** Extra TLS options (tests only, e.g. a custom CA). */
  tls?: { ca?: string | Buffer };
}

export interface SafeFetchResponse {
  status: number;
  contentType: string;
  body: Buffer;
  /** Address the response actually came from (after pinning). */
  address: string;
}

async function resolvePinned(url: URL, opts: SafeFetchOptions): Promise<ResolvedAddress> {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const literal = isIP(host);
  if (literal) {
    if (!isAllowedAddress(host, opts.allowPrivate)) throw new SafeFetchError("address_not_allowed");
    return { address: host, family: literal === 6 ? 6 : 4 };
  }
  let addrs: ResolvedAddress[];
  try {
    addrs = await (opts.resolver ?? systemResolver)(host);
  } catch {
    throw new SafeFetchError("dns_failed");
  }
  if (addrs.length === 0) throw new SafeFetchError("dns_failed");
  // All records must be acceptable – otherwise an attacker could mix a public
  // and a private record and hope the private one gets picked.
  for (const a of addrs) {
    if (!isAllowedAddress(a.address, opts.allowPrivate))
      throw new SafeFetchError("address_not_allowed");
  }
  return addrs[0] as ResolvedAddress;
}

function checkScheme(url: URL, allowPrivate: boolean): void {
  if (url.username || url.password) throw new SafeFetchError("bad_url");
  if (url.protocol === "https:") return;
  if (url.protocol === "http:" && allowPrivate && isLocalhostName(url.hostname)) return;
  throw new SafeFetchError("scheme_not_allowed");
}

function requestOnce(
  url: URL,
  pinned: ResolvedAddress,
  opts: SafeFetchOptions,
  signal: AbortSignal,
): Promise<{ status: number; location: string | undefined; contentType: string; body: Buffer }> {
  const maxBytes = opts.maxBytes ?? 16 * 1024;
  const pinnedLookup: LookupFunction = (_hostname, options, cb) => {
    if (options && typeof options === "object" && options.all) {
      // biome-ignore lint/suspicious/noExplicitAny: node's overloaded callback signature
      (cb as any)(null, [{ address: pinned.address, family: pinned.family }]);
    } else {
      cb(null, pinned.address, pinned.family);
    }
  };
  const isHttps = url.protocol === "https:";
  const lib = isHttps ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        protocol: url.protocol,
        hostname: url.hostname.replace(/^\[|\]$/g, ""),
        port: url.port || (isHttps ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: "GET",
        agent: false,
        lookup: pinnedLookup,
        signal,
        headers: {
          accept: "application/json",
          "user-agent": "flowplan-push-relay/1 (+https://github.com/yannicschuller/flowplan-push)",
          "accept-encoding": "identity",
        },
        ...(isHttps
          ? { minVersion: "TLSv1.2" as const, rejectUnauthorized: true, ...(opts.tls ?? {}) }
          : {}),
      },
      (res) => {
        const status = res.statusCode ?? 0;
        const location =
          typeof res.headers.location === "string" ? res.headers.location : undefined;
        const contentType = String(res.headers["content-type"] ?? "");
        const declared = Number(res.headers["content-length"] ?? "0");
        if (declared > maxBytes) {
          res.destroy();
          reject(new SafeFetchError("too_large"));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxBytes) {
            res.destroy();
            reject(new SafeFetchError("too_large"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () =>
          resolve({ status, location, contentType, body: Buffer.concat(chunks) }),
        );
        res.on("error", (err) =>
          reject(
            signal.aborted
              ? new SafeFetchError("timeout")
              : new SafeFetchError("network", err.message),
          ),
        );
      },
    );
    req.on("error", (err) =>
      reject(
        signal.aborted ? new SafeFetchError("timeout") : new SafeFetchError("network", err.message),
      ),
    );
    req.end();
  });
}

export async function safeFetch(input: string, opts: SafeFetchOptions): Promise<SafeFetchResponse> {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new SafeFetchError("bad_url");
  }
  const origin = url.origin;
  const maxRedirects = opts.maxRedirects ?? 3;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 5000);
  const abortable = <T>(p: Promise<T>): Promise<T> =>
    new Promise<T>((resolve, reject) => {
      const onAbort = () => reject(new SafeFetchError("timeout"));
      if (controller.signal.aborted) return onAbort();
      controller.signal.addEventListener("abort", onAbort, { once: true });
      p.then(resolve, reject).finally(() =>
        controller.signal.removeEventListener("abort", onAbort),
      );
    });
  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      checkScheme(url, opts.allowPrivate);
      const pinned = await abortable(resolvePinned(url, opts));
      const res = await abortable(requestOnce(url, pinned, opts, controller.signal));
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        if (!res.location) throw new SafeFetchError("network", "redirect without location");
        let next: URL;
        try {
          next = new URL(res.location, url);
        } catch {
          throw new SafeFetchError("bad_url");
        }
        if (next.origin !== origin) throw new SafeFetchError("cross_origin_redirect");
        url = next;
        continue;
      }
      return {
        status: res.status,
        contentType: res.contentType,
        body: res.body,
        address: pinned.address,
      };
    }
    throw new SafeFetchError("too_many_redirects");
  } finally {
    clearTimeout(timer);
  }
}

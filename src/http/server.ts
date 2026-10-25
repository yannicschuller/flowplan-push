import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { safeEqual } from "../crypto/encoding.ts";
import type { Logger } from "../log.ts";
import type { RelayMetrics } from "../metrics.ts";
import { MAX_REGISTER_BODY_BYTES, MAX_SEND_BODY_BYTES } from "../protocol.ts";
import type { HttpResult, Relay } from "../relay.ts";

/** Handles everything under /admin (see src/admin/handler.ts). */
export interface AdminRoute {
  handle(req: IncomingMessage, method: string, url: URL, ip: string): Promise<HttpResult>;
}

export interface ServerDeps {
  relay: Relay;
  metrics: RelayMetrics;
  logger: Logger;
  metricsToken: string | null;
  trustProxyHops: number;
  hsts: boolean;
  healthCheck?: () => boolean;
  /** Admin dashboard; null/undefined = disabled, /admin answers 404. */
  admin?: AdminRoute | null;
}

const SECURITY_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "content-security-policy":
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "cross-origin-resource-policy": "same-origin",
  "cross-origin-opener-policy": "same-origin",
  "permissions-policy": "interest-cohort=(), camera=(), microphone=(), geolocation=()",
  "x-robots-tag": "noindex, nofollow",
};

class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

/**
 * Client IP: the socket address, or – behind `trustProxyHops` reverse proxies
 * (one Traefik/Caddy/nginx in front = 1) – the address that many hops back in
 * X-Forwarded-For. Entries added by the client itself are never trusted.
 */
export function clientIp(req: IncomingMessage, trustProxyHops: number): string {
  const socketIp = req.socket.remoteAddress ?? "0.0.0.0";
  if (trustProxyHops <= 0) return socketIp;
  const header = req.headers["x-forwarded-for"];
  const raw = Array.isArray(header) ? header.join(",") : (header ?? "");
  const chain = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  // chain = [client, proxy1, …]; the last proxy appended the socket peer of the
  // previous one. With N trusted hops the client is the N-th entry from the end.
  const candidate = chain[chain.length - trustProxyHops];
  return candidate && isIP(candidate) ? candidate : socketIp;
}

function send(res: ServerResponse, result: HttpResult, hsts: boolean): void {
  if (res.headersSent) return;
  const headers: Record<string, string | string[]> = {
    ...SECURITY_HEADERS,
    ...(result.headers ?? {}),
  };
  if (hsts) headers["strict-transport-security"] = "max-age=63072000; includeSubDomains";
  let payload: string | undefined;
  if (result.body !== undefined) {
    payload = typeof result.body === "string" ? result.body : JSON.stringify(result.body);
    headers["content-type"] ??= "application/json; charset=utf-8";
    headers["content-length"] = String(Buffer.byteLength(payload));
  }
  res.writeHead(result.status, headers);
  res.end(payload);
}

function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const ctype = String(req.headers["content-type"] ?? "").toLowerCase();
    if (!/^application\/json\s*(;\s*charset=utf-8\s*)?$/.test(ctype)) {
      reject(new HttpError(415, "unsupported_media_type"));
      return;
    }
    const declared = req.headers["content-length"];
    if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > limit)) {
      reject(new HttpError(413, "payload_too_large"));
      return;
    }
    const encoding = req.headers["content-encoding"];
    if (encoding && encoding !== "identity") {
      reject(new HttpError(415, "unsupported_content_encoding"));
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on("data", (c: Buffer) => {
      if (done) return;
      size += c.length;
      if (size > limit) {
        done = true;
        reject(new HttpError(413, "payload_too_large"));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks));
    });
    req.on("error", () => {
      if (done) return;
      done = true;
      reject(new HttpError(400, "bad_request"));
    });
  });
}

function routeName(method: string, path: string): string {
  if (path === "/healthz") return "healthz";
  if (path === "/metrics") return "metrics";
  if (path === "/v1/send") return "send";
  if (path === "/v1/devices") return "register";
  if (path.startsWith("/v1/devices/")) return "unregister";
  if (path === "/admin" || path.startsWith("/admin/")) return "admin";
  return method === "GET" ? "not_found" : "other";
}

export function createRequestHandler(deps: ServerDeps) {
  const { relay, metrics, logger, hsts } = deps;

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const method = req.method ?? "GET";
    const rawUrl = req.url ?? "/";
    let path: string;
    let url: URL;
    try {
      if (rawUrl.length > 2048 || !rawUrl.startsWith("/")) throw new Error();
      url = new URL(rawUrl, "http://relay.invalid");
      path = url.pathname;
    } catch {
      send(res, { status: 400, body: { error: "bad_request" } }, hsts);
      return;
    }
    const route = routeName(method, path);
    let result: HttpResult;
    try {
      result = await dispatch(method, path, url, req);
    } catch (e) {
      if (e instanceof HttpError) {
        result = { status: e.status, body: { error: e.code } };
        if (e.status === 413) result.headers = { connection: "close" };
      } else {
        logger.error("unhandled error", { route, error: e });
        result = { status: 500, body: { error: "internal_error" } };
      }
    }
    metrics.httpRequests({ route, status: String(result.status) });
    send(res, result, hsts);
    if (result.status === 413 || result.status === 415) {
      // Do not keep reading an unwanted upload.
      req.unpipe();
      res.on("finish", () => req.destroy());
    }
  };

  async function dispatch(
    method: string,
    path: string,
    url: URL,
    req: IncomingMessage,
  ): Promise<HttpResult> {
    const ip = clientIp(req, deps.trustProxyHops);

    if (path === "/admin" || path.startsWith("/admin/")) {
      if (!deps.admin) {
        req.resume();
        return notFound();
      }
      return deps.admin.handle(req, method, url, ip);
    }

    if (path === "/healthz") {
      if (method !== "GET" && method !== "HEAD") return methodNotAllowed("GET, HEAD");
      const ok = deps.healthCheck ? deps.healthCheck() : true;
      return { status: ok ? 200 : 503, body: { status: ok ? "ok" : "unavailable" } };
    }

    if (path === "/metrics") {
      if (!deps.metricsToken) return notFound();
      if (method !== "GET") return methodNotAllowed("GET");
      const auth = String(req.headers.authorization ?? "");
      const presented = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      if (!safeEqual(presented, deps.metricsToken)) {
        return {
          status: 401,
          body: { error: "unauthorized" },
          headers: { "www-authenticate": "Bearer" },
        };
      }
      return {
        status: 200,
        body: metrics.registry.render(),
        headers: { "content-type": "text/plain; version=0.0.4; charset=utf-8" },
      };
    }

    if (path === "/v1/devices") {
      if (method !== "POST") return methodNotAllowed("POST");
      const body = await readBody(req, MAX_REGISTER_BODY_BYTES);
      return relay.register(ip, body);
    }

    const del = /^\/v1\/devices\/([^/]{1,200})$/.exec(path);
    if (del) {
      if (method !== "DELETE") return methodNotAllowed("DELETE");
      req.resume();
      return relay.unregister(ip, decodeURIComponentSafe(del[1] ?? ""));
    }

    if (path === "/v1/send") {
      if (method !== "POST") return methodNotAllowed("POST");
      const body = await readBody(req, MAX_SEND_BODY_BYTES);
      const instance = singleHeader(req, "flowplan-instance");
      const signature = singleHeader(req, "flowplan-signature");
      return relay.send(ip, instance, signature, body);
    }

    req.resume();
    return notFound();
  }
}

function singleHeader(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  return typeof v === "string" ? v : undefined;
}

function decodeURIComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return "";
  }
}

const notFound = (): HttpResult => ({ status: 404, body: { error: "not_found" } });
const methodNotAllowed = (allow: string): HttpResult => ({
  status: 405,
  body: { error: "method_not_allowed" },
  headers: { allow },
});

export function createHttpServer(deps: ServerDeps): http.Server {
  const handler = createRequestHandler(deps);
  const server = http.createServer(
    {
      maxHeaderSize: 16 * 1024,
      requestTimeout: 30_000,
      headersTimeout: 10_000,
      keepAliveTimeout: 5_000,
      // Node ≥ 22: reject requests with both Content-Length and Transfer-Encoding etc.
      insecureHTTPParser: false,
    },
    (req, res) => {
      handler(req, res).catch(() => {
        if (!res.headersSent) {
          res.writeHead(500, {
            "content-type": "application/json; charset=utf-8",
            ...SECURITY_HEADERS,
          });
          res.end('{"error":"internal_error"}');
        }
      });
    },
  );
  server.maxHeadersCount = 64;
  server.maxRequestsPerSocket = 1000;
  server.on("clientError", (_err, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    else socket.destroy();
  });
  return server;
}

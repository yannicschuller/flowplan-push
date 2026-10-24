import { createPublicKey, type KeyObject } from "node:crypto";
import { z } from "zod";
import { decodeBase64Url } from "../crypto/encoding.ts";
import { SafeFetchError, type SafeFetchOptions, safeFetch } from "../net/safeFetch.ts";

/**
 * Fetches and caches instance signing keys from
 * `{instance}/.well-known/flowplan-push` (PROTOCOL §1).
 *
 * - cached for at most 1 hour; stale keys are never used
 * - an unknown kid triggers a re-fetch, at most once per minute per origin
 *   (failed fetches are also throttled → no fetch amplification)
 * - concurrent lookups for the same origin share one fetch
 */

export const WELL_KNOWN_PATH = "/.well-known/flowplan-push";
export const KID_PATTERN = /^[A-Za-z0-9._~:+/=-]{1,128}$/;

const wellKnownSchema = z.object({
  version: z.literal(1),
  keys: z
    .array(
      z.object({
        id: z.string().regex(KID_PATTERN),
        alg: z.string().max(32),
        publicKey: z.string().max(64),
      }),
    )
    .min(1)
    .max(10),
});

export interface WellKnownKey {
  id: string;
  key: KeyObject;
}

export function parseWellKnown(body: Buffer | string): WellKnownKey[] {
  let json: unknown;
  try {
    json = JSON.parse(typeof body === "string" ? body : body.toString("utf8"));
  } catch {
    throw new Error("well-known document is not JSON");
  }
  const doc = wellKnownSchema.parse(json);
  const keys: WellKnownKey[] = [];
  for (const k of doc.keys) {
    if (k.alg !== "Ed25519") continue; // unknown algorithms are ignored (forward compatibility)
    const raw = decodeBase64Url(k.publicKey, 32);
    if (raw?.length !== 32) continue;
    keys.push({
      id: k.id,
      key: createPublicKey({
        key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
        format: "jwk",
      }),
    });
  }
  if (keys.length === 0) throw new Error("well-known document has no usable Ed25519 key");
  return keys;
}

export type KeyLookupResult =
  | { ok: true; key: KeyObject }
  | { ok: false; reason: "unknown_key" | "unreachable"; detail?: string };

interface CacheEntry {
  keys: Map<string, KeyObject> | null; // null = last fetch failed
  fetchedAt: number;
  detail?: string;
}

export interface KeyResolverOptions {
  fetchDocument?: (origin: string) => Promise<WellKnownKey[]>;
  fetchOptions?: SafeFetchOptions;
  now?: () => number;
  ttlMs?: number;
  refetchIntervalMs?: number;
  maxEntries?: number;
  onFetch?: (origin: string, outcome: "ok" | "error", detail?: string) => void;
}

export class InstanceKeyResolver {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inflight = new Map<string, Promise<CacheEntry>>();
  private readonly fetchDocument: (origin: string) => Promise<WellKnownKey[]>;
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly refetchIntervalMs: number;
  private readonly maxEntries: number;
  private readonly onFetch: KeyResolverOptions["onFetch"];

  constructor(opts: KeyResolverOptions = {}) {
    const fetchOptions = opts.fetchOptions ?? { allowPrivate: false };
    this.fetchDocument =
      opts.fetchDocument ??
      (async (origin) => {
        const res = await safeFetch(`${origin}${WELL_KNOWN_PATH}`, {
          timeoutMs: 5000,
          maxBytes: 16 * 1024,
          ...fetchOptions,
        });
        if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
        if (!/^application\/(json|[a-z0-9.+-]*\+json)\b/i.test(res.contentType)) {
          throw new Error("unexpected content type");
        }
        return parseWellKnown(res.body);
      });
    this.now = opts.now ?? Date.now;
    this.ttlMs = opts.ttlMs ?? 60 * 60 * 1000;
    this.refetchIntervalMs = opts.refetchIntervalMs ?? 60 * 1000;
    this.maxEntries = opts.maxEntries ?? 10_000;
    this.onFetch = opts.onFetch;
  }

  async getKey(origin: string, kid: string): Promise<KeyLookupResult> {
    const now = this.now();
    let entry = this.cache.get(origin);
    if (entry && now - entry.fetchedAt < this.ttlMs) {
      const key = entry.keys?.get(kid);
      if (key) return { ok: true, key };
    }
    // Unknown kid, failed or expired entry: re-fetch, but at most once per
    // interval per origin. refetchIntervalMs < ttlMs, so an entry that may
    // not be re-fetched yet is always still fresh.
    if (!entry || now - entry.fetchedAt >= this.refetchIntervalMs) {
      entry = await this.refresh(origin);
    }
    if (!entry.keys) return { ok: false, reason: "unreachable", detail: entry.detail };
    const key = entry.keys.get(kid);
    return key ? { ok: true, key } : { ok: false, reason: "unknown_key" };
  }

  invalidate(origin: string): void {
    this.cache.delete(origin);
  }

  private refresh(origin: string): Promise<CacheEntry> {
    const existing = this.inflight.get(origin);
    if (existing) return existing;
    const p = (async () => {
      let entry: CacheEntry;
      try {
        const keys = await this.fetchDocument(origin);
        entry = { keys: new Map(keys.map((k) => [k.id, k.key])), fetchedAt: this.now() };
        this.onFetch?.(origin, "ok");
      } catch (err) {
        const detail =
          err instanceof SafeFetchError ? err.code : err instanceof Error ? err.message : "error";
        entry = { keys: null, fetchedAt: this.now(), detail: detail.slice(0, 120) };
        this.onFetch?.(origin, "error", entry.detail);
      }
      this.cache.delete(origin);
      this.cache.set(origin, entry);
      while (this.cache.size > this.maxEntries) {
        const oldest = this.cache.keys().next().value;
        if (oldest === undefined) break;
        this.cache.delete(oldest);
      }
      return entry;
    })().finally(() => this.inflight.delete(origin));
    this.inflight.set(origin, p);
    return p;
  }
}

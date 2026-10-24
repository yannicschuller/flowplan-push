import { type KeyObject, verify } from "node:crypto";
import { decodeBase64Url, sha256Hex } from "../crypto/encoding.ts";
import { KID_PATTERN } from "../instance/keys.ts";

/** PROTOCOL §3 request signatures (Ed25519). */

export const SIGNATURE_CONTEXT = "flowplan-push-v1";
export const MAX_CLOCK_SKEW_SECONDS = 300;

export interface ParsedSignature {
  kid: string;
  ts: string;
  tsNum: number;
  sig: Buffer;
  sigText: string;
}

/** Parses `kid=<kid>, ts=<unix seconds>, sig=<base64url>`; returns null on any deviation. */
export function parseSignatureHeader(header: string | undefined): ParsedSignature | null {
  if (typeof header !== "string" || header.length === 0 || header.length > 512) return null;
  const fields = new Map<string, string>();
  for (const part of header.split(",")) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq <= 0) return null;
    const name = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!["kid", "ts", "sig"].includes(name) || fields.has(name)) return null;
    fields.set(name, value);
  }
  const kid = fields.get("kid");
  const ts = fields.get("ts");
  const sigText = fields.get("sig");
  if (!kid || !ts || !sigText) return null;
  if (!KID_PATTERN.test(kid)) return null;
  if (!/^[1-9][0-9]{0,11}$/.test(ts)) return null;
  const sig = decodeBase64Url(sigText, 64);
  if (sig?.length !== 64) return null;
  return { kid, ts, tsNum: Number(ts), sig, sigText: sig.toString("base64url") };
}

export function signingInput(instance: string, ts: string, body: Uint8Array | string): Buffer {
  return Buffer.from(`${SIGNATURE_CONTEXT}\n${instance}\n${ts}\n${sha256Hex(body)}`, "utf8");
}

export function isTimestampFresh(tsSeconds: number, nowMs: number): boolean {
  return Math.abs(nowMs / 1000 - tsSeconds) <= MAX_CLOCK_SKEW_SECONDS;
}

export function verifySignature(
  publicKey: KeyObject,
  instance: string,
  parsed: ParsedSignature,
  body: Uint8Array | string,
): boolean {
  try {
    return verify(null, signingInput(instance, parsed.ts, body), publicKey, parsed.sig);
  } catch {
    return false;
  }
}

/**
 * Remembers accepted signatures until their timestamp leaves the validity
 * window, so an identical request cannot be replayed. Bounded in size; on
 * overflow the oldest entry is evicted (counted via `evictedUnexpired`).
 */
export class ReplayCache {
  private readonly seen = new Map<string, number>(); // sig → expiry (ms)
  private readonly maxEntries: number;
  private readonly now: () => number;
  evictedUnexpired = 0;

  constructor(maxEntries = 100_000, now: () => number = Date.now) {
    this.maxEntries = maxEntries;
    this.now = now;
  }

  /** Returns false if the signature was already seen (replay), otherwise records it. */
  checkAndRemember(sigText: string, tsSeconds: number): boolean {
    const now = this.now();
    const existing = this.seen.get(sigText);
    if (existing !== undefined && existing > now) return false;
    this.sweep(now);
    this.seen.set(sigText, (tsSeconds + MAX_CLOCK_SKEW_SECONDS + 5) * 1000);
    return true;
  }

  get size(): number {
    return this.seen.size;
  }

  private sweep(now: number): void {
    // Entries are inserted roughly in expiry order; drop expired ones from the front.
    for (const [k, exp] of this.seen) {
      if (exp > now && this.seen.size < this.maxEntries) break;
      if (exp > now) this.evictedUnexpired++;
      this.seen.delete(k);
      if (this.seen.size < this.maxEntries && exp > now) break;
    }
  }
}

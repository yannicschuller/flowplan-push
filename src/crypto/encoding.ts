import { createHash, timingSafeEqual } from "node:crypto";

const B64URL = /^[A-Za-z0-9_-]*={0,2}$/;
const B64STD = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Strict base64url decoder. Accepts optional "=" padding, rejects every other
 * character and non-canonical encodings (trailing bits must be zero), so one
 * byte string has exactly one accepted (unpadded) representation.
 */
export function decodeBase64Url(input: string, maxBytes = Number.POSITIVE_INFINITY): Buffer | null {
  if (typeof input !== "string" || !B64URL.test(input)) return null;
  const unpadded = input.replace(/=+$/, "");
  if (unpadded.length % 4 === 1) return null;
  if (input.length !== unpadded.length && input.length % 4 !== 0) return null;
  // Cheap size check before allocating.
  if (Math.floor((unpadded.length * 3) / 4) > maxBytes) return null;
  const buf = Buffer.from(unpadded, "base64url");
  if (buf.toString("base64url") !== unpadded) return null;
  return buf;
}

export function encodeBase64Url(buf: Uint8Array): string {
  return Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength).toString("base64url");
}

/** Strict standard-base64 (or base64url) decoder used for configuration values. */
export function decodeBase64Any(input: string): Buffer | null {
  const s = input.trim();
  if (B64STD.test(s)) {
    const unpadded = s.replace(/=+$/, "");
    if (unpadded.length % 4 === 1) return null;
    const buf = Buffer.from(unpadded, "base64");
    if (buf.toString("base64").replace(/=+$/, "") !== unpadded) return null;
    return buf;
  }
  return decodeBase64Url(s);
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Constant-time string comparison. Both inputs are hashed first so the
 * comparison neither leaks the length nor short-circuits on content.
 */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a, "utf8").digest();
  const hb = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(ha, hb) && a.length === b.length;
}

import { randomBytes } from "node:crypto";
import { sha256Hex } from "./encoding.ts";

/** Relay tokens: 256 random bits, base64url (43 chars). Only their SHA-256 is stored. */
export const RELAY_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function generateRelayToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * SHA-256 is sufficient (no slow KDF needed): the input is a 256-bit random
 * value, so neither brute force nor rainbow tables apply. A database leak
 * therefore does not reveal usable relay tokens.
 */
export function hashRelayToken(token: string): string {
  return sha256Hex(`flowplan-push/relay-token/v1:${token}`);
}

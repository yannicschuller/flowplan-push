import { z } from "zod";
import { decodeBase64Url } from "./crypto/encoding.ts";
import { RELAY_TOKEN_PATTERN } from "./crypto/tokens.ts";

/** Request schemas for PROTOCOL v1 (§2 and §3). Unknown fields are ignored and never forwarded. */

export const MAX_SEND_BODY_BYTES = 512 * 1024;
export const MAX_REGISTER_BODY_BYTES = 8 * 1024;
export const MAX_MESSAGES = 100;
export const MAX_PAYLOAD_BYTES = 3000;
export const MAX_CONTENT_STATE_BYTES = 2048;
export const MAX_TTL_SECONDS = 2_419_200;
/** Envelope: version (1) + ephemeral public key (32) + nonce (12) + GCM tag (16). */
export const MIN_PAYLOAD_BYTES = 1 + 32 + 12 + 16;
export const PAYLOAD_VERSION = 0x01;

// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters on purpose
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
const APNS_TOKEN = /^[0-9a-fA-F]{64,200}$/;
const FCM_TOKEN = /^[A-Za-z0-9_:.-]{32,4096}$/;

export const registerSchema = z
  .object({
    platform: z.enum(["ios", "android", "ios-liveactivity"]),
    token: z.string().min(1).max(4096),
    environment: z.enum(["production", "sandbox"]).nullish(),
    bundleId: z.string().min(1).max(155),
    instance: z.string().min(1).max(255),
  })
  .superRefine((v, ctx) => {
    const ok =
      v.platform === "android"
        ? FCM_TOKEN.test(v.token)
        : APNS_TOKEN.test(v.token) && v.token.length % 2 === 0;
    if (!ok)
      ctx.addIssue({ code: "custom", path: ["token"], message: "invalid device token format" });
  });

export type RegisterRequest = z.infer<typeof registerSchema>;

function jsonBytes(v: unknown): number {
  return Buffer.byteLength(JSON.stringify(v) ?? "", "utf8");
}

const unixSeconds = z.number().int().min(0).max(4_102_444_800); // ≤ year 2100

export const liveActivitySchema = z.object({
  event: z.enum(["update", "end"]),
  contentState: z
    .record(z.string(), z.unknown())
    .refine((v) => jsonBytes(v) <= MAX_CONTENT_STATE_BYTES, "contentState exceeds 2 KB"),
  staleDate: unixSeconds.nullish(),
  dismissalDate: unixSeconds.nullish(),
});

export const messageSchema = z
  .object({
    to: z.string().regex(RELAY_TOKEN_PATTERN),
    type: z.enum(["alert", "background", "liveactivity"]),
    payload: z.string().max(8192).nullish(),
    category: z.enum(["task", "comment", "default"]).nullish(),
    collapseId: z
      .string()
      .min(1)
      .max(64)
      .refine(
        (s) => Buffer.byteLength(s, "utf8") <= 64 && !CONTROL_CHARS.test(s),
        "invalid collapseId",
      )
      .nullish(),
    badge: z.number().int().min(0).max(9999).nullish(),
    priority: z.enum(["high", "normal"]).nullish(),
    ttl: z.number().int().min(0).max(MAX_TTL_SECONDS).nullish(),
    liveActivity: liveActivitySchema.nullish(),
  })
  .superRefine((m, ctx) => {
    if (m.type === "liveactivity") {
      if (!m.liveActivity)
        ctx.addIssue({ code: "custom", path: ["liveActivity"], message: "required" });
      if (m.payload != null)
        ctx.addIssue({ code: "custom", path: ["payload"], message: "not allowed" });
    } else {
      if (m.liveActivity != null)
        ctx.addIssue({ code: "custom", path: ["liveActivity"], message: "not allowed" });
      const decoded = m.payload == null ? null : decodeBase64Url(m.payload, MAX_PAYLOAD_BYTES);
      if (!decoded || decoded.length < MIN_PAYLOAD_BYTES || decoded[0] !== PAYLOAD_VERSION) {
        ctx.addIssue({ code: "custom", path: ["payload"], message: "invalid payload" });
      }
    }
  });

export type Message = z.infer<typeof messageSchema>;

/** Top-level body; messages are validated one by one so a bad message only fails itself. */
export const sendBodySchema = z.object({
  messages: z.array(z.unknown()).min(1).max(MAX_MESSAGES),
});

export type ResultStatus = "ok" | "gone" | "forbidden" | "invalid" | "rate_limited" | "error";

export interface MessageResult {
  status: ResultStatus;
  retryAfter?: number;
}

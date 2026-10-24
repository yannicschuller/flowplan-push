import { decodeBase64Url } from "../crypto/encoding.ts";
import type { DeviceRecord } from "../db.ts";
import { MAX_PAYLOAD_BYTES, type Message } from "../protocol.ts";
import type { ApnsRequest } from "./apns.ts";
import type { FcmMessage } from "./fcm.ts";

/**
 * Translates a protocol message into what reaches Apple / Google
 * (PROTOCOL §3 "What reaches Apple / Google"). Only fields defined here are
 * forwarded; nothing else from the request is passed through.
 */

export const DEFAULT_TTL_SECONDS = 86_400;
export const PLACEHOLDER_TITLE = "Flowplan";
export const PLACEHOLDER_BODY = "New notification";

/** Canonical (unpadded) base64url form of the encrypted payload. */
function canonicalPayload(payload: string | null | undefined): string {
  const buf = payload == null ? null : decodeBase64Url(payload, MAX_PAYLOAD_BYTES);
  if (!buf) throw new Error("payload must be validated before building");
  return buf.toString("base64url");
}

export type BuildResult<T> = { ok: true; request: T } | { ok: false; status: "invalid" };

/** Message type must fit the registration's platform. */
export function typeMatchesPlatform(msg: Message, device: DeviceRecord): boolean {
  if (device.platform === "ios-liveactivity") return msg.type === "liveactivity";
  if (device.platform === "android") return msg.type === "alert" || msg.type === "background";
  return msg.type === "alert" || msg.type === "background";
}

export function buildApnsRequest(
  msg: Message,
  device: DeviceRecord,
  deviceToken: string,
  nowSeconds: number,
): BuildResult<ApnsRequest> {
  if (!typeMatchesPlatform(msg, device)) return { ok: false, status: "invalid" };
  const ttl = msg.ttl ?? DEFAULT_TTL_SECONDS;
  const expiration = ttl === 0 ? 0 : nowSeconds + ttl;
  const base = {
    deviceToken,
    environment: device.environment,
    expiration,
    collapseId: msg.collapseId ?? null,
  };

  if (msg.type === "alert") {
    const aps: Record<string, unknown> = {
      alert: { title: PLACEHOLDER_TITLE, body: PLACEHOLDER_BODY },
      "mutable-content": 1,
      sound: "default",
    };
    if (msg.category) aps.category = msg.category;
    if (msg.collapseId) aps["thread-id"] = msg.collapseId;
    if (msg.badge != null) aps.badge = msg.badge;
    return {
      ok: true,
      request: {
        ...base,
        topic: device.bundleId,
        pushType: "alert",
        priority: msg.priority === "normal" ? 5 : 10,
        payload: { aps, fp: canonicalPayload(msg.payload) },
      },
    };
  }

  if (msg.type === "background") {
    return {
      ok: true,
      request: {
        ...base,
        topic: device.bundleId,
        pushType: "background",
        priority: 5, // Apple requires priority 5 for background pushes
        payload: { aps: { "content-available": 1 }, fp: canonicalPayload(msg.payload) },
      },
    };
  }

  // liveactivity
  const la = msg.liveActivity;
  if (!la) return { ok: false, status: "invalid" };
  const aps: Record<string, unknown> = {
    timestamp: nowSeconds,
    event: la.event,
    "content-state": la.contentState,
  };
  if (la.staleDate != null) aps["stale-date"] = la.staleDate;
  if (la.dismissalDate != null) aps["dismissal-date"] = la.dismissalDate;
  return {
    ok: true,
    request: {
      ...base,
      topic: `${device.bundleId}.push-type.liveactivity`,
      pushType: "liveactivity",
      priority: msg.priority === "normal" ? 5 : 10,
      payload: { aps },
    },
  };
}

export function buildFcmMessage(
  msg: Message,
  device: DeviceRecord,
  deviceToken: string,
): BuildResult<FcmMessage> {
  if (!typeMatchesPlatform(msg, device) || msg.type === "liveactivity")
    return { ok: false, status: "invalid" };
  // FCM data values must be strings.
  const data: Record<string, string> = { fp: canonicalPayload(msg.payload), type: msg.type };
  if (msg.category) data.category = msg.category;
  if (msg.collapseId) data.collapseId = msg.collapseId;
  if (msg.badge != null) data.badge = String(msg.badge);
  const defaultPriority = msg.type === "alert" ? "high" : "normal";
  return {
    ok: true,
    request: {
      token: deviceToken,
      data,
      priority: msg.priority ?? defaultPriority,
      collapseKey: msg.collapseId ?? null,
      ttlSeconds: msg.ttl ?? DEFAULT_TTL_SECONDS,
    },
  };
}

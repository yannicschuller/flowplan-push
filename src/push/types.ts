export type DeliveryStatus = "ok" | "gone" | "invalid" | "error";

export interface DeliveryResult {
  status: DeliveryStatus;
  /** Provider reason (e.g. "BadDeviceToken", "UNREGISTERED") – for logs and metrics only. */
  reason?: string;
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms).unref?.());

/** Backoff before the single retry: honours Retry-After up to 5 s, otherwise 250–750 ms. */
export function retryDelayMs(retryAfterHeader: string | undefined, base: number): number {
  const ra = Number(retryAfterHeader);
  if (Number.isFinite(ra) && ra > 0) return Math.min(5000, ra * 1000);
  return base + Math.floor(Math.random() * base * 2);
}

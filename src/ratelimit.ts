/**
 * In-memory token buckets keyed by string (IP, IPv6 /64 or instance origin).
 * Memory is bounded: full (idle) buckets are dropped first, then the oldest.
 */

interface Bucket {
  tokens: number;
  updated: number;
}

export interface TakeResult {
  /** Number of tokens actually granted (0..requested). */
  granted: number;
  /** Seconds until the next token is available (only meaningful when granted < requested). */
  retryAfter: number;
}

export class TokenBucketLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly ratePerMs: number;
  readonly capacity: number;
  private readonly maxKeys: number;
  private readonly now: () => number;

  /**
   * @param capacity burst size
   * @param refillTokens tokens added per `refillIntervalMs`
   */
  constructor(
    capacity: number,
    refillTokens: number,
    refillIntervalMs: number,
    maxKeys = 100_000,
    now: () => number = Date.now,
  ) {
    this.capacity = capacity;
    this.ratePerMs = refillTokens / refillIntervalMs;
    this.maxKeys = maxKeys;
    this.now = now;
  }

  private bucket(key: string, now: number): Bucket {
    let b = this.buckets.get(key);
    if (!b) {
      if (this.buckets.size >= this.maxKeys) this.evict(now);
      b = { tokens: this.capacity, updated: now };
      this.buckets.set(key, b);
      return b;
    }
    b.tokens = Math.min(this.capacity, b.tokens + (now - b.updated) * this.ratePerMs);
    b.updated = now;
    return b;
  }

  /** Takes up to `n` tokens; partial grants are possible. */
  take(key: string, n = 1): TakeResult {
    const now = this.now();
    const b = this.bucket(key, now);
    const granted = Math.max(0, Math.min(n, Math.floor(b.tokens)));
    b.tokens -= granted;
    // When not everything was granted, fewer than one token is left: report
    // the time until the next whole token.
    const retryAfter =
      granted < n ? Math.max(1, Math.ceil((1 - b.tokens) / this.ratePerMs / 1000)) : 0;
    return { granted, retryAfter };
  }

  /** Takes exactly one token if available. */
  tryTake(key: string): TakeResult & { ok: boolean } {
    const r = this.take(key, 1);
    return { ...r, ok: r.granted === 1 };
  }

  /** True when the bucket is empty without consuming anything. */
  isExhausted(key: string): { exhausted: boolean; retryAfter: number } {
    const now = this.now();
    const b = this.buckets.get(key);
    if (!b) return { exhausted: false, retryAfter: 0 };
    const tokens = Math.min(this.capacity, b.tokens + (now - b.updated) * this.ratePerMs);
    if (tokens >= 1) return { exhausted: false, retryAfter: 0 };
    return {
      exhausted: true,
      retryAfter: Math.max(1, Math.ceil((1 - tokens) / this.ratePerMs / 1000)),
    };
  }

  get size(): number {
    return this.buckets.size;
  }

  private evict(now: number): void {
    for (const [k, b] of this.buckets) {
      if (b.tokens + (now - b.updated) * this.ratePerMs >= this.capacity) this.buckets.delete(k);
    }
    while (this.buckets.size >= this.maxKeys) {
      const oldest = this.buckets.keys().next().value;
      if (oldest === undefined) break;
      this.buckets.delete(oldest);
    }
  }
}

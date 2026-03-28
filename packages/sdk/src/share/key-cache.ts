/**
 * @cipherbox/sdk - Share key cache with TTL
 *
 * Caches fetched share keys per shareId with a configurable TTL.
 */

import type { ShareKeyType } from './shared-write';

export type CachedShareKey = {
  keyType: ShareKeyType;
  itemId: string;
  encryptedKey: string;
};

/**
 * TTL-based cache for share keys.
 * Avoids redundant API calls when navigating within a share.
 */
export class ShareKeyCache {
  private cache = new Map<string, { keys: CachedShareKey[]; fetchedAt: number }>();
  private ttlMs: number;

  constructor(ttlMs = 30_000) {
    this.ttlMs = ttlMs;
  }

  get(shareId: string): CachedShareKey[] | null {
    const entry = this.cache.get(shareId);
    if (!entry) return null;
    if (Date.now() - entry.fetchedAt > this.ttlMs) {
      this.cache.delete(shareId);
      return null;
    }
    return entry.keys;
  }

  set(shareId: string, keys: CachedShareKey[]): void {
    this.cache.set(shareId, { keys, fetchedAt: Date.now() });
  }

  invalidate(shareId: string): void {
    this.cache.delete(shareId);
  }

  /** Remove all expired entries. Call periodically to prevent unbounded growth. */
  pruneExpired(): void {
    const now = Date.now();
    for (const [shareId, entry] of this.cache) {
      if (now - entry.fetchedAt > this.ttlMs) {
        this.cache.delete(shareId);
      }
    }
  }

  clear(): void {
    this.cache.clear();
  }
}

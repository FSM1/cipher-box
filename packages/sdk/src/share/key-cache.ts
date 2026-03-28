/**
 * @cipherbox/sdk - Share key cache with TTL
 *
 * Extracted from apps/web/src/hooks/useSharedNavigation.ts shareKeysCache ref.
 * Caches fetched share keys per shareId with a configurable TTL.
 */

/**
 * A cached share key entry.
 */
export type CachedShareKey = {
  keyType: string;
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

  /**
   * @param ttlMs - Cache entry lifetime in milliseconds (default: 30000 = 30s)
   */
  constructor(ttlMs = 30_000) {
    this.ttlMs = ttlMs;
  }

  /**
   * Get cached keys for a share, or null if expired/missing.
   *
   * @param shareId - The share ID to look up
   * @returns Cached keys array or null
   */
  get(shareId: string): CachedShareKey[] | null {
    const entry = this.cache.get(shareId);
    if (!entry) return null;
    if (Date.now() - entry.fetchedAt > this.ttlMs) {
      this.cache.delete(shareId);
      return null;
    }
    return entry.keys;
  }

  /**
   * Store keys in the cache for a share.
   *
   * @param shareId - The share ID
   * @param keys - The share keys to cache
   */
  set(shareId: string, keys: CachedShareKey[]): void {
    this.cache.set(shareId, { keys, fetchedAt: Date.now() });
  }

  /**
   * Invalidate a specific share's cache entry.
   *
   * @param shareId - The share ID to invalidate
   */
  invalidate(shareId: string): void {
    this.cache.delete(shareId);
  }

  /** Clear all cached entries. */
  clear(): void {
    this.cache.clear();
  }
}

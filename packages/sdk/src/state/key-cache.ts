/**
 * @cipherbox/sdk - Key cache
 *
 * Caches derived keys to avoid redundant HKDF derivations.
 * All cached values are zeroed on clear() to prevent key material
 * from persisting in memory after the client is destroyed.
 */

export class KeyCache {
  private cache = new Map<string, Uint8Array>();

  /** Get a cached key by its derivation identifier */
  get(key: string): Uint8Array | undefined {
    return this.cache.get(key);
  }

  /** Cache a derived key, zeroing any previous value */
  set(key: string, value: Uint8Array): void {
    const existing = this.cache.get(key);
    if (existing && existing !== value) {
      existing.fill(0);
    }
    this.cache.set(key, value);
  }

  /**
   * Clear all cached keys, zeroing memory.
   * Called during client destroy().
   */
  clear(): void {
    for (const value of this.cache.values()) {
      value.fill(0);
    }
    this.cache.clear();
  }
}

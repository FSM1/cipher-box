/**
 * Short-TTL verified-record cache for IPNS publish-path signature verification (D-11)
 *
 * Security invariant: this cache may ONLY short-circuit re-verification of a
 * record that was ALREADY successfully verified by THIS server in this process.
 * The cache is NEVER populated from:
 *   - the resolve path (DHT / delegated routing)
 *   - external or untrusted inputs
 *   - anything other than a successful verifyIpnsRecordSignature call in publishRecord
 *
 * Cache key: `${ipnsName}:${base64(recordBytes)}`
 *
 * Using the full record bytes as the cache discriminator is strictly safer than
 * a (ipnsName, sequenceNumber, signatureV2) triple: it includes all fields
 * (signatureV2, sequence, CID, validity, pubKey if present). Any mutation to
 * signatureV2 bytes — whether a bit flip, a different signature, or a forged
 * record — produces different record bytes, a different key, and a mandatory
 * cache miss → full Ed25519 verify (T-60-20/T-60-21). This is the D-11 invariant:
 * the cache short-circuits ONLY the exact previously-verified bytes.
 *
 * TTL: 60 seconds. Short enough to limit exposure but long enough to absorb
 * rapid re-submissions of the same signed record (e.g. retry storms).
 */

/** Cache TTL in milliseconds */
export const CACHE_TTL_MS = 60_000;

/**
 * Maximum number of cached entries before oldest-first eviction. Because the key
 * includes the full record bytes (unique per publish), entries are essentially never
 * re-read after their TTL, so the lazy TTL eviction alone would let the Map grow
 * unbounded under a stream of one-off publishes. This hard cap bounds memory.
 */
export const CACHE_MAX_ENTRIES = 10_000;

export class IpnsVerifyCache {
  /** Internal store: key → insertion timestamp (ms) */
  private readonly store = new Map<string, number>();

  /**
   * Record that a given (ipnsName, recordBytes) combination has been
   * successfully verified by this server in this process.
   *
   * MUST only be called after a successful verifyIpnsRecordSignature() — never
   * from the resolve/DHT path.
   *
   * @param ipnsName - IPNS name (CIDv1 base36)
   * @param sequenceNumber - sequence number (pass '' when extracting from recordBytes directly)
   * @param recordBytesOrSigBase64 - base64(recordBytes) or base64(signatureV2), used as the
   *   discriminator; a forged record with different signature bytes produces a different key
   */
  recordVerified(ipnsName: string, sequenceNumber: string, recordBytesOrSigBase64: string): void {
    const key = `${ipnsName}:${sequenceNumber}:${recordBytesOrSigBase64}`;
    // Refresh insertion order on re-set so this entry counts as most-recent.
    this.store.delete(key);
    // Bound memory: evict oldest entries (Map preserves insertion order) until under cap.
    while (this.store.size >= CACHE_MAX_ENTRIES) {
      const oldest = this.store.keys().next().value;
      if (oldest === undefined) break;
      this.store.delete(oldest);
    }
    this.store.set(key, Date.now());
  }

  /**
   * Check whether the given (ipnsName, sequenceNumber, recordBytesOrSigBase64) was
   * already verified by this server within the TTL window.
   *
   * Returns true only if a prior successful verifyIpnsRecordSignature() recorded
   * this exact combination and the TTL has not yet expired.
   */
  isVerified(ipnsName: string, sequenceNumber: string, recordBytesOrSigBase64: string): boolean {
    const key = `${ipnsName}:${sequenceNumber}:${recordBytesOrSigBase64}`;
    const insertedAt = this.store.get(key);
    if (insertedAt === undefined) {
      return false;
    }
    if (Date.now() - insertedAt >= CACHE_TTL_MS) {
      // Entry expired — evict and report miss
      this.store.delete(key);
      return false;
    }
    return true;
  }

  /**
   * Clear all cache entries. Intended for use in tests only.
   * @internal
   */
  clear(): void {
    this.store.clear();
  }
}

/**
 * Singleton instance used by IpnsService.
 *
 * A module-level singleton is appropriate here: the cache is process-scoped
 * (by design — it only tracks in-process verified records), has no global
 * mutable state visible outside this module, and avoids NestJS DI overhead
 * on the hot publish path.
 *
 * Tests that import ipns-verify-cache should call `ipnsVerifyCache.clear()`
 * in their afterEach hook to prevent cross-test cache pollution.
 */
export const ipnsVerifyCache = new IpnsVerifyCache();

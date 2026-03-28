import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ShareKeyCache, type CachedShareKey } from '../share/key-cache';

const makeKeys = (prefix: string): CachedShareKey[] => [
  { keyType: 'file' as const, itemId: `${prefix}-f1`, encryptedKey: `enc-${prefix}-f1` },
  { keyType: 'folder' as const, itemId: `${prefix}-d1`, encryptedKey: `enc-${prefix}-d1` },
];

describe('ShareKeyCache', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('get / set', () => {
    it('returns null for a miss', () => {
      const cache = new ShareKeyCache();
      expect(cache.get('nonexistent')).toBeNull();
    });

    it('returns cached keys after set', () => {
      const cache = new ShareKeyCache();
      const keys = makeKeys('s1');
      cache.set('s1', keys);
      expect(cache.get('s1')).toEqual(keys);
    });

    it('returns different keys for different shareIds', () => {
      const cache = new ShareKeyCache();
      const keys1 = makeKeys('s1');
      const keys2 = makeKeys('s2');
      cache.set('s1', keys1);
      cache.set('s2', keys2);
      expect(cache.get('s1')).toEqual(keys1);
      expect(cache.get('s2')).toEqual(keys2);
    });

    it('overwrites existing entry on re-set', () => {
      const cache = new ShareKeyCache();
      cache.set('s1', makeKeys('old'));
      const newKeys = makeKeys('new');
      cache.set('s1', newKeys);
      expect(cache.get('s1')).toEqual(newKeys);
    });
  });

  describe('TTL expiration', () => {
    it('returns null after TTL expires', () => {
      const cache = new ShareKeyCache(1000); // 1 second TTL
      cache.set('s1', makeKeys('s1'));

      // Still valid at 999ms
      vi.advanceTimersByTime(999);
      expect(cache.get('s1')).not.toBeNull();

      // Expired at 1001ms
      vi.advanceTimersByTime(2);
      expect(cache.get('s1')).toBeNull();
    });

    it('uses default TTL of 30 seconds', () => {
      const cache = new ShareKeyCache();
      cache.set('s1', makeKeys('s1'));

      vi.advanceTimersByTime(29_999);
      expect(cache.get('s1')).not.toBeNull();

      vi.advanceTimersByTime(2);
      expect(cache.get('s1')).toBeNull();
    });

    it('deletes expired entry from internal map on get', () => {
      const cache = new ShareKeyCache(100);
      cache.set('s1', makeKeys('s1'));

      vi.advanceTimersByTime(101);
      expect(cache.get('s1')).toBeNull();

      // Second get should also return null (entry was removed)
      expect(cache.get('s1')).toBeNull();
    });

    it('re-set refreshes the TTL', () => {
      const cache = new ShareKeyCache(1000);
      cache.set('s1', makeKeys('s1'));

      vi.advanceTimersByTime(800);
      // Re-set before expiry
      const freshKeys = makeKeys('fresh');
      cache.set('s1', freshKeys);

      // 800ms after re-set: should still be valid
      vi.advanceTimersByTime(800);
      expect(cache.get('s1')).toEqual(freshKeys);

      // Now exceed TTL from re-set time
      vi.advanceTimersByTime(201);
      expect(cache.get('s1')).toBeNull();
    });
  });

  describe('invalidate', () => {
    it('removes a specific shareId', () => {
      const cache = new ShareKeyCache();
      cache.set('s1', makeKeys('s1'));
      cache.set('s2', makeKeys('s2'));

      cache.invalidate('s1');

      expect(cache.get('s1')).toBeNull();
      expect(cache.get('s2')).not.toBeNull();
    });

    it('is a no-op for nonexistent shareId', () => {
      const cache = new ShareKeyCache();
      // Should not throw
      cache.invalidate('nonexistent');
    });
  });

  describe('pruneExpired', () => {
    it('removes only expired entries', () => {
      const cache = new ShareKeyCache(1000);

      cache.set('s1', makeKeys('s1'));
      vi.advanceTimersByTime(500);
      cache.set('s2', makeKeys('s2'));
      vi.advanceTimersByTime(600);

      // s1 was set at t=0, now t=1100 -> expired
      // s2 was set at t=500, now t=1100 -> not expired (600ms old, TTL=1000)
      cache.pruneExpired();

      expect(cache.get('s1')).toBeNull();
      expect(cache.get('s2')).not.toBeNull();
    });

    it('removes all entries when all are expired', () => {
      const cache = new ShareKeyCache(100);
      cache.set('s1', makeKeys('s1'));
      cache.set('s2', makeKeys('s2'));

      vi.advanceTimersByTime(200);
      cache.pruneExpired();

      expect(cache.get('s1')).toBeNull();
      expect(cache.get('s2')).toBeNull();
    });

    it('is a no-op on empty cache', () => {
      const cache = new ShareKeyCache();
      // Should not throw
      cache.pruneExpired();
    });
  });

  describe('clear', () => {
    it('removes all entries regardless of TTL', () => {
      const cache = new ShareKeyCache();
      cache.set('s1', makeKeys('s1'));
      cache.set('s2', makeKeys('s2'));
      cache.set('s3', makeKeys('s3'));

      cache.clear();

      expect(cache.get('s1')).toBeNull();
      expect(cache.get('s2')).toBeNull();
      expect(cache.get('s3')).toBeNull();
    });

    it('is a no-op on empty cache', () => {
      const cache = new ShareKeyCache();
      // Should not throw
      cache.clear();
    });
  });
});

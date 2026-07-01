/**
 * TEE Key Derivation Tests
 *
 * Tests simulator-mode HKDF key derivation: determinism, epoch isolation,
 * key format, public key caching, and production guard.
 *
 * These tests verify TEE-specific HKDF derivation and epoch management.
 * The underlying secp256k1 math is not our concern.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { getKeypair, getPublicKey, getInternalCurrentEpoch } from '../services/tee-keys.js';

describe('tee-keys', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    process.env.TEE_MODE = 'simulator';
    delete process.env.CIPHERBOX_ENVIRONMENT;
    delete process.env.NODE_ENV;
    delete process.env.EPOCH_ZERO_TIMESTAMP_MS;
  });

  describe('getKeypair', () => {
    it('returns deterministic keypair for the same epoch', async () => {
      const kp1 = await getKeypair(1);
      const kp2 = await getKeypair(1);

      expect(Buffer.from(kp1.publicKey).toString('hex')).toBe(
        Buffer.from(kp2.publicKey).toString('hex')
      );
      expect(Buffer.from(kp1.privateKey).toString('hex')).toBe(
        Buffer.from(kp2.privateKey).toString('hex')
      );
    });

    it('produces different keypairs for different epochs', async () => {
      const kp1 = await getKeypair(1);
      const kp2 = await getKeypair(2);

      expect(Buffer.from(kp1.publicKey).toString('hex')).not.toBe(
        Buffer.from(kp2.publicKey).toString('hex')
      );
      expect(Buffer.from(kp1.privateKey).toString('hex')).not.toBe(
        Buffer.from(kp2.privateKey).toString('hex')
      );
    });

    it('returns 65-byte uncompressed public key with 0x04 prefix', async () => {
      const kp = await getKeypair(1);

      expect(kp.publicKey.length).toBe(65);
      expect(kp.publicKey[0]).toBe(0x04);
    });

    it('returns 32-byte private key', async () => {
      const kp = await getKeypair(1);

      expect(kp.privateKey.length).toBe(32);
    });

    it('throws in production with simulator mode (CIPHERBOX_ENVIRONMENT)', async () => {
      process.env.CIPHERBOX_ENVIRONMENT = 'production';

      await expect(getKeypair(1)).rejects.toThrow('not allowed in production');
    });

    it('throws in production with simulator mode (NODE_ENV fallback)', async () => {
      process.env.NODE_ENV = 'production';

      await expect(getKeypair(1)).rejects.toThrow('not allowed in production');
    });

    it('does not throw when CIPHERBOX_ENVIRONMENT is set to non-production', async () => {
      process.env.CIPHERBOX_ENVIRONMENT = 'staging';

      const kp = await getKeypair(1);
      expect(kp.publicKey.length).toBe(65);
    });
  });

  describe('getPublicKey', () => {
    it('returns same value as getKeypair().publicKey', async () => {
      const epoch = 42;
      const kp = await getKeypair(epoch);
      const pubKey = await getPublicKey(epoch);

      expect(Buffer.from(pubKey).toString('hex')).toBe(Buffer.from(kp.publicKey).toString('hex'));
    });

    it('returns cached value on subsequent calls', async () => {
      const epoch = 99;
      // First call populates cache
      const pk1 = await getPublicKey(epoch);
      // Second call should use cache
      const pk2 = await getPublicKey(epoch);

      expect(Buffer.from(pk1).toString('hex')).toBe(Buffer.from(pk2).toString('hex'));
    });

    it('returns different public keys for different epochs', async () => {
      const pk1 = await getPublicKey(10);
      const pk2 = await getPublicKey(20);

      expect(Buffer.from(pk1).toString('hex')).not.toBe(Buffer.from(pk2).toString('hex'));
    });
  });

  describe('getInternalCurrentEpoch', () => {
    /** 4-week epoch duration in ms (must match the implementation constant) */
    const FOUR_WEEKS_MS = 4 * 7 * 24 * 60 * 60 * 1000;
    /** 5 weeks in ms — one full 4-week epoch elapsed past the anchor */
    const FIVE_WEEKS_MS = 5 * 7 * 24 * 60 * 60 * 1000;

    afterEach(() => {
      delete process.env.EPOCH_ZERO_TIMESTAMP_MS;
    });

    it('returns 1 (MIN_EPOCH) when EPOCH_ZERO_TIMESTAMP_MS is unset', () => {
      // process.env.EPOCH_ZERO_TIMESTAMP_MS already deleted by outer beforeEach
      expect(getInternalCurrentEpoch()).toBe(1);
    });

    it('returns 2 when anchor is 5 weeks ago and EPOCH_DURATION_MS is 4 weeks', () => {
      // 5 weeks elapsed / 4-week epoch = 1.25 → Math.floor(1.25) + 1 = 2
      const anchor = Date.now() - FIVE_WEEKS_MS;
      process.env.EPOCH_ZERO_TIMESTAMP_MS = String(anchor);
      expect(getInternalCurrentEpoch()).toBe(2);
    });

    it('clamps to MIN_EPOCH (1) when anchor is in the future', () => {
      // Future anchor: elapsed is negative → Math.floor(negative) + 1 ≤ 0 → clamp to 1
      process.env.EPOCH_ZERO_TIMESTAMP_MS = String(Date.now() + FOUR_WEEKS_MS);
      expect(getInternalCurrentEpoch()).toBe(1);
    });

    it('returns MIN_EPOCH (1) for a malformed non-numeric anchor (never NaN)', () => {
      // parseInt('not-a-number') → NaN; the guard must treat it like an unset
      // anchor and never propagate a NaN epoch into the stale-key check.
      process.env.EPOCH_ZERO_TIMESTAMP_MS = 'not-a-number';
      const epoch = getInternalCurrentEpoch();
      expect(epoch).toBe(1);
      expect(Number.isNaN(epoch)).toBe(false);
    });

    it('returns MIN_EPOCH (1) for a non-positive anchor', () => {
      process.env.EPOCH_ZERO_TIMESTAMP_MS = '-1000';
      expect(getInternalCurrentEpoch()).toBe(1);
    });
  });
});

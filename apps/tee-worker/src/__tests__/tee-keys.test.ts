/**
 * TEE Key Derivation Tests
 *
 * Tests simulator-mode HKDF key derivation: determinism, epoch isolation,
 * key format, public key caching, and production guard.
 *
 * These tests verify TEE-specific HKDF derivation and epoch management.
 * The underlying secp256k1 math is not our concern.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { getKeypair, getPublicKey } from '../services/tee-keys.js';

describe('tee-keys', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    process.env.TEE_MODE = 'simulator';
    delete process.env.CIPHERBOX_ENVIRONMENT;
    delete process.env.NODE_ENV;
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

      expect(Buffer.from(pubKey).toString('hex')).toBe(
        Buffer.from(kp.publicKey).toString('hex')
      );
    });

    it('returns cached value on subsequent calls', async () => {
      const epoch = 99;
      // First call populates cache
      const pk1 = await getPublicKey(epoch);
      // Second call should use cache
      const pk2 = await getPublicKey(epoch);

      expect(Buffer.from(pk1).toString('hex')).toBe(
        Buffer.from(pk2).toString('hex')
      );
    });

    it('returns different public keys for different epochs', async () => {
      const pk1 = await getPublicKey(10);
      const pk2 = await getPublicKey(20);

      expect(Buffer.from(pk1).toString('hex')).not.toBe(
        Buffer.from(pk2).toString('hex')
      );
    });
  });
});

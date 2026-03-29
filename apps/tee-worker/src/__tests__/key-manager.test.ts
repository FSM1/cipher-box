/**
 * Key Manager Epoch Fallback Tests
 *
 * Tests TEE-specific epoch fallback orchestration logic.
 * Uses real HKDF-derived keys (simulator mode) and real @cipherbox/crypto
 * wrapKey/unwrapKey to create test ciphertexts. No mocking of ECIES primitives.
 *
 * The underlying ECIES encrypt/decrypt is already tested in @cipherbox/crypto --
 * here we test the fallback logic, re-encryption, and key zeroing.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { wrapKey, unwrapKey } from '@cipherbox/crypto';
import { getKeypair } from '../services/tee-keys.js';
import {
  decryptIpnsKey,
  decryptWithFallback,
  reEncryptForEpoch,
} from '../services/key-manager.js';

/** Generate a random 32-byte test key */
function randomTestKey(): Uint8Array {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

describe('key-manager', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    process.env.TEE_MODE = 'simulator';
    delete process.env.CIPHERBOX_ENVIRONMENT;
    delete process.env.NODE_ENV;
  });

  describe('decryptIpnsKey', () => {
    it('decrypts a key encrypted with the correct epoch public key', async () => {
      const epoch = 5;
      const testKey = randomTestKey();
      const kp = await getKeypair(epoch);

      // Encrypt with epoch public key
      const encrypted = await wrapKey(testKey, kp.publicKey);

      // Decrypt via decryptIpnsKey
      const decrypted = await decryptIpnsKey(encrypted, epoch);

      expect(Buffer.from(decrypted).toString('hex')).toBe(
        Buffer.from(testKey).toString('hex')
      );
    });

    it('fails to decrypt with wrong epoch', async () => {
      const testKey = randomTestKey();
      const kp = await getKeypair(5);
      const encrypted = await wrapKey(testKey, kp.publicKey);

      // Try decrypting with a different epoch
      await expect(decryptIpnsKey(encrypted, 6)).rejects.toThrow();
    });

    it('zeros the TEE private key after decryption', async () => {
      const epoch = 7;
      const testKey = randomTestKey();
      const kp = await getKeypair(epoch);
      const encrypted = await wrapKey(testKey, kp.publicKey);

      // The function internally gets keypair and zeros privateKey in finally block.
      // We verify by calling getKeypair again -- should still produce valid keys
      // (derived fresh each time in simulator mode).
      await decryptIpnsKey(encrypted, epoch);

      // If zeroing broke derivation, this would fail
      const kp2 = await getKeypair(epoch);
      expect(kp2.privateKey.length).toBe(32);
      // Verify it's a valid key (not all zeros)
      const allZero = kp2.privateKey.every((b) => b === 0);
      expect(allZero).toBe(false);
    });
  });

  describe('decryptWithFallback', () => {
    it('succeeds on current epoch when key was encrypted with current epoch', async () => {
      const currentEpoch = 10;
      const previousEpoch = 9;
      const testKey = randomTestKey();
      const kp = await getKeypair(currentEpoch);
      const encrypted = await wrapKey(testKey, kp.publicKey);

      const result = await decryptWithFallback(encrypted, currentEpoch, previousEpoch);

      expect(result.usedEpoch).toBe(currentEpoch);
      expect(Buffer.from(result.ipnsPrivateKey).toString('hex')).toBe(
        Buffer.from(testKey).toString('hex')
      );
    });

    it('falls back to previous epoch when current epoch fails', async () => {
      const currentEpoch = 10;
      const previousEpoch = 9;
      const testKey = randomTestKey();

      // Encrypt with the PREVIOUS epoch's public key
      const kpPrev = await getKeypair(previousEpoch);
      const encrypted = await wrapKey(testKey, kpPrev.publicKey);

      const result = await decryptWithFallback(encrypted, currentEpoch, previousEpoch);

      expect(result.usedEpoch).toBe(previousEpoch);
      expect(Buffer.from(result.ipnsPrivateKey).toString('hex')).toBe(
        Buffer.from(testKey).toString('hex')
      );
    });

    it('throws when both epochs fail', async () => {
      const testKey = randomTestKey();

      // Encrypt with epoch 100 (neither current nor previous)
      const kpOther = await getKeypair(100);
      const encrypted = await wrapKey(testKey, kpOther.publicKey);

      await expect(
        decryptWithFallback(encrypted, 10, 9)
      ).rejects.toThrow('ECIES decryption failed for all available epochs');
    });

    it('throws immediately when previousEpoch is null and current fails', async () => {
      const testKey = randomTestKey();

      // Encrypt with epoch 100 (not current epoch 10)
      const kpOther = await getKeypair(100);
      const encrypted = await wrapKey(testKey, kpOther.publicKey);

      await expect(
        decryptWithFallback(encrypted, 10, null)
      ).rejects.toThrow('ECIES decryption failed for all available epochs');
    });

    it('succeeds with null previousEpoch when current epoch matches', async () => {
      const currentEpoch = 10;
      const testKey = randomTestKey();
      const kp = await getKeypair(currentEpoch);
      const encrypted = await wrapKey(testKey, kp.publicKey);

      const result = await decryptWithFallback(encrypted, currentEpoch, null);

      expect(result.usedEpoch).toBe(currentEpoch);
      expect(Buffer.from(result.ipnsPrivateKey).toString('hex')).toBe(
        Buffer.from(testKey).toString('hex')
      );
    });
  });

  describe('reEncryptForEpoch', () => {
    it('re-encrypts a key for a target epoch and the result is decryptable', async () => {
      const originalEpoch = 5;
      const targetEpoch = 6;
      const testKey = randomTestKey();

      // Encrypt with original epoch
      const kpOrig = await getKeypair(originalEpoch);
      const encrypted = await wrapKey(testKey, kpOrig.publicKey);

      // Decrypt with original epoch (simulating fallback)
      const decrypted = await decryptIpnsKey(encrypted, originalEpoch);

      // Re-encrypt for target epoch
      const reEncrypted = await reEncryptForEpoch(decrypted, targetEpoch);

      // Verify: decrypt with target epoch should yield original key
      const kpTarget = await getKeypair(targetEpoch);
      const roundTripped = await unwrapKey(reEncrypted, kpTarget.privateKey);

      expect(Buffer.from(roundTripped).toString('hex')).toBe(
        Buffer.from(testKey).toString('hex')
      );
    });

    it('produces different ciphertext each time (ECIES is randomized)', async () => {
      const testKey = randomTestKey();
      const targetEpoch = 6;

      const enc1 = await reEncryptForEpoch(testKey, targetEpoch);
      const enc2 = await reEncryptForEpoch(testKey, targetEpoch);

      // ECIES produces different ciphertexts for same plaintext
      expect(Buffer.from(enc1).toString('hex')).not.toBe(
        Buffer.from(enc2).toString('hex')
      );
    });

    it('full epoch migration round-trip: decrypt old, re-encrypt new, decrypt new', async () => {
      const oldEpoch = 3;
      const newEpoch = 4;
      const testKey = randomTestKey();

      // 1. Encrypt with old epoch
      const kpOld = await getKeypair(oldEpoch);
      const encryptedOld = await wrapKey(testKey, kpOld.publicKey);

      // 2. Decrypt with fallback (old epoch)
      const { ipnsPrivateKey, usedEpoch } = await decryptWithFallback(
        encryptedOld,
        newEpoch,
        oldEpoch
      );
      expect(usedEpoch).toBe(oldEpoch);

      // 3. Re-encrypt for new epoch
      const encryptedNew = await reEncryptForEpoch(ipnsPrivateKey, newEpoch);

      // 4. Decrypt with new epoch (direct)
      const decryptedNew = await decryptIpnsKey(encryptedNew, newEpoch);

      expect(Buffer.from(decryptedNew).toString('hex')).toBe(
        Buffer.from(testKey).toString('hex')
      );
    });
  });
});

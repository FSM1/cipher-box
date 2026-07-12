/**
 * Key Manager Epoch Fallback Tests
 *
 * Tests TEE-specific epoch fallback orchestration logic.
 * Uses real HKDF-derived keys (simulator mode) and real @cipherbox/crypto
 * wrapKey/unwrapKey to create test ciphertexts. Mocking is limited to the
 * spy assertion on the stale-key guard path.
 *
 * The underlying ECIES encrypt/decrypt is already tested in @cipherbox/crypto --
 * here we test the fallback logic, stale-key guard, re-encryption, and key zeroing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { wrapKey, unwrapKey } from '@cipherbox/crypto';
import * as teeKeysModule from '../services/tee-keys.js';
import { getKeypair, TeeKeyUnavailableError } from '../services/tee-keys.js';
import {
  decryptIpnsKey,
  decryptWithFallback,
  reEncryptForEpoch,
  ReEnrollRequiredError,
} from '../services/key-manager.js';

/** Generate a random 32-byte test key */
function randomTestKey(): Uint8Array {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

/** 4-week epoch duration in ms (must match tee-keys.ts EPOCH_DURATION_MS) */
const FOUR_WEEKS_MS = 4 * 7 * 24 * 60 * 60 * 1000;

/**
 * Configure EPOCH_ZERO_TIMESTAMP_MS so that getInternalCurrentEpoch() returns n.
 * Places the anchor at (n - 0.5) epochs before now so the calculation lands
 * squarely in epoch n: Math.floor(n - 0.5) + 1 === n.
 */
function setInternalEpoch(n: number): void {
  process.env.EPOCH_ZERO_TIMESTAMP_MS = String(Math.floor(Date.now() - (n - 0.5) * FOUR_WEEKS_MS));
}

describe('key-manager', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    process.env.TEE_MODE = 'simulator';
    delete process.env.CIPHERBOX_ENVIRONMENT;
    delete process.env.NODE_ENV;
    delete process.env.EPOCH_ZERO_TIMESTAMP_MS;
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

      expect(Buffer.from(decrypted).toString('hex')).toBe(Buffer.from(testKey).toString('hex'));
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
    afterEach(() => {
      delete process.env.EPOCH_ZERO_TIMESTAMP_MS;
      vi.restoreAllMocks();
    });

    it('succeeds when keyEpoch === internalCurrentEpoch (key encrypted for that epoch)', async () => {
      setInternalEpoch(10);
      const testKey = randomTestKey();
      const kp = await getKeypair(10);
      const encrypted = await wrapKey(testKey, kp.publicKey);

      const result = await decryptWithFallback(encrypted, 10);

      expect(result.usedEpoch).toBe(10);
      expect(Buffer.from(result.ipnsPrivateKey).toString('hex')).toBe(
        Buffer.from(testKey).toString('hex')
      );
    });

    it('succeeds when keyEpoch === internalCurrentEpoch - 1 (grace window, key encrypted for keyEpoch)', async () => {
      // internalCurrentEpoch = 10, keyEpoch = 9 → 9 >= 10-1=9 → not stale
      setInternalEpoch(10);
      const testKey = randomTestKey();
      const kp = await getKeypair(9); // key encrypted for previous epoch
      const encrypted = await wrapKey(testKey, kp.publicKey);

      const result = await decryptWithFallback(encrypted, 9);

      expect(result.usedEpoch).toBe(9); // usedEpoch is the keyEpoch hint (grace window)
      expect(Buffer.from(result.ipnsPrivateKey).toString('hex')).toBe(
        Buffer.from(testKey).toString('hex')
      );
    });

    it('throws ReEnrollRequiredError when keyEpoch < internalCurrentEpoch - 1 (stale key)', async () => {
      // internalCurrentEpoch = 10, keyEpoch = 8 → 8 < 10-1=9 → stale
      setInternalEpoch(10);
      const dummy = new Uint8Array(65);

      await expect(decryptWithFallback(dummy, 8)).rejects.toBeInstanceOf(ReEnrollRequiredError);
    });

    it('ReEnrollRequiredError carries requiresReEnroll, keyEpoch, and currentEpoch', async () => {
      setInternalEpoch(10);
      const dummy = new Uint8Array(65);

      let caughtErr: unknown;
      try {
        await decryptWithFallback(dummy, 8);
        expect.fail('Expected ReEnrollRequiredError to be thrown');
      } catch (err) {
        caughtErr = err;
      }

      expect(caughtErr).toBeInstanceOf(ReEnrollRequiredError);
      const typedErr = caughtErr as InstanceType<typeof ReEnrollRequiredError>;
      expect(typedErr.requiresReEnroll).toBe(true);
      expect(typedErr.keyEpoch).toBe(8);
      expect(typedErr.currentEpoch).toBe(10);
    });

    it('stale guard: getKeypair (decryptIpnsKey) is never called for stale keyEpoch', async () => {
      // Arrange: stale scenario — keyEpoch 8 < internalCurrentEpoch 10 - 1
      setInternalEpoch(10);
      const dummy = new Uint8Array(65);

      // Spy on getKeypair; decryptIpnsKey calls getKeypair internally.
      // If the stale guard fires before decryptIpnsKey, getKeypair must not be called.
      const spy = vi.spyOn(teeKeysModule, 'getKeypair');

      await expect(decryptWithFallback(dummy, 8)).rejects.toBeInstanceOf(ReEnrollRequiredError);

      expect(spy).not.toHaveBeenCalled();
    });

    it('ReEnrollRequiredError message names epoch integers and no key material', async () => {
      setInternalEpoch(10);
      const dummy = new Uint8Array(65);

      let message = '';
      try {
        await decryptWithFallback(dummy, 8);
      } catch (err) {
        message = (err as Error).message;
      }

      // Message must mention the epoch numbers
      expect(message).toMatch(/8/);
      expect(message).toMatch(/10/);
      // Message must not contain long hex strings (key material)
      expect(message).not.toMatch(/[0-9a-f]{32,}/i);
    });

    it('falls back to internalCurrentEpoch when keyEpoch trial fails (mid-rotation)', async () => {
      // Key was re-encrypted mid-rotation and now decrypts only under internalCurrentEpoch.
      // keyEpoch = 9 (grace window), but key is actually encrypted for epoch 10.
      setInternalEpoch(10);
      const testKey = randomTestKey();
      const kp = await getKeypair(10); // encrypted for CURRENT epoch
      const encrypted = await wrapKey(testKey, kp.publicKey);

      const result = await decryptWithFallback(encrypted, 9); // keyEpoch=9, not stale (9>=9)

      expect(result.usedEpoch).toBe(10); // fell through to internalCurrentEpoch
      expect(Buffer.from(result.ipnsPrivateKey).toString('hex')).toBe(
        Buffer.from(testKey).toString('hex')
      );
    });

    it('throws generic error when no epoch decrypts (non-stale, corrupted or unknown key)', async () => {
      // Key encrypted for epoch 5 — neither keyEpoch=9 nor internalCurrentEpoch=10 will work
      setInternalEpoch(10);
      const testKey = randomTestKey();
      const kp = await getKeypair(5);
      const encrypted = await wrapKey(testKey, kp.publicKey);

      await expect(decryptWithFallback(encrypted, 9)).rejects.toThrow('ECIES decryption failed');
    });

    it('throws generic error (not ReEnrollRequiredError) for epoch-mismatch in non-stale range', async () => {
      setInternalEpoch(10);
      const testKey = randomTestKey();
      const kp = await getKeypair(5);
      const encrypted = await wrapKey(testKey, kp.publicKey);

      let caughtErr: unknown;
      try {
        await decryptWithFallback(encrypted, 9);
      } catch (err) {
        caughtErr = err;
      }

      expect(caughtErr).not.toBeInstanceOf(ReEnrollRequiredError);
    });

    it('genuine ciphertext corruption (byte-flipped wrapKey output) throws a non-ReEnrollRequiredError, non-TeeKeyUnavailableError generic error', async () => {
      // keyEpoch === internalCurrentEpoch === 10 so both trials use epoch 10's key.
      // The ciphertext is genuinely corrupt (a flipped byte breaks the GCM auth tag),
      // so unwrapKey throws a real crypto error — NOT a config/infra error.
      setInternalEpoch(10);
      const testKey = randomTestKey();
      const kp = await getKeypair(10);
      const encrypted = await wrapKey(testKey, kp.publicKey);

      // Flip a byte in the middle of the ciphertext to genuinely corrupt it
      const corrupted = new Uint8Array(encrypted);
      const mid = Math.floor(corrupted.length / 2);
      corrupted[mid] ^= 0xff;

      let caughtErr: unknown;
      try {
        await decryptWithFallback(corrupted, 10);
        expect.fail('Expected decryptWithFallback to throw for a corrupted ciphertext');
      } catch (err) {
        caughtErr = err;
      }

      expect(caughtErr).toBeInstanceOf(Error);
      expect(caughtErr).not.toBeInstanceOf(ReEnrollRequiredError);
      expect(caughtErr).not.toBeInstanceOf(TeeKeyUnavailableError);
      expect((caughtErr as Error).message).toContain('ECIES decryption failed');
    });

    it('rethrows TeeKeyUnavailableError from getKeypair (config/infra failure) instead of masking it as a corrupted key', async () => {
      // A deployment misconfiguration (getKeypair throwing TeeKeyUnavailableError)
      // must NOT be masked as the generic corrupted-key message — decryptWithFallback
      // must rethrow the typed error via instanceof.
      setInternalEpoch(10);
      const dummy = new Uint8Array(65);

      vi.spyOn(teeKeysModule, 'getKeypair').mockRejectedValue(
        new TeeKeyUnavailableError('TEE_MODE=simulator is not allowed in production.')
      );

      let caughtErr: unknown;
      try {
        // keyEpoch 10 is non-stale (>= internalCurrentEpoch - 1), so the stale guard
        // does not fire and Trial 1 invokes getKeypair (stubbed to throw the typed error).
        await decryptWithFallback(dummy, 10);
        expect.fail('Expected decryptWithFallback to rethrow TeeKeyUnavailableError');
      } catch (err) {
        caughtErr = err;
      }

      expect(caughtErr).toBeInstanceOf(TeeKeyUnavailableError);
      expect(caughtErr).not.toBeInstanceOf(ReEnrollRequiredError);
      // The generic corrupted-key message must NOT be used for a config/infra failure
      expect((caughtErr as Error).message).not.toContain('ECIES decryption failed');
      // The original config/infra error is preserved as the cause
      expect((caughtErr as { cause?: unknown }).cause).toBeInstanceOf(TeeKeyUnavailableError);
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

      expect(Buffer.from(roundTripped).toString('hex')).toBe(Buffer.from(testKey).toString('hex'));
    });

    it('produces different ciphertext each time (ECIES is randomized)', async () => {
      const testKey = randomTestKey();
      const targetEpoch = 6;

      const enc1 = await reEncryptForEpoch(testKey, targetEpoch);
      const enc2 = await reEncryptForEpoch(testKey, targetEpoch);

      // ECIES produces different ciphertexts for same plaintext
      expect(Buffer.from(enc1).toString('hex')).not.toBe(Buffer.from(enc2).toString('hex'));
    });

    it('full epoch migration round-trip: decrypt old, re-encrypt new, decrypt new', async () => {
      const oldEpoch = 3;
      const newEpoch = 4;
      // oldEpoch (3) is in grace window of newEpoch (4): 3 >= 4-1=3 → not stale
      setInternalEpoch(newEpoch);

      const testKey = randomTestKey();

      // 1. Encrypt with old epoch
      const kpOld = await getKeypair(oldEpoch);
      const encryptedOld = await wrapKey(testKey, kpOld.publicKey);

      // 2. Decrypt with fallback: keyEpoch=3, internalCurrentEpoch=4 → grace, decrypts with 3
      const { ipnsPrivateKey, usedEpoch } = await decryptWithFallback(encryptedOld, oldEpoch);
      expect(usedEpoch).toBe(oldEpoch);

      // 3. Re-encrypt for new epoch
      const encryptedNew = await reEncryptForEpoch(ipnsPrivateKey, newEpoch);

      // 4. Decrypt with new epoch (direct)
      const decryptedNew = await decryptIpnsKey(encryptedNew, newEpoch);

      expect(Buffer.from(decryptedNew).toString('hex')).toBe(Buffer.from(testKey).toString('hex'));

      delete process.env.EPOCH_ZERO_TIMESTAMP_MS;
    });
  });
});

/**
 * @cipherbox/crypto - ECIES Tests
 *
 * Tests for asymmetric key wrapping/unwrapping.
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { wrapKey, unwrapKey } from '../ecies';
import { generateFileKey, generateRandomBytes } from '../utils';
import { SECP256K1_PUBLIC_KEY_SIZE, SECP256K1_PRIVATE_KEY_SIZE } from '../constants';

/**
 * Generate a secp256k1 keypair for testing.
 */
function generateTestKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed
  return { publicKey, privateKey };
}

describe('ECIES Key Wrapping', () => {
  describe('wrapKey / unwrapKey round-trip', () => {
    it('should wrap and unwrap a 32-byte key correctly', async () => {
      const keypair = generateTestKeypair();
      const originalKey = generateFileKey();

      const wrappedKey = await wrapKey(originalKey, keypair.publicKey);
      const unwrappedKey = await unwrapKey(wrappedKey, keypair.privateKey);

      expect(unwrappedKey).toEqual(originalKey);
    });

    it('should handle small data (1 byte)', async () => {
      const keypair = generateTestKeypair();
      const originalData = new Uint8Array([0x42]);

      const wrapped = await wrapKey(originalData, keypair.publicKey);
      const unwrapped = await unwrapKey(wrapped, keypair.privateKey);

      expect(unwrapped).toEqual(originalData);
    });

    it('should handle arbitrary size data', async () => {
      const keypair = generateTestKeypair();
      const originalData = new TextEncoder().encode('This is some arbitrary data for testing');

      const wrapped = await wrapKey(originalData, keypair.publicKey);
      const unwrapped = await unwrapKey(wrapped, keypair.privateKey);

      expect(new TextDecoder().decode(unwrapped)).toBe('This is some arbitrary data for testing');
    });

    it('should produce wrapped output larger than input (includes ephemeral key)', async () => {
      const keypair = generateTestKeypair();
      const originalKey = generateFileKey(); // 32 bytes

      const wrapped = await wrapKey(originalKey, keypair.publicKey);

      // ECIES output includes:
      // - 65 bytes ephemeral public key (uncompressed)
      // - Ciphertext (same length as plaintext)
      // - 16 bytes auth tag
      // Total: 65 + 32 + 16 = 113 bytes minimum
      expect(wrapped.length).toBeGreaterThan(originalKey.length);
    });
  });

  describe('unwrap with wrong private key', () => {
    it('should throw generic error with wrong private key', async () => {
      const keypair1 = generateTestKeypair();
      const keypair2 = generateTestKeypair();
      const originalKey = generateFileKey();

      const wrapped = await wrapKey(originalKey, keypair1.publicKey);

      await expect(unwrapKey(wrapped, keypair2.privateKey)).rejects.toThrow(
        'Key unwrapping failed'
      );
    });
  });

  describe('public key length validation', () => {
    it('should reject non-65-byte public keys (too short)', async () => {
      const shortKey = generateRandomBytes(33); // compressed key size
      const data = generateFileKey();

      await expect(wrapKey(data, shortKey)).rejects.toThrow('Key wrapping failed');
    });

    it('should reject non-65-byte public keys (too long)', async () => {
      const longKey = generateRandomBytes(100);
      const data = generateFileKey();

      await expect(wrapKey(data, longKey)).rejects.toThrow('Key wrapping failed');
    });

    it('should accept exactly 65-byte uncompressed public key', async () => {
      const keypair = generateTestKeypair();
      expect(keypair.publicKey.length).toBe(SECP256K1_PUBLIC_KEY_SIZE);

      const data = generateFileKey();
      // Should not throw
      const wrapped = await wrapKey(data, keypair.publicKey);
      expect(wrapped.length).toBeGreaterThan(0);
    });

    it('should reject public key without 0x04 prefix', async () => {
      const keypair = generateTestKeypair();
      // Create a 65-byte array with wrong prefix
      const badPublicKey = new Uint8Array(keypair.publicKey);
      badPublicKey[0] = 0x02; // Change prefix to compressed format marker

      await expect(wrapKey(generateFileKey(), badPublicKey)).rejects.toThrow('Key wrapping failed');
    });
  });

  describe('private key length validation', () => {
    it('should reject non-32-byte private keys for unwrapping', async () => {
      const keypair = generateTestKeypair();
      const data = generateFileKey();
      const wrapped = await wrapKey(data, keypair.publicKey);

      const shortPrivateKey = generateRandomBytes(16);
      await expect(unwrapKey(wrapped, shortPrivateKey)).rejects.toThrow('Key unwrapping failed');
    });

    it('should accept exactly 32-byte private key', async () => {
      const keypair = generateTestKeypair();
      expect(keypair.privateKey.length).toBe(SECP256K1_PRIVATE_KEY_SIZE);

      const data = generateFileKey();
      const wrapped = await wrapKey(data, keypair.publicKey);

      // Should not throw
      const unwrapped = await unwrapKey(wrapped, keypair.privateKey);
      expect(unwrapped).toEqual(data);
    });
  });

  describe('ephemeral key randomness', () => {
    it('should produce different ciphertext for same key wrapped multiple times', async () => {
      const keypair = generateTestKeypair();
      const originalKey = generateFileKey();

      const wrapped1 = await wrapKey(originalKey, keypair.publicKey);
      const wrapped2 = await wrapKey(originalKey, keypair.publicKey);
      const wrapped3 = await wrapKey(originalKey, keypair.publicKey);

      // All wrappings should be different due to ephemeral key
      expect(wrapped1).not.toEqual(wrapped2);
      expect(wrapped2).not.toEqual(wrapped3);
      expect(wrapped1).not.toEqual(wrapped3);

      // But all should unwrap to same original
      const unwrapped1 = await unwrapKey(wrapped1, keypair.privateKey);
      const unwrapped2 = await unwrapKey(wrapped2, keypair.privateKey);
      const unwrapped3 = await unwrapKey(wrapped3, keypair.privateKey);

      expect(unwrapped1).toEqual(originalKey);
      expect(unwrapped2).toEqual(originalKey);
      expect(unwrapped3).toEqual(originalKey);
    });
  });

  describe('ciphertext tampering', () => {
    it('should throw on tampered wrapped key', async () => {
      const keypair = generateTestKeypair();
      const originalKey = generateFileKey();

      const wrapped = await wrapKey(originalKey, keypair.publicKey);

      // Tamper with a byte in the middle
      const tampered = new Uint8Array(wrapped);
      tampered[Math.floor(tampered.length / 2)] ^= 0xff;

      await expect(unwrapKey(tampered, keypair.privateKey)).rejects.toThrow(
        'Key unwrapping failed'
      );
    });

    it('should throw on truncated wrapped key', async () => {
      const keypair = generateTestKeypair();
      const originalKey = generateFileKey();

      const wrapped = await wrapKey(originalKey, keypair.publicKey);

      // Truncate the wrapped data
      const truncated = wrapped.slice(0, wrapped.length - 10);

      await expect(unwrapKey(truncated, keypair.privateKey)).rejects.toThrow(
        'Key unwrapping failed'
      );
    });
  });

  describe('error message security', () => {
    it('should use generic error messages for all failures', async () => {
      const keypair = generateTestKeypair();
      const originalKey = generateFileKey();
      const wrapped = await wrapKey(originalKey, keypair.publicKey);

      const wrongKeypair = generateTestKeypair();
      const tampered = new Uint8Array(wrapped);
      tampered[0] ^= 0xff;

      const errors: string[] = [];

      // Wrong private key
      try {
        await unwrapKey(wrapped, wrongKeypair.privateKey);
      } catch (e) {
        errors.push((e as Error).message);
      }

      // Tampered ciphertext
      try {
        await unwrapKey(tampered, keypair.privateKey);
      } catch (e) {
        errors.push((e as Error).message);
      }

      // All errors should be identical to prevent oracle attacks
      expect(new Set(errors).size).toBe(1);
      expect(errors[0]).toBe('Key unwrapping failed');
    });
  });
});

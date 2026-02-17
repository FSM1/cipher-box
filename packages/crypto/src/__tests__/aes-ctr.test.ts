/**
 * @cipherbox/crypto - AES-256-CTR Tests
 *
 * Tests for CTR-mode symmetric encryption/decryption including
 * random-access range decryption for streaming media.
 */

import { describe, it, expect } from 'vitest';
import { encryptAesCtr, decryptAesCtr, decryptAesCtrRange } from '../aes';
import { generateFileKey, generateRandomBytes, generateCtrIv } from '../utils';
import { AES_CTR_IV_SIZE, AES_CTR_NONCE_SIZE } from '../constants';
import { CryptoError } from '../types';

describe('AES-256-CTR', () => {
  describe('encryptAesCtr / decryptAesCtr round-trip', () => {
    it('should encrypt and decrypt empty data', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new Uint8Array(0);

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const decrypted = await decryptAesCtr(ciphertext, key, iv);

      expect(decrypted.length).toBe(0);
    });

    it('should encrypt and decrypt 1 byte', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new Uint8Array([0x42]);

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const decrypted = await decryptAesCtr(ciphertext, key, iv);

      expect(decrypted).toEqual(plaintext);
    });

    it('should encrypt and decrypt 15 bytes (less than one block)', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = generateRandomBytes(15);

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const decrypted = await decryptAesCtr(ciphertext, key, iv);

      expect(decrypted).toEqual(plaintext);
    });

    it('should encrypt and decrypt 16 bytes (exactly one block)', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = generateRandomBytes(16);

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const decrypted = await decryptAesCtr(ciphertext, key, iv);

      expect(decrypted).toEqual(plaintext);
    });

    it('should encrypt and decrypt 17 bytes (one block + 1)', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = generateRandomBytes(17);

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const decrypted = await decryptAesCtr(ciphertext, key, iv);

      expect(decrypted).toEqual(plaintext);
    });

    it('should encrypt and decrypt 1MB data', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();

      // Generate 1MB by concatenating 32KB chunks (crypto.getRandomValues limit)
      const totalSize = 1024 * 1024;
      const chunkSize = 32 * 1024;
      const plaintext = new Uint8Array(totalSize);
      for (let i = 0; i < totalSize; i += chunkSize) {
        const size = Math.min(chunkSize, totalSize - i);
        plaintext.set(generateRandomBytes(size), i);
      }

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const decrypted = await decryptAesCtr(ciphertext, key, iv);

      expect(decrypted).toEqual(plaintext);
    });

    it('should encrypt and decrypt string data correctly', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new TextEncoder().encode('Hello, CipherBox CTR!');

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const decrypted = await decryptAesCtr(ciphertext, key, iv);

      expect(new TextDecoder().decode(decrypted)).toBe('Hello, CipherBox CTR!');
    });
  });

  describe('CTR output size', () => {
    it('should produce ciphertext of exactly the same size as plaintext (no auth tag)', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new TextEncoder().encode('Test CTR output size');

      const ciphertext = await encryptAesCtr(plaintext, key, iv);

      // CTR is a stream cipher -- no auth tag, no padding
      expect(ciphertext.length).toBe(plaintext.length);
    });

    it('should produce same-size output for various sizes', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();

      for (const size of [0, 1, 15, 16, 17, 31, 32, 100, 256, 1000]) {
        const plaintext = generateRandomBytes(size);
        const ciphertext = await encryptAesCtr(plaintext, key, iv);
        expect(ciphertext.length).toBe(size);
      }
    });
  });

  describe('decryptAesCtrRange', () => {
    // Create a known buffer: 256 bytes with sequential values 0-255
    async function createTestData() {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        plaintext[i] = i;
      }
      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      return { key, iv, plaintext, ciphertext };
    }

    it('should decrypt first block [0, 15]', async () => {
      const { key, iv, plaintext, ciphertext } = await createTestData();

      const range = await decryptAesCtrRange(ciphertext, key, iv, 0, 15);

      expect(range).toEqual(plaintext.slice(0, 16));
    });

    it('should decrypt second block [16, 31]', async () => {
      const { key, iv, plaintext, ciphertext } = await createTestData();

      const range = await decryptAesCtrRange(ciphertext, key, iv, 16, 31);

      expect(range).toEqual(plaintext.slice(16, 32));
    });

    it('should decrypt cross-block range [10, 25] (not block-aligned)', async () => {
      const { key, iv, plaintext, ciphertext } = await createTestData();

      const range = await decryptAesCtrRange(ciphertext, key, iv, 10, 25);

      expect(range).toEqual(plaintext.slice(10, 26));
    });

    it('should decrypt entire file [0, 255]', async () => {
      const { key, iv, plaintext, ciphertext } = await createTestData();

      const range = await decryptAesCtrRange(ciphertext, key, iv, 0, 255);

      expect(range).toEqual(plaintext);
    });

    it('should decrypt last block [240, 255]', async () => {
      const { key, iv, plaintext, ciphertext } = await createTestData();

      const range = await decryptAesCtrRange(ciphertext, key, iv, 240, 255);

      expect(range).toEqual(plaintext.slice(240, 256));
    });

    it('should decrypt single byte [100, 100]', async () => {
      const { key, iv, plaintext, ciphertext } = await createTestData();

      const range = await decryptAesCtrRange(ciphertext, key, iv, 100, 100);

      expect(range.length).toBe(1);
      expect(range[0]).toBe(plaintext[100]);
    });

    it('should clamp endByte beyond data length', async () => {
      const { key, iv, plaintext, ciphertext } = await createTestData();

      // endByte = 999 but data is only 256 bytes
      const range = await decryptAesCtrRange(ciphertext, key, iv, 240, 999);

      expect(range).toEqual(plaintext.slice(240, 256));
    });

    it('should return empty for range entirely beyond data', async () => {
      const { key, iv, ciphertext } = await createTestData();

      const range = await decryptAesCtrRange(ciphertext, key, iv, 300, 400);

      expect(range.length).toBe(0);
    });

    it('should reject startByte > endByte', async () => {
      const { key, iv, ciphertext } = await createTestData();

      await expect(decryptAesCtrRange(ciphertext, key, iv, 100, 50)).rejects.toThrow(CryptoError);
    });

    it('should reject negative offsets', async () => {
      const { key, iv, ciphertext } = await createTestData();

      await expect(decryptAesCtrRange(ciphertext, key, iv, -1, 10)).rejects.toThrow(CryptoError);
    });
  });

  describe('key uniqueness', () => {
    it('should produce different ciphertext with different keys', async () => {
      const key1 = generateFileKey();
      const key2 = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new TextEncoder().encode('Same plaintext');

      const ciphertext1 = await encryptAesCtr(plaintext, key1, iv);
      const ciphertext2 = await encryptAesCtr(plaintext, key2, iv);

      expect(ciphertext1).not.toEqual(ciphertext2);
    });
  });

  describe('nonce uniqueness', () => {
    it('should produce different ciphertext with different IVs', async () => {
      const key = generateFileKey();
      const iv1 = generateCtrIv();
      const iv2 = generateCtrIv();
      const plaintext = new TextEncoder().encode('Same plaintext');

      const ciphertext1 = await encryptAesCtr(plaintext, key, iv1);
      const ciphertext2 = await encryptAesCtr(plaintext, key, iv2);

      expect(ciphertext1).not.toEqual(ciphertext2);
    });
  });

  describe('key length validation', () => {
    it('should reject non-32-byte keys for encryption', async () => {
      const shortKey = generateRandomBytes(16);
      const iv = generateCtrIv();
      const plaintext = new TextEncoder().encode('Test');

      await expect(encryptAesCtr(plaintext, shortKey, iv)).rejects.toThrow('Encryption failed');
    });

    it('should reject non-32-byte keys for decryption', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new TextEncoder().encode('Test');

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const shortKey = generateRandomBytes(16);

      await expect(decryptAesCtr(ciphertext, shortKey, iv)).rejects.toThrow('Decryption failed');
    });

    it('should reject non-32-byte keys for range decryption', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new TextEncoder().encode('Test data for range');

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const shortKey = generateRandomBytes(16);

      await expect(decryptAesCtrRange(ciphertext, shortKey, iv, 0, 5)).rejects.toThrow(
        'Decryption failed'
      );
    });
  });

  describe('IV length validation', () => {
    it('should reject non-16-byte IVs for encryption', async () => {
      const key = generateFileKey();
      const shortIv = generateRandomBytes(12); // GCM size, not CTR
      const plaintext = new TextEncoder().encode('Test');

      await expect(encryptAesCtr(plaintext, key, shortIv)).rejects.toThrow('Encryption failed');
    });

    it('should reject non-16-byte IVs for decryption', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new TextEncoder().encode('Test');

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const wrongIv = generateRandomBytes(12);

      await expect(decryptAesCtr(ciphertext, key, wrongIv)).rejects.toThrow('Decryption failed');
    });

    it('should reject non-16-byte IVs for range decryption', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const plaintext = new TextEncoder().encode('Test data');

      const ciphertext = await encryptAesCtr(plaintext, key, iv);
      const wrongIv = generateRandomBytes(12);

      await expect(decryptAesCtrRange(ciphertext, key, wrongIv, 0, 3)).rejects.toThrow(
        'Decryption failed'
      );
    });
  });

  describe('generateCtrIv', () => {
    it('should return 16 bytes', () => {
      const iv = generateCtrIv();
      expect(iv.length).toBe(AES_CTR_IV_SIZE);
    });

    it('should have last 8 bytes all zero (counter starts at 0)', () => {
      const iv = generateCtrIv();
      const counterPortion = iv.slice(AES_CTR_NONCE_SIZE); // bytes 8-15

      expect(counterPortion).toEqual(new Uint8Array(8));
    });

    it('should have non-zero nonce (probabilistic, 10 attempts)', () => {
      // The probability of all 8 random bytes being zero is 2^-64,
      // essentially impossible. Run 10 times to be safe.
      let hasNonZeroNonce = false;
      for (let i = 0; i < 10; i++) {
        const iv = generateCtrIv();
        const nonce = iv.slice(0, AES_CTR_NONCE_SIZE);
        if (nonce.some((b) => b !== 0)) {
          hasNonZeroNonce = true;
          break;
        }
      }
      expect(hasNonZeroNonce).toBe(true);
    });

    it('should produce different IVs on each call', () => {
      const iv1 = generateCtrIv();
      const iv2 = generateCtrIv();
      const iv3 = generateCtrIv();

      // Nonce portions should differ
      expect(iv1.slice(0, AES_CTR_NONCE_SIZE)).not.toEqual(iv2.slice(0, AES_CTR_NONCE_SIZE));
      expect(iv2.slice(0, AES_CTR_NONCE_SIZE)).not.toEqual(iv3.slice(0, AES_CTR_NONCE_SIZE));
    });
  });

  describe('large file range decrypt', () => {
    it('should correctly range-decrypt from the middle of a 1MB file', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();

      // Create 1MB plaintext with deterministic pattern
      const totalSize = 1024 * 1024;
      const plaintext = new Uint8Array(totalSize);
      // Fill with a repeating pattern (mod 256 of index)
      for (let i = 0; i < totalSize; i++) {
        plaintext[i] = i % 256;
      }

      const ciphertext = await encryptAesCtr(plaintext, key, iv);

      // Decrypt a range in the middle: bytes 500000-500999
      const rangeStart = 500000;
      const rangeEnd = 500999;
      const rangeDecrypted = await decryptAesCtrRange(ciphertext, key, iv, rangeStart, rangeEnd);

      expect(rangeDecrypted.length).toBe(1000);
      expect(rangeDecrypted).toEqual(plaintext.slice(rangeStart, rangeEnd + 1));
    });
  });

  describe('CryptoError codes', () => {
    it('should throw CryptoError with INVALID_KEY_SIZE code', async () => {
      const shortKey = generateRandomBytes(16);
      const iv = generateCtrIv();
      const plaintext = new TextEncoder().encode('Test');

      try {
        await encryptAesCtr(plaintext, shortKey, iv);
        expect.unreachable('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_KEY_SIZE');
      }
    });

    it('should throw CryptoError with INVALID_IV_SIZE code', async () => {
      const key = generateFileKey();
      const wrongIv = generateRandomBytes(12);
      const plaintext = new TextEncoder().encode('Test');

      try {
        await encryptAesCtr(plaintext, key, wrongIv);
        expect.unreachable('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_IV_SIZE');
      }
    });

    it('should throw CryptoError with INVALID_INPUT code for bad range', async () => {
      const key = generateFileKey();
      const iv = generateCtrIv();
      const ciphertext = generateRandomBytes(32);

      try {
        await decryptAesCtrRange(ciphertext, key, iv, 20, 10);
        expect.unreachable('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_INPUT');
      }
    });
  });
});

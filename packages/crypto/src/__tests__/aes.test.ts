/**
 * @cipherbox/crypto - AES-256-GCM Tests
 *
 * Tests for symmetric encryption/decryption.
 */

import { describe, it, expect } from 'vitest';
import { encryptAesGcm, decryptAesGcm } from '../aes';
import { generateFileKey, generateIv, generateRandomBytes } from '../utils';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_TAG_SIZE } from '../constants';

describe('AES-256-GCM', () => {
  describe('encryptAesGcm / decryptAesGcm round-trip', () => {
    it('should encrypt and decrypt data correctly', async () => {
      const key = generateFileKey();
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Hello, CipherBox!');

      const ciphertext = await encryptAesGcm(plaintext, key, iv);
      const decrypted = await decryptAesGcm(ciphertext, key, iv);

      expect(new TextDecoder().decode(decrypted)).toBe('Hello, CipherBox!');
    });

    it('should handle empty plaintext', async () => {
      const key = generateFileKey();
      const iv = generateIv();
      const plaintext = new Uint8Array(0);

      const ciphertext = await encryptAesGcm(plaintext, key, iv);
      const decrypted = await decryptAesGcm(ciphertext, key, iv);

      expect(decrypted.length).toBe(0);
    });

    it('should handle large data (100KB)', async () => {
      const key = generateFileKey();
      const iv = generateIv();

      // Generate large data by concatenating smaller random chunks
      // (crypto.getRandomValues has 65536 byte limit)
      const chunks: Uint8Array[] = [];
      const chunkSize = 32 * 1024; // 32KB per chunk
      const totalSize = 100 * 1024; // 100KB total
      for (let i = 0; i < totalSize; i += chunkSize) {
        const size = Math.min(chunkSize, totalSize - i);
        chunks.push(generateRandomBytes(size));
      }

      // Combine chunks into single array
      const plaintext = new Uint8Array(totalSize);
      let offset = 0;
      for (const chunk of chunks) {
        plaintext.set(chunk, offset);
        offset += chunk.length;
      }

      const ciphertext = await encryptAesGcm(plaintext, key, iv);
      const decrypted = await decryptAesGcm(ciphertext, key, iv);

      expect(decrypted).toEqual(plaintext);
    });

    it('should include 16-byte auth tag in ciphertext', async () => {
      const key = generateFileKey();
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Test');

      const ciphertext = await encryptAesGcm(plaintext, key, iv);

      // Ciphertext = plaintext + 16-byte auth tag
      expect(ciphertext.length).toBe(plaintext.length + AES_TAG_SIZE);
    });

    it('should match DATA_FLOWS.md test vector format', async () => {
      // Test with "Hello, CipherBox!" as per test vector specification
      const key = generateFileKey();
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Hello, CipherBox!');

      const ciphertext = await encryptAesGcm(plaintext, key, iv);
      const decrypted = await decryptAesGcm(ciphertext, key, iv);

      expect(new TextDecoder().decode(decrypted)).toBe('Hello, CipherBox!');
      // Verify ciphertext structure (plaintext length + auth tag)
      expect(ciphertext.length).toBe(17 + AES_TAG_SIZE); // "Hello, CipherBox!".length = 17
    });
  });

  describe('decryption with wrong key', () => {
    it('should throw generic error with wrong key', async () => {
      const key1 = generateFileKey();
      const key2 = generateFileKey();
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Secret data');

      const ciphertext = await encryptAesGcm(plaintext, key1, iv);

      await expect(decryptAesGcm(ciphertext, key2, iv)).rejects.toThrow('Decryption failed');
    });
  });

  describe('decryption with modified ciphertext', () => {
    it('should throw on modified ciphertext (auth tag failure)', async () => {
      const key = generateFileKey();
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Authenticated data');

      const ciphertext = await encryptAesGcm(plaintext, key, iv);

      // Modify first byte of ciphertext
      const tampered = new Uint8Array(ciphertext);
      tampered[0] ^= 0xff;

      await expect(decryptAesGcm(tampered, key, iv)).rejects.toThrow('Decryption failed');
    });

    it('should throw on modified auth tag', async () => {
      const key = generateFileKey();
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Authenticated data');

      const ciphertext = await encryptAesGcm(plaintext, key, iv);

      // Modify last byte (part of auth tag)
      const tampered = new Uint8Array(ciphertext);
      tampered[tampered.length - 1] ^= 0xff;

      await expect(decryptAesGcm(tampered, key, iv)).rejects.toThrow('Decryption failed');
    });
  });

  describe('each encryption produces different ciphertext', () => {
    it('should produce different ciphertext with different IVs (no IV reuse)', async () => {
      const key = generateFileKey();
      const plaintext = new TextEncoder().encode('Same plaintext');

      const iv1 = generateIv();
      const iv2 = generateIv();

      const ciphertext1 = await encryptAesGcm(plaintext, key, iv1);
      const ciphertext2 = await encryptAesGcm(plaintext, key, iv2);

      // Ciphertexts should be different with different IVs
      expect(ciphertext1).not.toEqual(ciphertext2);
    });
  });

  describe('key length validation', () => {
    it('should reject non-32-byte keys for encryption', async () => {
      const shortKey = generateRandomBytes(16); // 128-bit, too short
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Test');

      await expect(encryptAesGcm(plaintext, shortKey, iv)).rejects.toThrow('Encryption failed');
    });

    it('should reject non-32-byte keys for decryption', async () => {
      const key = generateFileKey();
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Test');

      const ciphertext = await encryptAesGcm(plaintext, key, iv);
      const shortKey = generateRandomBytes(16);

      await expect(decryptAesGcm(ciphertext, shortKey, iv)).rejects.toThrow('Decryption failed');
    });

    it('should accept exactly 32-byte keys', async () => {
      const key = new Uint8Array(AES_KEY_SIZE).fill(0x42);
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Test');

      // Should not throw
      const ciphertext = await encryptAesGcm(plaintext, key, iv);
      const decrypted = await decryptAesGcm(ciphertext, key, iv);
      expect(new TextDecoder().decode(decrypted)).toBe('Test');
    });
  });

  describe('IV length validation', () => {
    it('should reject non-12-byte IVs for encryption', async () => {
      const key = generateFileKey();
      const longIv = generateRandomBytes(16); // 128-bit, too long
      const plaintext = new TextEncoder().encode('Test');

      await expect(encryptAesGcm(plaintext, key, longIv)).rejects.toThrow('Encryption failed');
    });

    it('should reject non-12-byte IVs for decryption', async () => {
      const key = generateFileKey();
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Test');

      const ciphertext = await encryptAesGcm(plaintext, key, iv);
      const wrongIv = generateRandomBytes(16);

      await expect(decryptAesGcm(ciphertext, key, wrongIv)).rejects.toThrow('Decryption failed');
    });

    it('should accept exactly 12-byte IVs', async () => {
      const key = generateFileKey();
      const iv = new Uint8Array(AES_IV_SIZE).fill(0x12);
      const plaintext = new TextEncoder().encode('Test');

      // Should not throw
      const ciphertext = await encryptAesGcm(plaintext, key, iv);
      expect(ciphertext.length).toBe(plaintext.length + AES_TAG_SIZE);
    });
  });

  describe('error message security', () => {
    it('should not reveal specific failure reason in errors', async () => {
      const key = generateFileKey();
      const iv = generateIv();
      const plaintext = new TextEncoder().encode('Test');
      const ciphertext = await encryptAesGcm(plaintext, key, iv);

      // All decryption failures should have same generic message
      const wrongKey = generateFileKey();
      const wrongIv = generateIv();
      const tampered = new Uint8Array(ciphertext);
      tampered[0] ^= 0xff;

      const errors: string[] = [];

      try {
        await decryptAesGcm(ciphertext, wrongKey, iv);
      } catch (e) {
        errors.push((e as Error).message);
      }

      try {
        await decryptAesGcm(ciphertext, key, wrongIv);
      } catch (e) {
        errors.push((e as Error).message);
      }

      try {
        await decryptAesGcm(tampered, key, iv);
      } catch (e) {
        errors.push((e as Error).message);
      }

      // All errors should be identical to prevent oracle attacks
      expect(new Set(errors).size).toBe(1);
      expect(errors[0]).toBe('Decryption failed');
    });
  });
});

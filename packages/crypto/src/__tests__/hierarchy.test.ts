/**
 * @cipherbox/crypto - Key Hierarchy Tests
 *
 * Tests for key derivation and generation functions.
 */

import { describe, it, expect } from 'vitest';
import { deriveKey, deriveContextKey, generateFolderKey, generateFileKey } from '../keys';
import { AES_KEY_SIZE } from '../constants';

describe('HKDF Key Derivation', () => {
  describe('deriveKey', () => {
    it('should produce consistent output for same inputs', async () => {
      const inputKey = new Uint8Array(32).fill(0x42);
      const salt = new TextEncoder().encode('test-salt');
      const info = new TextEncoder().encode('test-info');

      const derived1 = await deriveKey({ inputKey, salt, info });
      const derived2 = await deriveKey({ inputKey, salt, info });

      expect(derived1).toEqual(derived2);
    });

    it('should produce different output for different input keys', async () => {
      const inputKey1 = new Uint8Array(32).fill(0x42);
      const inputKey2 = new Uint8Array(32).fill(0x43);
      const salt = new TextEncoder().encode('test-salt');
      const info = new TextEncoder().encode('test-info');

      const derived1 = await deriveKey({ inputKey: inputKey1, salt, info });
      const derived2 = await deriveKey({ inputKey: inputKey2, salt, info });

      expect(derived1).not.toEqual(derived2);
    });

    it('should produce different output for different salts', async () => {
      const inputKey = new Uint8Array(32).fill(0x42);
      const salt1 = new TextEncoder().encode('salt-one');
      const salt2 = new TextEncoder().encode('salt-two');
      const info = new TextEncoder().encode('test-info');

      const derived1 = await deriveKey({ inputKey, salt: salt1, info });
      const derived2 = await deriveKey({ inputKey, salt: salt2, info });

      expect(derived1).not.toEqual(derived2);
    });

    it('should produce different output for different info', async () => {
      const inputKey = new Uint8Array(32).fill(0x42);
      const salt = new TextEncoder().encode('test-salt');
      const info1 = new TextEncoder().encode('info-one');
      const info2 = new TextEncoder().encode('info-two');

      const derived1 = await deriveKey({ inputKey, salt, info: info1 });
      const derived2 = await deriveKey({ inputKey, salt, info: info2 });

      expect(derived1).not.toEqual(derived2);
    });

    it('should default to 32-byte output length', async () => {
      const inputKey = new Uint8Array(32).fill(0x42);
      const salt = new TextEncoder().encode('test-salt');
      const info = new TextEncoder().encode('test-info');

      const derived = await deriveKey({ inputKey, salt, info });

      expect(derived.length).toBe(AES_KEY_SIZE);
    });

    it('should respect custom output length', async () => {
      const inputKey = new Uint8Array(32).fill(0x42);
      const salt = new TextEncoder().encode('test-salt');
      const info = new TextEncoder().encode('test-info');

      const derived16 = await deriveKey({ inputKey, salt, info, outputLength: 16 });
      const derived64 = await deriveKey({ inputKey, salt, info, outputLength: 64 });

      expect(derived16.length).toBe(16);
      expect(derived64.length).toBe(64);
    });

    it('should accept small input keys', async () => {
      const inputKey = new Uint8Array(8).fill(0x42);
      const salt = new TextEncoder().encode('test-salt');
      const info = new TextEncoder().encode('test-info');

      const derived = await deriveKey({ inputKey, salt, info });

      expect(derived.length).toBe(32);
    });

    it('should accept large input keys', async () => {
      const inputKey = new Uint8Array(128).fill(0x42);
      const salt = new TextEncoder().encode('test-salt');
      const info = new TextEncoder().encode('test-info');

      const derived = await deriveKey({ inputKey, salt, info });

      expect(derived.length).toBe(32);
    });

    it('should accept empty salt', async () => {
      const inputKey = new Uint8Array(32).fill(0x42);
      const salt = new Uint8Array(0);
      const info = new TextEncoder().encode('test-info');

      const derived = await deriveKey({ inputKey, salt, info });

      expect(derived.length).toBe(32);
    });

    it('should accept empty info', async () => {
      const inputKey = new Uint8Array(32).fill(0x42);
      const salt = new TextEncoder().encode('test-salt');
      const info = new Uint8Array(0);

      const derived = await deriveKey({ inputKey, salt, info });

      expect(derived.length).toBe(32);
    });
  });

  describe('deriveContextKey', () => {
    it('should produce consistent output for same master key and context', async () => {
      const masterKey = new Uint8Array(32).fill(0x42);
      const context = 'root-folder';

      const derived1 = await deriveContextKey(masterKey, context);
      const derived2 = await deriveContextKey(masterKey, context);

      expect(derived1).toEqual(derived2);
    });

    it('should produce different output for different contexts', async () => {
      const masterKey = new Uint8Array(32).fill(0x42);

      const folderKey = await deriveContextKey(masterKey, 'folder-key');
      const ipnsKey = await deriveContextKey(masterKey, 'ipns-key');

      expect(folderKey).not.toEqual(ipnsKey);
    });

    it('should produce different output for different master keys', async () => {
      const masterKey1 = new Uint8Array(32).fill(0x42);
      const masterKey2 = new Uint8Array(32).fill(0x43);
      const context = 'root-folder';

      const derived1 = await deriveContextKey(masterKey1, context);
      const derived2 = await deriveContextKey(masterKey2, context);

      expect(derived1).not.toEqual(derived2);
    });

    it('should produce 32-byte keys', async () => {
      const masterKey = new Uint8Array(32).fill(0x42);
      const context = 'test-context';

      const derived = await deriveContextKey(masterKey, context);

      expect(derived.length).toBe(32);
    });
  });
});

describe('Key Generation', () => {
  describe('generateFolderKey', () => {
    it('should generate 32-byte keys', async () => {
      const key = await generateFolderKey();

      expect(key.length).toBe(32);
    });

    it('should generate unique keys (randomness)', async () => {
      const key1 = await generateFolderKey();
      const key2 = await generateFolderKey();
      const key3 = await generateFolderKey();

      // All keys should be different
      expect(key1).not.toEqual(key2);
      expect(key2).not.toEqual(key3);
      expect(key1).not.toEqual(key3);
    });

    it('should generate keys with high entropy', async () => {
      const key = await generateFolderKey();

      // Check for non-trivial values (not all zeros, not all same byte)
      const uniqueBytes = new Set(key);
      expect(uniqueBytes.size).toBeGreaterThan(1);
    });
  });

  describe('generateFileKey', () => {
    it('should generate 32-byte keys', async () => {
      const key = generateFileKey();

      expect(key.length).toBe(32);
    });

    it('should generate unique keys (randomness)', async () => {
      const key1 = generateFileKey();
      const key2 = generateFileKey();
      const key3 = generateFileKey();

      // All keys should be different
      expect(key1).not.toEqual(key2);
      expect(key2).not.toEqual(key3);
      expect(key1).not.toEqual(key3);
    });
  });
});

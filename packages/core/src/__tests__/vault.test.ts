/**
 * @cipherbox/core - Vault Tests
 *
 * Tests for vault initialization and key encryption/decryption.
 * After the v3 hard-cut (NODE-06), vault carries two independent root keys:
 * rootReadKey and rootWriteKey (no longer rootFolderKey).
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { ED25519_PUBLIC_KEY_SIZE, ED25519_PRIVATE_KEY_SIZE, AES_KEY_SIZE } from '@cipherbox/crypto';
import { initializeVault, encryptVaultKeys, decryptVaultKeys } from '../vault';

/**
 * Generate a secp256k1 keypair for testing.
 */
function generateTestKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed
  return { publicKey, privateKey };
}

describe('Vault Initialization', () => {
  describe('initializeVault', () => {
    it('should return valid VaultInit structure with two root keys', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      expect(vault).toHaveProperty('rootReadKey');
      expect(vault).toHaveProperty('rootWriteKey');
      expect(vault).toHaveProperty('rootIpnsKeypair');
      expect(vault.rootIpnsKeypair).toHaveProperty('publicKey');
      expect(vault.rootIpnsKeypair).toHaveProperty('privateKey');
    });

    it('should not have rootFolderKey (removed in v3)', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      expect(vault).not.toHaveProperty('rootFolderKey');
    });

    it('should generate 32-byte rootReadKey', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      expect(vault.rootReadKey.length).toBe(AES_KEY_SIZE);
    });

    it('should generate 32-byte rootWriteKey', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      expect(vault.rootWriteKey.length).toBe(AES_KEY_SIZE);
    });

    it('rootReadKey and rootWriteKey must be independent (T-62-08)', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      // Keys must not be equal — they are independently generated (RESEARCH Open Q2)
      expect(vault.rootReadKey).not.toEqual(vault.rootWriteKey);
    });

    it('should generate Ed25519 keypair with correct sizes', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      expect(vault.rootIpnsKeypair.publicKey.length).toBe(ED25519_PUBLIC_KEY_SIZE);
      expect(vault.rootIpnsKeypair.privateKey.length).toBe(ED25519_PRIVATE_KEY_SIZE);
    });

    it('should produce unique root keys but deterministic IPNS keys for different private keys', async () => {
      const userKeypair1 = generateTestKeypair();
      const userKeypair2 = generateTestKeypair();
      const userKeypair3 = generateTestKeypair();

      const vault1 = await initializeVault(userKeypair1.privateKey);
      const vault2 = await initializeVault(userKeypair2.privateKey);
      const vault3 = await initializeVault(userKeypair3.privateKey);

      // Read keys should be unique (random)
      expect(vault1.rootReadKey).not.toEqual(vault2.rootReadKey);
      expect(vault2.rootReadKey).not.toEqual(vault3.rootReadKey);

      // Write keys should be unique (random)
      expect(vault1.rootWriteKey).not.toEqual(vault2.rootWriteKey);
      expect(vault2.rootWriteKey).not.toEqual(vault3.rootWriteKey);

      // IPNS keypairs should be unique for different private keys
      expect(vault1.rootIpnsKeypair.publicKey).not.toEqual(vault2.rootIpnsKeypair.publicKey);
      expect(vault1.rootIpnsKeypair.privateKey).not.toEqual(vault2.rootIpnsKeypair.privateKey);
    });

    it('should generate keys with high entropy', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      // Check rootReadKey has non-trivial entropy
      const readKeyUnique = new Set(vault.rootReadKey);
      expect(readKeyUnique.size).toBeGreaterThan(1);

      // Check rootWriteKey has non-trivial entropy
      const writeKeyUnique = new Set(vault.rootWriteKey);
      expect(writeKeyUnique.size).toBeGreaterThan(1);

      // Check IPNS private key has non-trivial entropy
      const ipnsKeyUnique = new Set(vault.rootIpnsKeypair.privateKey);
      expect(ipnsKeyUnique.size).toBeGreaterThan(1);
    });
  });
});

describe('Vault Key Encryption/Decryption', () => {
  describe('encryptVaultKeys', () => {
    it('should return EncryptedVaultKeys structure with two encrypted root keys', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      expect(encrypted).toHaveProperty('encryptedRootReadKey');
      expect(encrypted).toHaveProperty('encryptedRootWriteKey');
      expect(encrypted).toHaveProperty('encryptedIpnsPrivateKey');
    });

    it('should not have encryptedRootFolderKey (removed in v3)', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      expect(encrypted).not.toHaveProperty('encryptedRootFolderKey');
    });

    it('should produce encrypted data larger than plaintext', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      // ECIES adds ephemeral key (65 bytes) + tag (16 bytes)
      expect(encrypted.encryptedRootReadKey.length).toBeGreaterThan(vault.rootReadKey.length);
      expect(encrypted.encryptedRootWriteKey.length).toBeGreaterThan(vault.rootWriteKey.length);
      expect(encrypted.encryptedIpnsPrivateKey.length).toBeGreaterThan(
        vault.rootIpnsKeypair.privateKey.length
      );
    });

    it('should produce different encrypted data each time due to ECIES ephemeral keys', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      const encrypted1 = await encryptVaultKeys(vault, userKeypair.publicKey);
      const encrypted2 = await encryptVaultKeys(vault, userKeypair.publicKey);

      // Same plaintext should produce different ciphertext
      expect(encrypted1.encryptedRootReadKey).not.toEqual(encrypted2.encryptedRootReadKey);
      expect(encrypted1.encryptedRootWriteKey).not.toEqual(encrypted2.encryptedRootWriteKey);
      expect(encrypted1.encryptedIpnsPrivateKey).not.toEqual(encrypted2.encryptedIpnsPrivateKey);
    });
  });

  describe('decryptVaultKeys', () => {
    it('should recover both root keys after encrypt/decrypt round-trip', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);
      const decrypted = await decryptVaultKeys(encrypted, userKeypair.privateKey);

      expect(decrypted.rootReadKey).toEqual(vault.rootReadKey);
      expect(decrypted.rootWriteKey).toEqual(vault.rootWriteKey);
      expect(decrypted.rootIpnsKeypair.publicKey).toEqual(vault.rootIpnsKeypair.publicKey);
      expect(decrypted.rootIpnsKeypair.privateKey).toEqual(vault.rootIpnsKeypair.privateKey);
    });

    it('decrypted rootReadKey and rootWriteKey must differ (T-62-08)', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);
      const decrypted = await decryptVaultKeys(encrypted, userKeypair.privateKey);

      expect(decrypted.rootReadKey).not.toEqual(decrypted.rootWriteKey);
    });

    it('should throw with wrong private key', async () => {
      const userKeypair1 = generateTestKeypair();
      const userKeypair2 = generateTestKeypair();
      const vault = await initializeVault(userKeypair1.privateKey);

      const encrypted = await encryptVaultKeys(vault, userKeypair1.publicKey);

      await expect(decryptVaultKeys(encrypted, userKeypair2.privateKey)).rejects.toThrow(
        'Key unwrapping failed'
      );
    });

    it('should throw on tampered encrypted root read key', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      const tampered = { ...encrypted };
      tampered.encryptedRootReadKey = new Uint8Array(encrypted.encryptedRootReadKey);
      tampered.encryptedRootReadKey[10] ^= 0xff;

      await expect(decryptVaultKeys(tampered, userKeypair.privateKey)).rejects.toThrow(
        'Key unwrapping failed'
      );
    });

    it('should throw on tampered encrypted root write key', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      const tampered = { ...encrypted };
      tampered.encryptedRootWriteKey = new Uint8Array(encrypted.encryptedRootWriteKey);
      tampered.encryptedRootWriteKey[10] ^= 0xff;

      await expect(decryptVaultKeys(tampered, userKeypair.privateKey)).rejects.toThrow(
        'Key unwrapping failed'
      );
    });

    it('should throw on tampered encrypted IPNS private key', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      const tampered = { ...encrypted };
      tampered.encryptedIpnsPrivateKey = new Uint8Array(encrypted.encryptedIpnsPrivateKey);
      tampered.encryptedIpnsPrivateKey[10] ^= 0xff;

      await expect(decryptVaultKeys(tampered, userKeypair.privateKey)).rejects.toThrow(
        'Key unwrapping failed'
      );
    });
  });

  describe('full lifecycle', () => {
    it('should work for multiple encrypt/decrypt cycles', async () => {
      const userKeypair = generateTestKeypair();
      const vault = await initializeVault(userKeypair.privateKey);

      // Simulate multiple login sessions
      for (let i = 0; i < 3; i++) {
        const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);
        const decrypted = await decryptVaultKeys(encrypted, userKeypair.privateKey);

        expect(decrypted.rootReadKey).toEqual(vault.rootReadKey);
        expect(decrypted.rootWriteKey).toEqual(vault.rootWriteKey);
        expect(decrypted.rootIpnsKeypair.publicKey).toEqual(vault.rootIpnsKeypair.publicKey);
        expect(decrypted.rootIpnsKeypair.privateKey).toEqual(vault.rootIpnsKeypair.privateKey);
      }
    });

    it('should work with different user keypairs for different users', async () => {
      const user1Keypair = generateTestKeypair();
      const user2Keypair = generateTestKeypair();

      const vault1 = await initializeVault(user1Keypair.privateKey);
      const vault2 = await initializeVault(user2Keypair.privateKey);

      // User 1 encrypts and can decrypt
      const encrypted1 = await encryptVaultKeys(vault1, user1Keypair.publicKey);
      const decrypted1 = await decryptVaultKeys(encrypted1, user1Keypair.privateKey);
      expect(decrypted1.rootReadKey).toEqual(vault1.rootReadKey);
      expect(decrypted1.rootWriteKey).toEqual(vault1.rootWriteKey);

      // User 2 encrypts and can decrypt
      const encrypted2 = await encryptVaultKeys(vault2, user2Keypair.publicKey);
      const decrypted2 = await decryptVaultKeys(encrypted2, user2Keypair.privateKey);
      expect(decrypted2.rootReadKey).toEqual(vault2.rootReadKey);
      expect(decrypted2.rootWriteKey).toEqual(vault2.rootWriteKey);

      // User 1 cannot decrypt User 2's encrypted keys
      await expect(decryptVaultKeys(encrypted2, user1Keypair.privateKey)).rejects.toThrow();
    });
  });
});

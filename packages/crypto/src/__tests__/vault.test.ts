/**
 * @cipherbox/crypto - Vault Tests
 *
 * Tests for vault initialization and key encryption/decryption.
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { initializeVault, encryptVaultKeys, decryptVaultKeys } from '../vault';
import { ED25519_PUBLIC_KEY_SIZE, ED25519_PRIVATE_KEY_SIZE, AES_KEY_SIZE } from '../constants';

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
    it('should return valid VaultInit structure', async () => {
      const vault = await initializeVault();

      expect(vault).toHaveProperty('rootFolderKey');
      expect(vault).toHaveProperty('rootIpnsKeypair');
      expect(vault.rootIpnsKeypair).toHaveProperty('publicKey');
      expect(vault.rootIpnsKeypair).toHaveProperty('privateKey');
    });

    it('should generate 32-byte root folder key', async () => {
      const vault = await initializeVault();

      expect(vault.rootFolderKey.length).toBe(AES_KEY_SIZE);
    });

    it('should generate Ed25519 keypair with correct sizes', async () => {
      const vault = await initializeVault();

      expect(vault.rootIpnsKeypair.publicKey.length).toBe(ED25519_PUBLIC_KEY_SIZE);
      expect(vault.rootIpnsKeypair.privateKey.length).toBe(ED25519_PRIVATE_KEY_SIZE);
    });

    it('should produce unique keys on each initialization', async () => {
      const vault1 = await initializeVault();
      const vault2 = await initializeVault();
      const vault3 = await initializeVault();

      // Root folder keys should be unique
      expect(vault1.rootFolderKey).not.toEqual(vault2.rootFolderKey);
      expect(vault2.rootFolderKey).not.toEqual(vault3.rootFolderKey);

      // IPNS keypairs should be unique
      expect(vault1.rootIpnsKeypair.publicKey).not.toEqual(vault2.rootIpnsKeypair.publicKey);
      expect(vault1.rootIpnsKeypair.privateKey).not.toEqual(vault2.rootIpnsKeypair.privateKey);
    });

    it('should generate keys with high entropy', async () => {
      const vault = await initializeVault();

      // Check root folder key has non-trivial entropy
      const folderKeyUnique = new Set(vault.rootFolderKey);
      expect(folderKeyUnique.size).toBeGreaterThan(1);

      // Check IPNS private key has non-trivial entropy
      const ipnsKeyUnique = new Set(vault.rootIpnsKeypair.privateKey);
      expect(ipnsKeyUnique.size).toBeGreaterThan(1);
    });
  });
});

describe('Vault Key Encryption/Decryption', () => {
  describe('encryptVaultKeys', () => {
    it('should return EncryptedVaultKeys structure', async () => {
      const vault = await initializeVault();
      const userKeypair = generateTestKeypair();

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      expect(encrypted).toHaveProperty('encryptedRootFolderKey');
      expect(encrypted).toHaveProperty('encryptedIpnsPrivateKey');
      expect(encrypted).toHaveProperty('rootIpnsPublicKey');
    });

    it('should produce encrypted data larger than plaintext', async () => {
      const vault = await initializeVault();
      const userKeypair = generateTestKeypair();

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      // ECIES adds ephemeral key (65 bytes) + tag (16 bytes)
      expect(encrypted.encryptedRootFolderKey.length).toBeGreaterThan(vault.rootFolderKey.length);
      expect(encrypted.encryptedIpnsPrivateKey.length).toBeGreaterThan(
        vault.rootIpnsKeypair.privateKey.length
      );
    });

    it('should preserve IPNS public key in plaintext', async () => {
      const vault = await initializeVault();
      const userKeypair = generateTestKeypair();

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      // Public key should be identical (not encrypted)
      expect(encrypted.rootIpnsPublicKey).toEqual(vault.rootIpnsKeypair.publicKey);
    });

    it('should produce different encrypted data each time due to ECIES ephemeral keys', async () => {
      const vault = await initializeVault();
      const userKeypair = generateTestKeypair();

      const encrypted1 = await encryptVaultKeys(vault, userKeypair.publicKey);
      const encrypted2 = await encryptVaultKeys(vault, userKeypair.publicKey);

      // Same plaintext should produce different ciphertext
      expect(encrypted1.encryptedRootFolderKey).not.toEqual(encrypted2.encryptedRootFolderKey);
      expect(encrypted1.encryptedIpnsPrivateKey).not.toEqual(encrypted2.encryptedIpnsPrivateKey);
    });
  });

  describe('decryptVaultKeys', () => {
    it('should recover original keys after encrypt/decrypt round-trip', async () => {
      const vault = await initializeVault();
      const userKeypair = generateTestKeypair();

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);
      const decrypted = await decryptVaultKeys(encrypted, userKeypair.privateKey);

      expect(decrypted.rootFolderKey).toEqual(vault.rootFolderKey);
      expect(decrypted.rootIpnsKeypair.publicKey).toEqual(vault.rootIpnsKeypair.publicKey);
      expect(decrypted.rootIpnsKeypair.privateKey).toEqual(vault.rootIpnsKeypair.privateKey);
    });

    it('should throw with wrong private key', async () => {
      const vault = await initializeVault();
      const userKeypair1 = generateTestKeypair();
      const userKeypair2 = generateTestKeypair();

      const encrypted = await encryptVaultKeys(vault, userKeypair1.publicKey);

      await expect(decryptVaultKeys(encrypted, userKeypair2.privateKey)).rejects.toThrow(
        'Key unwrapping failed'
      );
    });

    it('should throw on tampered encrypted root folder key', async () => {
      const vault = await initializeVault();
      const userKeypair = generateTestKeypair();

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      // Tamper with encrypted data
      const tampered = { ...encrypted };
      tampered.encryptedRootFolderKey = new Uint8Array(encrypted.encryptedRootFolderKey);
      tampered.encryptedRootFolderKey[10] ^= 0xff;

      await expect(decryptVaultKeys(tampered, userKeypair.privateKey)).rejects.toThrow(
        'Key unwrapping failed'
      );
    });

    it('should throw on tampered encrypted IPNS private key', async () => {
      const vault = await initializeVault();
      const userKeypair = generateTestKeypair();

      const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);

      // Tamper with encrypted data
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
      const vault = await initializeVault();
      const userKeypair = generateTestKeypair();

      // Simulate multiple login sessions
      for (let i = 0; i < 3; i++) {
        const encrypted = await encryptVaultKeys(vault, userKeypair.publicKey);
        const decrypted = await decryptVaultKeys(encrypted, userKeypair.privateKey);

        expect(decrypted.rootFolderKey).toEqual(vault.rootFolderKey);
        expect(decrypted.rootIpnsKeypair.publicKey).toEqual(vault.rootIpnsKeypair.publicKey);
        expect(decrypted.rootIpnsKeypair.privateKey).toEqual(vault.rootIpnsKeypair.privateKey);
      }
    });

    it('should work with different user keypairs for different users', async () => {
      // Simulate two different users with the same vault keys
      // (This wouldn't happen in practice, but tests the crypto works)
      const vault = await initializeVault();

      const user1Keypair = generateTestKeypair();
      const user2Keypair = generateTestKeypair();

      // User 1 encrypts and can decrypt
      const encrypted1 = await encryptVaultKeys(vault, user1Keypair.publicKey);
      const decrypted1 = await decryptVaultKeys(encrypted1, user1Keypair.privateKey);
      expect(decrypted1.rootFolderKey).toEqual(vault.rootFolderKey);

      // User 2 encrypts and can decrypt
      const encrypted2 = await encryptVaultKeys(vault, user2Keypair.publicKey);
      const decrypted2 = await decryptVaultKeys(encrypted2, user2Keypair.privateKey);
      expect(decrypted2.rootFolderKey).toEqual(vault.rootFolderKey);

      // User 1 cannot decrypt User 2's encrypted keys
      await expect(decryptVaultKeys(encrypted2, user1Keypair.privateKey)).rejects.toThrow();
    });
  });
});

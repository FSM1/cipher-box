/**
 * @cipherbox/crypto - Vault IPNS Derivation Tests
 *
 * Tests for deterministic vault IPNS keypair derivation and
 * domain separation from registry IPNS derivation.
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { deriveVaultIpnsKeypair } from '../vault/derive-ipns';
import { deriveRegistryIpnsKeypair } from '../registry/derive-ipns';
import { initializeVault } from '../vault';
import { CryptoError } from '../types';

/**
 * Generate a random secp256k1 private key for testing.
 */
function randomPrivateKey(): Uint8Array {
  return secp256k1.utils.randomPrivateKey();
}

describe('deriveVaultIpnsKeypair', () => {
  it('produces the same keypair and IPNS name for the same privateKey (determinism)', async () => {
    const privateKey = randomPrivateKey();

    const result1 = await deriveVaultIpnsKeypair(privateKey);
    const result2 = await deriveVaultIpnsKeypair(privateKey);

    expect(result1.privateKey).toEqual(result2.privateKey);
    expect(result1.publicKey).toEqual(result2.publicKey);
    expect(result1.ipnsName).toBe(result2.ipnsName);
  });

  it('produces different results for different private keys', async () => {
    const privateKey1 = randomPrivateKey();
    const privateKey2 = randomPrivateKey();

    const result1 = await deriveVaultIpnsKeypair(privateKey1);
    const result2 = await deriveVaultIpnsKeypair(privateKey2);

    expect(result1.ipnsName).not.toBe(result2.ipnsName);
    expect(result1.privateKey).not.toEqual(result2.privateKey);
    expect(result1.publicKey).not.toEqual(result2.publicKey);
  });

  it('produces a different IPNS name than deriveRegistryIpnsKeypair for the same key (domain separation)', async () => {
    const privateKey = randomPrivateKey();

    const vaultResult = await deriveVaultIpnsKeypair(privateKey);
    const registryResult = await deriveRegistryIpnsKeypair(privateKey);

    expect(vaultResult.ipnsName).not.toBe(registryResult.ipnsName);
    expect(vaultResult.privateKey).not.toEqual(registryResult.privateKey);
    expect(vaultResult.publicKey).not.toEqual(registryResult.publicKey);
  });

  it('throws CryptoError with INVALID_KEY_SIZE for 31-byte key', async () => {
    const shortKey = new Uint8Array(31);

    await expect(deriveVaultIpnsKeypair(shortKey)).rejects.toThrow(
      'Invalid private key size for vault derivation'
    );

    try {
      await deriveVaultIpnsKeypair(shortKey);
    } catch (error) {
      expect(error).toBeInstanceOf(CryptoError);
      expect((error as CryptoError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('produces an IPNS name starting with k51', async () => {
    const privateKey = randomPrivateKey();

    const result = await deriveVaultIpnsKeypair(privateKey);

    expect(result.ipnsName).toMatch(/^k51/);
  });
});

describe('initializeVault with deterministic IPNS', () => {
  it('produces the same rootIpnsKeypair for the same privateKey (deterministic IPNS)', async () => {
    const privateKey = randomPrivateKey();

    const vault1 = await initializeVault(privateKey);
    const vault2 = await initializeVault(privateKey);

    expect(vault1.rootIpnsKeypair.publicKey).toEqual(vault2.rootIpnsKeypair.publicKey);
    expect(vault1.rootIpnsKeypair.privateKey).toEqual(vault2.rootIpnsKeypair.privateKey);
  });

  it('produces a DIFFERENT rootFolderKey each time (random)', async () => {
    const privateKey = randomPrivateKey();

    const vault1 = await initializeVault(privateKey);
    const vault2 = await initializeVault(privateKey);

    expect(vault1.rootFolderKey).not.toEqual(vault2.rootFolderKey);
  });

  it('rootIpnsKeypair matches deriveVaultIpnsKeypair output for the same key', async () => {
    const privateKey = randomPrivateKey();

    const vault = await initializeVault(privateKey);
    const derived = await deriveVaultIpnsKeypair(privateKey);

    expect(vault.rootIpnsKeypair.publicKey).toEqual(derived.publicKey);
    expect(vault.rootIpnsKeypair.privateKey).toEqual(derived.privateKey);
  });
});

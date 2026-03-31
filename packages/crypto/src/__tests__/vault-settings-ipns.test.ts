/**
 * @cipherbox/crypto - Vault Settings IPNS Derivation Tests
 *
 * Tests for deterministic vault settings IPNS keypair derivation,
 * domain separation from vault IPNS derivation, and input validation.
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { deriveVaultSettingsIpnsKeypair, deriveVaultIpnsKeypair } from '../vault/derive-ipns';
import { CryptoError } from '../types';

function randomPrivateKey(): Uint8Array {
  return secp256k1.utils.randomPrivateKey();
}

describe('deriveVaultSettingsIpnsKeypair', () => {
  it('produces the same keypair and IPNS name for the same privateKey (determinism)', async () => {
    const privateKey = randomPrivateKey();

    const result1 = await deriveVaultSettingsIpnsKeypair(privateKey);
    const result2 = await deriveVaultSettingsIpnsKeypair(privateKey);

    expect(result1.privateKey).toEqual(result2.privateKey);
    expect(result1.publicKey).toEqual(result2.publicKey);
    expect(result1.ipnsName).toBe(result2.ipnsName);
  });

  it('produces different results for different private keys', async () => {
    const privateKey1 = randomPrivateKey();
    const privateKey2 = randomPrivateKey();

    const result1 = await deriveVaultSettingsIpnsKeypair(privateKey1);
    const result2 = await deriveVaultSettingsIpnsKeypair(privateKey2);

    expect(result1.ipnsName).not.toBe(result2.ipnsName);
    expect(result1.privateKey).not.toEqual(result2.privateKey);
  });

  it('produces a different IPNS name than deriveVaultIpnsKeypair for the same key (domain separation)', async () => {
    const privateKey = randomPrivateKey();

    const settingsResult = await deriveVaultSettingsIpnsKeypair(privateKey);
    const vaultResult = await deriveVaultIpnsKeypair(privateKey);

    expect(settingsResult.ipnsName).not.toBe(vaultResult.ipnsName);
    expect(settingsResult.privateKey).not.toEqual(vaultResult.privateKey);
  });

  it('throws CryptoError with INVALID_KEY_SIZE for wrong-length key', async () => {
    const shortKey = new Uint8Array(31);

    await expect(deriveVaultSettingsIpnsKeypair(shortKey)).rejects.toThrow(
      'Invalid private key size for vault settings derivation'
    );

    try {
      await deriveVaultSettingsIpnsKeypair(shortKey);
    } catch (error) {
      expect(error).toBeInstanceOf(CryptoError);
      expect((error as CryptoError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('produces an IPNS name starting with k51', async () => {
    const privateKey = randomPrivateKey();

    const result = await deriveVaultSettingsIpnsKeypair(privateKey);

    expect(result.ipnsName).toMatch(/^k51/);
  });
});

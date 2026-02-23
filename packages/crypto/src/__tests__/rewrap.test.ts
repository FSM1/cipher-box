/**
 * @cipherbox/crypto - ECIES Re-Wrapping Tests
 *
 * Tests for key re-wrapping used in user-to-user sharing.
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { wrapKey, unwrapKey, reWrapKey } from '../ecies';
import { generateRandomBytes } from '../utils';
import { CryptoError } from '../types';

/**
 * Generate a secp256k1 keypair for testing.
 */
function generateTestKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed
  return { publicKey, privateKey };
}

describe('ECIES Key Re-Wrapping', () => {
  it('re-wrapped key decrypts to same value', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();

    // Create a random 32-byte key and wrap it for Alice
    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    // Re-wrap from Alice to Bob
    const wrappedForBob = await reWrapKey(wrappedForAlice, alice.privateKey, bob.publicKey);

    // Bob unwraps with his private key
    const bobsKey = await unwrapKey(wrappedForBob, bob.privateKey);

    // Both should get the same original key
    expect(bobsKey).toEqual(originalKey);
  });

  it('re-wrapping preserves key across multiple recipients', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();
    const charlie = generateTestKeypair();

    // Create a random 32-byte key and wrap it for Alice
    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    // Re-wrap from Alice to Bob
    const wrappedForBob = await reWrapKey(wrappedForAlice, alice.privateKey, bob.publicKey);

    // Re-wrap from Alice to Charlie
    const wrappedForCharlie = await reWrapKey(wrappedForAlice, alice.privateKey, charlie.publicKey);

    // All three should unwrap to the same key
    const aliceKey = await unwrapKey(wrappedForAlice, alice.privateKey);
    const bobKey = await unwrapKey(wrappedForBob, bob.privateKey);
    const charlieKey = await unwrapKey(wrappedForCharlie, charlie.privateKey);

    expect(aliceKey).toEqual(originalKey);
    expect(bobKey).toEqual(originalKey);
    expect(charlieKey).toEqual(originalKey);
  });

  it('reWrapKey fails with wrong owner private key', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();
    const wrongKeypair = generateTestKeypair();

    // Wrap a key for Alice
    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    // Try to re-wrap with wrong private key
    await expect(
      reWrapKey(wrappedForAlice, wrongKeypair.privateKey, bob.publicKey)
    ).rejects.toThrow(CryptoError);

    await expect(
      reWrapKey(wrappedForAlice, wrongKeypair.privateKey, bob.publicKey)
    ).rejects.toThrow('Key re-wrapping failed');
  });

  it('reWrapKey fails with invalid recipient public key', async () => {
    const alice = generateTestKeypair();

    // Wrap a key for Alice
    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    // Create an invalid 65-byte public key (valid length, invalid curve point)
    const invalidPublicKey = new Uint8Array(65);
    invalidPublicKey[0] = 0x04;
    invalidPublicKey.fill(0xff, 1);

    // Try to re-wrap with invalid recipient public key
    await expect(reWrapKey(wrappedForAlice, alice.privateKey, invalidPublicKey)).rejects.toThrow(
      CryptoError
    );

    await expect(reWrapKey(wrappedForAlice, alice.privateKey, invalidPublicKey)).rejects.toThrow(
      'Key re-wrapping failed'
    );
  });

  it('reWrapKey fails with corrupted ciphertext', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();

    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    // Corrupt the ciphertext by flipping bits
    const corrupted = new Uint8Array(wrappedForAlice);
    corrupted[corrupted.length - 1] ^= 0xff;

    await expect(reWrapKey(corrupted, alice.privateKey, bob.publicKey)).rejects.toThrow(
      CryptoError
    );
    await expect(reWrapKey(corrupted, alice.privateKey, bob.publicKey)).rejects.toThrow(
      'Key re-wrapping failed'
    );
  });

  it('reWrapKey produces unique ciphertexts per recipient', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();
    const charlie = generateTestKeypair();

    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    const wrappedForBob = await reWrapKey(wrappedForAlice, alice.privateKey, bob.publicKey);
    const wrappedForCharlie = await reWrapKey(wrappedForAlice, alice.privateKey, charlie.publicKey);

    // Different recipients should produce different ciphertexts
    expect(wrappedForBob).not.toEqual(wrappedForCharlie);

    // But both should decrypt to the same key
    const bobKey = await unwrapKey(wrappedForBob, bob.privateKey);
    const charlieKey = await unwrapKey(wrappedForCharlie, charlie.privateKey);
    expect(bobKey).toEqual(charlieKey);
  });

  it('reWrapKey produces unique ciphertexts per invocation (ephemeral keys)', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();

    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    // Re-wrap twice for the same recipient
    const wrap1 = await reWrapKey(wrappedForAlice, alice.privateKey, bob.publicKey);
    const wrap2 = await reWrapKey(wrappedForAlice, alice.privateKey, bob.publicKey);

    // Should produce different ciphertexts (due to ephemeral key generation)
    expect(wrap1).not.toEqual(wrap2);

    // But both should decrypt to the same key
    const key1 = await unwrapKey(wrap1, bob.privateKey);
    const key2 = await unwrapKey(wrap2, bob.privateKey);
    expect(key1).toEqual(key2);
    expect(key1).toEqual(originalKey);
  });

  it('recipient cannot unwrap key meant for different recipient', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();
    const charlie = generateTestKeypair();

    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    // Re-wrap for Bob
    const wrappedForBob = await reWrapKey(wrappedForAlice, alice.privateKey, bob.publicKey);

    // Charlie tries to unwrap Bob's key -- should fail
    await expect(unwrapKey(wrappedForBob, charlie.privateKey)).rejects.toThrow(CryptoError);
  });

  it('reWrapKey handles large keys (64 bytes)', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();

    const largeKey = generateRandomBytes(64);
    const wrappedForAlice = await wrapKey(largeKey, alice.publicKey);

    const wrappedForBob = await reWrapKey(wrappedForAlice, alice.privateKey, bob.publicKey);
    const result = await unwrapKey(wrappedForBob, bob.privateKey);
    expect(result).toEqual(largeKey);
  });

  it('reWrapKey fails with truncated private key', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();

    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    // Truncated private key (16 bytes instead of 32)
    const truncatedKey = alice.privateKey.slice(0, 16);

    await expect(reWrapKey(wrappedForAlice, truncatedKey, bob.publicKey)).rejects.toThrow(
      CryptoError
    );
  });

  it('reWrapKey error message does not leak key material', async () => {
    const alice = generateTestKeypair();
    const bob = generateTestKeypair();
    const wrongKeypair = generateTestKeypair();

    const originalKey = generateRandomBytes(32);
    const wrappedForAlice = await wrapKey(originalKey, alice.publicKey);

    try {
      await reWrapKey(wrappedForAlice, wrongKeypair.privateKey, bob.publicKey);
      expect.fail('Should have thrown');
    } catch (err) {
      const error = err as CryptoError;
      // Error message should be generic -- no key material
      expect(error.message).toBe('Key re-wrapping failed');
      expect(error.code).toBe('KEY_REWRAP_FAILED');
      // Ensure the error message doesn't contain hex-encoded key bytes
      expect(error.message).not.toMatch(/[0-9a-f]{16,}/i);
      expect(error.stack || '').not.toMatch(/privateKey|plainKey/i);
    }
  });
});

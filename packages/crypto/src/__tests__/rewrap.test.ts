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
});

/**
 * @cipherbox/crypto - Ed25519 Tests
 *
 * Tests for Ed25519 key generation, signing, and verification.
 */

import { describe, it, expect } from 'vitest';
import { generateEd25519Keypair, signEd25519, verifyEd25519 } from '../ed25519';
import {
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
} from '../constants';

describe('Ed25519 Key Generation', () => {
  it('generates keypair with correct sizes', () => {
    const keypair = generateEd25519Keypair();

    expect(keypair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keypair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keypair.publicKey.length).toBe(ED25519_PUBLIC_KEY_SIZE);
    expect(keypair.privateKey.length).toBe(ED25519_PRIVATE_KEY_SIZE);
  });

  it('generates unique keypairs (randomness test)', () => {
    const keypair1 = generateEd25519Keypair();
    const keypair2 = generateEd25519Keypair();

    // Public keys should be different
    expect(keypair1.publicKey).not.toEqual(keypair2.publicKey);
    // Private keys should be different
    expect(keypair1.privateKey).not.toEqual(keypair2.privateKey);
  });
});

describe('Ed25519 Signing', () => {
  it('signs message and returns 64-byte signature', async () => {
    const keypair = generateEd25519Keypair();
    const message = new TextEncoder().encode('Hello, CipherBox!');

    const signature = await signEd25519(message, keypair.privateKey);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(ED25519_SIGNATURE_SIZE);
  });

  it('validates private key length', async () => {
    const message = new TextEncoder().encode('test message');
    const invalidPrivateKey = new Uint8Array(16); // Wrong size

    await expect(signEd25519(message, invalidPrivateKey)).rejects.toThrow('Signing failed');
  });

  it('produces deterministic signatures for same message and key', async () => {
    const keypair = generateEd25519Keypair();
    const message = new TextEncoder().encode('deterministic test');

    const signature1 = await signEd25519(message, keypair.privateKey);
    const signature2 = await signEd25519(message, keypair.privateKey);

    // Ed25519 signatures are deterministic
    expect(signature1).toEqual(signature2);
  });
});

describe('Ed25519 Verification', () => {
  it('verifies valid signature returns true', async () => {
    const keypair = generateEd25519Keypair();
    const message = new TextEncoder().encode('verify me');

    const signature = await signEd25519(message, keypair.privateKey);
    const isValid = await verifyEd25519(signature, message, keypair.publicKey);

    expect(isValid).toBe(true);
  });

  it('verifies with wrong public key returns false', async () => {
    const keypair1 = generateEd25519Keypair();
    const keypair2 = generateEd25519Keypair();
    const message = new TextEncoder().encode('signed by keypair1');

    const signature = await signEd25519(message, keypair1.privateKey);
    const isValid = await verifyEd25519(signature, message, keypair2.publicKey);

    expect(isValid).toBe(false);
  });

  it('verifies with modified message returns false', async () => {
    const keypair = generateEd25519Keypair();
    const originalMessage = new TextEncoder().encode('original message');
    const modifiedMessage = new TextEncoder().encode('modified message');

    const signature = await signEd25519(originalMessage, keypair.privateKey);
    const isValid = await verifyEd25519(signature, modifiedMessage, keypair.publicKey);

    expect(isValid).toBe(false);
  });

  it('verifies with modified signature returns false', async () => {
    const keypair = generateEd25519Keypair();
    const message = new TextEncoder().encode('test message');

    const signature = await signEd25519(message, keypair.privateKey);

    // Modify one byte of the signature
    const modifiedSignature = new Uint8Array(signature);
    modifiedSignature[0] = (modifiedSignature[0] + 1) % 256;

    const isValid = await verifyEd25519(modifiedSignature, message, keypair.publicKey);

    expect(isValid).toBe(false);
  });

  it('validates public key length', async () => {
    const keypair = generateEd25519Keypair();
    const message = new TextEncoder().encode('test');
    const signature = await signEd25519(message, keypair.privateKey);

    const invalidPublicKey = new Uint8Array(16); // Wrong size
    const isValid = await verifyEd25519(signature, message, invalidPublicKey);

    expect(isValid).toBe(false);
  });

  it('validates signature length', async () => {
    const keypair = generateEd25519Keypair();
    const message = new TextEncoder().encode('test');

    const invalidSignature = new Uint8Array(32); // Wrong size
    const isValid = await verifyEd25519(invalidSignature, message, keypair.publicKey);

    expect(isValid).toBe(false);
  });
});

describe('Ed25519 Sign/Verify Round-trip', () => {
  it('round-trip succeeds with generated keypair', async () => {
    const keypair = generateEd25519Keypair();
    const message = new TextEncoder().encode('Round-trip test message for Ed25519');

    const signature = await signEd25519(message, keypair.privateKey);
    const isValid = await verifyEd25519(signature, message, keypair.publicKey);

    expect(isValid).toBe(true);
  });

  it('works with empty message', async () => {
    const keypair = generateEd25519Keypair();
    const message = new Uint8Array(0);

    const signature = await signEd25519(message, keypair.privateKey);
    const isValid = await verifyEd25519(signature, message, keypair.publicKey);

    expect(isValid).toBe(true);
    expect(signature.length).toBe(ED25519_SIGNATURE_SIZE);
  });

  it('works with large message', async () => {
    const keypair = generateEd25519Keypair();
    // Use 64KB which is within crypto.getRandomValues limit
    const message = new Uint8Array(65536);
    crypto.getRandomValues(message);

    const signature = await signEd25519(message, keypair.privateKey);
    const isValid = await verifyEd25519(signature, message, keypair.publicKey);

    expect(isValid).toBe(true);
    expect(signature.length).toBe(ED25519_SIGNATURE_SIZE);
  });
});

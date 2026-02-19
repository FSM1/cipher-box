/**
 * @cipherbox/crypto - IPNS Tests
 *
 * Tests for IPNS record signing utilities.
 */

import { describe, it, expect } from 'vitest';
import { signIpnsData, IPNS_SIGNATURE_PREFIX } from '../ipns';
import { generateEd25519Keypair, verifyEd25519 } from '../ed25519';
import { ED25519_SIGNATURE_SIZE } from '../constants';

describe('IPNS Signature Prefix', () => {
  it('has correct bytes for "ipns-signature:"', () => {
    // Verify prefix is correct UTF-8 encoding of "ipns-signature:"
    const expectedString = 'ipns-signature:';
    const decoded = new TextDecoder().decode(IPNS_SIGNATURE_PREFIX);

    expect(decoded).toBe(expectedString);
    expect(IPNS_SIGNATURE_PREFIX.length).toBe(15);
  });

  it('matches IPFS spec byte values', () => {
    // Verify individual byte values per IPFS spec
    const expected = [
      0x69,
      0x70,
      0x6e,
      0x73,
      0x2d, // "ipns-"
      0x73,
      0x69,
      0x67,
      0x6e,
      0x61, // "signa"
      0x74,
      0x75,
      0x72,
      0x65,
      0x3a, // "ture:"
    ];

    expect(Array.from(IPNS_SIGNATURE_PREFIX)).toEqual(expected);
  });
});

describe('IPNS Data Signing', () => {
  it('returns 64-byte signature', async () => {
    const keypair = generateEd25519Keypair();
    const cborData = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

    const signature = await signIpnsData(cborData, keypair.privateKey);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(ED25519_SIGNATURE_SIZE);
  });

  it('signature is verifiable with Ed25519 using prefixed data', async () => {
    const keypair = generateEd25519Keypair();
    const cborData = new Uint8Array([0xa1, 0x63, 0x66, 0x6f, 0x6f, 0x63, 0x62, 0x61, 0x72]); // CBOR example

    const signature = await signIpnsData(cborData, keypair.privateKey);

    // Reconstruct the signed data (prefix + cbor)
    const dataToVerify = new Uint8Array(IPNS_SIGNATURE_PREFIX.length + cborData.length);
    dataToVerify.set(IPNS_SIGNATURE_PREFIX, 0);
    dataToVerify.set(cborData, IPNS_SIGNATURE_PREFIX.length);

    // Verify with standard Ed25519 verification
    const isValid = await verifyEd25519(signature, dataToVerify, keypair.publicKey);

    expect(isValid).toBe(true);
  });

  it('same data signed with same key produces same signature (deterministic)', async () => {
    const keypair = generateEd25519Keypair();
    const cborData = new TextEncoder().encode('deterministic cbor data');

    const signature1 = await signIpnsData(cborData, keypair.privateKey);
    const signature2 = await signIpnsData(cborData, keypair.privateKey);

    // Ed25519 signatures are deterministic
    expect(signature1).toEqual(signature2);
  });

  it('different data produces different signature', async () => {
    const keypair = generateEd25519Keypair();
    const cborData1 = new TextEncoder().encode('data version 1');
    const cborData2 = new TextEncoder().encode('data version 2');

    const signature1 = await signIpnsData(cborData1, keypair.privateKey);
    const signature2 = await signIpnsData(cborData2, keypair.privateKey);

    expect(signature1).not.toEqual(signature2);
  });

  it('works with empty CBOR data', async () => {
    const keypair = generateEd25519Keypair();
    const emptyCbor = new Uint8Array(0);

    const signature = await signIpnsData(emptyCbor, keypair.privateKey);

    expect(signature.length).toBe(ED25519_SIGNATURE_SIZE);

    // Verify signature is valid for just the prefix
    const isValid = await verifyEd25519(signature, IPNS_SIGNATURE_PREFIX, keypair.publicKey);
    expect(isValid).toBe(true);
  });

  it('different keys produce different signatures', async () => {
    const keypair1 = generateEd25519Keypair();
    const keypair2 = generateEd25519Keypair();
    const cborData = new TextEncoder().encode('test data');

    const signature1 = await signIpnsData(cborData, keypair1.privateKey);
    const signature2 = await signIpnsData(cborData, keypair2.privateKey);

    expect(signature1).not.toEqual(signature2);
  });

  it('validates private key length (via Ed25519)', async () => {
    const invalidPrivateKey = new Uint8Array(16); // Wrong size
    const cborData = new TextEncoder().encode('test');

    await expect(signIpnsData(cborData, invalidPrivateKey)).rejects.toThrow('Signing failed');
  });
});

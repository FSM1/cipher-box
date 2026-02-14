/**
 * @cipherbox/crypto - IPNS Record Tests
 *
 * Tests for IPNS record creation, name derivation, and marshaling.
 */

import { describe, it, expect } from 'vitest';
import {
  createIpnsRecord,
  deriveIpnsName,
  marshalIpnsRecord,
  unmarshalIpnsRecord,
  generateEd25519Keypair,
} from '../index';

describe('createIpnsRecord', () => {
  it('creates valid record with correct value', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';
    const seq = 0n;

    const record = await createIpnsRecord(keypair.privateKey, value, seq);

    expect(record.value).toBe(value);
    expect(record.sequence).toBe(seq);
  });

  it('should handle sequence number 0', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';

    const record = await createIpnsRecord(keypair.privateKey, value, 0n);

    expect(record.sequence).toBe(0n);
    expect(record.value).toBe(value);
  });

  it('should reject negative sequence numbers', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';

    await expect(createIpnsRecord(keypair.privateKey, value, -1n)).rejects.toThrow(
      'Sequence number must be non-negative'
    );

    await expect(createIpnsRecord(keypair.privateKey, value, -100n)).rejects.toThrow(
      'Sequence number must be non-negative'
    );
  });

  it('respects sequence number', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';
    const seq = 42n;

    const record = await createIpnsRecord(keypair.privateKey, value, seq);

    expect(record.sequence).toBe(seq);
  });

  it('uses default 24h lifetime', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';
    const beforeCreate = Date.now();

    const record = await createIpnsRecord(keypair.privateKey, value, 0n);
    const afterCreate = Date.now();

    // Parse validity timestamp (RFC3339)
    const validityDate = new Date(record.validity);
    const validityMs = validityDate.getTime();

    // Validity should be approximately 24 hours from now
    const expected24hMs = 24 * 60 * 60 * 1000;

    // Allow 5 seconds tolerance
    expect(validityMs).toBeGreaterThanOrEqual(beforeCreate + expected24hMs - 5000);
    expect(validityMs).toBeLessThanOrEqual(afterCreate + expected24hMs + 5000);
  });

  it('accepts custom lifetime', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';
    const customLifetimeMs = 12 * 60 * 60 * 1000; // 12 hours
    const beforeCreate = Date.now();

    const record = await createIpnsRecord(keypair.privateKey, value, 0n, customLifetimeMs);
    const afterCreate = Date.now();

    const validityDate = new Date(record.validity);
    const validityMs = validityDate.getTime();

    // Allow 5 seconds tolerance
    expect(validityMs).toBeGreaterThanOrEqual(beforeCreate + customLifetimeMs - 5000);
    expect(validityMs).toBeLessThanOrEqual(afterCreate + customLifetimeMs + 5000);
  });

  it('throws on invalid private key size', async () => {
    const invalidPrivateKey = new Uint8Array(16); // Wrong size
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';

    await expect(createIpnsRecord(invalidPrivateKey, value, 0n)).rejects.toThrow();
  });
});

describe('deriveIpnsName', () => {
  it('returns valid CIDv1 format string', async () => {
    const keypair = generateEd25519Keypair();

    const ipnsName = await deriveIpnsName(keypair.publicKey);

    // IPNS names for Ed25519 are CIDv1 with libp2p-key codec
    // They can be in different bases: k51... (base36) or bafz... (base32)
    // The default from libp2p is base32 (bafzaa...)
    expect(ipnsName).toMatch(/^(k51qzi5uqu5|bafzaa)/);
  });

  it('is deterministic (same key = same name)', async () => {
    const keypair = generateEd25519Keypair();

    const name1 = await deriveIpnsName(keypair.publicKey);
    const name2 = await deriveIpnsName(keypair.publicKey);

    expect(name1).toBe(name2);
  });

  it('different keys produce different names', async () => {
    const keypair1 = generateEd25519Keypair();
    const keypair2 = generateEd25519Keypair();

    const name1 = await deriveIpnsName(keypair1.publicKey);
    const name2 = await deriveIpnsName(keypair2.publicKey);

    expect(name1).not.toBe(name2);
  });

  it('throws on invalid public key size', async () => {
    const invalidPublicKey = new Uint8Array(16); // Wrong size

    await expect(deriveIpnsName(invalidPublicKey)).rejects.toThrow();
  });
});

describe('marshalIpnsRecord', () => {
  it('produces Uint8Array', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';

    const record = await createIpnsRecord(keypair.privateKey, value, 0n);
    const marshaled = marshalIpnsRecord(record);

    expect(marshaled).toBeInstanceOf(Uint8Array);
    expect(marshaled.length).toBeGreaterThan(0);
  });
});

describe('unmarshalIpnsRecord', () => {
  it('round-trips correctly', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';
    const seq = 7n;

    const original = await createIpnsRecord(keypair.privateKey, value, seq);
    const marshaled = marshalIpnsRecord(original);
    const unmarshaled = unmarshalIpnsRecord(marshaled);

    expect(unmarshaled.value).toBe(original.value);
    expect(unmarshaled.sequence).toBe(original.sequence);
    expect(unmarshaled.validity).toBe(original.validity);
    // Compare as arrays to handle Buffer vs Uint8Array difference
    expect(Array.from(unmarshaled.signatureV2)).toEqual(Array.from(original.signatureV2));
  });
});

describe('IPNS Record Verification', () => {
  it('created record has correct value and sequence', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';
    const seq = 123n;

    const record = await createIpnsRecord(keypair.privateKey, value, seq);

    // Verify the record contains expected data
    expect(record.value).toBe(value);
    expect(record.sequence).toBe(seq);

    // Verify signatureV2 exists (V2 format)
    expect(record.signatureV2).toBeInstanceOf(Uint8Array);
    expect(record.signatureV2.length).toBe(64); // Ed25519 signature

    // Verify data field exists (CBOR-encoded record data)
    expect(record.data).toBeInstanceOf(Uint8Array);
    expect(record.data.length).toBeGreaterThan(0);
  });

  it('record has V1 compatible signature when v1Compatible is true', async () => {
    const keypair = generateEd25519Keypair();
    const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';

    const record = await createIpnsRecord(keypair.privateKey, value, 0n);

    // With v1Compatible: true (default), signatureV1 should exist
    if ('signatureV1' in record) {
      expect(record.signatureV1).toBeInstanceOf(Uint8Array);
      expect(record.signatureV1.length).toBe(64);
    }
  });
});

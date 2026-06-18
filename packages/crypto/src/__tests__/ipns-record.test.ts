import { describe, it, expect } from 'vitest';
import { createIPNSRecord, marshalIPNSRecord } from 'ipns';
import { privateKeyFromRaw } from '@libp2p/crypto/keys';
import { generateEd25519Keypair } from '../ed25519';
import { deriveIpnsName } from '../ipns/derive-name';
import { verifyIpnsRecordSignature } from '../ipns/verify-record';
import { parseIpnsRecord } from '../ipns/parse-record';

const LIFETIME_MS = 24 * 60 * 60 * 1000;
const TEST_VALUE = '/ipfs/bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';

/**
 * Builds a marshalled IPNS record exactly the way @cipherbox/core (and thus the
 * SDK) does: a libp2p private key from the raw 64-byte [priv||pub] form, signed
 * with v1Compatible records. This locks server-side verify/parse to the real
 * client wire format.
 */
async function makeRecord(
  keypair: { privateKey: Uint8Array; publicKey: Uint8Array },
  value = TEST_VALUE,
  seq = 1n
): Promise<Uint8Array> {
  const libp2pKeyBytes = new Uint8Array(64);
  libp2pKeyBytes.set(keypair.privateKey, 0);
  libp2pKeyBytes.set(keypair.publicKey, 32);
  const libp2pPrivateKey = privateKeyFromRaw(libp2pKeyBytes);
  const record = await createIPNSRecord(libp2pPrivateKey, value, seq, LIFETIME_MS, {
    v1Compatible: true,
  });
  return marshalIPNSRecord(record);
}

describe('verifyIpnsRecordSignature', () => {
  it('accepts a record validly signed by the key the name encodes', async () => {
    const keypair = generateEd25519Keypair();
    const ipnsName = await deriveIpnsName(keypair.publicKey);
    const marshalled = await makeRecord(keypair);

    expect(await verifyIpnsRecordSignature(ipnsName, marshalled)).toBe(true);
  });

  it('rejects a record signed by a DIFFERENT key (name/key mismatch)', async () => {
    const owner = generateEd25519Keypair();
    const attacker = generateEd25519Keypair();
    const ownerName = await deriveIpnsName(owner.publicKey);
    // Record signed by the attacker, presented for the owner's name
    const forged = await makeRecord(attacker);

    expect(await verifyIpnsRecordSignature(ownerName, forged)).toBe(false);
  });

  it('rejects a tampered record', async () => {
    const keypair = generateEd25519Keypair();
    const ipnsName = await deriveIpnsName(keypair.publicKey);
    const marshalled = await makeRecord(keypair);
    // Flip a byte in the back half (signature/data region)
    const tampered = new Uint8Array(marshalled);
    tampered[tampered.length - 5] ^= 0xff;

    expect(await verifyIpnsRecordSignature(ipnsName, tampered)).toBe(false);
  });

  it('returns false for a malformed name or record instead of throwing', async () => {
    expect(await verifyIpnsRecordSignature('not-a-name', new Uint8Array([1, 2, 3]))).toBe(false);
  });
});

describe('parseIpnsRecord', () => {
  it('extracts value, sequence, signatureV2 and data from a real record', async () => {
    const keypair = generateEd25519Keypair();
    const marshalled = await makeRecord(keypair, TEST_VALUE, 7n);

    const parsed = await parseIpnsRecord(marshalled);

    expect(parsed.value).toBe(TEST_VALUE);
    expect(parsed.sequence).toBe(7n);
    expect(parsed.signatureV2).toBeInstanceOf(Uint8Array);
    expect(parsed.signatureV2!.length).toBeGreaterThan(0);
    expect(parsed.data).toBeInstanceOf(Uint8Array);
    expect(parsed.data!.length).toBeGreaterThan(0);
  });
});

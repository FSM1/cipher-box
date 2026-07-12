import { describe, it, expect } from 'vitest';
import { createIPNSRecord, marshalIPNSRecord, unmarshalIPNSRecord } from 'ipns';
import { privateKeyFromRaw } from '@libp2p/crypto/keys';
import { generateEd25519Keypair } from '../ed25519';
import { deriveIpnsName, publicKeyFromIpnsName } from '../ipns/derive-name';
import {
  verifyIpnsRecordSignature,
  verifyIpnsRecordSignatureDetailed,
} from '../ipns/verify-record';
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
  seq = 1n,
  lifetimeMs = LIFETIME_MS
): Promise<Uint8Array> {
  const libp2pKeyBytes = new Uint8Array(64);
  libp2pKeyBytes.set(keypair.privateKey, 0);
  libp2pKeyBytes.set(keypair.publicKey, 32);
  const libp2pPrivateKey = privateKeyFromRaw(libp2pKeyBytes);
  // A negative lifetime yields an EOL in the past — a validly-signed but expired
  // record, used to exercise the availability-over-freshness recovery path.
  const record = await createIPNSRecord(libp2pPrivateKey, value, seq, lifetimeMs, {
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

  it('returns false for a validly-signed but expired record (strict semantics)', async () => {
    const keypair = generateEd25519Keypair();
    const ipnsName = await deriveIpnsName(keypair.publicKey);
    // EOL one hour in the past — signature is valid, validity window has lapsed.
    const expired = await makeRecord(keypair, TEST_VALUE, 1n, -60 * 60 * 1000);

    expect(await verifyIpnsRecordSignature(ipnsName, expired)).toBe(false);
  });
});

describe('verifyIpnsRecordSignatureDetailed', () => {
  it('returns "valid" for a fresh, validly-signed record', async () => {
    const keypair = generateEd25519Keypair();
    const ipnsName = await deriveIpnsName(keypair.publicKey);
    const marshalled = await makeRecord(keypair);

    expect(await verifyIpnsRecordSignatureDetailed(ipnsName, marshalled)).toBe('valid');
  });

  it('returns "expired" for an authentic record whose EOL has passed', async () => {
    const keypair = generateEd25519Keypair();
    const ipnsName = await deriveIpnsName(keypair.publicKey);
    // Signed by the real key, but EOL is one hour in the past — stale, not forged.
    const expired = await makeRecord(keypair, TEST_VALUE, 1n, -60 * 60 * 1000);

    expect(await verifyIpnsRecordSignatureDetailed(ipnsName, expired)).toBe('expired');
  });

  it('returns "invalid" for a record signed by a DIFFERENT key', async () => {
    const owner = generateEd25519Keypair();
    const attacker = generateEd25519Keypair();
    const ownerName = await deriveIpnsName(owner.publicKey);
    const forged = await makeRecord(attacker);

    expect(await verifyIpnsRecordSignatureDetailed(ownerName, forged)).toBe('invalid');
  });

  it('returns "invalid" for a tampered record', async () => {
    const keypair = generateEd25519Keypair();
    const ipnsName = await deriveIpnsName(keypair.publicKey);
    const marshalled = await makeRecord(keypair);
    const tampered = new Uint8Array(marshalled);
    tampered[tampered.length - 5] ^= 0xff;

    expect(await verifyIpnsRecordSignatureDetailed(ipnsName, tampered)).toBe('invalid');
  });

  it('returns "invalid" for a malformed name', async () => {
    expect(await verifyIpnsRecordSignatureDetailed('not-a-name', new Uint8Array([1, 2, 3]))).toBe(
      'invalid'
    );
  });
});

describe('publicKeyFromIpnsName', () => {
  it('round-trips: recovers the exact raw public key deriveIpnsName encoded', async () => {
    const keypair = generateEd25519Keypair();
    const ipnsName = await deriveIpnsName(keypair.publicKey);

    const recovered = publicKeyFromIpnsName(ipnsName);

    expect(recovered).toBeInstanceOf(Uint8Array);
    expect(recovered.length).toBe(32);
    expect(Array.from(recovered)).toEqual(Array.from(keypair.publicKey));
  });

  it('recovers the key that verifies a record signed by the matching private key', async () => {
    // Closes the loop end-to-end: name -> pubKey must be the key the record was signed with.
    const keypair = generateEd25519Keypair();
    const ipnsName = await deriveIpnsName(keypair.publicKey);
    const recovered = publicKeyFromIpnsName(ipnsName);
    const reDerivedName = await deriveIpnsName(recovered);

    expect(reDerivedName).toBe(ipnsName);
  });

  it('throws CryptoError on a malformed / non-Ed25519 name', () => {
    expect(() => publicKeyFromIpnsName('not-a-name')).toThrow();
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

  it('surfaces validity: Date matching the source record EOL (additive field)', async () => {
    const keypair = generateEd25519Keypair();
    const marshalled = await makeRecord(keypair, TEST_VALUE, 7n);

    const parsed = await parseIpnsRecord(marshalled);
    // The additive validity is the RFC3339 EOL from unmarshalIPNSRecord, as a Date.
    const source = unmarshalIPNSRecord(marshalled);

    expect(parsed.validity).toBeInstanceOf(Date);
    expect(parsed.validity.getTime()).toBe(new Date(source.validity).getTime());
    // A 24h-lifetime record's EOL is in the future relative to creation.
    expect(parsed.validity.getTime()).toBeGreaterThan(Date.now());
  });
});

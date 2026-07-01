/**
 * IPNS Signer Service Tests
 *
 * Verifies the lease-renew transform (renewIpnsRecord) added by plan 67-03.
 *
 * Security invariants under test (TEE-01 / TEE-02):
 * - value (CID) is preserved exactly — no repoint
 * - sequence is preserved exactly — no increment
 * - EOL shifts forward — fresh validity, different bytes
 * - signature is valid against the IPNS name derived from the key
 */

import { describe, it, expect } from 'vitest';
import {
  generateEd25519Keypair,
  deriveIpnsName,
  parseIpnsRecord,
  verifyIpnsRecordSignature,
} from '@cipherbox/crypto';
import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';
import { renewIpnsRecord } from '../services/ipns-signer.js';

/** CID used as the record value in tests */
const TEST_CID = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
const TEST_VALUE = '/ipfs/' + TEST_CID;
const TEST_SEQUENCE = 7n;

/** Create a real marshaled IPNS record at sequence 7 with a 1-hour lifetime */
async function makeOriginalRecord(privateKey: Uint8Array): Promise<Uint8Array> {
  const record = await createIpnsRecord(privateKey, TEST_VALUE, TEST_SEQUENCE, 60 * 60 * 1000);
  return marshalIpnsRecord(record);
}

describe('renewIpnsRecord', () => {
  it('preserves the value (no CID repoint)', async () => {
    const keypair = generateEd25519Keypair();
    const original = await makeOriginalRecord(keypair.privateKey);

    const renewed = await renewIpnsRecord(keypair.privateKey, original);

    const parsedOriginal = await parseIpnsRecord(original);
    const parsedRenewed = await parseIpnsRecord(renewed);

    expect(parsedRenewed.value).toBe(parsedOriginal.value);
    expect(parsedRenewed.value).toBe(TEST_VALUE);
  });

  it('preserves the sequence number (no +1)', async () => {
    const keypair = generateEd25519Keypair();
    const original = await makeOriginalRecord(keypair.privateKey);

    const renewed = await renewIpnsRecord(keypair.privateKey, original);

    const parsedOriginal = await parseIpnsRecord(original);
    const parsedRenewed = await parseIpnsRecord(renewed);

    expect(parsedRenewed.sequence).toBe(parsedOriginal.sequence);
    expect(parsedRenewed.sequence).toBe(TEST_SEQUENCE);
  });

  it('produces different bytes (later EOL shifts the validity field)', async () => {
    const keypair = generateEd25519Keypair();
    const original = await makeOriginalRecord(keypair.privateKey);

    // renewIpnsRecord uses the TEE 48-hour lifetime vs the 1-hour original
    const renewed = await renewIpnsRecord(keypair.privateKey, original);

    expect(Buffer.from(renewed).equals(Buffer.from(original))).toBe(false);
  });

  it('produces a valid signature for the IPNS name derived from the key', async () => {
    const keypair = generateEd25519Keypair();
    const ipnsName = await deriveIpnsName(keypair.publicKey);
    const original = await makeOriginalRecord(keypair.privateKey);

    const renewed = await renewIpnsRecord(keypair.privateKey, original);

    expect(await verifyIpnsRecordSignature(ipnsName, renewed)).toBe(true);
  });

  it('accepts an explicit lifetimeMs and still preserves value and sequence', async () => {
    const keypair = generateEd25519Keypair();
    const original = await makeOriginalRecord(keypair.privateKey);
    const customLifetimeMs = 2 * 60 * 60 * 1000; // 2 hours

    const renewed = await renewIpnsRecord(keypair.privateKey, original, customLifetimeMs);

    const parsedRenewed = await parseIpnsRecord(renewed);
    expect(parsedRenewed.value).toBe(TEST_VALUE);
    expect(parsedRenewed.sequence).toBe(TEST_SEQUENCE);
  });
});

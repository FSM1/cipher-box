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

import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  generateEd25519Keypair,
  deriveIpnsName,
  parseIpnsRecord,
  verifyIpnsRecordSignature,
} from '@cipherbox/crypto';
import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';
import { renewIpnsRecord, EolRollbackError } from '../services/ipns-signer.js';

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

  // ───────────────────────────────────────────────────────────────────────────
  // Strictly-later-EOL invariant (SC3 item 4 / T-76-11) — compared against the
  // PARSED EXISTING record's validity, never Date.now() wall-clock arithmetic.
  // ───────────────────────────────────────────────────────────────────────────

  it('advances the EOL: renewed.validity is strictly later than the existing validity', async () => {
    const keypair = generateEd25519Keypair();
    const original = await makeOriginalRecord(keypair.privateKey); // 1h lifetime

    // Default 48h renewal window is well past the 1h original EOL.
    const renewed = await renewIpnsRecord(keypair.privateKey, original);

    const parsedOriginal = await parseIpnsRecord(original);
    const parsedRenewed = await parseIpnsRecord(renewed);
    expect(parsedRenewed.validity.getTime()).toBeGreaterThan(parsedOriginal.validity.getTime());
  });

  describe('EOL rollback rejection (deterministic via faked Date)', () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    // Fake ONLY Date so createIpnsRecord's EOL (fakeNow + lifetime) is deterministic,
    // without stalling the real microtask queue the crypto awaits.
    function freezeClock(): void {
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
    }

    it('rejects an EQUAL new EOL (same lifetime at the same instant) — no rollback', async () => {
      freezeClock();
      const keypair = generateEd25519Keypair();
      const lifetimeMs = 60 * 60 * 1000; // 1h
      const original = await makeOriginalRecord(keypair.privateKey); // EOL = base + 1h

      // Renew with the identical lifetime at the frozen instant → new EOL == existing EOL.
      await expect(
        renewIpnsRecord(keypair.privateKey, original, lifetimeMs)
      ).rejects.toBeInstanceOf(EolRollbackError);
    });

    it('rejects an EARLIER new EOL (shorter renewal lifetime)', async () => {
      freezeClock();
      const keypair = generateEd25519Keypair();
      const original = await makeOriginalRecord(keypair.privateKey); // EOL = base + 1h

      // 30-minute renewal at the frozen instant → new EOL (base+30m) < existing (base+1h).
      await expect(
        renewIpnsRecord(keypair.privateKey, original, 30 * 60 * 1000)
      ).rejects.toBeInstanceOf(EolRollbackError);
    });

    it('rejects when the original lifetime is LONGER than the default renewal window', async () => {
      freezeClock();
      const keypair = generateEd25519Keypair();
      // Original with a 96h lifetime — longer than the 48h default renewal window.
      const longRecord = await createIpnsRecord(
        keypair.privateKey,
        TEST_VALUE,
        TEST_SEQUENCE,
        96 * 60 * 60 * 1000
      );
      const original = marshalIpnsRecord(longRecord); // EOL = base + 96h

      // Default 48h renewal at the frozen instant → new EOL (base+48h) < existing (base+96h).
      await expect(renewIpnsRecord(keypair.privateKey, original)).rejects.toBeInstanceOf(
        EolRollbackError
      );
    });

    it('accepts a strictly-later new EOL at the frozen instant', async () => {
      freezeClock();
      const keypair = generateEd25519Keypair();
      const original = await makeOriginalRecord(keypair.privateKey); // EOL = base + 1h

      // 2h renewal → new EOL (base+2h) > existing (base+1h).
      const renewed = await renewIpnsRecord(keypair.privateKey, original, 2 * 60 * 60 * 1000);

      const parsedOriginal = await parseIpnsRecord(original);
      const parsedRenewed = await parseIpnsRecord(renewed);
      expect(parsedRenewed.validity.getTime()).toBeGreaterThan(parsedOriginal.validity.getTime());
    });
  });
});

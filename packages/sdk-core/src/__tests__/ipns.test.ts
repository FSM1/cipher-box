import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../ipns';

// Mock the api-client functions
vi.mock('@cipherbox/api-client', () => ({
  ipnsControllerPublishRecord: vi.fn(),
  ipnsControllerPublishBatch: vi.fn(),
  ipnsControllerResolveRecord: vi.fn(),
}));

// Mock the core functions
vi.mock('@cipherbox/core', () => ({
  createIpnsRecord: vi.fn().mockResolvedValue({ value: '/ipfs/QmTest' }),
  marshalIpnsRecord: vi.fn().mockReturnValue(new Uint8Array([1, 2, 3])),
  IPNS_SIGNATURE_PREFIX: new TextEncoder().encode('ipns-signature:'),
}));

// Mock crypto functions
vi.mock('@cipherbox/crypto', () => ({
  verifyEd25519: vi.fn().mockResolvedValue(true),
  deriveEd25519PublicKey: vi.fn().mockReturnValue(new Uint8Array(32).fill(7)),
  deriveIpnsName: vi.fn().mockResolvedValue('k51resolve'),
  concatBytes: vi.fn((...args: Uint8Array[]) => {
    const total = args.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const arr of args) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }),
}));

describe('IPNS operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('createAndPublishIpnsRecord', () => {
    it('creates and publishes IPNS record with correct params', async () => {
      const { ipnsControllerPublishRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerPublishRecord).mockResolvedValue({
        success: true,
        sequenceNumber: '2',
        ipnsName: 'k51testname',
      });

      const result = await createAndPublishIpnsRecord({
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51testname',
        metadataCid: 'QmMetaCid',
        sequenceNumber: 1n,
      });

      expect(ipnsControllerPublishRecord).toHaveBeenCalledWith(
        expect.objectContaining({
          ipnsName: 'k51testname',
          metadataCid: 'QmMetaCid',
          publicKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
        }),
        undefined
      );
      expect(result.success).toBe(true);
      expect(result.sequenceNumber).toBe(2n);
    });

    it('passes TEE-encrypted key when provided', async () => {
      const { ipnsControllerPublishRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerPublishRecord).mockResolvedValue({
        success: true,
        sequenceNumber: '1',
        ipnsName: 'k51test',
      });

      await createAndPublishIpnsRecord({
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51test',
        metadataCid: 'QmCid',
        sequenceNumber: 0n,
        encryptedIpnsPrivateKey: 'aabbccdd',
        keyEpoch: 3,
      });

      expect(ipnsControllerPublishRecord).toHaveBeenCalledWith(
        expect.objectContaining({
          encryptedIpnsPrivateKey: 'aabbccdd',
          keyEpoch: 3,
          publicKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
        }),
        undefined
      );
    });

    // SC4(a): 410 (IPNS_TOMBSTONED) from ipnsControllerPublishRecord must be caught and
    // mapped to a tombstoned result instead of letting a raw AxiosError propagate.
    // Mirrors the existing 404-detection idiom used by resolveIpnsRecord (lines 317-325).
    it('SC4(a): maps a 410 rejection to { success:false, tombstoned:true }', async () => {
      const { ipnsControllerPublishRecord } = await import('@cipherbox/api-client');
      const error = new Error('Gone') as Error & { response?: { status?: number } };
      error.response = { status: 410 };
      vi.mocked(ipnsControllerPublishRecord).mockRejectedValue(error);

      const result = await createAndPublishIpnsRecord({
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51tombstoned',
        metadataCid: 'QmTombstonedCid',
        sequenceNumber: 1n,
      });

      expect(result.success).toBe(false);
      // Return type does not yet declare `tombstoned` (added in Task 2/GREEN) — cast locally
      // so this RED test compiles and fails at runtime.
      expect((result as { tombstoned?: boolean }).tombstoned).toBe(true);
    });

    // Regression guard: a non-410 rejection must still propagate unchanged (no swallowing).
    it('SC4(a) regression: a non-410 rejection (500) still rethrows unchanged', async () => {
      const { ipnsControllerPublishRecord } = await import('@cipherbox/api-client');
      const error = new Error('Internal Server Error') as Error & {
        response?: { status?: number };
      };
      error.response = { status: 500 };
      vi.mocked(ipnsControllerPublishRecord).mockRejectedValue(error);

      await expect(
        createAndPublishIpnsRecord({
          ipnsPrivateKey: new Uint8Array(64),
          ipnsName: 'k51notfound500',
          metadataCid: 'QmCid500',
          sequenceNumber: 1n,
        })
      ).rejects.toThrow('Internal Server Error');
    });
  });

  describe('resolveIpnsRecord', () => {
    it('resolves IPNS name and returns CID with sequence number (with valid sig)', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
      const { encode } = await import('cborg');
      vi.mocked(verifyEd25519).mockResolvedValue(true);
      vi.mocked(deriveIpnsName).mockResolvedValue('k51resolve');
      // Provide a properly signed response with matching CBOR data (D-05: unsigned throws)
      const cbor = encode({
        TTL: 300000000000,
        Value: new TextEncoder().encode('/ipfs/QmResolvedCid'),
        Sequence: 5,
        Validity: new TextEncoder().encode('2099-01-01T00:00:00.000000000Z'),
        ValidityType: 0,
      });
      const data = Buffer.from(cbor).toString('base64');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: true,
        cid: 'QmResolvedCid',
        sequenceNumber: '5',
        signatureV2: btoa('sig'),
        data,
        pubKey: btoa('pubkey'),
      });

      const result = await resolveIpnsRecord('k51resolve');

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('QmResolvedCid');
      expect(result!.sequenceNumber).toBe(5n);
      expect(result!.signatureVerified).toBe(true);
    });

    it('returns null when IPNS name not found', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: false,
        cid: '',
        sequenceNumber: '0',
      });

      const result = await resolveIpnsRecord('k51notfound');

      expect(result).toBeNull();
    });

    it('returns null on 404 error', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      const error = new Error('Not found') as Error & { status: number };
      error.status = 404;
      vi.mocked(ipnsControllerResolveRecord).mockRejectedValue(error);

      const result = await resolveIpnsRecord('k51missing');

      expect(result).toBeNull();
    });

    it('propagates non-404 errors', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerResolveRecord).mockRejectedValue(new Error('Server error'));

      await expect(resolveIpnsRecord('k51error')).rejects.toThrow('Server error');
    });

    it('verifies signature and pubKey-to-ipnsName binding when signature fields present', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
      // Use real CBOR data that matches cid/sequenceNumber for the D-07/D-08 binding check.
      const { encode: cborEncode } = await import('cborg');
      const cbor = cborEncode({
        TTL: 300000000000,
        Value: new TextEncoder().encode('/ipfs/QmSignedCid'),
        Sequence: 10,
        Validity: new TextEncoder().encode('2099-01-01T00:00:00.000000000Z'),
        ValidityType: 0,
      });
      const data = Buffer.from(cbor).toString('base64');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: true,
        cid: 'QmSignedCid',
        sequenceNumber: '10',
        signatureV2: btoa('fake-sig-bytes'),
        data,
        pubKey: btoa('fake-pubkey-bytes'),
      });
      vi.mocked(deriveIpnsName).mockResolvedValue('k51verified');

      const result = await resolveIpnsRecord('k51verified');

      expect(verifyEd25519).toHaveBeenCalled();
      expect(deriveIpnsName).toHaveBeenCalled();
      expect(result).not.toBeNull();
      expect(result!.signatureVerified).toBe(true);
      expect(result!.cid).toBe('QmSignedCid');
    });

    it('throws when pubKey does not derive to requested ipnsName', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      const { deriveIpnsName } = await import('@cipherbox/crypto');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: true,
        cid: 'QmFakedCid',
        sequenceNumber: '1',
        signatureV2: btoa('sig'),
        data: btoa('data'),
        pubKey: btoa('wrongkey'),
      });
      vi.mocked(deriveIpnsName).mockResolvedValue('k51different-name');

      await expect(resolveIpnsRecord('k51requested-name')).rejects.toThrow(
        'IPNS public key does not match requested name'
      );
    });

    it('throws when signature verification fails', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      const { verifyEd25519 } = await import('@cipherbox/crypto');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: true,
        cid: 'QmTampered',
        sequenceNumber: '1',
        signatureV2: btoa('bad-sig'),
        data: btoa('data'),
        pubKey: btoa('key'),
      });
      vi.mocked(verifyEd25519).mockResolvedValue(false);

      await expect(resolveIpnsRecord('k51tampered')).rejects.toThrow(
        'IPNS signature verification failed'
      );
    });

    // S2 regression guard (D-02): PARTIAL signature fields must fail closed.
    // A record with some-but-not-all of {signatureV2, data, pubKey} carries
    // unverifiable signature material and must NOT be downgraded to the legacy
    // allow path (an attacker could strip fields to bypass verification). Only
    // an all-absent record is treated as legacy (signatureVerified=false).
    it('S2: throws on partial signature fields (only signatureV2 present)', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: true,
        cid: 'QmPartial',
        sequenceNumber: '3',
        signatureV2: btoa('only-sig'),
        // data and pubKey omitted → partial → fail closed
      });

      await expect(resolveIpnsRecord('k51partial')).rejects.toThrow('incomplete signature data');
      // Must fail BEFORE attempting verification or name derivation.
      expect(verifyEd25519).not.toHaveBeenCalled();
      expect(deriveIpnsName).not.toHaveBeenCalled();
    });

    it('S2: throws on empty-string signature fields (all present but empty)', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: true,
        cid: 'QmEmptySig',
        sequenceNumber: '3',
        signatureV2: '',
        data: '',
        pubKey: '',
      });
      await expect(resolveIpnsRecord('k51empty')).rejects.toThrow('incomplete signature data');
      expect(verifyEd25519).not.toHaveBeenCalled();
      expect(deriveIpnsName).not.toHaveBeenCalled();
    });

    // D-07/D-08 CBOR binding tests (Task 4, 58-01)
    // These tests verify that resolveIpnsRecord checks the signed CBOR `data` field
    // against the response cid/sequenceNumber after signature verification.
    //
    // Helper: encode CBOR data matching the Rust build_cbor_data layout.
    // Uses cborg directly (same library used in the implementation).
    describe('D-07/D-08: CBOR cid and sequence binding', () => {
      // Encode CBOR bytes matching Rust build_cbor_data layout:
      // {TTL: int, Value: bytes("/ipfs/<cid>"), Sequence: int, Validity: bytes, ValidityType: int}
      async function makeCborData(cid: string, seq: number): Promise<string> {
        const { encode } = await import('cborg');
        const cbor = encode({
          TTL: 300000000000,
          Value: new TextEncoder().encode(`/ipfs/${cid}`),
          Sequence: seq,
          Validity: new TextEncoder().encode('2099-01-01T00:00:00.000000000Z'),
          ValidityType: 0,
        });
        return Buffer.from(cbor).toString('base64');
      }

      it('throws on cid binding mismatch (D-08)', async () => {
        const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
        const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
        vi.mocked(verifyEd25519).mockResolvedValue(true);
        // CBOR encodes "/ipfs/bafyREAL" but response.cid = "bafyDIFFERENT"
        const data = await makeCborData('bafyREAL', 5);
        vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
          success: true,
          cid: 'bafyDIFFERENT',
          sequenceNumber: '5',
          signatureV2: btoa('valid-sig'),
          data,
          pubKey: btoa('pubkey'),
        });
        vi.mocked(deriveIpnsName).mockResolvedValue('k51cid-binding');

        await expect(resolveIpnsRecord('k51cid-binding')).rejects.toThrow(/cid binding mismatch/i);
      });

      it('throws on sequence binding mismatch (D-07)', async () => {
        const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
        const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
        vi.mocked(verifyEd25519).mockResolvedValue(true);
        // CBOR encodes seq=99 but response.sequenceNumber = "5"
        const data = await makeCborData('bafyCID', 99);
        vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
          success: true,
          cid: 'bafyCID',
          sequenceNumber: '5',
          signatureV2: btoa('valid-sig'),
          data,
          pubKey: btoa('pubkey'),
        });
        vi.mocked(deriveIpnsName).mockResolvedValue('k51seq-binding');

        await expect(resolveIpnsRecord('k51seq-binding')).rejects.toThrow(
          /sequence binding mismatch/i
        );
      });

      // D-05 (Plan 60-03): first-publish skew disjunct removed — embedded seq=0 with resp=1 now throws.
      // Previously this was accepted as a "first-publish exception" (D-09). After Plan 60-02 unified
      // all producers to embed 1, the skew window no longer exists. Any embedded=0 is now invalid.
      it('D-05: throws on first-publish skew: embedded seq=0 with response sequenceNumber=1 (skew disjunct removed)', async () => {
        const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
        const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
        vi.mocked(verifyEd25519).mockResolvedValue(true);
        // CBOR embeds seq=0 (old IPNS-native first publish), response.sequenceNumber = "1" (DB).
        // After D-05, the skew disjunct is removed — this is now a sequence binding mismatch.
        const data = await makeCborData('bafyFIRST', 0);
        vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
          success: true,
          cid: 'bafyFIRST',
          sequenceNumber: '1',
          signatureV2: btoa('valid-sig'),
          data,
          pubKey: btoa('pubkey'),
        });
        vi.mocked(deriveIpnsName).mockResolvedValue('k51first-publish');

        await expect(resolveIpnsRecord('k51first-publish')).rejects.toThrow(
          /sequence binding mismatch/i
        );
      });

      it('embedded seq=0 with response=2 throws (sequence binding mismatch)', async () => {
        const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
        const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
        vi.mocked(verifyEd25519).mockResolvedValue(true);
        // embedded seq=0 but response.sequenceNumber = "2" — rollback/tamper
        const data = await makeCborData('bafyCID', 0);
        vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
          success: true,
          cid: 'bafyCID',
          sequenceNumber: '2',
          signatureV2: btoa('valid-sig'),
          data,
          pubKey: btoa('pubkey'),
        });
        vi.mocked(deriveIpnsName).mockResolvedValue('k51skew-scope');

        await expect(resolveIpnsRecord('k51skew-scope')).rejects.toThrow(
          /sequence binding mismatch/i
        );
      });

      it('throws on wrong-typed Sequence in CBOR (D-07 type guard)', async () => {
        const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
        const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
        vi.mocked(verifyEd25519).mockResolvedValue(true);
        // Encode CBOR with a boolean Sequence — cborg passes booleans through as CBOR true/false.
        // The implementation must reject this rather than silently coercing (BigInt(true) = 1n).
        const { encode } = await import('cborg');
        const cbor = encode({
          TTL: 300000000000,
          Value: new TextEncoder().encode('/ipfs/bafyTYPEGUARD'),
          Sequence: true, // boolean, not number or bigint
          Validity: new TextEncoder().encode('2099-01-01T00:00:00.000000000Z'),
          ValidityType: 0,
        });
        const data = Buffer.from(cbor).toString('base64');
        vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
          success: true,
          cid: 'bafyTYPEGUARD',
          sequenceNumber: '1',
          signatureV2: btoa('valid-sig'),
          data,
          pubKey: btoa('pubkey'),
        });
        vi.mocked(deriveIpnsName).mockResolvedValue('k51typeguard');

        await expect(resolveIpnsRecord('k51typeguard')).rejects.toThrow(
          /sequence binding mismatch/i
        );
      });

      it('resolves with matching cid and sequence (D-07/D-08 positive)', async () => {
        const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
        const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
        vi.mocked(verifyEd25519).mockResolvedValue(true);
        const data = await makeCborData('bafyMATCH', 7);
        vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
          success: true,
          cid: 'bafyMATCH',
          sequenceNumber: '7',
          signatureV2: btoa('valid-sig'),
          data,
          pubKey: btoa('pubkey'),
        });
        vi.mocked(deriveIpnsName).mockResolvedValue('k51match');

        const result = await resolveIpnsRecord('k51match');

        expect(result).not.toBeNull();
        expect(result!.cid).toBe('bafyMATCH');
        expect(result!.sequenceNumber).toBe(7n);
        expect(result!.signatureVerified).toBe(true);
      });

      // D-05 (Plan 60-03): all-absent signature fields now throw (fail closed).
      // Previously returned { signatureVerified: false } as a legacy path — that is removed.
      it('D-05: throws when all signature fields absent (legacy path removed, fail closed)', async () => {
        const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
        // All three signature fields absent — no longer tolerated as a legacy record
        vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
          success: true,
          cid: 'bafyLEGACY',
          sequenceNumber: '3',
          // signatureV2, data, pubKey all absent
        });

        // Must throw, not return { signatureVerified: false }
        await expect(resolveIpnsRecord('k51legacy')).rejects.toThrow(
          /fail closed|signature fields/i
        );
      });

      it('binding mismatch error is NOT swallowed as 404 — propagates', async () => {
        const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
        const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
        vi.mocked(verifyEd25519).mockResolvedValue(true);
        // cid mismatch → throws; the catch block must NOT swallow it as 404
        const data = await makeCborData('bafyREAL', 1);
        vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
          success: true,
          cid: 'bafyTAMPERED',
          sequenceNumber: '1',
          signatureV2: btoa('sig'),
          data,
          pubKey: btoa('key'),
        });
        vi.mocked(deriveIpnsName).mockResolvedValue('k51propagate');

        // Must throw (not return null)
        await expect(resolveIpnsRecord('k51propagate')).rejects.toThrow(/cid binding mismatch/i);
      });
    });
  });
});

// ---------------------------------------------------------------------------
// D-11/D-12: Cross-language verify vector tests
//
// Loads the shared fixture tests/vectors/ipns/verify.json (8 cases) and drives
// resolveIpnsRecord against each vector, mocking only the crypto signature and
// name-binding primitives to reflect the case — the REAL CBOR `data` bytes from
// the fixture are passed through to cborDecode so the binding check exercises
// the actual byte-construction from the generator.
//
// This is the JS side of D-12: both Rust (crates/fuse/tests/ipns_verify_vectors.rs)
// and JS consume the SAME fixture, so Rust↔JS byte-construction drift fails an
// already-required CI check.
// ---------------------------------------------------------------------------

import vectors from '../../../../tests/vectors/ipns/verify.json';

describe('D-11/D-12 cross-language IPNS verify vectors', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fixture has exactly 8 cases', () => {
    expect(vectors).toHaveLength(8);
  });

  it('valid — resolves with signatureVerified=true', async () => {
    const v = vectors.find((x) => x.description.startsWith('valid'));
    if (!v) throw new Error('valid vector not found');
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(verifyEd25519).mockResolvedValue(true);
    vi.mocked(deriveIpnsName).mockResolvedValue(v.ipns_name);
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: v.cid,
      sequenceNumber: v.sequence_number,
      signatureV2: v.signature_v2 ?? undefined,
      data: v.data ?? undefined,
      pubKey: v.pub_key ?? undefined,
    });

    const result = await resolveIpnsRecord(v.ipns_name);

    expect(result, `${v.description}`).not.toBeNull();
    expect(result!.signatureVerified, `${v.description}`).toBe(true);
    expect(result!.cid, `${v.description}`).toBe(v.cid);
  });

  it('tampered-sig — throws on invalid signature', async () => {
    const v = vectors.find((x) => x.description.startsWith('tampered-sig'));
    if (!v) throw new Error('tampered-sig vector not found');
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    // Tampered signature: verifyEd25519 returns false (Ed25519 check fails)
    vi.mocked(verifyEd25519).mockResolvedValue(false);
    vi.mocked(deriveIpnsName).mockResolvedValue(v.ipns_name);
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: v.cid,
      sequenceNumber: v.sequence_number,
      signatureV2: v.signature_v2 ?? undefined,
      data: v.data ?? undefined,
      pubKey: v.pub_key ?? undefined,
    });

    await expect(resolveIpnsRecord(v.ipns_name), `${v.description}`).rejects.toThrow(
      /signature verification failed/i
    );
  });

  it('name-mismatch — throws on pubKey-to-name binding failure', async () => {
    const v = vectors.find((x) => x.description.startsWith('name-mismatch'));
    if (!v) throw new Error('name-mismatch vector not found');
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(verifyEd25519).mockResolvedValue(true);
    // pub_key derives to a DIFFERENT name than ipns_name
    vi.mocked(deriveIpnsName).mockResolvedValue('k51different-name-from-vector');
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: v.cid,
      sequenceNumber: v.sequence_number,
      signatureV2: v.signature_v2 ?? undefined,
      data: v.data ?? undefined,
      pubKey: v.pub_key ?? undefined,
    });

    await expect(resolveIpnsRecord(v.ipns_name), `${v.description}`).rejects.toThrow(
      /public key does not match/i
    );
  });

  it('cid-swapped — throws on cid binding mismatch (real data bytes)', async () => {
    // The fixture data field embeds CID_A but response.cid is CID_B.
    // The Ed25519 sig is valid over the data (mock returns true); only the binding fails.
    const v = vectors.find((x) => x.description.startsWith('cid-swapped'));
    if (!v) throw new Error('cid-swapped vector not found');
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(verifyEd25519).mockResolvedValue(true);
    vi.mocked(deriveIpnsName).mockResolvedValue(v.ipns_name);
    // response.cid is the swapped CID (CID_B), data contains the original CID_A
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: v.cid, // This is CID_B (the swapped value)
      sequenceNumber: v.sequence_number,
      signatureV2: v.signature_v2 ?? undefined,
      data: v.data ?? undefined, // This encodes /ipfs/CID_A — REAL bytes from fixture
      pubKey: v.pub_key ?? undefined,
    });

    // Binding check must throw because embedded CID_A != response CID_B
    await expect(resolveIpnsRecord(v.ipns_name), `${v.description}`).rejects.toThrow(
      /cid binding mismatch/i
    );
  });

  it('seq-mismatch — throws on sequence binding mismatch (real data bytes)', async () => {
    // The fixture data field encodes seq=99 but response.sequenceNumber is 5.
    // Ed25519 sig is valid (mock returns true); only the binding fails.
    const v = vectors.find((x) => x.description.startsWith('seq-mismatch'));
    if (!v) throw new Error('seq-mismatch vector not found');
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(verifyEd25519).mockResolvedValue(true);
    vi.mocked(deriveIpnsName).mockResolvedValue(v.ipns_name);
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: v.cid,
      sequenceNumber: v.sequence_number, // "5"
      signatureV2: v.signature_v2 ?? undefined,
      data: v.data ?? undefined, // REAL bytes: encodes Sequence=99
      pubKey: v.pub_key ?? undefined,
    });

    // Binding check must throw because embedded seq=99 != response seq=5
    await expect(resolveIpnsRecord(v.ipns_name), `${v.description}`).rejects.toThrow(
      /sequence binding mismatch/i
    );
  });

  // D-05 (Plan 60-03): first-publish-skew vector now expected_result="invalid".
  // The skew disjunct (embedded=0, resp=1 accepted) is removed. All producers now embed 1 (Plan 60-02).
  it('first-publish-skew — throws on embedded seq=0 vs response sequenceNumber=1 (D-05 strict)', async () => {
    const v = vectors.find((x) => x.description.startsWith('first-publish-skew'));
    if (!v) throw new Error('first-publish-skew vector not found');
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(verifyEd25519).mockResolvedValue(true);
    vi.mocked(deriveIpnsName).mockResolvedValue(v.ipns_name);
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: v.cid,
      sequenceNumber: v.sequence_number, // "1"
      signatureV2: v.signature_v2 ?? undefined,
      data: v.data ?? undefined, // REAL bytes: encodes Sequence=0
      pubKey: v.pub_key ?? undefined,
    });

    // After D-05: embedded=0 vs resp=1 is a sequence binding mismatch → throw
    await expect(resolveIpnsRecord(v.ipns_name), `${v.description}`).rejects.toThrow(
      /sequence binding mismatch/i
    );
  });

  it('partial-fields — throws on incomplete signature data (downgrade vector)', async () => {
    const v = vectors.find((x) => x.description.startsWith('partial-fields'));
    if (!v) throw new Error('partial-fields vector not found');
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: v.cid,
      sequenceNumber: v.sequence_number,
      signatureV2: v.signature_v2 ?? undefined, // present
      data: v.data ?? undefined, // null
      pubKey: v.pub_key ?? undefined, // null
    });

    // Partial fields: fail-closed before even reaching verification
    await expect(resolveIpnsRecord(v.ipns_name), `${v.description}`).rejects.toThrow(
      /incomplete signature data/i
    );
    // Verify was never called (guard fires first)
    expect(verifyEd25519).not.toHaveBeenCalled();
    expect(deriveIpnsName).not.toHaveBeenCalled();
  });

  // D-05 (Plan 60-03): legacy-absent vector now expected_result="invalid".
  // All-absent signature fields previously returned { signatureVerified: false } (D-04 legacy path).
  // After D-05, absent fields throw (fail closed). The vector.json will be reclassified in Plan 60-10.
  it('legacy-absent — throws when all signature fields absent (D-05 fail closed)', async () => {
    const v = vectors.find((x) => x.description.startsWith('legacy-absent'));
    if (!v) throw new Error('legacy-absent vector not found');
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: v.cid,
      sequenceNumber: v.sequence_number,
      // All three signature fields absent
    });

    // After D-05: absent fields → throw (fail closed), not { signatureVerified: false }
    await expect(resolveIpnsRecord(v.ipns_name), `${v.description}`).rejects.toThrow(
      /fail closed|signature fields/i
    );
  });
});

// ---------------------------------------------------------------------------
// D-05 / D-07: Strict throw-path tests (Plan 60-03)
//
// These 4 tests express the NEW strict contract for resolveIpnsRecord:
//   (a) absent-signature-fields → throws (no legacy soft return)
//   (b) first-publish skew (embedded seq=0, resp seq=1) → throws (skew disjunct removed)
//   (c) expired Validity → throws (EOL enforcement, D-07)
//   (d) valid in-window record → still returns verified result
//
// RED: all 4 fail before the implementation is updated.
// GREEN: after implementation update, all 4 pass.
// ---------------------------------------------------------------------------

describe('D-05/D-07: strict throw-path (Plan 60-03)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Helper: encode CBOR data with controllable Validity bytes
  async function makeCborDataWithValidity(
    cid: string,
    seq: number,
    validityStr: string
  ): Promise<string> {
    const { encode } = await import('cborg');
    const cbor = encode({
      TTL: 300000000000,
      Value: new TextEncoder().encode(`/ipfs/${cid}`),
      Sequence: seq,
      Validity: new TextEncoder().encode(validityStr),
      ValidityType: 0,
    });
    return Buffer.from(cbor).toString('base64');
  }

  // (a) D-05: absent signature fields → throws (fail closed), does NOT return { signatureVerified: false }
  it('D-05-a: throws when all signature fields absent (fail closed, not legacy soft return)', async () => {
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'bafyLEGACY',
      sequenceNumber: '3',
      // signatureV2, data, pubKey all absent — triggers the old console.warn path
    });

    // Must throw, not return { signatureVerified: false }
    await expect(resolveIpnsRecord('k51absent-fields')).rejects.toThrow(
      /fail closed|signature fields/i
    );
  });

  // (b) D-05: first-publish skew (embedded=0, resp=1) → throws (skew disjunct removed)
  it('D-05-b: throws on first-publish skew (embedded seq=0 with response sequenceNumber=1)', async () => {
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(verifyEd25519).mockResolvedValue(true);
    vi.mocked(deriveIpnsName).mockResolvedValue('k51first-skew-strict');
    // CBOR embeds seq=0 but response.sequenceNumber=1 — the old skew disjunct accepted this
    const data = await makeCborDataWithValidity('bafyFIRST', 0, '2099-01-01T00:00:00.000000000Z');
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'bafyFIRST',
      sequenceNumber: '1',
      signatureV2: btoa('sig'),
      data,
      pubKey: btoa('pubkey'),
    });

    // After D-05 skew disjunct removed: embedded=0 vs resp=1 is a sequence mismatch → throw
    await expect(resolveIpnsRecord('k51first-skew-strict')).rejects.toThrow(
      /sequence binding mismatch/i
    );
  });

  // (c) D-07: expired Validity timestamp → throws with expiry message
  it('D-07-c: throws when CBOR Validity timestamp is in the past', async () => {
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(verifyEd25519).mockResolvedValue(true);
    vi.mocked(deriveIpnsName).mockResolvedValue('k51expired');
    // Validity is in the past (2020)
    const data = await makeCborDataWithValidity('bafyEXP', 5, '2020-01-01T00:00:00.000000000Z');
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'bafyEXP',
      sequenceNumber: '5',
      signatureV2: btoa('sig'),
      data,
      pubKey: btoa('pubkey'),
    });

    await expect(resolveIpnsRecord('k51expired')).rejects.toThrow(/expired|validity/i);
  });

  // (d) D-07: valid in-window record → still resolves with signatureVerified=true
  it('D-07-d: returns verified result for valid signature with future Validity', async () => {
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(verifyEd25519).mockResolvedValue(true);
    vi.mocked(deriveIpnsName).mockResolvedValue('k51valid-expiry');
    // Validity is in the far future (2099)
    const data = await makeCborDataWithValidity('bafyVALID', 7, '2099-01-01T00:00:00.000000000Z');
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'bafyVALID',
      sequenceNumber: '7',
      signatureV2: btoa('sig'),
      data,
      pubKey: btoa('pubkey'),
    });

    const result = await resolveIpnsRecord('k51valid-expiry');
    expect(result).not.toBeNull();
    expect(result!.signatureVerified).toBe(true);
    expect(result!.cid).toBe('bafyVALID');
    expect(result!.sequenceNumber).toBe(7n);
  });

  // (e) D-07: absent Validity field → throws (fail closed), mirroring the Rust verifier
  // (crates/api-client/src/ipns.rs treats a missing Validity field as expired/Invalid).
  // Cross-layer parity: both verifiers must reject a Validity-less record identically.
  it('D-07-e: throws when CBOR data has no Validity field (fail closed, Rust/TS parity)', async () => {
    const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
    const { verifyEd25519, deriveIpnsName } = await import('@cipherbox/crypto');
    vi.mocked(verifyEd25519).mockResolvedValue(true);
    vi.mocked(deriveIpnsName).mockResolvedValue('k51no-validity');
    // Encode CBOR with NO Validity field — the implementation must fail closed, not skip EOL.
    const { encode } = await import('cborg');
    const cbor = encode({
      TTL: 300000000000,
      Value: new TextEncoder().encode('/ipfs/bafyNOVAL'),
      Sequence: 5,
      ValidityType: 0,
    });
    const data = Buffer.from(cbor).toString('base64');
    vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'bafyNOVAL',
      sequenceNumber: '5',
      signatureV2: btoa('sig'),
      data,
      pubKey: btoa('pubkey'),
    });

    await expect(resolveIpnsRecord('k51no-validity')).rejects.toThrow(
      /no Validity field|fail closed/i
    );
  });
});

// ---------------------------------------------------------------------------
// S3 caller-owns-key guard tests (D-05 / T-47-01)
// createAndPublishIpnsRecord is a CALLEE: it must NOT zero the caller-passed
// ipnsPrivateKey buffer. Callers reuse the same buffer across operations (the SDK
// client caches per-folder IPNS keys; publishWithCas reuses it across CAS retries),
// so zeroing here corrupts long-lived key material and breaks every subsequent
// publish (server rejects with 400 "publicKey does not correspond to the given
// ipnsName"). Terminal owners zero their own keys (client.destroy(), clearBytes(),
// publishVaultKeyBlob / shared-write on their freshly-derived keypairs).
// These tests guard against re-introducing the zeroization regression.
// ---------------------------------------------------------------------------

describe('createAndPublishIpnsRecord caller-owns-key (S3/D-05)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Test A: key is PRESERVED on the success path (callee does not own it)
  it('A: does NOT zero the ipnsPrivateKey buffer after a successful publish', async () => {
    const { ipnsControllerPublishRecord } = await import('@cipherbox/api-client');
    vi.mocked(ipnsControllerPublishRecord).mockResolvedValue({
      success: true,
      sequenceNumber: '1',
      ipnsName: 'k51zeroize',
    });

    const key = new Uint8Array(32).fill(5);
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: key,
      ipnsName: 'k51zeroize',
      metadataCid: 'QmCid',
      sequenceNumber: 0n,
    });

    // T-47-01: caller-owned buffer must be left intact so it can be reused.
    expect(key.every((b) => b === 5)).toBe(true);
  });

  // Test B: key is PRESERVED even when the publish rejects (no finally-zero)
  it('B: does NOT zero the ipnsPrivateKey buffer when publish throws', async () => {
    const { ipnsControllerPublishRecord } = await import('@cipherbox/api-client');
    vi.mocked(ipnsControllerPublishRecord).mockRejectedValue(new Error('publish failed'));

    const key = new Uint8Array(32).fill(9);
    await expect(
      createAndPublishIpnsRecord({
        ipnsPrivateKey: key,
        ipnsName: 'k51zeroize-throw',
        metadataCid: 'QmCid',
        sequenceNumber: 0n,
      })
    ).rejects.toThrow('publish failed');

    // Buffer must survive the throw — the caller owns and zeroes it.
    expect(key.every((b) => b === 9)).toBe(true);
  });
});

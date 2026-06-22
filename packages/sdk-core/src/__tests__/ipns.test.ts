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
  });

  describe('resolveIpnsRecord', () => {
    it('resolves IPNS name and returns CID with sequence number', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: true,
        cid: 'QmResolvedCid',
        sequenceNumber: '5',
      });

      const result = await resolveIpnsRecord('k51resolve');

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('QmResolvedCid');
      expect(result!.sequenceNumber).toBe(5n);
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
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: true,
        cid: 'QmSignedCid',
        sequenceNumber: '10',
        signatureV2: btoa('fake-sig-bytes'),
        data: btoa('fake-cbor-data'),
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
        return btoa(String.fromCharCode(...cbor));
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

      it('legacy record is NOT subjected to CBOR binding (D-04)', async () => {
        const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
        // All three signature fields absent → legacy, no binding check
        vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
          success: true,
          cid: 'bafyLEGACY',
          sequenceNumber: '3',
          // signatureV2, data, pubKey all absent
        });

        const result = await resolveIpnsRecord('k51legacy');

        expect(result).not.toBeNull();
        expect(result!.signatureVerified).toBe(false);
        expect(result!.cid).toBe('bafyLEGACY');
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

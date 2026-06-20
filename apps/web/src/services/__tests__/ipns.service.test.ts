/**
 * ipns.service.ts — resolveIpnsRecord fail-closed tests (S2 / D-02 / D-03)
 *
 * Covers the four required behaviors:
 *  1. Present-but-invalid signature → throw (D-02, fail closed)
 *  2. pubKey → ipnsName mismatch → throw (D-02, key substitution guard)
 *  3. Absent signature fields → allow + flag signatureVerified=false (D-03)
 *  4. Valid signature + matching name → signatureVerified=true
 *  5. 404 error → null (narrow outer catch preserved)
 *  6. Non-404 error → rethrow (verification errors not swallowed)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { resolveIpnsRecord } from '../ipns.service';
import * as apiClient from '@cipherbox/api-client';
import * as crypto from '@cipherbox/crypto';

vi.mock('@cipherbox/api-client', () => ({
  ipnsControllerResolveRecord: vi.fn(),
  ipnsControllerPublishRecord: vi.fn(),
  ipnsControllerPublishBatch: vi.fn(),
}));

vi.mock('@cipherbox/core', () => ({
  createIpnsRecord: vi.fn(),
  marshalIpnsRecord: vi.fn(),
  IPNS_SIGNATURE_PREFIX: new TextEncoder().encode('ipns-signature:'),
}));

vi.mock('@cipherbox/crypto', () => ({
  verifyEd25519: vi.fn().mockResolvedValue(true),
  deriveEd25519PublicKey: vi.fn().mockReturnValue(new Uint8Array(32)),
  deriveIpnsName: vi.fn().mockResolvedValue('k51testname'),
  concatBytes: vi.fn((...args: Uint8Array[]) => {
    const total = args.reduce((sum: number, a: Uint8Array) => sum + a.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const arr of args) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }),
}));

describe('resolveIpnsRecord', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws when signature fields are present but verification returns false (D-02)', async () => {
    vi.mocked(apiClient.ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'QmTamperedCid',
      sequenceNumber: '3',
      signatureV2: btoa('bad-signature-bytes'),
      data: btoa('cbor-data'),
      pubKey: btoa('pubkey-bytes'),
    });
    vi.mocked(crypto.verifyEd25519).mockResolvedValue(false);

    await expect(resolveIpnsRecord('k51testname')).rejects.toThrow(
      'IPNS signature verification failed'
    );
  });

  it('throws when pubKey does not derive to requested ipnsName (key substitution, D-02)', async () => {
    vi.mocked(apiClient.ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'QmSubstitutedCid',
      sequenceNumber: '2',
      signatureV2: btoa('valid-sig'),
      data: btoa('cbor-data'),
      pubKey: btoa('attacker-pubkey'),
    });
    vi.mocked(crypto.verifyEd25519).mockResolvedValue(true);
    vi.mocked(crypto.deriveIpnsName).mockResolvedValue('k51different-name');

    await expect(resolveIpnsRecord('k51requested-name')).rejects.toThrow(
      'IPNS public key does not match requested name'
    );
  });

  it('returns signatureVerified=false without throw when signature fields absent (D-03)', async () => {
    vi.mocked(apiClient.ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'QmLegacyCid',
      sequenceNumber: '1',
      // No signatureV2, data, or pubKey — legacy record
    });

    const result = await resolveIpnsRecord('k51legacyname');

    expect(result).not.toBeNull();
    expect(result!.signatureVerified).toBe(false);
    expect(result!.cid).toBe('QmLegacyCid');
    expect(result!.sequenceNumber).toBe(1n);
  });

  it('returns signatureVerified=true when signature is valid and pubKey matches name', async () => {
    vi.mocked(apiClient.ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'QmVerifiedCid',
      sequenceNumber: '7',
      signatureV2: btoa('valid-signature'),
      data: btoa('valid-cbor-data'),
      pubKey: btoa('valid-pubkey'),
    });
    vi.mocked(crypto.verifyEd25519).mockResolvedValue(true);
    vi.mocked(crypto.deriveIpnsName).mockResolvedValue('k51verified');

    const result = await resolveIpnsRecord('k51verified');

    expect(result).not.toBeNull();
    expect(result!.signatureVerified).toBe(true);
    expect(result!.cid).toBe('QmVerifiedCid');
    expect(result!.sequenceNumber).toBe(7n);
  });

  it('returns null on 404 error (narrow outer catch preserved)', async () => {
    const error = new Error('Not found') as Error & { status: number };
    error.status = 404;
    vi.mocked(apiClient.ipnsControllerResolveRecord).mockRejectedValue(error);

    const result = await resolveIpnsRecord('k51notfound');

    expect(result).toBeNull();
  });

  it('propagates non-404 errors without swallowing (verification errors not null-ified)', async () => {
    const networkError = new Error('Network connection failed');
    vi.mocked(apiClient.ipnsControllerResolveRecord).mockRejectedValue(networkError);

    await expect(resolveIpnsRecord('k51networkerror')).rejects.toThrow('Network connection failed');
  });

  // D-02: partial signature fields must fail closed, not be downgraded to the legacy
  // allow path (an attacker could strip fields to bypass verification).
  it('throws on partial signature fields (only signatureV2 present)', async () => {
    vi.mocked(apiClient.ipnsControllerResolveRecord).mockResolvedValue({
      success: true,
      cid: 'QmPartial',
      sequenceNumber: '3',
      signatureV2: btoa('only-sig'),
      // data and pubKey omitted → partial → fail closed
    });

    await expect(resolveIpnsRecord('k51partial')).rejects.toThrow('incomplete signature data');
    expect(crypto.verifyEd25519).not.toHaveBeenCalled();
    expect(crypto.deriveIpnsName).not.toHaveBeenCalled();
  });
});

/**
 * TDD tests for folder/registration.ts — TEE key wiring in createSubfolder (67-04).
 *
 * RED phase: tests written before implementation.
 *
 * Four behaviors under test:
 *   1. When teeKeys is provided, createAndPublishIpnsRecord receives a non-empty
 *      encryptedIpnsPrivateKey hex string and the correct keyEpoch.
 *   2. The returned object includes encryptedIpnsPrivateKey (hex) and keyEpoch.
 *   3. When teeKeys is omitted, createAndPublishIpnsRecord receives undefined for
 *      encryptedIpnsPrivateKey and the return carries no TEE fields.
 *   4. When teeKeys.currentPublicKey is empty, createSubfolder throws (fail-closed).
 *
 * Mock boundary: all network I/O (@cipherbox/core codec, ipfs, ipns) and
 * @cipherbox/crypto are mocked so the test is fast and hermetic.
 *
 * D-09: caller-owned keys (ipnsPrivateKey, readKey, writeKey) must NOT be zeroed
 * by createSubfolder — terminal-owner convention.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Module mocks — hoisted before imports (vitest hoisting requirement)
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  generateEd25519Keypair: vi.fn(),
  generateRandomBytes: vi.fn(),
  deriveIpnsName: vi.fn(),
  wrapKey: vi.fn(),
  bytesToHex: vi.fn(),
  hexToBytes: vi.fn(),
  sealNode: vi.fn(),
  addToIpfs: vi.fn(),
  createAndPublishIpnsRecord: vi.fn(),
}));

vi.mock('@cipherbox/crypto', () => ({
  generateEd25519Keypair: mockFns.generateEd25519Keypair,
  generateRandomBytes: mockFns.generateRandomBytes,
  deriveIpnsName: mockFns.deriveIpnsName,
  wrapKey: mockFns.wrapKey,
  bytesToHex: mockFns.bytesToHex,
  hexToBytes: mockFns.hexToBytes,
}));

vi.mock('@cipherbox/core', () => ({
  sealNode: mockFns.sealNode,
}));

vi.mock('../ipfs', () => ({
  addToIpfs: mockFns.addToIpfs,
}));

vi.mock('../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
}));

// ---------------------------------------------------------------------------
// Imports of code under test (after mocks are registered)
// ---------------------------------------------------------------------------

import { createSubfolder } from './registration';
import type { SdkContext, TeeKeys } from '../types';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const FAKE_IPNS_PRIVATE_KEY = new Uint8Array(32).fill(0x01);
const FAKE_IPNS_PUBLIC_KEY = new Uint8Array(32).fill(0x02);
const FAKE_READ_KEY = new Uint8Array(32).fill(0x03);
const FAKE_WRITE_KEY = new Uint8Array(32).fill(0x04);
const FAKE_IPNS_NAME = 'k51qzi5uqu5dh9ihzd5hfcj1qpz7a5s9hkiyk4a9w8t2m5lv3e6q2r4n5j8x7f';
const FAKE_CID = 'QmTestCid123';
const FAKE_TEE_PUBLIC_KEY_HEX = 'deadbeef0102030405060708090a0b0c0d0e0f10';
const FAKE_TEE_EPOCH = 3;
const FAKE_WRAPPED_BYTES = new Uint8Array([0xec, 0xaa, 0xbb, 0xcc]);
const FAKE_WRAPPED_HEX = 'ecaabbcc';

const mockCtx: SdkContext = {
  apiUrl: 'http://localhost:3000',
  getAccessToken: async () => 'test-token',
};

const validTeeKeys: TeeKeys = {
  currentPublicKey: FAKE_TEE_PUBLIC_KEY_HEX,
  currentEpoch: FAKE_TEE_EPOCH,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('createSubfolder — TEE key wiring (67-04)', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Happy-path defaults
    mockFns.generateEd25519Keypair.mockResolvedValue({
      publicKey: FAKE_IPNS_PUBLIC_KEY,
      privateKey: FAKE_IPNS_PRIVATE_KEY,
    });
    mockFns.generateRandomBytes
      .mockReturnValueOnce(FAKE_READ_KEY)
      .mockReturnValueOnce(FAKE_WRITE_KEY);
    mockFns.deriveIpnsName.mockResolvedValue(FAKE_IPNS_NAME);
    mockFns.sealNode.mockResolvedValue({ schema: 'node/v3', kind: 'folder', sealed: true });
    mockFns.addToIpfs.mockResolvedValue({ cid: FAKE_CID, size: 128, recorded: true });
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 1n });
    mockFns.hexToBytes.mockReturnValue(new Uint8Array([0xde, 0xad]));
    mockFns.wrapKey.mockResolvedValue(FAKE_WRAPPED_BYTES);
    mockFns.bytesToHex.mockReturnValue(FAKE_WRAPPED_HEX);
  });

  it('forwards encryptedIpnsPrivateKey and keyEpoch to createAndPublishIpnsRecord when teeKeys provided', async () => {
    await createSubfolder({ name: 'test-folder', ctx: mockCtx, teeKeys: validTeeKeys });

    expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledOnce();
    const callArg = mockFns.createAndPublishIpnsRecord.mock.calls[0][0] as {
      encryptedIpnsPrivateKey?: string;
      keyEpoch?: number;
    };
    expect(callArg.encryptedIpnsPrivateKey).toBe(FAKE_WRAPPED_HEX);
    expect(callArg.keyEpoch).toBe(FAKE_TEE_EPOCH);
  });

  it('returns encryptedIpnsPrivateKey and keyEpoch in the result when teeKeys provided', async () => {
    const result = await createSubfolder({
      name: 'test-folder',
      ctx: mockCtx,
      teeKeys: validTeeKeys,
    });

    expect(result.encryptedIpnsPrivateKey).toBe(FAKE_WRAPPED_HEX);
    expect(result.keyEpoch).toBe(FAKE_TEE_EPOCH);
  });

  it('omits TEE fields when teeKeys is not provided', async () => {
    await createSubfolder({ name: 'test-folder', ctx: mockCtx });

    expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledOnce();
    const callArg = mockFns.createAndPublishIpnsRecord.mock.calls[0][0] as {
      encryptedIpnsPrivateKey?: string;
      keyEpoch?: number;
    };
    expect(callArg.encryptedIpnsPrivateKey).toBeUndefined();
    expect(callArg.keyEpoch).toBeUndefined();

    const result = await createSubfolder({ name: 'test-folder', ctx: mockCtx });
    expect(result.encryptedIpnsPrivateKey).toBeUndefined();
    expect(result.keyEpoch).toBeUndefined();
  });

  it('throws fail-closed when teeKeys.currentPublicKey is empty (does not publish)', async () => {
    const malformedTeeKeys: TeeKeys = {
      currentPublicKey: '',
      currentEpoch: FAKE_TEE_EPOCH,
    };

    await expect(
      createSubfolder({ name: 'test-folder', ctx: mockCtx, teeKeys: malformedTeeKeys })
    ).rejects.toThrow();

    // Must not reach publish
    expect(mockFns.createAndPublishIpnsRecord).not.toHaveBeenCalled();
  });
});

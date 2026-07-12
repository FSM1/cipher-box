/**
 * fetchAndDecryptMetadata — current node/v3 contract
 *
 * Rewritten against the CURRENT `fetchAndDecryptMetadata` implementation
 * (packages/sdk-core/src/folder/load.ts): fetchFromIpfs → JSON.parse → unsealNode.
 * The function does NOT wrap errors in a typed Error (no CID-in-message / D-13
 * try-catch exists in the current implementation) — it propagates whatever the
 * composed steps throw as-is. Tests that:
 *  1. Malformed bytes (JSON.parse fails) → rejects with the raw parse error
 *  2. Valid JSON but wrong folderKey (unsealNode throws) → rejects with unsealNode's error
 *  3. Happy path → returns the Node produced by unsealNode unchanged
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// We mock the heavy dependencies so we can test fetchAndDecryptMetadata's
// composition logic in isolation, against the CURRENT unsealNode-based contract.
vi.mock('@cipherbox/core', () => ({
  unsealNode: vi.fn(),
}));

vi.mock('../../ipfs', () => {
  return {
    fetchFromIpfs: vi.fn(),
  };
});

vi.mock('../../perf', () => ({
  withPerf: vi.fn((_name: string, fn: () => unknown) => fn()),
}));

import { fetchAndDecryptMetadata } from '../load';
import * as core from '@cipherbox/core';
import * as ipfsModule from '../../ipfs';
import type { Node } from '@cipherbox/core';

const mockUnsealNode = vi.mocked(core.unsealNode);
const mockFetchFromIpfs = vi.mocked(ipfsModule.fetchFromIpfs);

const TEST_CID = 'QmTestCid1234';
const DUMMY_KEY = new Uint8Array(32);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const DUMMY_CTX: any = {};

describe('fetchAndDecryptMetadata (current node/v3 contract)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects with the raw parse error when bytes fail JSON.parse', async () => {
    // Malformed bytes — not valid JSON
    mockFetchFromIpfs.mockResolvedValue(new TextEncoder().encode('NOT_JSON{{{{'));

    await expect(fetchAndDecryptMetadata(TEST_CID, DUMMY_KEY, DUMMY_CTX)).rejects.toBeInstanceOf(
      SyntaxError
    );
    // unsealNode is never reached — JSON.parse throws first.
    expect(mockUnsealNode).not.toHaveBeenCalled();
  });

  it('rejects with unsealNode error when the key is wrong', async () => {
    // Valid JSON PublishedNode envelope, but unsealNode throws (auth tag mismatch)
    const fakePublished = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'node-id',
      generation: 0,
      aeadVersion: 1,
      readSealed: 'aaaa',
    };
    mockFetchFromIpfs.mockResolvedValue(new TextEncoder().encode(JSON.stringify(fakePublished)));
    mockUnsealNode.mockRejectedValue(new Error('decryption failed'));

    await expect(fetchAndDecryptMetadata(TEST_CID, DUMMY_KEY, DUMMY_CTX)).rejects.toThrow(
      'decryption failed'
    );
    expect(mockUnsealNode).toHaveBeenCalledWith(fakePublished, DUMMY_KEY);
  });

  it('returns the decrypted Node unchanged on the happy path', async () => {
    const fakePublished = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'node-id',
      generation: 0,
      aeadVersion: 1,
      readSealed: 'aaaa',
    };
    mockFetchFromIpfs.mockResolvedValue(new TextEncoder().encode(JSON.stringify(fakePublished)));

    const expectedNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
    };
    mockUnsealNode.mockResolvedValue(expectedNode);

    const result = await fetchAndDecryptMetadata(TEST_CID, DUMMY_KEY, DUMMY_CTX);
    expect(result).toBe(expectedNode);
    expect(mockFetchFromIpfs).toHaveBeenCalledWith(DUMMY_CTX, TEST_CID);
    expect(mockUnsealNode).toHaveBeenCalledWith(fakePublished, DUMMY_KEY);
  });
});

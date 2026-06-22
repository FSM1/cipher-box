/**
 * fetchAndDecryptMetadata — typed-failure try-catch (D-13)
 *
 * Tests that:
 *  1. Malformed bytes (JSON.parse fails) → typed Error with CID in message and { cause }
 *  2. Valid JSON but wrong folderKey (decryptFolderMetadata throws) → same typed Error
 *  3. Happy path → returns decrypted metadata unchanged
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// We mock the heavy dependencies so we can test the error-wrapping logic in isolation.
vi.mock('@cipherbox/core', () => ({
  decryptFolderMetadata: vi.fn(),
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

const mockDecryptFolderMetadata = vi.mocked(core.decryptFolderMetadata);
const mockFetchFromIpfs = vi.mocked(ipfsModule.fetchFromIpfs);

const TEST_CID = 'QmTestCid1234';
const DUMMY_KEY = new Uint8Array(32);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const DUMMY_CTX: any = {};

describe('fetchAndDecryptMetadata (D-13 typed-failure)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws a typed Error containing the CID when bytes fail JSON.parse', async () => {
    // Malformed bytes — not valid JSON
    mockFetchFromIpfs.mockResolvedValue(new TextEncoder().encode('NOT_JSON{{{{'));

    await expect(fetchAndDecryptMetadata(TEST_CID, DUMMY_KEY, DUMMY_CTX)).rejects.toSatisfy(
      (err: unknown) => {
        const e = err as Error;
        return (
          e instanceof Error &&
          e.message.includes(TEST_CID) &&
          e.message.includes('decode or decrypt') &&
          e.cause !== undefined
        );
      }
    );
  });

  it('throws a typed Error containing the CID when decryptFolderMetadata throws', async () => {
    // Valid JSON structure but wrong key — decryptFolderMetadata throws
    const fakeEncrypted = JSON.stringify({ iv: 'aaa', data: 'bbb' });
    mockFetchFromIpfs.mockResolvedValue(new TextEncoder().encode(fakeEncrypted));
    mockDecryptFolderMetadata.mockRejectedValue(new Error('decryption failed'));

    await expect(fetchAndDecryptMetadata(TEST_CID, DUMMY_KEY, DUMMY_CTX)).rejects.toSatisfy(
      (err: unknown) => {
        const e = err as Error;
        return (
          e instanceof Error &&
          e.message.includes(TEST_CID) &&
          e.message.includes('decode or decrypt') &&
          e.cause instanceof Error &&
          (e.cause as Error).message === 'decryption failed'
        );
      }
    );
  });

  it('returns decrypted metadata unchanged on the happy path', async () => {
    const fakeEncrypted = JSON.stringify({ iv: 'iv-bytes', data: 'encrypted-data' });
    mockFetchFromIpfs.mockResolvedValue(new TextEncoder().encode(fakeEncrypted));

    const expectedMetadata = {
      version: 'v2' as const,
      children: [],
    };
    mockDecryptFolderMetadata.mockResolvedValue(expectedMetadata);

    const result = await fetchAndDecryptMetadata(TEST_CID, DUMMY_KEY, DUMMY_CTX);
    expect(result).toBe(expectedMetadata);
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Module mocks (hoisted before imports of the module under test)
// ---------------------------------------------------------------------------

vi.mock('@cipherbox/core', () => ({
  encryptFileMetadata: vi.fn(),
  decryptFileMetadata: vi.fn(),
  createIpnsRecord: vi.fn(),
  marshalIpnsRecord: vi.fn(),
  generateFileIpnsKeypair: vi.fn(),
}));

vi.mock('@cipherbox/crypto', () => ({
  wrapKey: vi.fn(),
  bytesToHex: vi.fn(),
  hexToBytes: vi.fn(),
}));

vi.mock('../ipfs', () => ({
  addToIpfs: vi.fn(),
  fetchFromIpfs: vi.fn(),
}));

vi.mock('../ipns', () => ({
  resolveIpnsRecord: vi.fn(),
  createAndPublishIpnsRecord: vi.fn(),
}));

vi.mock('../errors', () => ({
  ConflictError: class ConflictError extends Error {
    readonly ipnsName: string;
    readonly attempts: number;
    readonly lastRemoteSeq: bigint;
    constructor(ipnsName: string, attempts: number, lastRemoteSeq: bigint) {
      super(
        `IPNS conflict unresolved after ${attempts} attempts for ${ipnsName} (remote seq: ${lastRemoteSeq})`
      );
      this.name = 'ConflictError';
      this.ipnsName = ipnsName;
      this.attempts = attempts;
      this.lastRemoteSeq = lastRemoteSeq;
    }
  },
  is409: (error: unknown): boolean =>
    (error as { status?: number } | null)?.status === 409 ||
    (error as { response?: { status?: number } } | null)?.response?.status === 409,
}));

// ---------------------------------------------------------------------------
// Imports of code under test (after mocks are registered)
// ---------------------------------------------------------------------------

import { mergeVersions, updateFileMetadata } from '../file';
import { resolveIpnsRecord, createAndPublishIpnsRecord } from '../ipns';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import type { SdkContext, IpfsAddResult } from '../types';

// @cipherbox/core functions accessed via vi.mocked after the vi.mock factory above.
// We do NOT import from '@cipherbox/core' directly here because its dist is not
// built in the worktree, causing vite module resolution to fail before the mock
// factory can intercept the request. Instead we access the mocks via dynamic import.
let encryptFileMetadata: ReturnType<typeof vi.fn>;
let decryptFileMetadata: ReturnType<typeof vi.fn>;

// ---------------------------------------------------------------------------
// Local VersionEntry shape (mirrors @cipherbox/core type; avoids dist resolution)
// ---------------------------------------------------------------------------

type VersionEntry = {
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  size: number;
  timestamp: number;
  encryptionMode: 'GCM' | 'CTR';
};

// Local FileMetadata / EncryptedFileMetadata shapes (mirror @cipherbox/core types;
// avoids dist resolution — see note above).
type FileMetadata = {
  version: 'v1';
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  size: number;
  mimeType: string;
  encryptionMode?: 'GCM' | 'CTR';
  createdAt: number;
  modifiedAt: number;
  versions?: VersionEntry[];
};

type EncryptedFileMetadata = {
  iv: string;
  data: string;
};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeVersion = (cid: string, timestamp: number, size = 100): VersionEntry => ({
  cid,
  fileKeyEncrypted: `key-${cid}`,
  fileIv: `iv-${cid}`,
  size,
  timestamp,
  encryptionMode: 'GCM',
});

// ---------------------------------------------------------------------------
// mergeVersions
// ---------------------------------------------------------------------------

describe('mergeVersions', () => {
  it('returns empty arrays for undefined inputs', () => {
    const result = mergeVersions(undefined, undefined, 10);
    expect(result.versions).toEqual([]);
    expect(result.prunedCids).toEqual([]);
  });

  it('returns merged array when one input is undefined', () => {
    const a = [makeVersion('cid-a', 2000), makeVersion('cid-b', 1000)];
    const result = mergeVersions(a, undefined, 10);
    expect(result.versions).toHaveLength(2);
    expect(result.prunedCids).toEqual([]);
  });

  it('deduplicates by cid keeping first occurrence', () => {
    const a = [makeVersion('shared', 2000)];
    const b = [makeVersion('shared', 1500), makeVersion('unique-b', 1000)];
    const result = mergeVersions(a, b, 10);
    const cids = result.versions.map((v) => v.cid);
    expect(cids.filter((c) => c === 'shared')).toHaveLength(1);
    // First occurrence (from `a`) wins — timestamp stays 2000
    expect(result.versions.find((v) => v.cid === 'shared')?.timestamp).toBe(2000);
  });

  it('sorts entries by timestamp descending', () => {
    const a = [makeVersion('old', 1000)];
    const b = [makeVersion('new', 3000), makeVersion('mid', 2000)];
    const result = mergeVersions(a, b, 10);
    expect(result.versions[0].cid).toBe('new');
    expect(result.versions[1].cid).toBe('mid');
    expect(result.versions[2].cid).toBe('old');
  });

  it('caps to maxVersions and returns prunedCids for overflow', () => {
    const versions = Array.from({ length: 12 }, (_, i) => makeVersion(`cid-${i}`, (12 - i) * 1000));
    const result = mergeVersions(versions, undefined, 10);
    expect(result.versions).toHaveLength(10);
    expect(result.prunedCids).toHaveLength(2);
    // The two overflow entries are the oldest (smallest timestamp)
    expect(result.prunedCids).toContain('cid-10');
    expect(result.prunedCids).toContain('cid-11');
  });

  it('prunedCids are the oldest entries beyond the cap', () => {
    const versions = [
      makeVersion('newest', 5000),
      makeVersion('older', 3000),
      makeVersion('oldest', 1000),
    ];
    const result = mergeVersions(versions, undefined, 2);
    expect(result.versions.map((v) => v.cid)).toEqual(['newest', 'older']);
    expect(result.prunedCids).toEqual(['oldest']);
  });
});

// ---------------------------------------------------------------------------
// updateFileMetadata CAS + conflict
// ---------------------------------------------------------------------------

// TODO(phase 65): updateFileMetadata stub throws — revive when phase 65 implements file node seal.
describe.skip('updateFileMetadata CAS + conflict — TODO(phase 65)', () => {
  const mockCtx = { axiosInstance: null } as unknown as SdkContext;
  const mockFolderKey = new Uint8Array(32).fill(1);
  // Reinitialized per test in beforeEach: updateFileMetadata zeroizes
  // fileIpnsPrivateKey in-place, so a shared buffer would be all-zero after test 1.
  let mockPrivateKey: Uint8Array;

  const baseCurrentMetadata = {
    version: 'v1' as const,
    cid: 'current-cid',
    fileKeyEncrypted: 'current-key',
    fileIv: 'current-iv',
    size: 512,
    mimeType: 'text/plain',
    encryptionMode: 'GCM' as const,
    createdAt: 1000,
    modifiedAt: 5000,
    versions: [] as VersionEntry[],
  };

  beforeEach(async () => {
    vi.clearAllMocks();
    mockPrivateKey = new Uint8Array(32).fill(2);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const coreMocks = await vi.importMock<any>('@cipherbox/core');
    // encryptFileMetadata / decryptFileMetadata are retired from @cipherbox/core in phase 62.
    // Access via `any` cast to avoid TS2551; phase 65 will replace with Node-seal mocks.
    encryptFileMetadata = coreMocks.encryptFileMetadata as ReturnType<typeof vi.fn>;
    decryptFileMetadata = coreMocks.decryptFileMetadata as ReturnType<typeof vi.fn>;

    encryptFileMetadata.mockResolvedValue({
      iv: 'test-iv',
      data: 'encrypted-data',
    } satisfies EncryptedFileMetadata);
    vi.mocked(addToIpfs).mockResolvedValue({ cid: 'new-meta-cid' } as unknown as IpfsAddResult);

    vi.mocked(resolveIpnsRecord).mockResolvedValue({
      cid: 'old-meta-cid',
      sequenceNumber: 5n,
      signatureVerified: true,
    });

    vi.mocked(createAndPublishIpnsRecord).mockResolvedValue({ success: true, sequenceNumber: 6n });
  });

  it('passes expectedSequenceNumber equal to resolved seq on happy path', async () => {
    const result = await updateFileMetadata({
      fileIpnsPrivateKey: mockPrivateKey,
      fileMetaIpnsName: 'k51-file-ipns',
      folderKey: mockFolderKey,
      currentMetadata: baseCurrentMetadata,
      updates: { cid: 'new-cid', size: 1024 },
      createVersion: false,
      ctx: mockCtx,
    });

    expect(createAndPublishIpnsRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedSequenceNumber: '5',
        sequenceNumber: 6n,
        ipnsName: 'k51-file-ipns',
        metadataCid: 'new-meta-cid',
      })
    );
    expect(result.ipnsName).toBe('k51-file-ipns');
    expect(result.metadataCid).toBe('new-meta-cid');
    expect(result.newSequenceNumber).toBe(6n);
    expect(result.prunedCids).toEqual([]);
  });

  it('returns prunedCids from version cap on happy path with createVersion=true', async () => {
    const oldVersions = Array.from({ length: 10 }, (_, i) =>
      makeVersion(`old-${i}`, (10 - i) * 100)
    );
    const metaWithVersions = { ...baseCurrentMetadata, versions: oldVersions };

    const result = await updateFileMetadata({
      fileIpnsPrivateKey: mockPrivateKey,
      fileMetaIpnsName: 'k51-file-ipns',
      folderKey: mockFolderKey,
      currentMetadata: metaWithVersions,
      updates: { cid: 'new-cid', size: 1024 },
      createVersion: true,
      ctx: mockCtx,
    });

    // new version entry + 10 old = 11 total; capped at 10; 1 pruned
    expect(result.prunedCids).toHaveLength(1);
  });

  it('preserves local loser cid as VersionEntry when remote is newer on 409', async () => {
    const localModifiedAt = 3000;
    const remoteModifiedAt = 8000; // remote newer → local loses

    const localCurrent = { ...baseCurrentMetadata, cid: 'local-cid', modifiedAt: localModifiedAt };
    const remoteMeta = {
      ...baseCurrentMetadata,
      cid: 'remote-cid',
      fileKeyEncrypted: 'remote-key',
      fileIv: 'remote-iv',
      size: 999,
      modifiedAt: remoteModifiedAt,
      versions: [] as VersionEntry[],
    };

    vi.mocked(resolveIpnsRecord)
      .mockResolvedValueOnce({ cid: 'old-meta', sequenceNumber: 5n, signatureVerified: true })
      .mockResolvedValueOnce({
        cid: 'remote-meta-cid',
        sequenceNumber: 6n,
        signatureVerified: true,
      });

    const conflict409 = Object.assign(new Error('Conflict'), { status: 409 });
    vi.mocked(createAndPublishIpnsRecord)
      .mockRejectedValueOnce(conflict409)
      .mockResolvedValueOnce({ success: true, sequenceNumber: 7n });

    vi.mocked(fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ iv: 'r-iv', data: 'r-data' }))
    );
    decryptFileMetadata.mockResolvedValue(remoteMeta satisfies FileMetadata);

    const result = await updateFileMetadata({
      fileIpnsPrivateKey: mockPrivateKey,
      fileMetaIpnsName: 'k51-file-ipns',
      folderKey: mockFolderKey,
      currentMetadata: localCurrent,
      updates: { cid: 'local-cid', size: localCurrent.size },
      createVersion: false,
      ctx: mockCtx,
    });

    // Remote won — decryptFileMetadata should have been called to fetch remote state
    expect(decryptFileMetadata).toHaveBeenCalled();
    // The retry publish should use remote's seq+1
    const secondPublish = vi.mocked(createAndPublishIpnsRecord).mock.calls[1][0];
    expect(secondPublish.expectedSequenceNumber).toBe('6');
    expect(result.newSequenceNumber).toBe(7n);
  });

  it('preserves local version history when remote wins conflict (loser.versions)', async () => {
    // Regression test: when the remote write wins a 409, the loser is the LOCAL metadata,
    // so its prior version history must survive the merge. A previous bug passed
    // remoteMeta.versions (not loser.versions) as the second mergeVersions arg, silently
    // dropping the local writer's history. maxVersions defaults to 10 → nothing is capped.
    //
    // updateFileMetadata stamps updatedMetadata.modifiedAt = Date.now(), so the only way to
    // force the remote to win latest-wins is a remote modifiedAt beyond now (far-future ts).
    const localVersions: VersionEntry[] = [
      makeVersion('local-v1', 4000),
      makeVersion('local-v2', 2000),
    ];
    const localCurrent = {
      ...baseCurrentMetadata,
      cid: 'local-cid',
      versions: localVersions,
    };
    const remoteMeta = {
      ...baseCurrentMetadata,
      cid: 'remote-cid',
      fileKeyEncrypted: 'remote-key',
      fileIv: 'remote-iv',
      size: 999,
      modifiedAt: 9_999_999_999_999, // far future (~year 2286) > Date.now() → remote wins
      versions: [makeVersion('remote-v1', 6000)] as VersionEntry[],
    };

    vi.mocked(resolveIpnsRecord)
      .mockResolvedValueOnce({ cid: 'old-meta', sequenceNumber: 5n, signatureVerified: true })
      .mockResolvedValueOnce({
        cid: 'remote-meta-cid',
        sequenceNumber: 6n,
        signatureVerified: true,
      });

    const conflict409 = Object.assign(new Error('Conflict'), { status: 409 });
    vi.mocked(createAndPublishIpnsRecord)
      .mockRejectedValueOnce(conflict409)
      .mockResolvedValueOnce({ success: true, sequenceNumber: 7n });

    vi.mocked(fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ iv: 'r-iv', data: 'r-data' }))
    );
    decryptFileMetadata.mockResolvedValue(remoteMeta satisfies FileMetadata);

    await updateFileMetadata({
      fileIpnsPrivateKey: mockPrivateKey,
      fileMetaIpnsName: 'k51-file-ipns',
      folderKey: mockFolderKey,
      currentMetadata: localCurrent,
      updates: { cid: 'local-cid', size: localCurrent.size },
      createVersion: false,
      ctx: mockCtx,
    });

    // The retry (merged) payload must retain the local writer's prior version history…
    const retryPayload = encryptFileMetadata.mock.calls[1][0];
    const retryVersionCids: string[] = (retryPayload.versions ?? []).map(
      (v: VersionEntry) => v.cid
    );
    expect(retryVersionCids).toContain('local-v1');
    expect(retryVersionCids).toContain('local-v2');
    // …plus the local current content promoted to a version (loser-becomes-version)…
    expect(retryVersionCids).toContain('local-cid');
    // …and the winning remote's own history.
    expect(retryVersionCids).toContain('remote-v1');
  });

  it('keeps local content as winner and preserves remote content as version when local is newer', async () => {
    const localModifiedAt = 9000; // local newer → local wins
    const remoteModifiedAt = 3000;

    const localCurrent = { ...baseCurrentMetadata, cid: 'local-cid', modifiedAt: localModifiedAt };
    const remoteMeta = {
      ...baseCurrentMetadata,
      cid: 'remote-cid',
      fileKeyEncrypted: 'remote-key',
      fileIv: 'remote-iv',
      size: 222,
      modifiedAt: remoteModifiedAt,
      versions: [] as VersionEntry[],
    };

    vi.mocked(resolveIpnsRecord)
      .mockResolvedValueOnce({ cid: 'old-meta', sequenceNumber: 5n, signatureVerified: true })
      .mockResolvedValueOnce({
        cid: 'remote-meta-cid',
        sequenceNumber: 6n,
        signatureVerified: true,
      });

    const conflict409 = Object.assign(new Error('Conflict'), { status: 409 });
    vi.mocked(createAndPublishIpnsRecord)
      .mockRejectedValueOnce(conflict409)
      .mockResolvedValueOnce({ success: true, sequenceNumber: 7n });

    vi.mocked(fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ iv: 'r-iv', data: 'r-data' }))
    );
    decryptFileMetadata.mockResolvedValue(remoteMeta satisfies FileMetadata);

    const result = await updateFileMetadata({
      fileIpnsPrivateKey: mockPrivateKey,
      fileMetaIpnsName: 'k51-file-ipns',
      folderKey: mockFolderKey,
      currentMetadata: localCurrent,
      updates: { cid: 'local-cid', size: localCurrent.size },
      createVersion: false,
      ctx: mockCtx,
    });

    // Local won → second publish should still happen
    const secondPublish = vi.mocked(createAndPublishIpnsRecord).mock.calls[1][0];
    expect(secondPublish.sequenceNumber).toBe(7n);
    expect(secondPublish.expectedSequenceNumber).toBe('6');
    expect(result.newSequenceNumber).toBe(7n);
  });

  it('WR-08: prunedCids does not contain CIDs referenced by the published mergedMetadata (CR-02 filter)', async () => {
    // CR-02 scenario: a CID pruned by the pre-conflict positional slice is resurrected
    // into mergedMetadata.versions[] by the remote's data. Without the fix it ends up in
    // prunedCids and gets unconditionally unpinned, destroying a live version.
    //
    // maxVersionsPerFile = 2
    // localCurrent.versions = [v-old(100), v-NEW(9000)]  (unsorted — old first, NEW at position 1)
    // createVersion=true → allVersions = [pre-update-cid(~Date.now()), v-old(100), v-NEW(9000)]
    //   positional slice(0,2): versions = [pre-update-cid, v-old]
    //   positional slice(2):   prunedCids = ['v-NEW']       ← CR-02 victim (high ts, wrong position)
    //
    // Local always wins: updatedMetadata.modifiedAt = Date.now() >> remoteModifiedAt=1
    // remote.versions = [v-NEW(9000)]    ← remote retained v-NEW
    // loserAsVersion.cid = 'remote-cid', ts = 1
    //
    // mergeVersions a=[pre-update-cid(now), v-old(100), remote-cid(1)]
    //              b=[v-NEW(9000)]    cap=2
    // combined deduped sorted: [pre-update-cid(now), v-NEW(9000), v-old(100), remote-cid(1)]
    // capped at 2: mergedVersions = [pre-update-cid, v-NEW]    ← v-NEW resurrected!
    // extraPruned = ['v-old', 'remote-cid']
    //
    // BEFORE fix: prunedCids = ['v-NEW','v-old','remote-cid']
    //   publishedRefs = {merged-upload-cid, pre-update-cid, v-NEW}
    //   overlap = ['v-NEW']  ← destructive unpin of a live version
    //
    // AFTER fix: reference filter removes 'v-NEW' → prunedCids = ['v-old','remote-cid']
    //   v-old is genuinely overflowed and not referenced → stays in prunedCids (assertion c)

    const existingVersions: VersionEntry[] = [
      makeVersion('v-old', 100), // older, at position 0
      makeVersion('v-NEW', 9000), // high timestamp but at position 1 — pruned by positional slice
    ];
    const localCurrent = {
      ...baseCurrentMetadata,
      cid: 'pre-update-cid',
      versions: existingVersions,
    };

    // Remote retains v-NEW — mergeVersions will resurrect it into mergedVersions
    const remoteMeta = {
      ...baseCurrentMetadata,
      cid: 'remote-cid',
      fileKeyEncrypted: 'remote-key',
      fileIv: 'remote-iv',
      size: 400,
      modifiedAt: 1, // very old; local always wins
      versions: [makeVersion('v-NEW', 9000)] as VersionEntry[],
    };

    vi.mocked(resolveIpnsRecord)
      .mockResolvedValueOnce({ cid: 'old-meta', sequenceNumber: 5n, signatureVerified: true })
      .mockResolvedValueOnce({
        cid: 'remote-meta-cid',
        sequenceNumber: 6n,
        signatureVerified: true,
      });

    const conflict409 = Object.assign(new Error('Conflict'), { status: 409 });
    vi.mocked(createAndPublishIpnsRecord)
      .mockRejectedValueOnce(conflict409)
      .mockResolvedValueOnce({ success: true, sequenceNumber: 7n });

    vi.mocked(fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ iv: 'r-iv', data: 'r-data' }))
    );
    decryptFileMetadata.mockResolvedValue(remoteMeta satisfies FileMetadata);

    vi.mocked(addToIpfs)
      .mockResolvedValueOnce({ cid: 'initial-upload-cid' } as unknown as IpfsAddResult)
      .mockResolvedValueOnce({ cid: 'merged-upload-cid' } as unknown as IpfsAddResult);

    const result = await updateFileMetadata({
      fileIpnsPrivateKey: mockPrivateKey,
      fileMetaIpnsName: 'k51-file-ipns',
      folderKey: mockFolderKey,
      currentMetadata: localCurrent,
      updates: { cid: 'local-new-cid', size: 800 },
      createVersion: true,
      maxVersionsPerFile: 2,
      ctx: mockCtx,
    });

    // (a) Retry encryptFileMetadata payload (calls[1][0]) must show v-NEW resurrected in versions[].
    //     Local wins → loser=remoteMeta → loserAsVersion.cid='remote-cid' (ts=1, pruned by cap).
    //     v-NEW (ts=9000) from remote.versions survives in mergedVersions via input b.
    const retryPayload = encryptFileMetadata.mock.calls[1][0];
    const retryVersionCids: string[] = (retryPayload.versions ?? []).map(
      (v: VersionEntry) => v.cid
    );
    expect(retryVersionCids).toContain('v-NEW');

    // (b) CR-02 core assertion: prunedCids ∩ published references must be empty.
    //     Before fix: 'v-NEW' is in both prunedCids (initial prune) and mergedVersions → overlap=['v-NEW']
    //     After fix: 'v-NEW' is filtered out → overlap=[]
    const publishedRefs = new Set([
      result.metadataCid,
      ...(retryPayload.versions ?? []).map((v: VersionEntry) => v.cid),
    ]);
    const overlap = result.prunedCids.filter((c) => publishedRefs.has(c));
    expect(overlap).toHaveLength(0);

    // (c) 'v-old' is genuinely overflowed (not in mergedVersions) — must still be pruned.
    //     This ensures the reference filter is not over-broad.
    expect(result.prunedCids).toContain('v-old');
  });

  it('throws ConflictError after exhausting all four consecutive 409 attempts', async () => {
    // File path was reconciled UP to 4 attempts + backoff (plan 47-01 locked decision 1),
    // unifying it with the folder path. Provide enough authoritative re-resolves to cover
    // the initial base resolve plus one re-resolve per 409 attempt.
    vi.mocked(resolveIpnsRecord).mockResolvedValue({
      cid: 'remote-meta',
      sequenceNumber: 6n,
      signatureVerified: true,
    });

    const remoteMeta = {
      ...baseCurrentMetadata,
      cid: 'remote-cid',
      modifiedAt: 9000,
      versions: [] as VersionEntry[],
    };
    vi.mocked(fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ iv: 'r-iv', data: 'r-data' }))
    );
    decryptFileMetadata.mockResolvedValue(remoteMeta satisfies FileMetadata);

    const conflict409 = Object.assign(new Error('Conflict'), { status: 409 });
    vi.mocked(createAndPublishIpnsRecord).mockRejectedValue(conflict409);

    await expect(
      updateFileMetadata({
        fileIpnsPrivateKey: mockPrivateKey,
        fileMetaIpnsName: 'k51-file-ipns',
        folderKey: mockFolderKey,
        currentMetadata: baseCurrentMetadata,
        updates: {},
        createVersion: false,
        ctx: mockCtx,
      })
    ).rejects.toMatchObject({ name: 'ConflictError', attempts: 4 });
  });

  it('propagates non-409 errors without wrapping in ConflictError', async () => {
    const networkError = new Error('Network timeout');
    vi.mocked(createAndPublishIpnsRecord).mockRejectedValue(networkError);

    await expect(
      updateFileMetadata({
        fileIpnsPrivateKey: mockPrivateKey,
        fileMetaIpnsName: 'k51-file-ipns',
        folderKey: mockFolderKey,
        currentMetadata: baseCurrentMetadata,
        updates: {},
        createVersion: false,
        ctx: mockCtx,
      })
    ).rejects.toThrow('Network timeout');
  });

  it('respects maxVersionsPerFile parameter in version cap', async () => {
    const oldVersions = Array.from({ length: 5 }, (_, i) => makeVersion(`old-${i}`, (5 - i) * 100));
    const metaWithVersions = { ...baseCurrentMetadata, versions: oldVersions };

    const result = await updateFileMetadata({
      fileIpnsPrivateKey: mockPrivateKey,
      fileMetaIpnsName: 'k51-file-ipns',
      folderKey: mockFolderKey,
      currentMetadata: metaWithVersions,
      updates: { cid: 'new-cid', size: 1024 },
      createVersion: true,
      maxVersionsPerFile: 3,
      ctx: mockCtx,
    });

    // new version + 5 old = 6 total; capped at 3; 3 pruned
    expect(result.prunedCids).toHaveLength(3);
  });
});

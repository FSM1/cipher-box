/**
 * File Metadata Service tests — pure `mergeVersions` utility.
 *
 * RETIRED (79-03): the `describe.skip('updateFileMetadata CAS + conflict...')` suite
 * previously quarantined here (68.1-07) mocked the retired `@cipherbox/core` exports
 * `encryptFileMetadata`/`decryptFileMetadata` and asserted a CAS-retry/conflict-merge
 * loop that the CURRENT `updateFileMetadata` (packages/sdk-core/src/file/index.ts:433)
 * does not have — it republishes directly, single-shot (no `expectedSequenceNumber`
 * CAS, no 409 retry, no remote-merge), matching packages/sdk/src/share/shared-write.ts's
 * `updateSharedFile`. Un-skipping verbatim would neither compile (retired exports, old
 * `currentMetadata`/`updates` shape) nor test real behavior.
 *
 * This is NOT a coverage gap: packages/sdk-core/src/__tests__/file/file-node.test.ts's
 * `describe('updateFileMetadata', ...)` (Phase 68.1-07) already exercises the CURRENT
 * single-shot contract end-to-end against the real @cipherbox/core codec (sealNode/
 * unsealNode run for real; only I/O is mocked) — sequenceNumber threading
 * (fileSequenceNumber+1n), nodeId/generation/originalCreatedAt preservation (verified
 * via a full seal to publish to unseal round-trip), and version-capping via capVersions
 * (createVersion:true/false, maxVersionsPerFile). The write-side rollback-guard
 * coverage flagged by T-79-03 (expectedSequenceNumber/CAS-style assertions) is already
 * satisfied there — nothing is lost by this retirement; see 79-03-SUMMARY.md.
 *
 * If CAS-retry/conflict-merge for file updates is ever reintroduced, a fresh suite
 * should be written against that future contract; the legacy assertions previously
 * quarantined here are not a useful starting point (retired exports, incompatible
 * currentMetadata/updates shape).
 */
import { describe, it, expect } from 'vitest';

import { mergeVersions } from '../file';

// ---------------------------------------------------------------------------
// Local FileVersionEntry-shaped fixture (mirrors @cipherbox/sdk-core's
// FileVersionEntry — mergeVersions's own pure-utility signature).
// ---------------------------------------------------------------------------

type VersionEntry = {
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  size: number;
  timestamp: number;
  encryptionMode: 'GCM' | 'CTR';
};

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

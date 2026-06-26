---
phase: 44-ipns-conflict-handling
plan: "03"
subsystem: sdk-core
tags:
  - conflict-handling
  - cas-publish
  - lost-update-fix
  - file-metadata
  - tdd
dependency_graph:
  requires:
    - ConflictError class (44-01)
  provides:
    - mergeVersions helper
    - updateFileMetadata CAS publish with 409 conflict merge
    - maxVersionsPerFile param
  affects:
    - packages/sdk-core (file module)
    - Plan 44-04 callers (useFileOperations.ts, shared-write.ts) must consume new return shape
tech_stack:
  added: []
  patterns:
    - TDD RED/GREEN with vitest
    - CAS publish pattern (expectedSequenceNumber) mirroring folder/index.ts
    - Latest-wins conflict merge (modifiedAt)
    - Loser-becomes-version (VersionEntry preservation)
    - Key zeroization in finally block
key_files:
  created:
    - packages/sdk-core/src/__tests__/file.test.ts
  modified:
    - packages/sdk-core/src/file/index.ts
decisions:
  - "Built @cipherbox/core and @cipherbox/crypto dist artifacts to enable vi.mock with factory (worktree lacked built packages)"
  - "Defined VersionEntry shape inline in test file instead of importing from @cipherbox/core to avoid direct import resolution issues"
  - "Used vi.importMock in beforeEach to access @cipherbox/core mock functions without a static import"
  - "Extracted encryptAndUpload helper to avoid code duplication between initial upload and conflict-merge re-upload"
metrics:
  duration: "8m 51s"
  completed: "2026-06-13"
  tasks_completed: 2
  files_created: 1
  files_modified: 1
---

# Phase 44 Plan 03: File CAS Publish and Conflict Merge Summary

File metadata TOCTOU window closed via CAS publish; on 409 the losing write's content is preserved as a recoverable VersionEntry with latest-wins merge semantics.

## What Was Built

### Task 1: mergeVersions helper + maxVersionsPerFile param

`packages/sdk-core/src/file/index.ts` gains:

- Exported `function mergeVersions(a, b, maxVersions)` implementing RESEARCH Pattern 5:
  - `combined = [...(a ?? []), ...(b ?? [])]`
  - Dedupe by `cid` via `Set<string>` filter (first occurrence wins)
  - Sort by `timestamp` DESC (newest first)
  - `versions = combined.slice(0, maxVersions)`, `prunedCids = combined.slice(maxVersions).map(v => v.cid)`
  - Both inputs accept `undefined` (returns `{ versions: [], prunedCids: [] }`)
- Optional `maxVersionsPerFile?: number` param added to `updateFileMetadata`
- Both existing version-cap paths (createVersion path and conflict merge path) now use `const maxVersions = params.maxVersionsPerFile ?? MAX_VERSIONS_PER_FILE` instead of the bare constant

### Task 2: File CAS publish + latest-wins conflict path

`packages/sdk-core/src/file/index.ts` contract change to `updateFileMetadata`:

**Old return shape:** `{ ipnsRecord: FileIpnsRecordPayload; prunedCids: string[] }` (caller responsible for publish)

**New return shape:** `{ ipnsName: string; metadataCid: string; newSequenceNumber: bigint; prunedCids: string[] }` (publish happens internally)

**Plan 04 must update these 2 callers:**

- `apps/web/src/hooks/useFileOperations.ts` around line 416: currently receives `ipnsRecord` and calls `batchPublishIpnsRecords` with it. Must instead consume `{ ipnsName, metadataCid, newSequenceNumber, prunedCids }` directly (publish already done).
- `packages/sdk/src/share/shared-write.ts` around line 450: same pattern; receives returned `ipnsRecord` for batch publish. Must instead consume the new shape.

**Publish flow (D-06):**

1. Resolve seq via `resolveIpnsRecord` (throws if null)
2. Build `updatedMetadata` (with version history using `maxVersions`)
3. Encrypt + upload to IPFS via `encryptAndUpload` helper
4. `createAndPublishIpnsRecord({ ..., expectedSequenceNumber: currentSeq.toString() })` — CAS closes TOCTOU
5. On success: return `{ ipnsName, metadataCid, newSequenceNumber, prunedCids }`

**Conflict path on 409 (D-07):**

1. Re-resolve authoritatively — `currentSeq = reResolved.sequenceNumber`
2. Fetch + decrypt remote `FileMetadata` via `fetchFromIpfs` + `decryptFileMetadata`
3. Latest-wins: `localWins = (localModifiedAt >= remoteModifiedAt)` (`>=` prefers local on tie)
4. `loserAsVersion: VersionEntry = { cid, fileKeyEncrypted, fileIv, size, timestamp: loser.modifiedAt, encryptionMode }`
5. `mergeVersions([...(winner.versions ?? []), loserAsVersion], remoteMeta.versions, maxVersions)` — accumulate `prunedCids`
6. Build `mergedMetadata` = winner content pointer + merged versions
7. Re-encrypt + re-upload merged metadata via `encryptAndUpload`
8. Retry publish with `currentSeq + 1n` / `expectedSequenceNumber: currentSeq.toString()`
9. On second 409: `throw new ConflictError(params.fileMetaIpnsName, 2, currentSeq)` (D-07 bounded retry)
10. Non-409 errors propagate unchanged at both attempts

**Key zeroization:** `params.fileIpnsPrivateKey.fill(0)` in `finally` block (T-44-12 / PATTERNS shared pattern).

### Tests

`packages/sdk-core/src/__tests__/file.test.ts` (new, 13 tests):

**describe('mergeVersions')** — 6 tests:

- `returns empty arrays for undefined inputs`
- `returns merged array when one input is undefined`
- `deduplicates by cid keeping first occurrence`
- `sorts entries by timestamp descending`
- `caps to maxVersions and returns prunedCids for overflow`
- `prunedCids are the oldest entries beyond the cap`

**describe('updateFileMetadata CAS + conflict')** — 7 tests:

- `passes expectedSequenceNumber equal to resolved seq on happy path`
- `returns prunedCids from version cap on happy path with createVersion=true`
- `preserves local loser cid as VersionEntry when remote is newer on 409`
- `keeps local content as winner and preserves remote content as version when local is newer`
- `throws ConflictError after second consecutive 409`
- `propagates non-409 errors without wrapping in ConflictError`
- `respects maxVersionsPerFile parameter in version cap`

## TDD Gate Compliance

RED gate commit: `ee81e0df9` — `test(44-03): add failing tests for mergeVersions and updateFileMetadata CAS conflict path`

GREEN gate commit: `181ae3e4b` — `feat(44-03): implement mergeVersions helper and updateFileMetadata CAS with conflict merge`

Both gates present in order. 13/13 tests pass.

## Deviations from Plan

### Build Artifact Bootstrapping

The worktree was missing built dist artifacts for `@cipherbox/core` and `@cipherbox/crypto`. These are required for vite to resolve the modules at test collection time, even when `vi.mock` with a factory is provided.

- **Found during:** RED gate setup
- **Fix:** Ran `pnpm --filter @cipherbox/core build` and `pnpm --filter @cipherbox/crypto build` to produce dist artifacts. These are build outputs (not source files) and are gitignored.
- **Impact:** Required 2 extra build steps before tests could run; no source changes.

### Test File Module Import Strategy

`file.test.ts` does not import `encryptFileMetadata`/`decryptFileMetadata` from `@cipherbox/core` as static imports because vite's import analysis resolves the module entry before the `vi.mock` factory can intercept it (even with `vi.mock` hoisting). Instead:

- Mocked via `vi.mock('@cipherbox/core', () => ({ ... }))` factory
- Accessed via `vi.importMock<...>('@cipherbox/core')` in `beforeEach` after `vi.clearAllMocks()`
- `VersionEntry` shape defined inline in test file (mirrors `@cipherbox/core` type)

This is a test-file-only adaptation; the production code imports normally.

### encryptAndUpload Private Helper Added

Extracted a private `encryptAndUpload(metadata, folderKey, ctx)` helper to avoid duplicating the encrypt-JSON-upload pipeline between the initial upload and the conflict-merge re-upload. Does not affect the public API surface.

## Threat Surface Scan

Threat mitigations from plan applied:

| Threat | Status |
| --- | --- |
| T-44-09: updateFileMetadata TOCTOU | Mitigated via `expectedSequenceNumber` CAS; 409 loser preserved as VersionEntry, tested both directions |
| T-44-10: versions[] unbounded growth | Mitigated via `maxVersionsPerFile` param (default 10) capping all paths; overflow to `prunedCids` |
| T-44-12: merged metadata re-encrypted | Mitigated via `encryptAndUpload` always using `params.folderKey`; never plaintext to IPFS |
| T-44-13: file conflict livelock | Mitigated via bounded 2 total attempts; `ConflictError` thrown on second 409 |

No new network endpoints, auth paths, or schema changes introduced beyond what the plan specifies.

## Self-Check: PASSED

- `packages/sdk-core/src/file/index.ts` modified, exists on disk
- `packages/sdk-core/src/__tests__/file.test.ts` created, exists on disk
- RED commit `ee81e0df9` verified in git log
- GREEN commit `181ae3e4b` verified in git log
- `pnpm --filter @cipherbox/sdk-core test src/__tests__/file.test.ts` exits 0 (13/13 pass)
- `pnpm --filter @cipherbox/sdk-core exec tsc --noEmit -p tsconfig.json` clean (no errors in file/index.ts)

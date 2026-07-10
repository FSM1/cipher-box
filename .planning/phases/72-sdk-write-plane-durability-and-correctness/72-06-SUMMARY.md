---
phase: 72-sdk-write-plane-durability-and-correctness
plan: 06
subsystem: sdk
tags: [ipns, listing-cache, zeroize, node-v3, sdk-unit]

# Dependency graph
requires:
  - phase: 68.2-sdk-owned-read-chain-and-resolved-folder-listings
    provides: "listingCache (client.ts) and the shipped updateSharedFile 68.2-02 Rule-1-fix invalidation one-liner this plan mirrors"
provides:
  - "listingCache invalidation on a real file-only publish (SC#4), gated on an actual size/cid change"
  - "updateSharedSingleFile zeroes both file keys even when the second unwrapKey throws"
affects: [72-07, 72-08, 72-09, 72-10, apps/web file-replace/version-restore UI (SC#4 manual check in 72-VALIDATION.md)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "listingCache invalidation on any file-only publish: this.listingCache.delete(folderIpnsName), gated on a caller-computed `fileContentChanged` boolean rather than re-derived inside the shared seam"
    - "D-09 zeroize idiom: null-init the derived key locals BEFORE the try, move every unwrap/derive call INSIDE the try, so a throw on a LATER derive still reaches the existing finally cleanup for an EARLIER-derived key"

key-files:
  created:
    - packages/sdk/src/__tests__/maybe-republish-listing-cache.test.ts
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/__tests__/update-shared-single-file.test.ts

key-decisions:
  - "SC#4 reframed per 72-RESEARCH.md Critical Finding 1: the SealedChildRef.size/modifiedAt mirror the original todo described was reverted in 68.2-12 and was NOT reintroduced. The fix is `this.listingCache.delete(folderIpnsName)` in maybeRepublishFolderForFileMigration, mirroring the shipped updateSharedFile 68.2-02 one-liner."
  - "The 'did size/mtime actually change' gate is a caller-computed boolean (`fileContentChanged`), not re-derived inside maybeRepublishFolderForFileMigration -- each of replaceFile/restoreFileVersion/deleteFileVersion already holds both the prior NodeContent (currentMetadata) and the new UpdateFileContentParams (updates), so the comparison (`updates.size !== currentMetadata.size || updates.cid !== currentMetadata.cid`) is computed once per call site and threaded through as a new positional param."
  - "deleteFileVersion's `updates` carries the SAME live content descriptor as `currentMetadata` per its own docstring (only a past version entry is pruned) -- fileContentChanged normally evaluates false there, so a version-history-only delete does not needlessly bust the cache, matching the plan's locked gating intent."
  - "The cache-invalidation call runs unconditionally on BOTH the migration branch and the no-op branch of maybeRepublishFolderForFileMigration (placed once, after the migration `if`, before the final resolveListingChildren+emit), per the plan's explicit instruction."

patterns-established:
  - "maybeRepublishFolderForFileMigration's signature grew a required `fileContentChanged: boolean` positional param (inserted before the existing optional `migratedIpnsPrivateKeyEncrypted?`) -- all three call sites updated in the same change."

requirements-completed: [SC#4]

coverage:
  - id: D1
    description: "A real file-only publish (size or cid actually changed) invalidates the parent's listingCache entry, so the next folder:updated emission re-resolves the just-edited file and carries its fresh size"
    requirement: "SC#4"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/maybe-republish-listing-cache.test.ts#busts the parent listingCache and emits the fresh size when the file content actually changed"
        status: pass
    human_judgment: false
  - id: D2
    description: "A no-op edit (fileContentChanged=false) preserves the listingCache entry -- no re-resolve, emitted children still reflect the cached (pre-call) values"
    requirement: "SC#4"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/maybe-republish-listing-cache.test.ts#preserves the listingCache (no re-resolve) when the file content did not change"
        status: pass
    human_judgment: false
  - id: D3
    description: "No size/modifiedAt fields were added to SealedChildRef (NODE-03 frozen field set preserved)"
    requirement: "SC#4"
    verification:
      - kind: unit
        ref: "grep -nE 'size\\??:|modifiedAt\\??:' packages/core/src/node/types.ts -- confirmed the only matches are VersionEntry.size/NodeContent.size/Node.modifiedAt, none on SealedChildRef"
        status: pass
    human_judgment: false
  - id: D4
    description: "updateSharedSingleFile zeroes fileReadKey even when the SECOND unwrapKey (fileWriteKey) call throws"
    requirement: "todo (zeroize, 2026-07-10)"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/update-shared-single-file.test.ts#zeroes the first unwrapped key when the SECOND unwrapKey call throws (72-06 zeroize fix)"
        status: pass
    human_judgment: false
  - id: D5
    description: "The happy path and all 4 pre-existing it-blocks in update-shared-single-file.test.ts are unaffected by moving the unwrap calls inside the try"
    requirement: "todo (zeroize, 2026-07-10)"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/update-shared-single-file.test.ts -- 6/6 passed"
        status: pass
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test -- 389 passed, 36 skipped, 0 failed"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-07-10
status: complete
---

# Phase 72 Plan 06: listingCache invalidation (SC#4) + updateSharedSingleFile zeroize fix Summary

**A file-only publish now busts the parent's listingCache when the file's size/cid actually changed (mirroring the shipped updateSharedFile 68.2-02 fix, no SealedChildRef schema change), and updateSharedSingleFile zeroes both unwrapped keys even when the second unwrap throws.**

## Performance

- **Duration:** ~20 min
- **Tasks:** 2 completed
- **Files modified:** 2 source-adjacent test files (1 new), 1 source file

## Accomplishments

- Closed the reframed SC#4 gap (72-RESEARCH.md Critical Finding 1): `replaceFile`/`restoreFileVersion`/`deleteFileVersion` publish only the file's own IPNS record — the parent folder's sequence number never bumps, so `listingCache` (keyed on `(ipnsName, sequenceNumber)`) survived the edit and the next `folder:updated` emission served the PRE-edit size/modifiedAt. `maybeRepublishFolderForFileMigration` now calls `this.listingCache.delete(folderIpnsName)` before its existing `resolveListingChildren` + emit, gated on a new `fileContentChanged: boolean` param.
- The gate is computed once per caller (`replaceFile`/`restoreFileVersion`/`deleteFileVersion`) by comparing `updates.size`/`updates.cid` against `currentMetadata.size`/`currentMetadata.cid` — each caller already holds both descriptors, so the seam itself never re-derives the comparison. `deleteFileVersion`'s live content descriptor is unchanged by design (only a past version is pruned), so it normally evaluates `false` there — a version-history-only delete does not needlessly invalidate an otherwise-valid cache.
- Verified no fields were added to `SealedChildRef` — its field set stays frozen to `{name, ipnsName, generation, versionFloor, readKeySealed}` (NODE-03).
- Closed the 2026-07-10 zeroize todo: `updateSharedSingleFile` previously unwrapped `fileReadKey` and `fileWriteKey` with two `unwrapKey` calls BEFORE the `try` that owns the `finally { fileReadKey?.fill(0); fileWriteKey?.fill(0); ... }` cleanup — a throw on the second call left the already-unwrapped first key un-zeroed until GC. Both calls now live inside the `try` (locals null-initialized before it), so any failure path reaches the existing cleanup.
- Full `pnpm --filter @cipherbox/sdk test`: 389 passed, 36 skipped, 0 failed (51 test files).

## Task Commits

Each task was committed atomically, RED before GREEN per the plan's TDD requirement:

1. **Task 1: Invalidate listingCache on a file-only publish (SC#4), gated on a real change**
   - `ba596826c` — `test(72-06): add failing listingCache invalidation test for SC#4` (RED)
   - `2fa71e12b` — `feat(72-06): invalidate listingCache on real file-only publish SC#4` (GREEN)
2. **Task 2: Zero file keys when a later unwrap throws in updateSharedSingleFile**
   - `7c9d0a2c3` — `test(72-06): add failing zeroize-on-second-unwrap-throw test` (RED)
   - `27683110e` — `feat(72-06): zero file keys when the second unwrap throws` (GREEN)

_TDD Gate Compliance: RED confirmed before each GREEN commit. Task 1's RED failed via a thrown `TypeError` (calling the pre-fix 3-positional-arg signature with a `true` boolean as the third argument was misinterpreted as a truthy `migratedIpnsPrivateKeyEncrypted`, entering the unrelated migration branch and hitting the mocked `updateFolderMetadataAndPublish`'s default `undefined` return) — a valid RED failure (the pre-fix code has no `fileContentChanged` param to receive the intended signal). Task 2's RED failed cleanly on the buffer-not-zeroed assertion (`expect(trackedFirstKey).toEqual(new Uint8Array(32))`), since the pre-fix unwrap calls happen before the `try` and the throw never reaches `finally`._

## Files Created/Modified

- `packages/sdk/src/__tests__/maybe-republish-listing-cache.test.ts` (new) — 2 unit tests driving the private `maybeRepublishFolderForFileMigration` seam directly (real `@cipherbox/core` seal/unseal fixtures; only `resolveIpnsRecord`/`fetchFromIpfs`/`updateFolderMetadataAndPublish` mocked), proving cache-bust-on-real-change and cache-preserved-on-no-change
- `packages/sdk/src/client.ts` — `maybeRepublishFolderForFileMigration` gained the `fileContentChanged` param + gated `listingCache.delete` call; `replaceFile`/`restoreFileVersion`/`deleteFileVersion` each compute and thread `fileContentChanged`; `updateSharedSingleFile`'s two `unwrapKey` calls moved inside its `try` block (null-init before)
- `packages/sdk/src/__tests__/update-shared-single-file.test.ts` — added 1 new `it` block covering the second-unwrap-throws zeroization proof

## Decisions Made

- Chose `size !== size || cid !== cid` as the "did content actually change" comparison (not `modifiedAt`, which is computed internally by `sdk-core`'s `updateFileMetadata` as `Date.now()` and is never caller-visible ahead of the publish) — this is the only comparison the caller can genuinely make before the seam runs, consistent with the plan's instruction to pass "whatever change-signal the callers already compute rather than re-deriving inside this seam."
- Drove Task 1's regression tests against the private `maybeRepublishFolderForFileMigration` seam directly (per the plan's "driving replaceFile (or the seam directly)" option) rather than through the full `replaceFile`/`resolveFileWriteChainKeys` write-chain crypto path — isolates the cache-invalidation behavior under test from `replaceFile`'s much larger write-chain key-recovery surface (already covered by `client-file-ops.test.ts`, currently quarantined, and by 72-01 through 72-05's own write-chain suites).

## Deviations from Plan

None — plan executed exactly as written. Both tasks matched their `<action>`/`<acceptance_criteria>` blocks; `grep -c 'listingCache.delete' packages/sdk/src/client.ts` increased by exactly 1 (1 → 2), and no `size`/`modifiedAt` fields were added to `SealedChildRef` in `packages/core/src/node/types.ts`.

## Issues Encountered

None.

## User Setup Required

None.

## Next Phase Readiness

- SC#4 fully delivered at the unit level: a real in-place file edit now busts the parent's `listingCache` so the next listing emit carries fresh size/modifiedAt; a genuine no-op edit does not.
- The zeroize todo is fully closed: `updateSharedSingleFile` zeroes both derived file keys on every exit path, including a throw on the second unwrap.
- Per 72-PLAN.md's `<verification>` section, SC#4 also has a manual web check documented in `72-VALIDATION.md` (upload a file, replace with larger content, confirm the list row size/date updates without a manual refresh) — not exercised in this SDK-only session; recommend running it alongside the phase-level verification gate.

---
*Phase: 72-sdk-write-plane-durability-and-correctness*
*Completed: 2026-07-10*

## Self-Check: PASSED

- FOUND: packages/sdk/src/client.ts
- FOUND: packages/sdk/src/__tests__/maybe-republish-listing-cache.test.ts
- FOUND: packages/sdk/src/__tests__/update-shared-single-file.test.ts
- FOUND commit: ba596826c (RED, Task 1)
- FOUND commit: 2fa71e12b (GREEN, Task 1)
- FOUND commit: 7c9d0a2c3 (RED, Task 2)
- FOUND commit: 27683110e (GREEN, Task 2)

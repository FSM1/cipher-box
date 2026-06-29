---
phase: 65-sdk-write-chain-bin-re-link-and-invite-claim
plan: "02"
subsystem: sdk-bin
tags: [bin, restore, re-link, sealChildReadKey, tdd]
dependency_graph:
  requires: []
  provides: [addToBin-impl, restoreFromBin-impl, BinEntry.nodeReadKey]
  affects: [packages/sdk/src/bin/index.ts, packages/core/src/bin/types.ts]
tech_stack:
  added: []
  patterns: [sealChildReadKey-role-0x02, unsealChildReadKey, pure-re-link-restore]
key_files:
  created: []
  modified:
    - packages/core/src/bin/types.ts
    - packages/sdk/src/bin/index.ts
    - packages/sdk/src/__tests__/bin.test.ts
decisions:
  - "Restore is a pure re-link: sealChildReadKey(entry.nodeReadKey, destParentReadKey) with no content re-encryption"
  - "addToBin resolves child IPNS to extract plaintext PublishedNode id/kind for unsealChildReadKey AAD (mirrors moveItem pattern)"
  - "nodeRef.id must be a valid UUID in test fixtures because uuidToBytes validates format"
  - "Use sealSpy.mockRestore() not vi.restoreAllMocks() to avoid resetting module-level vi.fn() mocks across tests"
metrics:
  duration: "~45 minutes"
  completed: "2026-06-30"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 3
status: complete
---

# Phase 65 Plan 02: Bin Re-Link Summary

Implemented recycle-bin restore as a pure key re-link via `sealChildReadKey` (role 0x02) with no content re-encryption. Both `addToBin` and `restoreFromBin` in `packages/sdk/src/bin/index.ts` are now fully implemented. All 20 bin tests pass (10 existing + 10 new).

## Tasks

### Task 1 — RED: Failing bin re-link spec (commit `7b524fcf9`)

Added `nodeReadKey?: Uint8Array` and `nodeIpnsName?: string` to `BinEntry` in `packages/core/src/bin/types.ts`. Un-skipped the `addToBin` and `restoreFromBin` describe blocks in `bin.test.ts`, removing legacy `originalFolderKeyEncrypted` fixture entries and `FolderChild` import. Changed mocks to `importOriginal + ...actual` spread to keep real AES-GCM primitives for the AEAD asymmetry test. Added 10 new tests: 4 for `addToBin` (happy-path, revoke-ordering, abort-on-revoke-fail, not-loaded guard) and 5 for `restoreFromBin` (happy-path, AEAD asymmetry proof, bin-entry-not-found, folder-not-loaded, nodeReadKey-missing).

Tests ran RED as expected: all 10 new tests failed with the Phase-65 stub marker.

### Task 2 — GREEN: Implement addToBin and restoreFromBin (commit `03c1b0ac1`)

**addToBin** implementation:

1. Validates source folder is loaded (throws "Folder not loaded")
2. Resolves child IPNS record and fetches `PublishedNode` bytes to extract plaintext `id` and `kind` for AAD binding (mirrors `moveItem` pattern in `client.ts:589-606`)
3. Calls `unsealChildReadKey(childRef.readKeySealed, folderState.folderKey, id, kind, generation)` to recover `nodeReadKey`
4. If `revokeSharesForItemsFn` provided, calls it BEFORE any destructive mutation (fail-closed)
5. Calls `deleteFromFolder` (pure sync transform) then `updateFolderMetadataAndPublish`
6. Builds `BinEntry` with `nodeReadKey`, `nodeIpnsName`, and `nodeRef` from the parsed envelope
7. Saves bin metadata via `saveBinMetadata`

**restoreFromBin** implementation:

1. Finds bin entry by `entryId` (throws "Bin entry not found")
2. Validates `entry.nodeReadKey` is present (throws if missing)
3. Validates target folder is loaded (throws "Folder not loaded")
4. Calls `sealChildReadKey(entry.nodeReadKey, targetFolder.folderKey, nodeId, nodeKind, generation)` — pure re-link, no content re-encryption
5. Builds `SealedChildRef` with `{ name, ipnsName: entry.nodeIpnsName, generation, versionFloor: 0n, readKeySealed }`
6. Calls `updateFolderMetadataAndPublish` with restored ref added to target folder children
7. Removes entry from bin and saves updated bin metadata

All 20 tests pass GREEN.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing field] Added nodeIpnsName to BinEntry**

- **Found during:** Task 1 (test design)
- **Issue:** `restoreFromBin` needs `SealedChildRef.ipnsName` to build the restored ref without re-resolving the child's IPNS. `BinEntry` had no field to store this.
- **Fix:** Added `nodeIpnsName?: string` to `BinEntry` (in addition to the plan-specified `nodeReadKey?: Uint8Array`).
- **Files modified:** `packages/core/src/bin/types.ts`
- **Commit:** `7b524fcf9`

**2. [Rule 1 - Bug] Fixed vi.restoreAllMocks() resetting module-level vi.fn() mocks**

- **Found during:** Task 2 (GREEN run)
- **Issue:** The first `restoreFromBin` test called `vi.restoreAllMocks()` which — in Vitest — resets ALL tracked `vi.fn()` mocks including those defined in `vi.mock` factories (`deriveBinIpnsKeypair`, `encryptBinMetadata`, etc.). This caused `permanentDeleteFromBin` and `emptyBin` tests to fail in the subsequent test run.
- **Fix:** Replaced `vi.restoreAllMocks()` with `sealSpy.mockRestore()` (targeted restore of the specific `sealChildReadKey` spy only).
- **Files modified:** `packages/sdk/src/__tests__/bin.test.ts`
- **Commit:** `03c1b0ac1`

**3. [Rule 1 - Bug] Fixed invalid UUID in AEAD asymmetry test fixture**

- **Found during:** Task 2 (GREEN run — "Malformed UUID" CryptoError)
- **Issue:** `nodeRef.id = 'node-uuid-1'` is not a valid UUID format. `uuidToBytes` in `@cipherbox/crypto` validates the UUID format and throws `CryptoError('Malformed UUID')` when the real `sealChildReadKey` is invoked.
- **Fix:** Changed fixture `id` to `'00000000-0000-0000-0000-000000000001'` (valid UUID) and updated the `realUnseal` call to reference `nodeRef.id` instead of the hardcoded string.
- **Files modified:** `packages/sdk/src/__tests__/bin.test.ts`
- **Commit:** `03c1b0ac1`

## Verification

All 20 bin tests pass:

- loadBin: 4/4 pass (unchanged)
- addToBin: 4/4 pass (new)
- restoreFromBin: 6/6 pass (new, including duplicate "throws when bin entry not found")
- permanentDeleteFromBin: 3/3 pass (unchanged)
- emptyBin: 3/3 pass (unchanged)

AEAD asymmetry test proves the re-link property: `restoredItem.readKeySealed` unseals under the destination parent readKey and rejects under the source parent readKey using real `sealChildReadKey` / `unsealChildReadKey` (AES-256-GCM, role 0x02).

## Known Stubs

None. The plan-specified stub marker (`'not implemented — phase 65 (bin re-link)'`) has been removed from both `addToBin` and `restoreFromBin`.

## Threat Flags

No new security-relevant surface introduced. `addToBin` and `restoreFromBin` operate on existing IPFS/IPNS infrastructure. The `nodeReadKey` stored on `BinEntry` is protected at rest by the ECIES bin-blob encryption (`encryptBinMetadata` to the owner's public key) — threat model T-65-05 through T-65-08 mitigations remain intact.

## Self-Check: PASSED

- `packages/core/src/bin/types.ts` — FOUND (nodeReadKey and nodeIpnsName fields present)
- `packages/sdk/src/bin/index.ts` — FOUND (addToBin and restoreFromBin implemented)
- `packages/sdk/src/__tests__/bin.test.ts` — FOUND (20 tests, all pass)
- commit `7b524fcf9` — FOUND (test RED commit)
- commit `03c1b0ac1` — FOUND (feat GREEN commit)

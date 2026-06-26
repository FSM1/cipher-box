---
phase: 49-shared-folder-move-intra-share-and-usefoldernavigation-unwra
plan: "01"
subsystem: sdk
tags: [sdk, shared-folder, move, reencrypt, tdd, crypto]
dependency_graph:
  requires: []
  provides:
    - moveInSharedFolder stateless op (packages/sdk/src/share/shared-write.ts)
    - CipherBoxClient.moveInSharedFolder (packages/sdk/src/client.ts)
    - CipherBoxClient.enumerateSharedSubtree (packages/sdk/src/client.ts)
  affects:
    - packages/sdk/src/share/index.ts
tech_stack:
  added: []
  patterns:
    - Dual-context stateless op (srcCtx + destCtx) for cross-subfolder shared write
    - DFS enumeration with visited Set cycle guard over share_keys
    - finally-zeroing of all temp keys (T-49-04 pattern)
    - adoptSharedFolderResult for SOURCE only (never dest — Pitfall 1)
key_files:
  created:
    - packages/sdk/src/__tests__/move-in-shared-folder.test.ts
    - packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts
  modified:
    - packages/sdk/src/share/shared-write.ts
    - packages/sdk/src/share/index.ts
    - packages/sdk/src/client.ts
decisions:
  - "Write-cap check (T-49-01): validate both folder and folder-ipns records BEFORE unwrapping any keys; ensures throw is clean with no partial keys allocated"
  - "finally zeroing uses null-initialized variables so partial allocation on throw is safe"
  - "Test snapshot pattern: mock captures Uint8Array snapshots at call time because finally zeroes the same buffer references afterward"
  - "mockReset() in specific tests to prevent beforeEach mock queue interference on 3rd+ unwrapKey calls"
metrics:
  duration: 13min
  completed_date: "2026-06-18"
  tasks: 2
  files: 5
---

# Phase 49 Plan 01: moveInSharedFolder op + enumerateSharedSubtree Summary

**One-liner:** SDK crypto core for intra-share file move — dual-context stateless op with DEST-first publish, recipient file-ipns key re-encryption, and DFS shared-subtree enumeration with write-capability flags.

## What Was Built

### Feature 1: moveInSharedFolder (REQ-2)

Stateless op `moveInSharedFolder` in `packages/sdk/src/share/shared-write.ts`:

- Takes `{ ctx, srcCtx, destCtx, itemId, fileIpnsPrivateKey }` — dual context (one per subfolder)
- Calls `sdkCore.moveItem` (pure, throws on name collision)
- Publishes DEST first via `updateFolderMetadataAndPublish` (add-before-remove crash safety)
- If file item and `fileIpnsPrivateKey` non-null: calls `reencryptFileMetadataForFolderChange` to re-seal `FileMetadata` under dest `folderKey`
- Publishes SOURCE (removal)
- Returns `{ srcResult, destResult }`
- No `.fill(0)` — caller owns all zeroing

`CipherBoxClient.moveInSharedFolder` in `packages/sdk/src/client.ts`:

- Validates both `folder` and `folder-ipns` share_keys records BEFORE any `unwrapKey` (write-cap guard T-49-01)
- Unwraps dest folder keys; declares vars before `try` so `finally` can always zero them
- Calls `sdkCore.loadFolderMetadata` for fresh dest children (A1 — never a cached ref)
- Resolves file IPNS key from `share_keys keyType:'file-ipns'` (NEVER from `FilePointer.ipnsPrivateKeyEncrypted` — T-49-03)
- Calls stateless `shareOps.moveInSharedFolder`
- Calls `adoptSharedFolderResult(shareId, srcResult)` for SOURCE only (never dest — Pitfall 1)
- `finally` zeroes `destFolderKey`, `destIpnsPrivateKey`, `fileIpnsPrivateKey` (T-49-04)
- Wrapped in `this.withOperation('moveInSharedFolder', ...)`

### Feature 2: enumerateSharedSubtree (REQ-1)

`CipherBoxClient.enumerateSharedSubtree` in `packages/sdk/src/client.ts`:

- Starts from loaded share-root state (`requireSharedFolder(shareId)`)
- Stack-based DFS over folder children
- `visited = new Set<string>([rootState.ipnsName])` prevents cycles
- For each folder child: checks `share_keys keyType:'folder'` — skips if absent (no read access)
- Unwraps `folderKey` with `vaultPrivateKey`; sets `writable = share_keys.some(keyType:'folder-ipns' && itemId===child.id)`
- Calls `sdkCore.loadFolderMetadata` per node to descend
- Returns flat `Array<{ id, name, ipnsName, writable }>`
- Never zeroes `vaultPrivateKey` (caller owns)

## Test Coverage

- `move-in-shared-folder.test.ts`: 10 cases — publish ordering, re-key with correct keys, file-ipns key from share_keys, folder item no re-key, missing folder-ipns throws, missing folder throws, name collision propagates, adoptSharedFolderResult SOURCE only, finally zeroing on success and partial failure
- `enumerate-shared-subtree.test.ts`: 6 cases — all reachable nodes, writable flags, skipped nodes (no folder key), cycle guard, correct ipnsName/name, vaultPrivateKey not zeroed

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Write-cap check position restructured for correct finally coverage**

- **Found during:** GREEN implementation
- **Issue:** Initial implementation put write-cap `throw` before `try` block; when `destFolderIpnsRecord` missing, the `throw` fired before `destFolderKey` was allocated, so `finally` was never reached for a key that was never created
- **Fix:** Moved BOTH record existence checks before `try` but AFTER the record lookup (no unwrapping until inside the `try`); initialized `destFolderKey`, `destIpnsPrivateKey`, `fileIpnsPrivateKey` as null before `try` so `finally` safely checks and zeros them
- **Files modified:** `packages/sdk/src/client.ts`
- **Commit:** c2c021195

**2. [Rule 1 - Bug] Test mock queue interference fixed with mockReset()**

- **Found during:** GREEN verification
- **Issue:** Tests that set up custom `mockResolvedValueOnce` chains for `unwrapKey` were appending to `beforeEach`'s queue, causing the 3rd call to receive a wrong buffer (0x33 instead of 0x77)
- **Fix:** Added `vi.mocked(unwrapKey).mockReset()` before custom queue setup in affected tests; also updated two assertions to capture buffer snapshots at call time (since `finally` zeroes the same buffer references after)
- **Files modified:** `packages/sdk/src/__tests__/move-in-shared-folder.test.ts`
- **Commit:** c2c021195

## Self-Check

### Created files exist

- [x] `/packages/sdk/src/__tests__/move-in-shared-folder.test.ts` — exists
- [x] `/packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts` — exists
- [x] `moveInSharedFolder` in `shared-write.ts` — grep matches at line 529
- [x] `moveInSharedFolder` in `client.ts` — grep matches at line 2292
- [x] `enumerateSharedSubtree` in `client.ts` — grep matches at line 2401

### Commits exist

- [x] `233ad6752` — test(49-01): RED commit
- [x] `c2c021195` — feat(49-01): GREEN commit

### Test status

- Full SDK suite: 233 passed, 3 failed (integration.test.ts — pre-existing, require live API)
- `move-in-shared-folder.test.ts`: all cases PASS
- `enumerate-shared-subtree.test.ts`: all cases PASS
- TypeScript: `tsc --noEmit` clean

## Self-Check: PASSED

## Known Stubs

None — all methods are fully implemented with no placeholder data.

## Threat Flags

No new network endpoints or trust boundaries introduced beyond the plan's `<threat_model>`. The `share_keys` resolution and IPNS publish paths were pre-existing surfaces.

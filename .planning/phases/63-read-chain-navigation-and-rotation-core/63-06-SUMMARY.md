---
phase: 63-read-chain-navigation-and-rotation-core
plan: "06"
subsystem: sdk
tags: [d03, read-chain, share, fan-out-deletion, enumerate-shared-subtree]
dependency_graph:
  requires: [63-04]
  provides: [sdk-d03-deletion, enumerate-shared-subtree-impl]
  affects: [packages/sdk, packages/sdk/src/share, packages/sdk/src/client.ts]
tech_stack:
  added: []
  patterns: [parent-key-sealing, dfs-traversal, ecies-share-keys, d09-zeroization]
key_files:
  modified:
    - packages/sdk/src/share/index.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/share/shared-write.ts
    - packages/sdk/src/__tests__/share.test.ts
    - packages/sdk/src/__tests__/client-extended.test.ts
    - packages/sdk/src/__tests__/client-upload-concurrency.test.ts
    - packages/sdk/src/__tests__/client-move-reencrypt.test.ts
    - packages/sdk/src/__tests__/upload-batch.test.ts
    - packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts
decisions:
  - "enumerateSharedSubtree uses ECIES share_keys (schema unchanged until Phase 66) for child readKey derivation; SealedChildRef.ipnsName is the node identity in results (id=ipnsName)"
  - "parentId in enumerateSharedSubtree results is set to the parent SealedChildRef.ipnsName (not a UUID) — consistent with the id=ipnsName convention"
  - "SentShareInfo type kept in share/index.ts (used by types.ts getCoveringShares — not reWrapForRecipients)"
metrics:
  duration: "~45 min (continued session)"
  completed: "2026-06-29"
  tasks_total: 2
  tasks_completed: 2
  files_modified: 9
status: complete
---

# Phase 63 Plan 06: Delete reWrapForRecipients Fan-Out and Revive enumerateSharedSubtree Summary

Delete the legacy per-recipient ECIES fan-out from the SDK layer (D-03 SC#3): removed `reWrapForRecipients` from `packages/sdk/src/share/index.ts` and all call sites in `client.ts`, rewired add-item to parent-key sealing (READ-03 / O(1)), and implemented + revived `enumerateSharedSubtree` as an iterative DFS over `SealedChildRef` children.

## Tasks Completed

### Task 1: Delete reWrapForRecipients from sdk/share/index.ts

Removed the `reWrapForRecipients` function (including its docblock and `hexToBytes` import that was exclusively used by it). All other exports — `createShareKey`, `revokeShare`, `revokeSharesForItems`, `revokeBatchWithRetry`, shared-write re-exports — remained intact. `SentShareInfo` type was correctly preserved (required by `types.ts` for the `getCoveringShares` callback).

Commit: `08cd458d8`

### Task 2: Rewire client.ts add-item path and revive enumerate test

Changes in `packages/sdk/src/client.ts`:

- Deleted private `reWrapNewItems` method
- Deleted both re-wrap try/catch blocks from `uploadFile` and `uploadFiles`
- Deleted public `reWrapForRecipients` method
- Removed `SentShareInfo` import
- Fixed both `addFilePointerToFolder` call sites to the new async signature: `{children, childReadKey, parentReadKey, childId, childKind, childGeneration, name, ipnsName, versionFloor}` (Rule 1 auto-fix — these were broken by Plan 63-04 and not yet updated)
- Added `unwrapKey, hexToBytes` to `@cipherbox/crypto` import
- Implemented `enumerateSharedSubtree`: iterative DFS over `SealedChildRef[]`, ECIES-unwraps per-node folder readKey from `share_keys` entries (by ipnsName), loads sub-children via `loadFolderMetadata`, zeroes each locally-minted key in `finally` (D-09), does not zero caller-supplied `vaultPrivateKey`

Updated test files to remove all `reWrapForRecipients` mock entries and delete/rewrite tests for deleted behavior:
- `share.test.ts`: removed `reWrapForRecipients` import and its describe block
- `client-extended.test.ts`: replaced four re-wrapping tests with a single D-09 zeroization test
- `client-upload-concurrency.test.ts`, `client-move-reencrypt.test.ts`, `upload-batch.test.ts`: removed mock entries; replaced dead re-wrap test in upload-batch with assertion that `getCoveringShares` is never called

Revived `enumerate-shared-subtree.test.ts`:
- Removed `describe.skip`
- Updated import from `FolderChild, FolderEntry` to `SealedChildRef`
- Rewrote `makeFolderEntry` to return `SealedChildRef` shape (`{name, ipnsName, generation, versionFloor, readKeySealed}`)
- Changed share keys `itemId` from UUID to ipnsName
- Updated all assertions: `n.id` is now `child.ipnsName` (not a UUID); `parentId` is the parent's ipnsName
- All 8 tests pass

Commit: `3ea03d529`

## Verification Gates

```
grep -rn 'reWrapForRecipients' packages/sdk/src/  → 0 occurrences
grep -c 'reWrapForRecipients|reWrapNewItems' packages/sdk/src/client.ts → 0
grep -c 'addShareKeys' packages/sdk/src/types.ts → 3 (Phase-68 boundary preserved)
pnpm --filter @cipherbox/sdk build → build success
pnpm --filter @cipherbox/sdk test --run → 169 passed, 79 skipped, 0 failed
enumerate-shared-subtree.test.ts → 8/8 tests pass
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed addFilePointerToFolder call sites for new async signature**

- Found during: Task 2 (when verifying build after reWrapForRecipients deletion)
- Issue: Plan 63-04 changed `addFilePointerToFolder` from sync `{fileId, fileName, ...}` to async `{childReadKey, parentReadKey, childId, childKind, childGeneration, name, ipnsName, versionFloor}` but the two call sites in `client.ts` were not updated, causing TS2339/TS2353 build errors
- Fix: Updated both call sites in `uploadFile` and `uploadFiles` to `await` the call and use the new parameter names
- Files modified: `packages/sdk/src/client.ts`
- Commit: `3ea03d529`

**2. [Rule 2 - Missing critical functionality] Implemented enumerateSharedSubtree**

- Found during: Task 2 (plan specified "adjust to parent-key sealing model"; stub threw `not implemented`)
- Issue: The stub was blocking test revival; the plan's own Task 2 action requires implementing the method
- Fix: Implemented iterative DFS with ECIES key derivation per node, visited-set cycle guard, D-09 zeroization
- Files modified: `packages/sdk/src/client.ts`
- Commit: `3ea03d529`

## Known Stubs

None. The `enumerateSharedSubtree` implementation is complete (ECIES schema unchanged until Phase 66, consistent with design).

## Threat Flags

None. No new network endpoints or auth paths introduced. The deletion of the fan-out path removes the T-63-21 surface (revoked-recipient key disclosure) as designed.

## Self-Check: PASSED

- `packages/sdk/src/client.ts`: present, modified
- `packages/sdk/src/share/index.ts`: present, modified
- `packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts`: present, `.skip` removed, 8/8 pass
- Commit `08cd458d8`: confirmed in git log
- Commit `3ea03d529`: confirmed in git log
- Build: success (tsup + tsc -p tsconfig.build.json)
- Tests: 169 passed, 0 failed

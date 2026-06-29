---
phase: 62-unified-node-codec-core-keystone
plan: "07"
subsystem: sdk
tags: [compile-gate, type-swap, stub-sweep, quarantine]
status: complete

dependency_graph:
  requires:
    - 62-06 (sdk-core dist rebuilt with Node/SealedChildRef)
    - core dist (node/v3 types)
  provides:
    - packages/sdk dist rebuilt, typechecking against node/v3
  affects:
    - packages/sdk/src (types, client, events, reencrypt, bin, share)
    - packages/sdk/src/__tests__ (10 suites quarantined)

tech_stack:
  added: []
  patterns:
    - describe.skip quarantine with TODO(phase NN) annotation
    - throw new Error('not implemented — phase NN') stubs for all write-chain / read fan-out paths

key_files:
  modified:
    - packages/sdk/src/types.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/events.ts
    - packages/sdk/src/reencrypt.ts
    - packages/sdk/src/bin/index.ts
    - packages/sdk/src/share/shared-write.ts
    - packages/sdk/src/share/context.ts
    - packages/sdk/src/__tests__/helpers.ts
    - packages/sdk/src/__tests__/bin.test.ts
    - packages/sdk/src/__tests__/client-extended.test.ts
    - packages/sdk/src/__tests__/client-file-ops.test.ts
    - packages/sdk/src/__tests__/client-move-reencrypt.test.ts
    - packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts
    - packages/sdk/src/__tests__/ensure-folder-loaded.test.ts
    - packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts
    - packages/sdk/src/__tests__/integration.test.ts
    - packages/sdk/src/__tests__/move-in-shared-folder.test.ts
    - packages/sdk/src/__tests__/shared-write.test.ts

decisions:
  - "result.metadata.children ?? [] pattern: Node.children is optional (undefined for file nodes); always coalesce to [] when assigning to SealedChildRef[]"
  - "Delete unreachable private methods: collectFolderSubtree/collectSubtreeIpnsNamesAsync/maybePublishKeyMigration removed because their only callers became stubs; avoids TS6133"
  - "helpers.ts needs SealedChildRef fields: tsconfig.build.json excludes *.test.ts but NOT helpers.ts, so helpers.ts must compile as production code"
  - "All describe.skip on nested sub-describes (not full-file quarantine): surgical skips preserve active passing tests in same file"
  - "Integration test: changed describeIf const to describe.skip always; methods now throw prevents non-CI runs from calling live API"
  - "import type retired types: all @cipherbox/core imports in tests are import type so esbuild erases them; no Pitfall-3 VALUE import failures"

metrics:
  duration: "~90 min (across two sessions)"
  completed: "2026-06-29"
  tasks_completed: 2
  files_modified: 18
  tests_green_before: 0
  tests_green_after: 167
  tests_skipped: 89
---

# Phase 62 Plan 07: SDK Compile Gate Stub Sweep Summary

SDK compile-only stub sweep — swapped all retired types (FolderChild, FilePointer, FolderEntry, FolderMetadata, FileMetadata) to Node/SealedChildRef, stubbed write-chain/share/bin paths with explicit phase-attributed errors, and quarantined 89 behavioral tests with describe.skip.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Stub sdk source — type-swap + write-chain/bin/share stubs | `8ba25ac84` | 8 src files |
| 2 | Quarantine sdk test suites | `ad9caad9f` | 10 test files |

## Task 1: Source Stub Sweep

All sdk source files now compile against `@cipherbox/core` node/v3 types:

### Type Changes

- `types.ts`: `FolderState.children: SealedChildRef[]`, `FolderState.metadata: Node | null`, `SharedFolderState.children: SealedChildRef[]`
- `events.ts`: all `children: FolderChild[]` → `SealedChildRef[]` in SdkEvent union (3 event types)
- `share/context.ts`: `SharedWriteContextParams.children: SealedChildRef[]`
- `share/shared-write.ts`: `SharedWriteContext.children: SealedChildRef[]`

### Stubbed Paths

Write-chain / phase-65 stubs (throw `'not implemented — phase 65 ...'`):

- `reencrypt.ts`: `reencryptFileMetadataForFolderChange` — phase 65 (move re-encrypt)
- `share/shared-write.ts`: all write ops — `uploadToSharedFolder`, `createSharedSubfolder`, `renameInSharedFolder`, `deleteFromSharedFolder`, `updateSharedFile`, `moveInSharedFolder` — phase 65 write-chain
- `bin/index.ts`: `addToBin`, `restoreFromBin` — phase 65 bin re-link
- `client.ts`: `replaceFile`, `restoreFileVersion`, `deleteFileVersion`, `downloadFromIpns`, `collectRemovedItemIpnsNames`, `collectBinEntryIpnsNames`, `updateSharedFile` — phase 65

Navigation / phase-63 stubs (throw `'not implemented — phase 63 ...'`):

- `client.ts`: `ensureFolderLoaded`, `createFolder`, `moveItem`, `moveInSharedFolder`, `enumerateSharedSubtree` — phase 63

### Dead Code Removed

`collectFolderSubtree`, `collectSubtreeIpnsNamesAsync`, `maybePublishKeyMigration` removed from `client.ts` — their only callers became stubs, making them unreachable dead code that TS6133 would reject.

### helpers.ts

Added SealedChildRef required fields (`ipnsName`, `generation: 0`, `versionFloor: 0n`, `readKeySealed`) to mock child object while retaining legacy FolderChild fields for quarantined test reads. This file is NOT excluded by `tsconfig.build.json` and must compile as production code.

## Task 2: Test Suite Quarantine

### Fully Quarantined (entire top-level describe)

| File | Describe | TODO |
|------|----------|------|
| `client-file-ops.test.ts` | CipherBoxClient - file ops | phase 65 |
| `client-move-reencrypt.test.ts` | CipherBoxClient.moveItem re-encryption | phase 65 |
| `collect-subtree-ipns-names.test.ts` | collectSubtreeIpnsNamesAsync D-03 | phase 65 |
| `ensure-folder-loaded.test.ts` | CipherBoxClient.ensureFolderLoaded | phase 63 |
| `enumerate-shared-subtree.test.ts` | CipherBoxClient.enumerateSharedSubtree | phase 63 |
| `integration.test.ts` | SDK Integration (live API) | phase 65 |
| `move-in-shared-folder.test.ts` | CipherBoxClient.moveInSharedFolder + stateless op | phase 63 |

### Surgically Quarantined (sub-describe or it.skip)

**bin.test.ts** — inner describes skipped; `loadBin`, `permanentDeleteFromBin`, `emptyBin` remain active:

- `describe.skip('addToBin — TODO(phase 65)')` (15 tests skipped)
- `describe.skip('restoreFromBin — TODO(phase 65)')` (15 tests skipped)

**client-extended.test.ts** — outer describe kept; surgical skips:

- `describe.skip('moveItem — TODO(phase 63)')` (2 tests)
- `describe.skip('downloadFromIpns — TODO(phase 65)')` (1 test)
- `it.skip('shareFolder throws when folder not loaded — TODO(phase 63)')` (1 test)

**shared-write.test.ts** — outer describe kept; `updateSharePermission` active (2 tests); skipped:

- `describe.skip('uploadToSharedFolder — TODO(phase 65)')` (3 tests)
- `describe.skip('createSharedSubfolder — TODO(phase 65)')` (3 tests)
- `describe.skip('renameInSharedFolder — TODO(phase 65)')` (1 test)
- `describe.skip('deleteFromSharedFolder — TODO(phase 65)')` (1 test)
- `describe.skip('updateSharedFile — TODO(phase 65)')` (5 tests)

### Final Test Results

```
Test Files: 15 passed | 7 skipped (22)
     Tests: 167 passed | 89 skipped (256)
```

## Verification

Build gate: `pnpm --filter @cipherbox/sdk build` exits 0 (tsup + `tsc -p tsconfig.build.json`).

Zero retired-type references in non-test sdk source files.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

All stubs are intentional and documented in source JSDoc:

- `reencrypt.ts:reencryptFileMetadataForFolderChange` → phase 65
- `share/shared-write.ts:uploadToSharedFolder|createSharedSubfolder|renameInSharedFolder|deleteFromSharedFolder|updateSharedFile|moveInSharedFolder` → phase 65
- `bin/index.ts:addToBin|restoreFromBin` → phase 65
- `client.ts:replaceFile|restoreFileVersion|deleteFileVersion|downloadFromIpns|updateSharedFile|collectRemovedItemIpnsNames|collectBinEntryIpnsNames` → phase 65
- `client.ts:ensureFolderLoaded|createFolder|moveItem|moveInSharedFolder|enumerateSharedSubtree` → phase 63

These stubs are the intended output of this plan (D-01 stub discipline). Future phases revive them.

## Self-Check: PASSED

- `packages/sdk/dist/index.js` exists: FOUND
- `packages/sdk/dist/index.mjs` exists: FOUND
- Commit `8ba25ac84`: FOUND (refactor stub sweep)
- Commit `ad9caad9f`: FOUND (test quarantine)
- `pnpm --filter @cipherbox/sdk build`: exits 0
- `pnpm --filter @cipherbox/sdk test`: 167 passed / 89 skipped / 0 failed

---
phase: 62-unified-node-codec-core-keystone
plan: "05"
subsystem: core
tags: [node-codec, barrel-cutover, schema-migration, bin-adaptation, test-cleanup]
dependency_graph:
  requires: [62-02, 62-03]
  provides: [packages/core dist/ with node/ exports only; retired folder/ and file/]
  affects: [packages/sdk-core, packages/sdk, apps/web, apps/desktop]
tech_stack:
  added: []
  patterns:
    - nodeRef replacing filePointer/folderEntry in BinEntry (Phase 65 re-link)
    - describe.skip not needed — no deferred-behavior tests existed (pure ECIES round-trip + schema validation)
key_files:
  created: []
  modified:
    - packages/core/src/bin/types.ts
    - packages/core/src/bin/schema.ts
    - packages/core/src/index.ts
    - packages/core/src/__tests__/bin.test.ts
  deleted:
    - packages/core/src/folder/ (3 files: index.ts, metadata.ts, types.ts)
    - packages/core/src/file/ (4 files: derive-ipns.ts, index.ts, metadata.ts, types.ts)
    - packages/core/src/__tests__/folder-metadata.test.ts
    - packages/core/src/__tests__/file-ipns.test.ts
decisions:
  - "[62-05] nodeRef replaces filePointer + folderEntry + originalFolderKeyEncrypted in BinEntry; Phase 65 owns bin re-link behavior"
  - "[62-05] No describe.skip needed in bin.test.ts — all remaining tests are pure ECIES round-trip or schema validation, not bin re-link behavior"
  - "[62-05] Comment-only references to legacy types (in JSDoc of node/decode.ts, node/types.ts, registry/schema.ts) are retained as historical context; no live imports or type usages remain"
metrics:
  duration: "10 minutes"
  completed: "2026-06-28"
  tasks_completed: 3
  files_changed: 9
status: complete
---

# Phase 62 Plan 05: Core Barrel Cutover and Legacy Module Retirement Summary

Core barrel cut to node/ only; folder/ and file/ deleted; bin adapted to Node; 190 core tests green; dist/ rebuilt.

## What Was Built

Completed the final packages/core step (D-06) of the Phase 62 keystone replacement:

1. **bin/ adapted to Node (Task 1):** `bin/types.ts` — removed imports of `FilePointer` and `FolderEntry` from deleted modules; replaced `filePointer?`, `folderEntry?`, and `originalFolderKeyEncrypted?` fields with `nodeRef?: Node` (Phase 65 stub for bin re-link). `bin/schema.ts` — dropped the three removed-field validation blocks; added lenient `nodeRef` object-presence check consistent with the existing validation style.

2. **Barrel cutover + deletion (Task 2):** `packages/core/src/index.ts` — removed the folder block (7 exports) and file block (8 exports); added a node export block re-exporting all codec functions and types from `./node` (encodeReadBody, encodeWriteBody, decodeReadBody, decodeWriteBody, sealNode, unsealNode, sealChildReadKey, unsealChildReadKey, sealContent, unsealContent, validateNode, serializeContentForWire, deserializeContentFromWire + 8 types). `packages/core/src/folder/` (3 files) and `packages/core/src/file/` (4 files) deleted via `git rm -r` — greenfield delete-outright, no dual-codec needed.

3. **Test cleanup (Task 3):** Deleted `folder-metadata.test.ts` and `file-ipns.test.ts` (deleted-outright code, not stubbed behavior — deletion is the D-02 correct action). Updated `bin.test.ts`: replaced `filePointer`/`folderEntry`/`originalFolderKeyEncrypted` in test data helper with `nodeRef`-aware pattern; updated validation tests to test `nodeRef` instead; removed stale `filePointer` round-trip assertion; added `nodeRef` accepts/rejects tests.

## Verification

- `packages/core/src/folder/` and `packages/core/src/file/` do not exist
- Zero live imports or type-usage of `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` in `packages/core/src/`
- `pnpm --filter @cipherbox/core test`: 190 tests, 9 test files, all passed
- `pnpm --filter @cipherbox/core build`: tsup + tsc clean; dist/ rebuilt (ESM 32.72 KB, CJS 37.29 KB)
- `bin/types.ts` imports `Node` from `../node/types` and has `nodeRef?: Node`

## Commits

| Hash | Message |
|------|---------|
| `68db4f29d` | refactor(62-05): adapt bin/ to Node; retire FilePointer/FolderEntry/originalFolderKeyEncrypted |
| `cbd12ffc1` | feat(62-05): cut core barrel to node/; delete folder/ and file/ |
| `c4d1573c5` | chore(62-05): remove legacy tests; clean bin.test.ts of retired field refs |

## Deviations from Plan

### No deviations — plan executed exactly as specified

The plan anticipated possible `describe.skip` quarantine for bin re-link behavior tests. On inspection, `bin.test.ts` contained no bin restore/re-link behavior tests — only pure ECIES round-trip and schema validation tests. These were updated in-place (not skipped), which is the correct D-02 action for tests of surviving functionality with renamed fields.

## Known Stubs

| Stub | File | Note |
|------|------|------|
| `nodeRef?: Node` (undefined in all current bin entries) | `packages/core/src/bin/types.ts` | Phase 65 (bin re-link) will wire actual Node references when restoring from bin |
| bin restore behavior | `packages/core/src/__tests__/bin.test.ts` (comment only) | TODO(phase 65) comment in createTestBinMetadata helper |

These stubs are intentional and Phase 65 is their owner.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries introduced. This plan deletes modules and adapts an existing one — it reduces the attack surface. The `nodeRef?: Node` field in BinEntry is gated behind the existing ECIES encryption boundary; Phase 65 will validate the full Node shape on restore.

## Self-Check: PASSED

- `packages/core/src/folder/` missing: CONFIRMED (deleted)
- `packages/core/src/file/` missing: CONFIRMED (deleted)
- `packages/core/src/__tests__/folder-metadata.test.ts` missing: CONFIRMED (deleted)
- `packages/core/src/__tests__/file-ipns.test.ts` missing: CONFIRMED (deleted)
- `packages/core/dist/` rebuilt: CONFIRMED (build succeeded)
- Commits `68db4f29d`, `cbd12ffc1`, `c4d1573c5` present in git log: CONFIRMED

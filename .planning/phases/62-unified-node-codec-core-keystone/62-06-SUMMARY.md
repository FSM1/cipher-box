---
phase: 62-unified-node-codec-core-keystone
plan: "06"
subsystem: sdk-core
tags: [compile-gate, stub-sweep, quarantine, vault-v3, node-types]
dependency_graph:
  requires: [62-05]
  provides: [62-07]
  affects: [packages/sdk-core, packages/sdk, packages/api-client]
tech_stack:
  added: []
  patterns:
    - "throw new Error('not implemented — phase NN') stubs for behavioral placeholders"
    - "describe.skip with TODO(phase NN) pointer for quarantined test suites"
    - "// @ts-nocheck + eslint-disable ban-ts-comment for fully-retired type files"
    - "Local SealedChildRef-compatible type stubs to bridge retired FolderEntry/FilePointer to new API"
key_files:
  created: []
  modified:
    - packages/sdk-core/src/folder/load.ts
    - packages/sdk-core/src/folder/merge.ts
    - packages/sdk-core/src/folder/metadata-ops.ts
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk-core/src/file/index.ts
    - packages/sdk-core/src/vault/index.ts
    - packages/sdk-core/src/__tests__/folder.test.ts
    - packages/sdk-core/src/__tests__/folder-merge.test.ts
    - packages/sdk-core/src/__tests__/file.test.ts
    - packages/sdk-core/src/__tests__/vault.test.ts
    - packages/sdk-core/src/folder/__tests__/load.test.ts
decisions:
  - "vault/index.ts adapted to v3 two-key format (rootReadKey+rootWriteKey) — NOT stubbed (functional)"
  - "mergeVersions kept functional with local FileVersionEntry type (pure utility, no IPNS seal)"
  - "folder.test.ts uses eslint-disable + @ts-nocheck because @typescript-eslint/ban-ts-comment rejects @ts-nocheck; all 9 describes quarantined"
  - "folder-merge.test.ts uses local SealedChildRef-compatible types + @ts-expect-error on never-property accesses"
  - "cas.test.ts pre-existing tsc errors (union-type mock narrowing) left as-is; out-of-scope per deviation Rule boundary"
metrics:
  duration: "~45 minutes (continued from context-switch)"
  completed: "2026-06-28"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 11
status: complete
---

# Phase 62 Plan 06: sdk-core Compile Gate (Node/v3 Stub Sweep) Summary

Brought `packages/sdk-core` to COMPILE-ONLY against the new `node/v3` core. Zero new behavior — pure type-swap and explicit stub sweep.

## What Was Built

### Task 1: Source stub sweep

Swapped all retired `@cipherbox/core` type imports (`FolderMetadata`, `FileMetadata`, `FilePointer`, `FolderEntry`) to `Node`/`SealedChildRef` and stubbed every behavioral call site with `throw new Error('not implemented — phase NN')`:

- **`folder/load.ts`** — `fetchAndDecryptMetadata` and `loadFolderMetadata` stub to phase 63 (read-chain navigation)
- **`folder/merge.ts`** — `mergeChildren` stub to phase 64 (CAS merge on sealed child refs)
- **`folder/metadata-ops.ts`** — `renameInFolder`, `deleteFromFolder`, `addFilePointerToFolder`, `moveItem` stub to phase 63 (write-chain child ref mutation)
- **`folder/registration.ts`** — `createSubfolder`, `updateFolderMetadataAndPublish` stub to phase 63; `addFileToFolder`, `addFilesToFolder`, `replaceFileInFolder` stub to phase 65
- **`file/index.ts`** — all file metadata functions stub to phase 65; `mergeVersions` kept functional with local `FileVersionEntry` type; `FileIpnsRecordPayload` re-exported
- **`vault/index.ts`** — adapted to v3 two-key format (`rootReadKey`+`rootWriteKey`); NOT stubbed — `publishVaultKeyBlob` and `loadVaultKeyBlob` are functional using `serializeVaultBlobV3`/`deserializeVaultBlobV3`

Compile gate confirmed: `pnpm --filter @cipherbox/sdk-core exec tsc --noEmit -p tsconfig.build.json` exits 0.

### Task 2: Test suite quarantine + vault v3 update

Per D-02 / RESEARCH Pitfall 3 (import fails before describe.skip evaluates):

- **`vault.test.ts`** — updated to v3 API (rootReadKey+rootWriteKey, V3 mock functions); tests stay ACTIVE and GREEN (7 tests pass)
- **`folder.test.ts`** — eslint-disable ban-ts-comment + @ts-nocheck + 9 describes skipped (phase 63/65 owners); all tests quarantined (32 skipped)
- **`folder-merge.test.ts`** — retired core import replaced with local SealedChildRef-compatible stubs; `describe.skip` on `mergeChildren` (phase 64); ConflictError and is409 describes STAY ACTIVE
- **`file.test.ts`** — `describe.skip` on `updateFileMetadata CAS + conflict` (phase 65); `mergeVersions` describe STAYS ACTIVE; TS2551 on retired `encryptFileMetadata`/`decryptFileMetadata` fixed via `any` cast
- **`folder/__tests__/load.test.ts`** — `describe.skip` on entire suite (phase 63); TS2339 on retired `decryptFolderMetadata` fixed via `any` cast

Test gate confirmed: 17 test files pass, 2 skipped, 197 tests green, 55 skipped.

## Acceptance Criteria

- [x] `pnpm --filter @cipherbox/sdk-core exec tsc --noEmit -p tsconfig.build.json` exits 0
- [x] `pnpm --filter @cipherbox/sdk-core test` exits 0 (active suites green, quarantined skipped)
- [x] Zero references to `FolderMetadata`/`FileMetadata`/`FolderEntry`/`FilePointer` in sdk-core source (SC#5, D-02)
- [x] Every stub throws `new Error('not implemented — phase NN')` naming the owning phase (D-01)
- [x] Vault adapted to v3 two-key format and functional (D-05)
- [x] sdk-core dist rebuilt successfully

## Commits

- `6172a8eca` — refactor(62-06): stub sdk-core source to Node/SealedChildRef; adapt vault to v3
- `424d7aa0c` — test(62-06): quarantine sdk-core test suites for phase 62 compile gate

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] ESLint bans @ts-nocheck and @ts-ignore**

- **Found during:** Task 2 commit
- **Issue:** `@typescript-eslint/ban-ts-comment` rule rejects `@ts-nocheck` and `@ts-ignore`
- **Fix:** Used `/* eslint-disable @typescript-eslint/ban-ts-comment */` + `// @ts-nocheck` in `folder.test.ts` (where all 9 describes are quarantined); replaced `// @ts-ignore` with `// @ts-expect-error` in `folder-merge.test.ts`
- **Files modified:** `folder.test.ts`, `folder-merge.test.ts`
- **Commit:** `424d7aa0c`

**2. [Rule 1 - Bug] Local SealedChildRef-compatible types needed for folder-merge.test.ts**

- **Found during:** Task 2
- **Issue:** Replacing core type import with bare local types caused argument-type mismatch (FolderChild[] not assignable to SealedChildRef[]); RESEARCH Pitfall 3 required fixing imports before wrapping in describe.skip
- **Fix:** Defined local FolderEntry/FilePointer/FolderChild types including all required SealedChildRef fields (generation, versionFloor, readKeySealed) so structural subtyping resolves
- **Files modified:** `folder-merge.test.ts`
- **Commit:** `424d7aa0c`

## Known Stubs

These stubs are intentional per D-01 — each names the owning phase:

| Function | File | Owner Phase |
|----------|------|-------------|
| fetchAndDecryptMetadata | folder/load.ts | 63 (read-chain navigation) |
| loadFolderMetadata | folder/load.ts | 63 (read-chain navigation) |
| mergeChildren | folder/merge.ts | 64 (CAS merge on sealed child refs) |
| renameInFolder | folder/metadata-ops.ts | 63 (write-chain child ref mutation) |
| deleteFromFolder | folder/metadata-ops.ts | 63 (write-chain child ref mutation) |
| addFilePointerToFolder | folder/metadata-ops.ts | 63 (add file node + seal child readKey) |
| moveItem | folder/metadata-ops.ts | 63 (move node + re-seal child readKey) |
| createSubfolder | folder/registration.ts | 63 (create subfolder node + seal readKey under parent) |
| updateFolderMetadataAndPublish | folder/registration.ts | 63 (seal updated Node + publish to IPNS) |
| addFileToFolder | folder/registration.ts | 65 (add file Node + seal child readKey + batch-publish) |
| addFilesToFolder | folder/registration.ts | 65 (add file Nodes + seal child readKeys + batch-publish) |
| replaceFileInFolder | folder/registration.ts | 65 (replace file Node content + publish file IPNS) |
| createFileMetadata | file/index.ts | 65 (write-chain file node seal) |
| resolveFileMetadata | file/index.ts | 65 (write-chain file node seal) |
| updateFileMetadata | file/index.ts | 65 (write-chain file node seal) |

## Self-Check: PASSED

Files confirmed:
- packages/sdk-core/src/folder/load.ts — EXISTS
- packages/sdk-core/src/folder/merge.ts — EXISTS
- packages/sdk-core/src/folder/metadata-ops.ts — EXISTS
- packages/sdk-core/src/folder/registration.ts — EXISTS
- packages/sdk-core/src/file/index.ts — EXISTS
- packages/sdk-core/src/vault/index.ts — EXISTS

Commits confirmed:
- 6172a8eca — EXISTS (git log)
- 424d7aa0c — EXISTS (git log)

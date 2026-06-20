---
phase: 54-e2e-test-infra-typing
plan: 02
subsystem: e2e-test-infra
tags: [typescript-migration, sdk-core-scripts, e2e-helpers]
requires:
  - tests/e2e-helpers/auth.ts (authenticate, buildSdkContext, parseCliArgs)
  - tests/e2e-helpers/types.ts (AuthPayload)
  - tsconfig.scripts.json
provides:
  - packages/sdk-core/scripts/edit-filepointer.ts
  - packages/sdk-core/scripts/rename-folder.ts
  - packages/sdk-core/scripts/verify-filepointer.ts
affects:
  - tsconfig.scripts.json (added node typeRoots/types)
tech-stack:
  added: []
  patterns: [entrypoint-imports, shared-auth-helper, behavior-preserving-migration]
key-files:
  created:
    - packages/sdk-core/scripts/edit-filepointer.ts
    - packages/sdk-core/scripts/rename-folder.ts
    - packages/sdk-core/scripts/verify-filepointer.ts
  modified:
    - tsconfig.scripts.json
decisions:
  - "Wired @types/node into tsconfig.scripts.json (types + typeRoots) so Node globals (process/Buffer) resolve at tsc time — first scripts to use them"
  - "Added type-narrowing guards (filePointer.type !== 'file', subEntry.type !== 'folder') required because Array.find() does not narrow union element types"
metrics:
  duration: ~20m
  completed: 2026-06-20
requirements: [HARD-05]
---

# Phase 54 Plan 02: Migrate sdk-core E2E Helper Scripts to TypeScript Summary

Migrated the three highest-traffic `packages/sdk-core/scripts` helpers (edit-filepointer, rename-folder, verify-filepointer) from untyped `.mjs` to `.ts` using `@cipherbox/*` entrypoint imports and the shared `tests/e2e-helpers/auth.ts` module, preserving every CLI/env/stdout/exit contract (D-07). The `.mjs` originals remain in place for Wave 3 (plan 04) to delete in lockstep with the runner switch.

## What Was Built

### Task 1 — edit-filepointer.ts + rename-folder.ts (commit a2ed87f1c)

- `edit-filepointer.ts`: imports `loadVaultKeyBlob, loadFolderMetadata, resolveFileMetadata, updateFileMetadata, updateFolderMetadataAndPublish, addToIpfs, type SdkContext` from `@cipherbox/sdk-core`; `encryptAesGcm, generateFileKey, generateIv, wrapKey, unwrapKey, bytesToHex, hexToBytes, deriveVaultIpnsKeypair, clearBytes` from `@cipherbox/crypto`; `authenticate, buildSdkContext, parseCliArgs` from `../../../tests/e2e-helpers/auth`. Flow body (encrypt new content → addToIpfs → updateFileMetadata → republish folder metadata) unchanged. `clearBytes(fileKey)` and the two `.fill(0)` key-zeroization calls preserved.
- `rename-folder.ts`: imports `loadVaultKeyBlob, loadFolderMetadata, renameInFolder, updateFolderMetadataAndPublish, type SdkContext` from `@cipherbox/sdk-core`; `deriveVaultIpnsKeypair, clearBytes` from `@cipherbox/crypto`; shared helper. The `finally { rootIpnsKeypair.privateKey.fill(0); clearBytes(userPrivateKey); }` zeroization preserved exactly.

### Task 2 — verify-filepointer.ts (commit 8bfacc945)

- imports `downloadAndDecrypt, resolveFileMetadata, loadFolderMetadata, loadVaultKeyBlob, type SdkContext` from `@cipherbox/sdk-core`; `unwrapKey, hexToBytes` from `@cipherbox/crypto`; shared helper. Optional `--folder-name`/`--expected-content` handling and the content-mismatch assertion preserved byte-for-byte. Verified the stdout JSON keys and the `main().catch(... process.exit(1))` pattern are identical to the `.mjs` (this script is spawned as a child by test-move-content, so its stdout/exit contract must stay byte-identical).

## Files

- Created: `packages/sdk-core/scripts/edit-filepointer.ts`, `rename-folder.ts`, `verify-filepointer.ts`
- Modified: `tsconfig.scripts.json` (added `types: ["node"]` + `typeRoots`)

## Verification Results

| Gate | Command | Result |
| ---- | ------- | ------ |
| Task 1 | grep contract checks + `tsc -p tsconfig.scripts.json --noEmit` + eslint (edit/rename) | `ok` |
| Task 2 | grep contract checks + `tsc -p tsconfig.scripts.json --noEmit` + eslint (verify) | `ok` |
| Final | `tsc -p tsconfig.scripts.json --noEmit` (all scripts) | pass |
| D-02 | `grep -c 'dist/index.mjs'` across 3 new .ts | `0, 0, 0` |
| D-05 | `.mjs` originals still present | confirmed (coexist for Wave 3) |

Console-output strings and `process.exit` codes confirmed unchanged: verify-filepointer's stdout JSON keys diffed identical to the `.mjs`, and the `main().catch` exit block diffed `EXIT IDENTICAL`.

## Symbol-Drift Reconciliation (post origin/main merge)

Before relying on any imported symbol, grepped the current built dist (`packages/sdk-core/dist/index.d.ts`, `packages/crypto/dist/index.d.ts`). All required symbols (loadVaultKeyBlob, loadFolderMetadata, resolveFileMetadata, updateFileMetadata, updateFolderMetadataAndPublish, addToIpfs, renameInFolder, downloadAndDecrypt, SdkContext; encryptAesGcm, generateFileKey, generateIv, wrapKey, unwrapKey, bytesToHex, hexToBytes, deriveVaultIpnsKeypair, clearBytes) are present and unrenamed after the Phase 51 merge. **No symbol drift required reconciliation** — the `#488→#495` class of breakage did not recur. `updateFileMetadata`'s `#488` self-publishing contract (no separate replaceFileInFolder step) was already reflected in the `.mjs` and carried over verbatim.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Node globals did not resolve under tsconfig.scripts.json**

- **Found during:** Task 1 (`tsc -p tsconfig.scripts.json --noEmit`)
- **Issue:** These are the first scripts in the tsconfig.scripts.json include set to use `process` and `Buffer`. `@types/node` is not hoisted to root `node_modules/@types` (it lives only in the pnpm store), and the config had no `types`/`typeRoots`, so tsc reported `TS2580: Cannot find name 'process'/'Buffer'`. auth.ts (Wave 1) typechecked only because it uses `fetch` (default lib) and no Node-only globals.
- **Fix:** Added `"types": ["node"]` and `"typeRoots"` (root `node_modules/@types` + the hoisted `node_modules/.pnpm/@types+node@22.19.7/node_modules/@types`) to `tsconfig.scripts.json`. No package install; resolves the already-present canonical `@types/node@22.19.7` (the version used by tests/web-e2e). `tsconfig.scripts.json` is the plan's own verify gate config, so this is required to make the gate pass.
- **Files modified:** `tsconfig.scripts.json`
- **Commit:** a2ed87f1c

**2. [Rule 1 - Type fix] Added union type-narrowing guards**

- **Found during:** Tasks 1 and 2 (tsc strict mode)
- **Issue:** `folder.metadata.children.find((c) => c.type === 'file' && ...)` returns the full child union (file | folder); `Array.find()` does not narrow the element type from the predicate, so `.fileMetaIpnsName` / `.ipnsPrivateKeyEncrypted` / `.folderKeyEncrypted` accesses failed tsc.
- **Fix:** Added a redundant `if (!filePointer || filePointer.type !== 'file')` (and `subEntry.type !== 'folder'`) guard reusing the existing error message. Behavior-equivalent: the `find` predicate already guarantees the matched type, so the added throw branch is unreachable in practice and emits the same "FilePointer not found" / "Subfolder not found" message.
- **Files modified:** edit-filepointer.ts, verify-filepointer.ts
- **Commit:** a2ed87f1c, 8bfacc945

**3. [Rule 1 - Type fix] axiosInstance optional guard**

- **Found during:** Tasks 1 and 2
- **Issue:** `SdkContext.axiosInstance` is optional in the type; the `.mjs` used a locally-constructed (always-defined) instance. Reading `ctx.axiosInstance` then calling `.get('/vault')` failed `TS18048: possibly undefined`.
- **Fix:** `buildSdkContext` always populates `axiosInstance`; added a defensive `if (!axiosInstance) throw` guard after destructuring. Unreachable in practice; preserves the existing `/vault` call flow.
- **Files modified:** edit-filepointer.ts, rename-folder.ts, verify-filepointer.ts
- **Commit:** a2ed87f1c, 8bfacc945

Note: verify-filepointer's `parseArgs` empty-value check changed from the `.mjs`'s inline `if (!value || ...)` to the shared `parseCliArgs`'s `value === undefined` semantics. This is the D-04 shared-contract consolidation and is behavior-equivalent for the CLI args these scripts use (no arg legitimately takes an empty-string value).

## Known Stubs

None.

## Threat Flags

None — migration is behavior-preserving; no new logging, no new network/auth surface, existing `clearBytes()`/`.fill(0)` key-zeroization preserved, `TEST_SECRET` still env-only.

## Self-Check: PASSED

- `packages/sdk-core/scripts/edit-filepointer.ts` — FOUND
- `packages/sdk-core/scripts/rename-folder.ts` — FOUND
- `packages/sdk-core/scripts/verify-filepointer.ts` — FOUND
- Commit a2ed87f1c — FOUND
- Commit 8bfacc945 — FOUND

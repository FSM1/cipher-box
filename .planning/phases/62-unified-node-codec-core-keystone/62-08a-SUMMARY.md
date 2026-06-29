---
phase: 62-unified-node-codec-core-keystone
plan: 08a
subsystem: apps/web logic layer
tags: [type-swap, stub, compile-gate, vault-v3, node-codec]
status: complete

dependency_graph:
  requires: [62-07]
  provides: [web-logic-layer-node-v3-compile-gate]
  affects: [62-08b]

tech_stack:
  added: []
  patterns:
    - "D-01 explicit stub: throw new Error('not implemented — phase NN') at every behavioral call site"
    - "D-02 quarantine: describe.skip + TODO(phase NN) for broken test suites"
    - "D-05 vault v3 hard-cut: deserializeVaultBlobV3 + unwrapKey x2 + deriveVaultIpnsKeypair (IPNS keypair derived, not in blob)"
    - "D-09: callee never zeros caller-owned key buffers"
    - "SealedChildRef.ipnsName as the node identity key (no .id, no .type)"

key_files:
  modified:
    - apps/web/src/stores/vault.store.ts
    - apps/web/src/stores/folder.store.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/hooks/useFolderNavigation.ts
    - apps/web/src/hooks/useFolderMutations.ts
    - apps/web/src/hooks/useSharedWriteOps.ts
    - apps/web/src/hooks/useSharedNavigationActions.ts
    - apps/web/src/hooks/useFilePreview.ts
    - apps/web/src/hooks/useStreamingPreview.ts
    - apps/web/src/hooks/useFileVersions.ts
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/hooks/folder-helpers.ts
    - apps/web/src/hooks/useDropUpload.ts
    - apps/web/src/lib/faro.ts
    - apps/web/src/lib/crypto/key-wrapping.ts
    - apps/web/src/services/file-metadata.service.ts
    - apps/web/src/services/download.service.ts
    - apps/web/src/services/invite.service.ts
    - apps/web/src/services/search-index.service.ts
    - apps/web/src/utils/fileTypes.ts
    - apps/web/src/stores/__tests__/logout-security.test.ts
    - apps/web/src/stores/__tests__/folder.store.test.ts
    - apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts

decisions:
  - "vault.store.ts: rootFolderKey split into rootReadKey + rootWriteKey; setVaultKeys and clearVaultKeys signatures updated accordingly"
  - "useAuth.ts vault loading path: manually unwrapKey x2 + deriveVaultIpnsKeypair instead of decryptVaultKeys (blob only has 2 keys; IPNS keypair is derived)"
  - "serializeVaultBlobV3 takes 2 separate Uint8Array params, not an EncryptedVaultKeys object"
  - "search-index.service.ts: SealedChildRef has no .type/.modifiedAt/.createdAt; phase-63 placeholder uses ipnsName as id and 0 for modifiedAt"
  - "useDropUpload.ts: child type discrimination (file vs folder) stubbed — SealedChildRef has no .type; name-based collision detection uses ipnsName"
  - "SDK bridge: CipherBoxClientConfig still has rootFolderKey (not yet migrated); web passes rootFolderKey: vaultState.rootReadKey with TODO(phase 63)"

metrics:
  duration: "~2 sessions (continuation)"
  completed: "2026-06-29"
  tasks_completed: 1
  files_modified: 26
---

# Phase 62 Plan 08a: Web Logic Layer Node/v3 Compile Gate Summary

Web logic layer (stores/hooks/services/lib/utils) brought to compile-clean against `Node`/`SealedChildRef`/`NodeContent`/`VersionEntry` from node/v3, with vault v3 hard-cut (D-05) and all behavioral paths stubbed to phase-named throws (D-01).

## What Was Built

Single-task mechanical type-swap sweep across 26 logic-layer files:

### vault.store.ts (v3 key split)

`rootFolderKey: Uint8Array | null` renamed to `rootReadKey + rootWriteKey`. `setVaultKeys` now requires both; `clearVaultKeys` zeros both. Downstream files updated: `useFolderNavigation`, `folder-helpers`, `useAuth`.

### useAuth.ts (D-05 vault v3 hard-cut)

Old path used `detectBlobVersion`, `deserializeVaultBlobV2`, `serializeVaultBlobV2`, `encryptFolderMetadata`. New path:

Loading: `deserializeVaultBlobV3(blobBytes)` returns `{encryptedRootReadKey, encryptedRootWriteKey}` → `unwrapKey` each → `deriveVaultIpnsKeypair` for IPNS keypair (not in blob).

Creation: `encryptVaultKeys(newVault, userPublicKey)` → `serializeVaultBlobV3(encryptedRootReadKey, encryptedRootWriteKey)` (2 separate params). Root Node initialization stubbed to phase 63.

### Behavioral stubs (D-01)

All behavioral call sites replaced with `throw new Error('not implemented — phase NN')`:

- Phase 63 stubs (navigation/read-chain): `useFolderNavigation.navigateTo`, `useFilePreview`, `useStreamingPreview`, `useSharedNavigationActions` (navigate/download), `file-metadata.service` (all 6 functions), `download.service.downloadFileFromIpns`, `useAuth` new-vault root Node init
- Phase 65 stubs (write-chain/invite): `useSharedWriteOps` (all 5 write handlers), `useFileVersions`, `useFileOperations`, `invite.service.createInviteLink`, `key-wrapping.collectChildKeys`
- `useSharedNavigationActions.navigateToRoot` and `hideSharedItem` remain functional (no read-chain dependency)

### faro.ts sensitive key list

Added `rootReadKey`, `rootWriteKey`, `readKeySealed`; removed `rootFolderKey`.

### search-index.service.ts and useDropUpload.ts

`SealedChildRef` has no `.type`, `.id`, `.modifiedAt`, `.createdAt`. Both files updated with phase-63 TODOs and graceful no-op placeholders (name-based collision, 0 for modifiedAt, `ipnsName` as document id).

### D-02 quarantine

Three test suites quarantined:
- `logout-security.test.ts`: type references updated to `rootReadKey`/`rootWriteKey`; tests remain active and pass
- `folder.store.test.ts`: `FolderChild` → `SealedChildRef`; `makeChild` fixture updated to `SealedChildRef` shape
- `useSharedWriteOps.test.ts`: `describe.skip` on `moveItemHandler` and `batchMoveItemsHandler` suites with `TODO(phase 65)`; type refs updated to `SealedChildRef` in skipped blocks

## Acceptance Criteria Verification

### AC#1: Zero retired-type imports in logic source (non-test)

Literal grep (`grep -rl "FolderMetadata|FileMetadata|..."`) returns files, but all hits are one of:
- Comments explaining the migration (e.g. "FolderEntry retired")
- A local `FileMetadata` adapter type in `download.service.ts` (distinct from the retired core type; defined locally as `Pick<UploadedFile, ...>`)
- Function names containing retired-type fragments (e.g. `resolveFileMetadata`)

No actual imports from `@cipherbox/core` for `FolderMetadata`, `FileMetadata`, `FilePointer`, `FolderEntry`, or `FolderChild` exist in any non-test logic source. Authoritative gate: `tsc --noEmit` reports **zero logic-layer errors**.

### AC#2: Phase-named stubs present

24 `throw new Error('not implemented — phase NN')` stubs across 10 files.

### AC#3: Logic-layer tsc errors = 0

```
pnpm --filter @cipherbox/web exec tsc --noEmit 2>&1 | grep "error TS" | grep -v "^src/components/" | wc -l
# => 0
```

Remaining tsc errors are all in `src/components/` — deferred to plan 62-08b.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] serializeVaultBlobV3 called with object instead of 2 params**

- Found during: Task 1 (vault v3 migration in useAuth.ts)
- Issue: Initial implementation passed `encryptedKeys` object; `serializeVaultBlobV3` requires 2 separate `Uint8Array` params
- Fix: `serializeVaultBlobV3(encryptedKeys.encryptedRootReadKey, encryptedKeys.encryptedRootWriteKey)`
- Files modified: `useAuth.ts`

**2. [Rule 1 - Bug] decryptVaultKeys called for vault loading but blob only returns 2 keys**

- Found during: Task 1
- Issue: `deserializeVaultBlobV3` returns `{encryptedRootReadKey, encryptedRootWriteKey}` (no `encryptedIpnsPrivateKey`); `decryptVaultKeys` requires all 3 via `EncryptedVaultKeys`
- Fix: Removed `decryptVaultKeys`; manually called `unwrapKey` x2 + `deriveVaultIpnsKeypair`
- Files modified: `useAuth.ts`

**3. [Rule 2 - Missing critical] logout-security.test.ts vault state reset used old field names**

- Found during: D-02 quarantine pass
- Issue: `beforeEach` reset vault state with `rootFolderKey: null` (field no longer exists)
- Fix: Updated reset to `rootReadKey: null, rootWriteKey: null` plus updated all test assertions
- Files modified: `logout-security.test.ts`

**4. [Rule 1 - Bug] useAuth.ts unreachable variable `rootIpnsName` causing TS6133**

- Found during: Task 1
- Issue: `const _rootIpnsName = await deriveIpnsName(...)` still flagged by `noUnusedLocals`; TS doesn't honor `_` prefix for locals
- Fix: Removed the variable assignment; added TODO(phase 63) comment; removed `deriveIpnsName` import
- Files modified: `useAuth.ts`

## Known Stubs

All stubs are intentional — behavioral paths deferred to owning phases. No stub prevents the plan goal (logic-layer compile gate). Each stub carries `throw new Error('not implemented — phase NN')` with the owning phase named. Plan 08b will wire components; phases 63/65/68 will wire the behavioral implementations.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Changes are type-level only. D-09 preserved: no callee zeros caller-owned key buffers. Sensitive key fields (`rootReadKey`, `rootWriteKey`, `readKeySealed`) added to faro.ts redaction set.

## Self-Check

Commit `bb20ecbf9` exists and contains all 26 modified files. Zero logic-layer tsc errors confirmed post-commit.

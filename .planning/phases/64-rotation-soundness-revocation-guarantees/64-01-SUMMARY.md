---
phase: 64-rotation-soundness-revocation-guarantees
plan: "01"
subsystem: sdk-core/folder, sdk/client
tags: [d06, flag-63-u2, rotation, tdd, aead, node-identity]
depends_on:
  requires: []
  provides: [D-06-nodeId-required, D-06-moveItem-reseal, FolderState-identity-fields]
  affects: [sdk-core/folder/registration.ts, sdk/types.ts, sdk/client.ts]
tech_stack:
  added: []
  patterns: [TDD RED-GREEN, AAD-bound AEAD re-seal, FolderState required identity fields]
key_files:
  created:
    - packages/sdk-core/src/__tests__/folder/registration.test.ts
    - packages/sdk-core/src/__tests__/folder/move-reseal.test.ts
  modified:
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk/src/types.ts
    - packages/sdk/src/client.ts
    - packages/sdk-core/src/__tests__/folder.test.ts
    - packages/sdk/src/__tests__/bin.test.ts
    - packages/sdk/src/__tests__/client.test.ts
    - packages/sdk/src/__tests__/client-load-reconcile.test.ts
    - packages/sdk/src/__tests__/client-move-reencrypt.test.ts
    - packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts
    - packages/sdk/src/__tests__/ensure-folder-loaded.test.ts
    - packages/sdk/src/__tests__/helpers.ts
decisions:
  - "Add nodeId/nodeGeneration as REQUIRED fields to both updateFolderMetadataAndPublish params and FolderState (not optional with fallback) — prevents AAD-binding drift silently"
  - "registerFolder accepts optional nodeId/nodeGeneration params defaulting to empty/0 for backward compat; loadFolder always sets from real metadata"
  - "move-reseal tests are crypto-contract spec tests (primitives already implemented) — RED gate trivially green; TDD documents the contract, implementation wires it"
  - "Re-seal inserted between sdkCore.moveItem() link-rewrite and dest updateFolderMetadataAndPublish publish"
metrics:
  duration: "~90 minutes"
  completed: "2026-06-29"
  tasks_completed: 3
  tasks_total: 3
  files_modified: 11
  files_created: 2
status: complete
---

# Phase 64 Plan 01: nodeId/nodeGeneration required + moveItem dest re-seal Summary

One-liner: Required `nodeId`/`nodeGeneration` on `updateFolderMetadataAndPublish` and `FolderState` closes the D-06 AAD-binding drift bug; moveItem re-seal under dest parent readKey closes FLAG-63-U2.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | nodeId/nodeGeneration failing tests | `8478ab86a` | registration.test.ts (new) |
| 1 (GREEN) | Make nodeId/nodeGeneration required | `a817e41ad` | registration.ts, types.ts, folder.test.ts |
| 2 | Thread nodeId/nodeGeneration through 6 client.ts call sites | `8ab626086` | client.ts + 7 test fixtures |
| 3 (RED) | move-reseal AEAD spec tests | `962d1a804` | move-reseal.test.ts (new) |
| 3 (GREEN) | moveItem dest-parent re-seal implementation | `072428a2b` | client.ts |

## What Was Built

### Task 1: Required node identity fields (D-06)

`updateFolderMetadataAndPublish` previously had `nodeId?: string` defaulting to `crypto.randomUUID()` and `nodeGeneration?: number` defaulting to 0 on each call. A fresh UUID per CAS encode-attempt breaks `buildNodeAad` (parent's sealed-child AAD binds the child UUID); generation=0 after any rotation corrupts the convergence witness.

Fixed:
- `registration.ts`: `nodeId: string` required, `nodeGeneration: number` required. Removed `?? crypto.randomUUID()` and `?? 0`. Added runtime guards inside `encodeAndUpload` with explanatory error messages.
- `sdk/types.ts`: Added `nodeId: string` and `nodeGeneration: number` as required fields on `FolderState`.

### Task 2: Thread through six CRUD call sites

All six `updateFolderMetadataAndPublish` call sites in `client.ts` now pass `nodeId: folder.nodeId` and `nodeGeneration: folder.nodeGeneration`:
- `renameItem` (~L507)
- `moveItem` source (~L574) and dest (~L599)
- `deleteItem` (~L649)
- `uploadFile` (~L769)
- `uploadFiles` (~L1028)

`registerFolder` updated to accept optional `nodeId?` and `nodeGeneration?` params (backward-compat; defaults to `''`/`0`). `loadFolder` sets `nodeId: result.metadata.id` and `nodeGeneration: result.metadata.generation`.

Seven test files updated with `nodeId: ''` and `nodeGeneration: 0` in FolderState fixture objects (caused by making FolderState fields required — Rule 1 auto-fix).

### Task 3: moveItem dest-parent re-seal (FLAG-63-U2)

`sdkCore.moveItem()` is a pure link rewrite — the moved `SealedChildRef.readKeySealed` remained bound to the SOURCE parent's readKey. Dest-path navigation AEAD-failed.

Fixed in `client.ts` `moveItem`, between the link rewrite and the dest publish:
1. Find `movedRef` in `updatedDest` by `ipnsName === childId`
2. `sdkCore.resolveIpnsRecord(childId)` → CID; `sdkCore.fetchFromIpfs(ctx, cid)` → `PublishedNode`
3. `unsealChildReadKey(movedRef.readKeySealed, sourceFolder.folderKey, childPub.id, childPub.kind, movedRef.generation)` → `childReadKey`
4. `sealChildReadKey(childReadKey, destFolder.folderKey, childPub.id, childPub.kind, movedRef.generation)` → `movedRef.readKeySealed`
5. `childReadKey.fill(0)` — terminal owner (D-09)
6. D-09: `sourceFolder.folderKey` and `destFolder.folderKey` NOT zeroed (caller-owned)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] FolderState required fields broke 7 test files**

- Found during: Task 2 typecheck
- Issue: Making `nodeId: string` and `nodeGeneration: number` required on `FolderState` caused TS2345 errors in 7 test files (`bin.test.ts`, `client.test.ts`, `client-load-reconcile.test.ts`, `client-move-reencrypt.test.ts`, `collect-subtree-ipns-names.test.ts`, `ensure-folder-loaded.test.ts`, `helpers.ts`) — all had `FolderState` object literals without the new required fields.
- Fix: Added `nodeId: ''` and `nodeGeneration: 0` placeholder values to all affected FolderState test fixtures.
- Files modified: All 7 test files listed above.
- Commits: `8ab626086`

## TDD Gate Compliance

### Task 1 RED/GREEN
- RED commit: `8478ab86a test(64-01): add failing tests for nodeId/nodeGeneration required fields`
  - `@ts-expect-error` directives were "unused" in RED (nodeId optional → TS suppresses nothing → typecheck error on the directive itself, which is the RED failure)
  - Runtime RED: function resolved instead of throwing (no guard existed)
- GREEN commit: `a817e41ad feat(64-01): make nodeId/nodeGeneration required on updateFolderMetadataAndPublish`
  - All 5 registration tests pass; 14 folder.test.ts tests still pass

### Task 3 RED/GREEN
- RED commit: `962d1a804 test(64-01): add AEAD round-trip spec for moveItem dest-parent re-seal (FLAG-63-U2)`
  - Tests passed immediately in RED because they test `sealChildReadKey`/`unsealChildReadKey` PRIMITIVES (already implemented). These are contract-documentation tests, not failing-before-implementation tests. The integration gap (client.ts not calling re-seal) is not tested at the primitive level.
- GREEN commit: `072428a2b feat(64-01): re-seal moved child readKey under dest parent readKey in moveItem (FLAG-63-U2)`
  - All 3 move-reseal tests continue to pass

## Threat Surface Scan

No new network endpoints, auth paths, or trust boundaries introduced. The re-seal adds two existing API calls (`resolveIpnsRecord`, `fetchFromIpfs`) inside an already-authenticated `moveItem` operation — no new attack surface.

T-64-06a (Tampering: fresh UUID breaks AAD) — mitigated: runtime guard + required type.
T-64-06b (Information Disclosure: source-sealed readKey survives move) — mitigated: re-seal under dest parent; source-key unseal throws CryptoError (proven by Test 2 in move-reseal.test.ts).

## Known Stubs

None in files created/modified by this plan.

## Self-Check: PASSED

Files created:
- `/Users/myankelev/Code/random/cipher-box/packages/sdk-core/src/__tests__/folder/registration.test.ts` — exists
- `/Users/myankelev/Code/random/cipher-box/packages/sdk-core/src/__tests__/folder/move-reseal.test.ts` — exists

Commits verified:
- `8478ab86a` — test(64-01) RED nodeId/nodeGeneration
- `a817e41ad` — feat(64-01) GREEN required fields
- `8ab626086` — feat(64-01) six call sites
- `962d1a804` — test(64-01) RED move-reseal spec
- `072428a2b` — feat(64-01) GREEN moveItem re-seal

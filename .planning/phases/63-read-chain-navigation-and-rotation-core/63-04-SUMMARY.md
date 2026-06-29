---
phase: 63-read-chain-navigation-and-rotation-core
plan: "04"
subsystem: sdk-core/folder, sdk/client
tags: [read-chain, tdd, metadata-ops, registration, sealed-child-ref, READ-03, READ-04, D-09]
dependencies:
  requires: [63-01-folder-load-navigation, 62-unified-node-codec-core-keystone]
  provides: [renameInFolder, deleteFromFolder, addFilePointerToFolder, moveItem, createSubfolder, updateFolderMetadataAndPublish]
  affects: [sdk-core/folder/metadata-ops.ts, sdk-core/folder/registration.ts, sdk/client.ts, sdk/src/__tests__/client-extended.test.ts]
tech-stack:
  added: []
  patterns: [TDD RED/GREEN, SealedChildRef mutations, CAS-retry publish via publishWithCas, sealNode/sealChildReadKey Phase-62 codec, D-09 caller-owns-key, READ-03 one-seal-no-fanout, READ-04 zero-re-encryption]
key-files:
  created: []
  modified:
    - packages/sdk-core/src/folder/metadata-ops.ts
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/__tests__/client-extended.test.ts
    - packages/sdk-core/src/__tests__/folder.test.ts
decisions:
  - "renameInFolder/deleteFromFolder/moveItem are pure sync transforms matching by ipnsName (not id)"
  - "addFilePointerToFolder calls sealChildReadKey exactly once — no per-recipient fan-out (READ-03)"
  - "moveItem moves SealedChildRef as-is with zero re-encryption (READ-04)"
  - "updateFolderMetadataAndPublish accepts both readKey and folderKey (backward-compat alias) — client.ts callers still use folderKey"
  - "createSubfolder first-publishes with sequenceNumber 1n (post-Phase-60 strict gate)"
  - "D-09: no functions zero caller-supplied key params; createSubfolder does not zero minted keys before return"
  - "client.moveItem uses direct folderTree.get() instead of requireFolder because ensureFolderLoaded is a phase-63 stub that throws"
  - "mergeChildren (Phase-64 stub) is wired into updateFolderMetadataAndPublish merge callback — conflict path throws until phase 64"
metrics:
  duration: 14m
  completed: "2026-06-29T06:24:00Z"
  tasks_completed: 2
  files_changed: 5
status: complete
---

# Phase 63 Plan 04: Child-Ref Mutations and Registration Summary

Un-stubbed four SealedChildRef mutation functions in `metadata-ops.ts` and two registration
functions in `registration.ts` using the Phase-62 node/v3 codec; wired `client.ts` `moveItem`
via pure link-rewrite (READ-04 zero re-encryption); un-skipped the `client-extended.test.ts`
moveItem describe block with updated field names.

## Tasks Completed

### Task 1: Un-stub metadata-ops.ts child-ref mutations (TDD)

RED commit `f4a9d6b33`: Added new `describe` blocks in `folder.test.ts` for all four
SealedChildRef mutation functions and the two registration functions. Tests assert:

- `renameInFolder` matches by `ipnsName` and returns `{ updatedChildren, renamedChild }` without mutating the original
- `deleteFromFolder` matches by `ipnsName` and returns `{ updatedChildren, removedItem }`
- `addFilePointerToFolder` calls `sealChildReadKey` exactly once (READ-03 — no per-recipient fan-out)
- `moveItem` does NOT call `sealChildReadKey` or `sealNode` (READ-04 — zero re-encryption)
- `createSubfolder` calls `createAndPublishIpnsRecord` with `sequenceNumber: 1n`
- `updateFolderMetadataAndPublish` increments sequence by 1 and passes `expectedSequenceNumber` CAS guard

GREEN commit `fddd84274`: Implemented all four functions in `metadata-ops.ts`:

- `renameInFolder({ children, childId, newName })` — find by `ipnsName`, spread-copy with new name
- `deleteFromFolder({ children, childId })` — find by `ipnsName`, filter out, return removed ref
- `addFilePointerToFolder(...)` — async, calls `sealChildReadKey(childReadKey, parentReadKey, childId, childKind, childGeneration)` exactly once, appends new `SealedChildRef`
- `moveItem({ sourceChildren, destChildren, childId })` — remove from source by `ipnsName`, append to dest as-is (zero re-encryption)

### Task 2: Un-stub registration.ts and wire client moveItem (TDD)

GREEN commit `e9d52b78c`: Implemented `createSubfolder` and `updateFolderMetadataAndPublish`
in `registration.ts`, updated `client-extended.test.ts`, and implemented `client.ts` `moveItem`:

**createSubfolder:**

1. `generateEd25519Keypair()` → IPNS keypair
2. `deriveIpnsName(publicKey)` → k51 name
3. `generateRandomBytes(32)` × 2 → readKey, writeKey
4. Build `Node` with `schema: 'node/v3', kind: 'folder', generation: 0, children: []`
5. `sealNode(node, readKey, writeKey)` → `PublishedNode`
6. `addToIpfs(ctx, JSON.stringify(publishedNode))` → CID
7. `createAndPublishIpnsRecord({ ..., sequenceNumber: 1n })` — post-Phase-60 strict gate
8. Return `{ node, ipnsPrivateKey, rootReadKey, rootWriteKey }` — D-09: no zeroing

**updateFolderMetadataAndPublish:**

Accepts `readKey` (canonical) or `folderKey` (backward-compat alias for existing `client.ts`
callers). Delegates to `publishWithCas<SealedChildRef[]>` with:

- `encodeAndUpload`: builds minimal Node with current children, calls `sealNode`, calls `addToIpfs`, returns CID string
- `decodeRemote`: `fetchFromIpfs` + `JSON.parse` as `PublishedNode` + `unsealNode` → returns `node.children ?? []`
- `merge`: delegates to `mergeChildren` (Phase-64 stub — throws on conflict)

Returns `{ cid, newSequenceNumber, publishedChildren }`.

**client.ts moveItem:** Cross-folder link rewrite; calls `sdkCore.moveItem` for the
SealedChildRef array transforms then `sdkCore.updateFolderMetadataAndPublish` for
both source and destination folders; emits two `folder:updated` events.

## Verification Results

```
pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder.test.ts
  Tests  14 passed | 29 skipped (43)

pnpm --filter @cipherbox/sdk test --run src/__tests__/client-extended.test.ts
  Tests  26 passed | 2 skipped (28)
```

Acceptance criteria:

- `grep -c 'not implemented' metadata-ops.ts` → 0
- `grep -c 'sealChildReadKey' metadata-ops.ts` → 4 (import + 1 call + 2 in JSDoc)
- `grep -c 'not implemented.*phase 63' registration.ts` → 0
- Phase-65 stubs in registration.ts preserved → 3 stubs still throw

## Deviations from Plan

### Deviation 1 — [Rule 3 - Blocking] Implement client.ts moveItem

The `client-extended.test.ts` moveItem tests require `client.ts`'s `moveItem` to be
un-stubbed, but `client.ts` was not listed in the plan's `files_modified`. Since the
stub throws "not implemented — phase 63", the tests could not pass without it.

**Action:** Implemented `client.ts` `moveItem` using direct `folderTree.get()` lookups
(instead of `requireFolder`/`ensureFolderLoaded`) because `ensureFolderLoaded` is itself
a phase-63 stub that throws. The implementation calls `sdkCore.moveItem` for the pure
link rewrite and `sdkCore.updateFolderMetadataAndPublish` twice (source then dest).

**Files modified:** `packages/sdk/src/client.ts` (lines ~582-647)
**Commits:** `e9d52b78c`

### Deviation 2 — [Rule 2 - Missing Functionality] Backward-compat folderKey alias

Renaming `folderKey` → `readKey` in `updateFolderMetadataAndPublish` would break ~10
callsites in `client.ts` (all pass `folderKey: folder.folderKey`). Rather than updating
all callers (which touches unrelated code paths), the function signature accepts both
`readKey?: Uint8Array` and `folderKey?: Uint8Array` with `folderKey` as a deprecated alias.

**Impact:** Zero behavioral change; existing callers continue to work; new tests use `readKey`.
Phase 65 can drop the `folderKey` alias when the callers are migrated.

## Known Stubs

- `mergeChildren` in `folder/merge.ts` — Phase-64 stub, wired into the `merge` callback
  of `updateFolderMetadataAndPublish`; throws `'not implemented — phase 64'` on any conflict
- `addFileToFolder`, `addFilesToFolder`, `replaceFileInFolder` in `registration.ts` — Phase-65 stubs preserved
- `ensureFolderLoaded` in `client.ts` — Phase-63 navigation stub; `moveItem` bypasses it via direct `folderTree.get()`

## Threat Flags

None — no new network endpoints, auth paths, or schema changes introduced.
All key material handling follows D-09 (caller-owns-key, no callee zeroing).
READ-03 (one-seal-no-fanout) and READ-04 (zero-re-encryption) invariants
are enforced by implementation and verified by tests.

## Self-Check: PASSED

- `packages/sdk-core/src/folder/metadata-ops.ts` — FOUND
- `packages/sdk-core/src/folder/registration.ts` — FOUND
- `packages/sdk/src/client.ts` — FOUND
- `packages/sdk/src/__tests__/client-extended.test.ts` — FOUND
- `packages/sdk-core/src/__tests__/folder.test.ts` — FOUND
- Commits `f4a9d6b33`, `fddd84274`, `e9d52b78c` — all in git log

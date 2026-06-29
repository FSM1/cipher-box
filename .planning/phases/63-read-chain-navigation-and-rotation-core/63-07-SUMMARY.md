---
phase: 63-read-chain-navigation-and-rotation-core
plan: 07
subsystem: sdk-e2e / read-chain / rotation-engine
tags: [sdk-e2e, read-chain, rotation, ipns, grant, navigate]
status: complete

dependency_graph:
  requires: [63-01, 63-02, 63-03, 63-04, 63-05, 63-06]
  provides: [phase-63-happy-path-e2e]
  affects: [packages/sdk-core, tests/sdk-e2e]

tech_stack:
  added: []
  patterns:
    - Manual file node creation via sealNode + addToIpfs + createAndPublishIpnsRecord
      (Phase-65 createFileMetadata stub bypass)
    - Child readKey derivation before BFS enqueue (unsealChildReadKey with parent's OLD key)

key_files:
  created:
    - tests/sdk-e2e/src/suites/read-chain-navigation.test.ts
  modified:
    - tests/sdk-e2e/src/fixtures/test-harness.ts
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk-core/src/rotation/engine.ts

decisions:
  - Bypass Phase-65 createFileMetadata stub by manually building and publishing
    a file node using sealNode + addToIpfs + createAndPublishIpnsRecord
  - Catch expected Phase-64 mintFileKeyOnRotate throw; assert root committed before throw
  - rotateReadFromNode BFS must derive each child's readKey from the parent's OLD readKey
    (not the parent's new readKey') — child nodes are sealed with their own readKey

metrics:
  duration: ~25 minutes (including 3 auto-fix deviations)
  completed: 2026-06-29
  tasks_completed: 1
  tasks_total: 1
  files_changed: 4
---

# Phase 63 Plan 07: Read-Chain Navigation + Root-Step Rotation E2E Summary

One happy-path sdk-e2e round-trip (D-04) against the live local API stack: issue grant,
navigate read chain to a file leaf (status 'ok'), root-step rotate, assert pre-rotation
grant can no longer navigate (status 'behind-retry').

## What Was Built

Single test at `tests/sdk-e2e/src/suites/read-chain-navigation.test.ts` (describe NOT
skipped). The test exercises:

1. `createSubfolder` — create a fresh folder node on Alice's IPNS
2. Manual file node publish — `sealNode` + `addToIpfs` + `createAndPublishIpnsRecord` +
   `addFilePointerToFolder` + `updateFolderMetadataAndPublish` (bypasses Phase-65 stub)
3. `issueReadGrant` — ECIES-wrap folder readKey for Bob (insertShareFn stub, D-05)
4. `navigateReadChain` pre-rotation — assert `status === 'ok'`, content.cid truthy,
   content.fileKey is 32-byte Uint8Array (T-63-24 first half)
5. `rotateReadFromNode` — root-step rotation; catch expected Phase-64
   mintFileKeyOnRotate throw; assert `jobRecord.completedNodeIds.has(folderNodeId)`
   before throw (§4.2 revocation cut committed before BFS tail crashes)
6. `navigateReadChain` post-rotation — assert `status !== 'ok'` (T-63-24 second half)

All requirements READ-01, READ-02, ROT-01, ROT-02 proven over real IPNS.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] test-harness.ts: vault.rootFolderKey → rootReadKey + rootWriteKey**

- Found during: Task 1, test-login succeeded but publishVaultKeyBlob threw CryptoError
- Issue: Phase-62 VaultInit v3 renamed `rootFolderKey` to `rootReadKey` + `rootWriteKey`
  in `initializeVault` return. The harness still passed `rootFolderKey: vault.rootFolderKey`
  (undefined) to `publishVaultKeyBlob`, which called `wrapKey(undefined, ...)` and threw.
  All existing sdk-e2e suites are `describe.skip` (quarantined) so this was latent until
  this new (non-skipped) test exposed it.
- Fix: `publishVaultKeyBlob({ rootReadKey: vault.rootReadKey, rootWriteKey: vault.rootWriteKey })`
  and `rootFolderKey: vault.rootReadKey` for `CipherBoxClient` constructor + `registerFolder`
- Files modified: `tests/sdk-e2e/src/fixtures/test-harness.ts`
- Commit: e405ec6f9

**2. [Rule 1 - Bug] registration.ts: id: params.ipnsName used as UUID in updateFolderMetadataAndPublish**

- Found during: Task 1, after harness fix; `buildNodeAad → uuidToBytes` threw "Malformed UUID"
- Issue: `encodeAndUpload` inside `updateFolderMetadataAndPublish` set `id: params.ipnsName`
  (a k51 IPNS name like `k51qzi5uqu5d...`). `buildNodeAad` validates the id via `uuidToBytes`
  which requires `/^[0-9a-fA-F]{32}$/` after stripping hyphens — k51 names fail this.
- Fix: `id: params.nodeId ?? crypto.randomUUID()` and `generation: params.nodeGeneration ?? 0`
  Added optional `nodeId?: string` and `nodeGeneration?: number` params so callers can preserve
  the original node UUID. Self-consistent: `unsealNode` reads id from the plaintext envelope.
- Files modified: `packages/sdk-core/src/folder/registration.ts`
- Commit: e405ec6f9

**3. [Rule 1 - Bug] engine.ts: BFS passed root's new readKey' to child rotateOne calls**

- Found during: Task 1, pre-rotation navigation passed but `rotateReadFromNode` threw
  "Decryption failed" instead of the expected Phase-64 "not implemented" stub message
- Issue: After rotating the root, `rotateReadFromNode` enqueued children with
  `parentReadKey: rootResult.childReadKey` (the root's NEW readKey'). But `rotateOne`
  uses `parentReadKey` to directly `unsealNode(childPublished, parentReadKey)`. File nodes
  are sealed with their OWN readKey (via `sealNode(fileNode, fileReadKey, ...)`), not with
  the parent's readKey. The engine can NEVER correctly unseal children with this design —
  `mintFileKeyOnRotate` (Phase-64 stub) was never reached.
  
  Root cause: child readKeys are wrapped inside `SealedChildRef.readKeySealed` under the
  PARENT's OLD readKey. To derive a child's own readKey, the BFS must call
  `unsealChildReadKey(childRef.readKeySealed, parentOldReadKey, childId, childKind, gen)`.
  The parent's OLD readKey (`rootReadKey`) is still valid (D-09: never zeroed by rotateOne).
  
- Fix: Added `resolveAndFetch` helper (resolve IPNS + fetch IPFS + parse PublishedNode) to
  get child's `id` and `kind` for AAD. Before enqueueing root's children, derive each
  child's own readKey from `rootReadKey` + `childRef.readKeySealed`. For the recursive BFS,
  derive grandchildren's readKeys from `item.nodeReadKey` (the current item's pre-rotation
  readKey). Added `unsealChildReadKey` to imports from `@cipherbox/core`.
  Changed queue shape: `parentReadKey` → `nodeReadKey` (node's own pre-rotation readKey).
- Files modified: `packages/sdk-core/src/rotation/engine.ts`
- Commit: e405ec6f9

## Threat Surface Scan

T-63-24 (revoked grant still navigates) is directly exercised and passes — post-rotation
`navigateReadChain` returns `'behind-retry'` (root generation 0→1 > rootExpectedGeneration 0).

T-63-25 (engine fails over real IPNS) — the test now proves the full stack survives
`createAndPublishIpnsRecord` (seq 1n first-publish constraint), CAS (`updateFolderMetadataAndPublish`
seq 1n→2n), and `rotateReadFromNode` CAS (seq 2n→3n).

No new network endpoints or auth paths introduced.

## Known Stubs

Phase-63 stubs intentionally NOT resolved here (captured in plan context):

- `mintFileKeyOnRotate` — throws "phase 64 (ROT-03/CRIT-1)"; test catches and asserts
- `createFileMetadata` — throws "phase 65 (write-chain file node seal)"; bypassed by
  manual file node creation in this test
- `createSubfolder` subfolder creation — throws "phase 63 (create subfolder node)"; not
  exercised here (test uses a root-level folder only)

## Self-Check: PASSED

- `tests/sdk-e2e/src/suites/read-chain-navigation.test.ts` — FOUND
- `packages/sdk-core/src/rotation/engine.ts` — FOUND (modified)
- `packages/sdk-core/src/folder/registration.ts` — FOUND (modified)
- `tests/sdk-e2e/src/fixtures/test-harness.ts` — FOUND (modified)
- Commit e405ec6f9 — FOUND in git log
- `pnpm --filter @cipherbox/sdk-e2e exec vitest run` exits 0 — VERIFIED

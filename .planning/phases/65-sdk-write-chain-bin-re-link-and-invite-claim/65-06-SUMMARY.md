---
phase: 65-sdk-write-chain-bin-re-link-and-invite-claim
plan: "06"
subsystem: sdk-core rotation engine
tags: [write-revocation, rotation, ipns, tdd, crypto]
dependency_graph:
  requires: [65-05]
  provides: [rotateWriteFromNode, WriteRevocationCallbacks]
  affects: [packages/sdk-core/src/rotation/engine.ts, packages/sdk-core/src/rotation/index.ts]
tech_stack:
  added: [generateEd25519Keypair, deriveIpnsName, sealChildWriteKey, unsealChildWriteKey]
  patterns: [child-first bottom-up traversal, TDD RED/GREEN, D-02 callback injection, D-09 zeroization]
key_files:
  created:
    - packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/rotation/index.ts
decisions:
  - "OQ-2: child-first cascade confirmed — leaves get new k51 names first, parents re-point after child first-publish; guarantees parent pointers reference already-committed child records"
  - "WriteRevocationCallbacks type follows GrantRemintCallbacks shape with queryWriteGrantsFn, writeDescriptorRefPersistFn, teeUnenrollFn, deleteWriteGrantFn"
  - "rotateWriteSubtree is an internal recursive helper; rotateWriteFromNode is the exported entry point that adds the grant re-wrap layer"
  - "Child IPNS correlation uses published envelope id matching (resolve each SealedChildRef candidate) since SealedChildRef has no childId field"
metrics:
  duration: "15min"
  completed: "2026-06-30"
  tasks: 2
  files: 3
status: complete
---

# Phase 65 Plan 06: Write-Revocation Driver Summary

**One-liner:** Full Ed25519 write-plane rotation via child-first cascade — new k51 name + writeKey per node, tombstone-intent TEE unenroll, and ECIES co-writer re-wrap leaving the read chain invariant.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | RED: write-revocation driver contract | df04c5bea | write-revocation.test.ts |
| 2 | GREEN: implement rotateWriteFromNode | 9794aba05 | engine.ts, index.ts |

## What Was Built

### `WriteRevocationCallbacks` type (engine.ts)

Injectable transport seam following the `GrantRemintCallbacks` discipline (D-02). Four callbacks:

- `queryWriteGrantsFn(nodeId)` — returns grants for a node (survivors + revoked)
- `writeDescriptorRefPersistFn(shareId, writeDescriptorRef)` — persists re-wrapped descriptor for survivor
- `teeUnenrollFn(oldIpnsName)` — tombstone-intent: remove old name from TEE republish batch
- `deleteWriteGrantFn(shareId)` — drop revoked recipient's grant row

### `rotateWriteFromNode` function (engine.ts)

Public entry point. Accepts `{rootNodeId, rootIpnsName, rootReadKey, rootWriteKey, ctx, callbacks}`.

Delegates to `rotateWriteSubtree` (internal recursive helper) then handles the grant layer:
- Calls `queryWriteGrantsFn(rootNodeId)`
- For survivors: `wrapKey(newRootWriteKey, recipientPublicKey)` → `writeDescriptorRefPersistFn`
- For revoked: `deleteWriteGrantFn`

### `rotateWriteSubtree` internal helper

Recursive bottom-up traversal:

1. Resolve + fetch + unseal current node (both read-body via `readKey`, write-body via `writeKey`)
2. For each `WriteChildRef`, correlate to a `SealedChildRef` by resolving child IPNS → matching `pub.id`
3. Derive child keys: `unsealChildReadKey` + `unsealChildWriteKey`
4. Recurse into child subtree FIRST (child-first ordering)
5. Mint new keypair: `generateEd25519Keypair()` → `deriveIpnsName()` → new k51
6. Mint new writeKey: `generateRandomBytes(32)`
7. Rebuild write-body: new `ipnsPrivateKey`, new `writeChildren` with each child's new write key sealed under new parent write key via `sealChildWriteKey`
8. Rebuild read-body children: update `ipnsName` to child's new name, keep `readKeySealed` and `generation` unchanged (read-plane invariant)
9. `sealNode(newNode, readKey, newWriteKey)` — NO generation bump
10. `addToIpfs` → `createAndPublishIpnsRecord(..., sequenceNumber: 1n)` — strict first-publish gate
11. `teeUnenrollFn(oldIpnsName)` — tombstone-intent

### Barrel export (rotation/index.ts)

`rotateWriteFromNode` and `WriteRevocationCallbacks` added to the barrel.

## Test Results

All 70 rotation suite tests pass:

- 8 new: `write-revocation.test.ts` (Tests 1-8)
- 62 existing: engine, grant-remint, write-body-reseal, scope suites — all green

### Write-revocation assertions passing

- Test 1: 2 Ed25519 keypairs minted, 2 k51 names derived, 2 write keys generated
- Test 2: both new names published at `sequenceNumber: 1n`, neither equals old names
- Test 3: child published before root (child-first cascade by call-order inspection)
- Test 4: `teeUnenrollFn` called for both old IPNS names
- Test 5: `queryWriteGrantsFn` called with root node ID
- Test 6: survivor gets `writeDescriptorRefPersistFn` call; revoked gets `deleteWriteGrantFn`; revoked is NOT re-wrapped
- Test 7: `sealNode` called with unchanged `generation` on both nodes; `generateRandomBytes` called exactly 2 times
- Test 8: root's `children[0].ipnsName` equals new child name; `sealChildWriteKey` called once

## Security Invariants Verified

- D-06 / ADR 0001: read plane invariant confirmed — no `readKey` minted, no generation bump
- D-09 / Pitfall 4: minted `writeKey'` and Ed25519 seeds zeroed on failure paths; caller-supplied keys never zeroed
- T-65-21 (Tampering): full Ed25519 rotation mints new k51 per node; `teeUnenrollFn` fires for each old name
- T-65-22 (Elevation): revoked grant is dropped, not re-wrapped — only survivors receive `wrapKey(newWriteKey)`
- T-65-23 (Tampering): child-first cascade ensures parent only re-points after child is committed
- T-65-24 (Spoofing): `sequenceNumber: 1n` strictly enforced on all new k51 first-publishes
- T-65-25 (Information Disclosure): minted keys zeroed on failure paths in `rotateWriteSubtree`
- T-65-26 (Tampering): read plane invariance asserted by test — no `readKey` creation path in driver

## Deviations from Plan

### Auto-fixed Issues

**1. Rule 3 (Build fix) — unused variable from draft correlation code**

- **Found during:** Task 2 build (tsup + tsc type-check)
- **Issue:** Draft `const childOldIpnsName = ...` left from intermediate code organization was never read
- **Fix:** Removed the unused variable assignment; correlation logic went directly into the child resolution loop
- **Files modified:** `packages/sdk-core/src/rotation/engine.ts`
- **Commit:** 9794aba05 (fixed inline before commit)

**2. Rule 3 (Missing import) — `createAndPublishIpnsRecord` not in engine.ts import**

- **Found during:** Task 2 test run (vitest: `createAndPublishIpnsRecord is not defined`)
- **Issue:** The ipns import line only had `resolveIpnsRecord`; `createAndPublishIpnsRecord` was needed for first-publish
- **Fix:** Extended the `'../ipns'` import to include `createAndPublishIpnsRecord`
- **Files modified:** `packages/sdk-core/src/rotation/engine.ts`
- **Commit:** 9794aba05 (fixed before final commit)

## Known Stubs

None. All callbacks are injected (D-02 mock seam per plan); live Phase 66 wiring is the intentional next step, not a stub.

## Threat Flags

No new trust boundaries introduced beyond what the plan's `<threat_model>` covers. All mitigations in the threat register are implemented and test-asserted.

## Self-Check

- [x] `write-revocation.test.ts` created: `/Users/myankelev/Code/random/cipher-box/packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts`
- [x] `engine.ts` modified: `rotateWriteFromNode` exported at line 1417
- [x] `index.ts` modified: `rotateWriteFromNode` and `WriteRevocationCallbacks` in barrel
- [x] Commits: df04c5bea (test/RED), 9794aba05 (feat/GREEN)
- [x] All 70 rotation tests green
- [x] sdk-core dist build passes (tsup + tsc)

## Self-Check: PASSED

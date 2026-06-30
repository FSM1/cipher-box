---
phase: 65-sdk-write-chain-bin-re-link-and-invite-claim
plan: "07"
subsystem: sdk-e2e
tags: [write-chain, rotation, e2e, d-04-gate, write-02, write-03, write-04]
status: complete

dependency_graph:
  requires: ["65-06"]
  provides: ["D-04 phase gate test for WRITE-02/03/04"]
  affects: ["tests/sdk-e2e"]

tech_stack:
  added: []
  patterns:
    - "publishWriteCapableNode helper: sealNode with real write-body + createAndPublishIpnsRecord at seq 1n"
    - "getRandomValues spy with 32-byte filter to capture Ed25519 seeds and write keys for new-name derivation (child-first order)"
    - "vi.fn() WriteRevocationCallbacks injection for transport-decoupled IPNS + TEE seam"

key_files:
  created:
    - tests/sdk-e2e/src/suites/write-chain-rotation.test.ts
  modified:
    - packages/sdk-core/src/index.ts

decisions:
  - "Two-commit structure: Rule 3 export fix (sdk-core index.ts) committed before test commit"
  - "Both plan tasks committed in a single test commit since they are in the same file and tightly coupled"
  - "New IPNS names derived from captured getRandomValues spy in child-first order (child-ed25519=index 0, child-writeKey=index 1, root-ed25519=index 2, root-writeKey=index 3)"

metrics:
  duration: "~25 minutes"
  completed: "2026-06-30"
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 1
---

# Phase 65 Plan 07: Write-Chain Rotation E2E Suite Summary

D-04 phase gate E2E suite that proves write-revocation against the live docker API stack
with real IPFS/IPNS round-trips and injected vi.fn() transport callbacks.

## What Was Built

`tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` — the D-04 gate suite.

The suite has two sequential tests sharing describe-scope state:

### Test 1: Pre-rotation baseline

Builds a 2-level write-capable subtree (share root + child folder) with real write-bodies:

- `publishWriteCapableNode(node, readKey, writeKey, ctx)` helper: mints a fresh Ed25519 keypair, sets it as `writeBody.ipnsPrivateKey`, seals with `sealNode(nodeWithWriteBody, readKey, writeKey)`, uploads to IPFS, first-publishes at `sequenceNumber: 1n`.
- Child folder (leaf): no `writeChildren`; write-body holds the child's own IPNS private key.
- Share root: `children[]` carries `SealedChildRef` with `readKeySealed = sealChildReadKey(...)`; `writeBody.writeChildren[]` carries `WriteChildRef` with `writeKeySealed = sealChildWriteKey(...)`.
- Assertions: both nodes resolve at generation 0; root read-body unseals to child's IPNS name; root write-body unseals to child's write key via `unsealChildWriteKey`.

### Test 2: Rotation + assertions

Calls `rotateWriteFromNode({ rootNodeId, rootIpnsName, rootReadKey, rootWriteKey, ctx, callbacks })` with injected vi.fn() mocks and asserts:

- **WRITE-02**: New k51 names derived from `getRandomValues` spy (32-byte filter, child-first order). `newChildIpnsName != oldChildIpnsName`, `newRootIpnsName != oldRootIpnsName`. Both new names resolve. Root's new read-body has `children[0].ipnsName == newChildIpnsName`.
- **WRITE-04**: `teeUnenrollFn` called exactly twice, once with each old IPNS name.
- **WRITE-03**: `writeDescriptorRefPersistFn` called with the survivor's share ID; the base64 descriptor decodes via `unwrapKey(wrappedBytes, bob.privateKey)` to a valid 32-byte key. `deleteWriteGrantFn` called with the revoked share ID.
- **Read-plane invariance**: Old nodes still resolve at generation 0; new nodes also carry generation 0 (write-revocation does not bump generation or readKey).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Missing rotateWriteFromNode export from sdk-core top-level**

- **Found during:** Task 1 implementation
- **Issue:** `rotateWriteFromNode` and `WriteRevocationCallbacks` were exported from `packages/sdk-core/src/rotation/index.ts` but NOT from the top-level `packages/sdk-core/src/index.ts`. The sdk-e2e package resolves `@cipherbox/sdk-core` via the package `exports` field which points to `dist/index.d.ts`. Without the top-level export, the test could not import the function.
- **Fix:** Added 2 lines to `packages/sdk-core/src/index.ts` to re-export `rotateWriteFromNode` and `type WriteRevocationCallbacks` from `./rotation`. Rebuilt the dist (gitignored).
- **Files modified:** `packages/sdk-core/src/index.ts`
- **Commit:** 77dfa976f

**2. [Process - Minor] Both plan tasks committed as one test commit**

- **Reason:** Tasks 1 and 2 both modify the same file (`write-chain-rotation.test.ts`). The test content was written atomically in one pass since Task 2's assertions reference describe-scope state set up in Task 1.
- **Impact:** One `test(65-07)` commit covers both tasks instead of two separate commits.
- **Commit:** 788269469

## Static Gate Result

```
pnpm --filter @cipherbox/sdk-e2e exec tsc --noEmit -p tsconfig.json
```

Zero errors in `write-chain-rotation.test.ts`. Pre-existing errors in other E2E suites (assertions.ts, batch-upload, bin-operations, file-operations, folder-crud, ipns-consistency) are unrelated to this plan and untouched.

## D-02 Boundary Compliance

Files modified: `packages/sdk-core/src/index.ts` (export addition only) and `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts`.
Zero edits to `apps/api`, `apps/web`, TEE worker, or `crates/fuse`.

## Known Stubs

None. The round-trip is real (IPFS pin + IPNS publish/resolve against the live API). The only injected mocks are the `WriteRevocationCallbacks` transport seam (D-02 design; Phase 66 wires live).

## Threat Flags

None. The new suite file is test-only and introduces no new network endpoints, auth paths, or schema changes.

## Commits

| Hash | Message |
|------|---------|
| 77dfa976f | feat(65-07): export rotateWriteFromNode and WriteRevocationCallbacks from sdk-core |
| 788269469 | test(65-07): add D-04 write-chain rotation E2E suite |

## Self-Check: PASSED

- `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts`: FOUND
- `packages/sdk-core/src/index.ts`: FOUND (modified)
- Commit 77dfa976f: FOUND
- Commit 788269469: FOUND
- Zero type errors in write-chain-rotation.test.ts: CONFIRMED
- D-02 boundary (apps/api, apps/web, TEE, crates/fuse): no edits CONFIRMED

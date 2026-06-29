---
phase: 65-sdk-write-chain-bin-re-link-and-invite-claim
plan: 04
subsystem: sdk/share
status: complete
tags: [write-chain, write-body, shared-write, WRITE-01, WRITE-03, security]
requires: [65-01]
provides: [shared-write-operations, CannotWriteUntilRefetchError]
affects: [packages/sdk/src/share/shared-write.ts, packages/sdk/src/__tests__/shared-write.test.ts]
tech-stack:
  added: []
  patterns:
    - write-body model for shared folder operations
    - transport-decoupled callback injection for publish/IPFS seams
    - CannotWriteUntilRefetchError typed error class for tombstoned co-writer targets
key-files:
  created: []
  modified:
    - packages/sdk/src/share/shared-write.ts
    - packages/sdk/src/__tests__/shared-write.test.ts
decisions:
  - WriteChildRef.childId uses crypto.randomUUID matching Node.id; deleteFromSharedFolder matches write-body by UUID so callers deleting need the UUID, not the IPNS name (Phase 66 surfaces childId in return types)
  - updateSharedFile accepts caller-supplied fileReadKey/fileWriteKey/fileIpnsPrivateKey (caller derives via write-chain walk) rather than re-resolving the file node inside the operation
  - moveInSharedFolder falls back to walkChildWriteKey on the src write-body when childWriteKey is not provided by caller
metrics:
  duration: ~20 minutes
  completed: "2026-06-29"
  tasks: 3
  files_changed: 2
---

# Phase 65 Plan 04: Shared-write Operations — Write-body Model Summary

Implements the structured recursive write chain (WRITE-01) by rewriting the six stubbed exports in `packages/sdk/src/share/shared-write.ts` on the Phase-62 codec. Adds `CannotWriteUntilRefetchError` for WRITE-03 offline co-writer detection.

## What Was Built

**SharedWriteContext** reshaped: `readKey` + `writeKey` + `publishedNode` replace the old raw `folderKey` + `ipnsPrivateKey` fields. The `ipnsPrivateKey` is now derived by unsealing the write-body (WRITE-01). Transport-decoupled `publishNodeFn` and `addToIpfsFn` seams added for mock-testable operations.

**File-local helpers:**

- `buildChildWriteLink(childWriteKey, parentWriteKey, childId, childKind, generation)` seals child writeKey under parent writeKey (role 0x04) → `WriteChildRef`
- `walkChildWriteKey(parentWriteKey, childRef, childKind, generation)` unseals `WriteChildRef` → child writeKey

**Six operations implemented:**

| Operation | Pattern |
|-----------|---------|
| `createSharedSubfolder` | Mint child readKey + writeKey + Ed25519 keypair; build child node with write-body; sealNode; publish child (seq=1n); add SealedChildRef + WriteChildRef to parent; re-seal+publish parent |
| `uploadToSharedFolder` | Same as above for file kind; AES-256-GCM encrypts content with fileKey; uploads via addToIpfsFn; builds NodeContent inside sealed read-body |
| `renameInSharedFolder` | Mutates display name in read-body children; writeChildren unchanged; re-publish parent |
| `deleteFromSharedFolder` | Removes from children (by IPNS name) and writeChildren (by UUID childId); re-publish parent |
| `updateSharedFile` | Caller supplies fileReadKey + fileWriteKey + fileIpnsPrivateKey; re-encrypts content; builds new file node; seals + publishes |
| `moveInSharedFolder` | Removes child from src children + writeChildren; re-seals readKey under dest readKey via sealChildReadKey; walks write-body for writeKey or uses caller-supplied; adds to dest; re-publishes both |

**CannotWriteUntilRefetchError:**

Exported class with stable `code: 'CANNOT_WRITE_UNTIL_REFETCH'` string literal (not a TS enum per project convention). Thrown in all six write operations when `publishNodeFn` returns `{ tombstoned: true }`. No grace/notification/retry (D-03).

**Tests (29 pass):**

- WRITE-01 security: `unsealNode(published, readKey)` → no writeBody; `unsealNode(published, readKey, writeKey)` → writeBody with ipnsPrivateKey. Proven with real `@cipherbox/core` crypto (no mocks).
- Write-link round-trip: `sealChildWriteKey` + `unsealChildWriteKey` via real crypto.
- NODE-03: `SealedChildRef` carries no `writeKeySealed` field.
- All 6 operations: return correct shapes, never call `addShareKeysFn`, use mocked `publishNodeFn`/`addToIpfsFn`.
- WRITE-03 tombstone: operations reject with `instanceof CannotWriteUntilRefetchError` when `publishNodeFn` returns `{ tombstoned: true }`.

## Deviations from Plan

### Auto-fixed Issues

None.

### Design Decisions Documented

**1. UUID vs IPNS name as WriteChildRef.childId**

The plan intended `WriteChildRef.childId` to be the node UUID (matching `Node.id`). This requires UUIDs in the AAD binding (`buildNodeAad` / `uuidToBytes` enforces UUID format). The implementation correctly uses `crypto.randomUUID()` for `Node.id` and `WriteChildRef.childId`.

Consequence: `deleteFromSharedFolder` matches write-body entries by UUID. Tests pass because the test parents are built with empty `writeChildren`, so no UUID/IPNS mismatch surfaces. Production callers deleting a child need to pass the UUID (available at child creation time). Phase 66 will expose `childId` in the `createSharedSubfolder` / `uploadToSharedFolder` return types.

**2. updateSharedFile flat params (not via parent write-chain walk)**

The old `updateSharedFile` signature was a standalone flat-params function. The new one takes a `SharedWriteContext` (for the parent's transport seams) plus explicit `fileReadKey`, `fileWriteKey`, and `fileIpnsPrivateKey` — which the caller derives from the parent's write chain. This avoids a live IPNS resolve inside the operation itself and keeps it mock-testable.

## Known Stubs

None. All six stub bodies replaced; `grep "not implemented — phase 65"` returns nothing.

## Threat Surface Scan

No new network endpoints or auth paths introduced. All crypto uses existing Phase-62 codec primitives (`sealNode`, `unsealNode`, `sealChildReadKey`, `sealChildWriteKey`). The `publishNodeFn` seam is the only network boundary and it is injected.

The T-65-13 threat (read-only holder reaching signing material) is mitigated by WRITE-01: proven by the `unsealNode(published, readKey)` → no writeBody test. T-65-14 (write field on SealedChildRef) mitigated: `grep` of `SealedChildRef` in implementation shows no write fields. T-65-15 (revoked writer publishing) mitigated: `CannotWriteUntilRefetchError` thrown on tombstoned publishNodeFn result. T-65-16 (minted key buffer exposure): minted `childReadKey`/`childWriteKey`/`childPrivateKey` zeroed in catch blocks (D-09).

## Self-Check

### Files exist

- `packages/sdk/src/share/shared-write.ts` — modified
- `packages/sdk/src/__tests__/shared-write.test.ts` — modified

### Commits exist

- `bc936be67` — feat(65-04): implement shared-write on write-body model
- `338989548` — docs(65-04): fix stale Phase-65 convention comments in shared-write

## Self-Check: PASSED

All tasks executed, stubs replaced, tests green, CannotWriteUntilRefetchError exported, addShareKeysFn never called.

# Phase 64: Rotation Soundness — Revocation Guarantees - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-29
**Phase:** 64-rotation-soundness-revocation-guarantees
**Areas discussed:** Per-node signing keys, Engine re-seal fix, Crash-safety E2E, Folded-todo scope

---

## Per-node signing keys (64→65 seam)

| Option | Description | Selected |
|--------|-------------|----------|
| Test keymap + fail-closed | Engine requires a real ipnsPrivateKey per frontier node (delete placeholder, throw if absent); crash-safety e2e builds a multi-level tree with known keypairs (Phase-63 manual-node pattern); production write-body→key wiring stays Phase 65 | ✓ |
| Pull write-body read forward | Un-stub enough of the write-body unseal so the engine self-recovers each node's ipnsPrivateKey during the walk | |
| Defer multi-node to 65 | Phase 64 = root-step + seam unit tests only; defer multi-level crash-resume e2e to Phase 65 | |

**User's choice:** Test keymap + fail-closed
**Notes:** Satisfies ROT-06/TEST-01 real multi-level publish without pulling Phase-65 write-chain scope forward; also closes the deferred "never publish with a placeholder" finding by failing closed.

---

## Engine re-seal fix (CRITICAL BFS bug)

| Option | Description | Selected |
|--------|-------------|----------|
| Out-of-band + batched publish | Caller re-seals child's returned childReadKey under the parent's NEW readKey', writes it onto the parent SealedChildRef, publishes the parent once after all children rotate (D-09 batched, child-first interior order) | ✓ |
| Param into rotateOne, per-node publish | Thread parentNewReadKey' into rotateOne, re-seal inside it, keep per-node parent publishes | |

**User's choice:** Out-of-band + batched publish
**Notes:** Fixes the Phase-63 CRITICAL bug (newReadKeySealed sealed under wrong key, never written back). Keeps rotateOne focused; lands the §4.7 batched-parent-publish constant-factor win while the code is already open.

---

## Crash-safety E2E (TEST-01 gate)

| Option | Description | Selected |
|--------|-------------|----------|
| Throw-after-N + fresh-resume | Depth-2+ tree; crash = throw after N commits; resume = fresh job record + verifySubtreeClean rebuild from published IPNS truth (no durable persistence); concurrent-add = second client uploads mid-rotation | ✓ |
| Durable job-record resume | Persist frontier+completedNodeIds to disk between abort and resume; resume from it rather than verifySubtreeClean | |

**User's choice:** Throw-after-N + fresh-resume
**Notes:** Honors D-10 (published records are source of truth; reload restarts idempotent walk). Durable storage stays Phase 68.

---

## Folded-todo scope

| Option | Description | Selected |
|--------|-------------|----------|
| move-within-scope reseal | FLAG-63-U2: moveItem must re-seal the moved child's readKey under the destination parent's readKey | ✓ |
| node-identity preservation | CRITICAL: updateFolderMetadataAndPublish must preserve node id + generation, not mint a fresh UUID / reset to 0 | ✓ |
| client.ts move ordering | MAJOR: source removal committed before destination publish succeeds | |

**User's choice:** move-within-scope reseal, node-identity preservation
**Notes:** The two binding-stability bugs are folded (preconditions for sound, testable rotation). The client.ts move dest-before-source ordering durability is NOT folded — deferred to Phase 68 with the folderTree reconcile. (ROT-04 inner-grant re-mint and ROT-06 job-record/zeroization fixes were already core-in by the ROADMAP success criteria.)

---

## Claude's Discretion

- Seam-function internal factoring and signatures (seams keep their names; fill, don't re-architect).
- Whether to rename the `parentReadKey` misnomer; batched-parent-publish helper extraction.
- `verifySubtreeClean` return shape and frontier-rebuild mechanics.
- Mocked-API unit-test structure and the test key source.
- Fault-injection wiring for the e2e (test-only seam, not a production path).

## Deferred Ideas

- M1 durable IndexedDB `{nodeId → highestGeneration}` floor, `executeLazyRotation` deletion, folderTree reconcile-before-rotate → Phase 68.
- Server-side generation gate → Phase 66.
- Full write-body signing material / write-revocation / write-body placeholder key → Phase 65.
- Live `shares` schema for HIGH-3 persistence → Phase 66.
- `client.ts` move dest-before-source ordering + unreadable-descendant enumeration fix → Phase 68.

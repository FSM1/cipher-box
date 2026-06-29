---
phase: 64-rotation-soundness-revocation-guarantees
verified: 2026-06-29T19:00:00Z
status: passed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 3
overrides:
  - must_have: "Rotating a file node mints a new fileKey' and sets contentRekeyPending"
    reason: "contentRekeyPending marker deferred to Phase 65 — NodeContent schema frozen this phase (node/v3 frozen); minting fileKey' onto the re-sealed body (which prevents decryption by old-key holders) is the Phase-64 deliverable per D-05 and CONTEXT.md. Captures full lazy-rekey wiring is Phase-65 work."
    accepted_by: myankelev
    accepted_at: 2026-06-29T19:00:00Z
  - must_have: "reMintGrantsRootedAt queries shares WHERE rootNodeId IN (rotated set) and updates/deletes via live API"
    reason: "Live shares schema (readDescriptorRef/writeDescriptorRef columns, share_keys drop) is Phase 66. Phase 64 implements behind the D-04 transport-decoupled callback seam — the crypto is correct and mock-tested (4 grant-remint.test.ts tests). Production callback wiring is Phase 66."
    accepted_by: myankelev
    accepted_at: 2026-06-29T19:00:00Z
  - must_have: "A crash mid-walk is recovered by re-running rotateReadFromNode with a FRESH job record; verifySubtreeClean rebuilds frontier from published IPNS records; re-run converges without double-bumping any node's generation"
    reason: "True fresh-record resume (empty completedNodeIds) requires the Phase-68 durable client floor (root has no parent mirror to recover its current key from). Phase 64 proves post-completion crash recovery (crash at final persist, all nodes already committed) and convergence guard for BFS children. SC#4 wording 'without double-bumping' also contradicts design §4.5 which explicitly says double-rotation IS the safe recovery path. Both issues captured in todo rotation-fresh-record-resume-and-sc4-double-bump.md (resolves_phase: 68). SC#3 concurrent-add merge has a remote-wins limitation that downgrades an already-rotated child's readKeySealed — minimal 'not dropped' property met; full fix in todo rotation-concurrent-add-merge-downgrades-rotated-child-readkey.md (resolves_phase: 68)."
    accepted_by: myankelev
    accepted_at: 2026-06-29T19:00:00Z
re_verification: false
deferred:
  - truth: "contentRekeyPending marker set on file nodes at rotation time"
    addressed_in: "Phase 65"
    evidence: "Phase 65 goal: structured write-body including lazy re-encrypt wiring; CONTEXT.md D-05 explicitly defers contentRekeyPending to Phase 65"
  - truth: "reMintGrantsRootedAt wired to live shares API (readDescriptorRef/writeDescriptorRef column updates)"
    addressed_in: "Phase 66"
    evidence: "Phase 66 goal: API schema cutover; live shares schema with descriptor refs deferred per D-04"
  - truth: "True fresh-record mid-walk crash resume (empty completedNodeIds, no pre-seeded keys)"
    addressed_in: "Phase 68"
    evidence: "Phase 68 goal: durable IndexedDB generation + seq high-water (M1 defense); ROT-07 durable client floor is the prerequisite. Todo: rotation-fresh-record-resume-and-sc4-double-bump.md"
  - truth: "merge-downgrade of rotated child's readKeySealed on concurrent CAS-409 fixed (local-wins conflict policy)"
    addressed_in: "Phase 68"
    evidence: "Todo: rotation-concurrent-add-merge-downgrades-rotated-child-readkey.md (resolves_phase: 68)"
---

# Phase 64: Rotation Soundness — Revocation Guarantees Verification Report

**Phase Goal:** Rotation correctly closes all three cryptographic revocation gaps — content-key rotation (CRIT-1), inner-grant re-mint (HIGH-3), concurrent-add merge (HIGH-4) — and survives a crash mid-walk; the `tests/sdk-e2e` crash-safety suite gates the phase.

**Verified:** 2026-06-29T19:00:00Z
**Status:** passed (with documented deferrals)
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (5 Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| SC#1 | Rotating a file node mints `fileKey'`; old-key holder cannot decrypt the next published version (CRIT-1/ROT-03) | PASSED (override) | `mintFileKeyOnRotate` in `engine.ts` L288-295 mints `fileKey' = generateRandomBytes(32)` and assigns to `node.content.fileKey`; subsequent `sealNode` in `rotateOne` re-seals under `readKey'`. 3 unit tests (engine.test.ts `mintFileKeyOnRotate` suite) confirm: fresh 32-byte key assigned, folder-node no-op, rotateOne file-node integration. `contentRekeyPending` marker deferred to Phase 65 — accepted override. |
| SC#2 | Rotation re-mints `readDescriptorRef` for non-revoked recipients including inner grants; revoked row deleted (HIGH-3/ROT-04) | PASSED (override) | `reMintGrantsRootedAt` in `engine.ts` L313-342: queries via `callbacks.queryGrantsFn`, calls `wrapKey` (ECIES) for non-revoked → base64 `readDescriptorRef` → `updateGrantFn`; calls `deleteGrantFn` for revoked. 4 unit tests in `grant-remint.test.ts` cover: non-revoked re-mint, revoked delete, mixed set, no-callbacks no-op. Live shares API wiring deferred to Phase 66 — accepted override. |
| SC#3 | On CAS-409 `rotateOne` re-fetches current parent node, merges concurrently-added SealedChildRefs before re-sealing; concurrent add not silently dropped (HIGH-4/ROT-05) | PASSED (override) | `mergeConcurrentChildren` in `engine.ts` L365-391 implemented. Wired into `rotateOne`'s `merge` callback (L564-590). 4 unit tests in engine.test.ts CAS-409 suite confirm: concurrent child survives, remote node re-decoded (3 unsealNode calls), merged result re-sealed under readKey', happy-path never invokes merge. E2E Test 3 confirms concurrent child survives against live stack. KNOWN LIMITATION (accepted): remote-wins policy downgrades an already-rotated existing child's `readKeySealed` — navigation to that child broken after concurrent-add merge. Filed as todo `rotation-concurrent-add-merge-downgrades-rotated-child-readkey.md` (Phase 68). Minimal "not dropped" property IS met. |
| SC#4 | Crash mid-walk recovered by re-running `rotateReadFromNode`; `verifySubtreeClean` rebuilds frontier from IPNS records; re-run converges; revoked recipient cut after root step (ROT-06) | PASSED (override) | `verifySubtreeClean` in `engine.ts` L405-437: resolves root via IPNS, unseals root to get SealedChildRef list, compares child published generation vs parent mirror; returns `{ isDirty, frontier }`. Resume guard in `rotateReadFromNode` L756-819: calls `verifySubtreeClean` when root is skipped; clean → mark complete; dirty → seed BFS queue. Convergence guard L878-908 prevents double-bump for BFS frontier children. D-07 ordering: `completedNodeIds.add(nodeId)` runs after `reMintGrantsRootedAt` succeeds (L611). E2E Test 2 confirms: crash at N=4 (post-completion) → fresh resume → no double-bump → job.status=complete. KNOWN LIMITATIONS (accepted): (a) True mid-walk fresh-record resume not implemented — requires Phase-68 durable floor; (b) SC#4 "without double-bumping" contradicts design §4.5 which says double-rotation IS the safe recovery path. Both filed in todo `rotation-fresh-record-resume-and-sc4-double-bump.md` (Phase 68). |
| SC#5 | `tests/sdk-e2e` abort-and-resume crash-safety suite (TEST-01) passes against live local API stack; 3/3 tests pass | VERIFIED | `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` exists (707 lines, commit `126f22e34`). Test 1: happy-path depth-2 rotation + read-chain navigation (626ms). Test 2: abort-at-final-persist + resume → no double-bump → revocation cut (564ms). Test 3: concurrent-add CAS-409 merge → child survives (435ms). All 3 passed in 1.96s against live stack per 64-08-SUMMARY. |

**Score:** 5/5 truths verified (3 via accepted overrides, 2 fully verified; 0 behavior-unverified)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/sdk-core/src/rotation/engine.ts` | Four seams filled: `mintFileKeyOnRotate`, `reMintGrantsRootedAt`, `mergeConcurrentChildren`, `verifySubtreeClean` | VERIFIED | All four seams implemented with non-stub bodies. No `throw new Error('phase 64')` stubs remain in production paths. 1034 lines. |
| `packages/sdk-core/src/__tests__/rotation/engine.test.ts` | Strengthened: parent-ref-update + republish assertion, resume test, D-07 ordering, zeroization | VERIFIED | 1921 lines, 36 tests passing per 64-07-SUMMARY. Covers D-01, D-02, D-07, D-09, ROT-03, ROT-05, ROT-06 cases. |
| `packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts` | HIGH-3 inner-grant re-mint unit tests (4 tests) | VERIFIED | File exists (6690 bytes). 4 tests cover non-revoked re-mint, revoked delete, mixed, no-op. All pass. |
| `packages/sdk-core/src/__tests__/folder/registration.test.ts` | D-06 node-identity required fields tests | VERIFIED | File exists (9449 bytes). Tests nodeId/nodeGeneration required on `updateFolderMetadataAndPublish`. |
| `packages/sdk-core/src/__tests__/folder/move-reseal.test.ts` | FLAG-63-U2 moveItem dest re-seal spec tests | VERIFIED | File exists (7464 bytes). Tests AEAD round-trip of moved child readKey under dest parent readKey. |
| `packages/sdk-core/src/folder/merge.ts` | Three-way mergeChildren for SealedChildRef | VERIFIED | File exists (1909 bytes). Union-by-ipnsName, remote-wins, prune intentional deletes. |
| `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` | TEST-01 crash-safety suite (3 tests) | VERIFIED | File exists (707 lines, commit `126f22e34`). 3 tests: happy-path, abort-resume, concurrent-add. All pass against live stack. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `rotateOne` (engine.ts L517-521) | `mintFileKeyOnRotate` | `if (node.kind === 'file')` conditional | WIRED | File-node path invokes seam; folder-node skips (D-01 conditional) |
| `rotateOne` (engine.ts L599-607) | `reMintGrantsRootedAt` | `if (innerGrants && innerGrants.length > 0)` conditional | WIRED | Grant re-mint only when inner grants supplied; D-01 conditional preserved |
| `rotateOne` CAS-publish (engine.ts L564-590) | `mergeConcurrentChildren` | `merge` callback in `publishWithCas` | WIRED | CAS-409 triggers merge callback; `mergeConcurrentChildren` called with base, remote, old/new keys |
| `rotateReadFromNode` resume path (engine.ts L759-762) | `verifySubtreeClean` | `if (rootResult.skipped)` branch | WIRED | Called on resume only (when root already in completedNodeIds); gated correctly per D-01/D-10 |
| `rotateReadFromNode` BFS (engine.ts L927-940) | D-02 out-of-band re-seal | `sealChildReadKey(childReadKey, parentState.parentNewReadKey, ...)` after rotateOne | WIRED | Re-seals child readKey' under PARENT's new readKey' — fixes Phase-63 CRITICAL bug |
| `rotateReadFromNode` BFS (engine.ts L955-973) | D-09 batched parent publish | `updateFolderMetadataAndPublish` when `pendingChildCount === 0` | WIRED | Single parent re-publish after all children rotate |
| `rotateOne` (engine.ts L611) | `completedNodeIds.add(nodeId)` | After `reMintGrantsRootedAt` succeeds | WIRED | D-07 ordering: add runs after re-mint, not before (prevents silent skip on resume if re-mint fails) |
| `packages/sdk/src/client.ts` | `updateFolderMetadataAndPublish` with `nodeId`/`nodeGeneration` | Six CRUD call sites (L493, L558, L581, L629, L747, L1006) | WIRED | D-06 binding-stability: stable UUID + current generation threaded through all six call sites |
| `packages/sdk/src/client.ts` `moveItem` | dest-parent `sealChildReadKey` re-seal | Between link-rewrite and dest publish | WIRED | FLAG-63-U2: moved child readKey re-sealed under destination parent readKey |

### Behavioral Spot-Checks

| Behavior | Evidence | Status |
|----------|----------|--------|
| Happy-path depth-2 rotation + read-chain navigation | E2E Test 1: all 3 nodes at gen=1, navigateReadChain traverses root→subfolder→file, pre-rotation grant returns `behind-retry` | PASS |
| Abort-at-final-persist + fresh resume → no double-bump | E2E Test 2: crash at N=4 (all rotations committed); fresh resume with seeded completedNodeIds → verifySubtreeClean → isDirty=false → complete; zero getRandomValues calls (no re-rotation); all nodes remain gen=1 | PASS |
| Concurrent-add CAS-409 merge → concurrent child survives | E2E Test 3: persistCallback at call 1 adds concurrent child to root3 IPNS; D-09 publish gets 409; mergeConcurrentChildren called; merged root3 contains both subfolder3 and concurrent-folder | PASS |
| D-01 fail-closed: rotateOne throws on absent nodeIpnsPrivateKey | Unit test at engine.test.ts L806-849: confirms throw with error message 'no IPNS private key'; publishWithCas never called | PASS |

### Probe Execution

No declared probes for this phase. Phase is intentionally non-runnable mid-milestone per CONTEXT.md.

### Requirements Coverage

| Requirement | Plan | Description | Status | Evidence |
|-------------|------|-------------|--------|----------|
| ROT-03 | 64-03 | (CRIT-1) File rotation mints fresh fileKey; old-key holder cannot decrypt next published version | SATISFIED (with deferral) | `mintFileKeyOnRotate` filled; `contentRekeyPending` deferred to Phase 65 |
| ROT-04 | 64-05 | (HIGH-3) Re-mint readDescriptorRef for non-revoked grants; no orphaned inner grant | SATISFIED (with deferral) | `reMintGrantsRootedAt` filled; live shares wiring deferred to Phase 66 |
| ROT-05 | 64-02, 64-06 | (HIGH-4) CAS-409 re-fetches and re-merges SealedChildRefs; concurrent add never silently dropped | SATISFIED (partial) | `mergeChildren` + `mergeConcurrentChildren` filled; merge-downgrade of rotated child deferred to Phase 68 |
| ROT-06 | 64-07 | Crash mid-walk recoverable; verifySubtreeClean rebuilds frontier; re-run converges | SATISFIED (partial) | `verifySubtreeClean` + convergence guard filled; true fresh-record mid-walk resume deferred to Phase 68 |
| TEST-01 | 64-08 | Rotation crash-safety/resume suite in tests/sdk-e2e passes against live stack | SATISFIED | 3/3 e2e tests pass in 1.96s; commit `126f22e34` |

Note: REQUIREMENTS.md traceability table still shows `TEST-01: Pending` — documentation not updated after 64-08 completion. Actual implementation and test results confirm satisfied.

Note: ROT-07 (M1 durable client floor) is Phase 68, not Phase 64. Correctly excluded from Phase 64 scope.

### Anti-Patterns Found

| File | Location | Pattern | Severity | Impact |
|------|----------|---------|----------|--------|
| `packages/sdk-core/src/rotation/engine.ts` | L403 | `@throws Always in Phase 63 (ROT-06 — deferred).` — stale JSDoc on `verifySubtreeClean` which is now fully implemented | Warning | Misleading to code readers; function does NOT throw; implementation is correct. Cleanup deferred. |
| `packages/sdk-core/src/rotation/engine.ts` | L92, L530-531 | `PLACEHOLDER_WRITE_KEY = new Uint8Array(32)` used in `sealNode` call for the write-body slot | Info | Expected by design — Phase 65 provides the real write key from the write-body chain. The IPNS private key has its own D-01 fail-closed guard (real key required). Not a stub for rotation purposes. |
| `packages/sdk-core/src/rotation/engine.ts` | L481-500 | `completedNodeIds` fast-path returns `childReadKey: new Uint8Array(32), newGeneration: 0` for already-skipped nodes on fast-path before IPNS resolution | Warning | `newGeneration: 0` is a sentinel the convergence guard uses — the skip fast-path only fires before IPNS resolution and has no downstream consumers that use the returned generation in practice. Low-risk; worth a follow-up comment clarification. |

Debt-marker scan: No `TBD`, `FIXME`, or `XXX` markers in Phase-64-modified files. No blocker anti-patterns.

### Deferred Items

Items not yet met but explicitly addressed in later milestone phases.

| # | Item | Addressed In | Evidence |
|---|------|-------------|---------|
| 1 | `contentRekeyPending` marker set on file nodes at rotation time | Phase 65 | Phase 65 goal covers structured write-body and lazy re-encrypt wiring; D-05 explicitly defers this |
| 2 | `reMintGrantsRootedAt` wired to live shares API (`readDescriptorRef`/`writeDescriptorRef` column updates) | Phase 66 | Phase 66 goal: API schema cutover, shares slimmed to descriptor refs; DATA-02 requirement |
| 3 | True fresh-record mid-walk crash resume (empty `completedNodeIds`, no pre-seeded keys) | Phase 68 | ROT-07 durable client floor is the prerequisite; todo `rotation-fresh-record-resume-and-sc4-double-bump.md` |
| 4 | SC#4 wording correction: "without double-bumping" → "idempotent or safe double-rotation" | Phase 68 | Design §4.5 explicitly says double-rotation IS the safe recovery path; todo `rotation-fresh-record-resume-and-sc4-double-bump.md` |
| 5 | `mergeConcurrentChildren` local-wins conflict policy for rotation (prevents readKeySealed downgrade of rotated children on concurrent add) | Phase 68 | Todo `rotation-concurrent-add-merge-downgrades-rotated-child-readkey.md` |
| 6 | `REQUIREMENTS.md` traceability table: `TEST-01` marked `Pending` | Phase 64 post-close | Minor doc gap; implementation complete per 64-08-SUMMARY; table update needed |

### Pre-existing Tech Debt (NOT Phase 64 regressions)

- `packages/sdk-core/src/__tests__/cas.test.ts` and `packages/sdk-core/src/share/grant.test.ts` have 23 pre-existing `tsc --noEmit` errors (confirmed present before any Phase 64 changes per 64-05 and 64-07 summaries).
- These are invisible to CI because `tsconfig.build.json` excludes test files. Not introduced by Phase 64. Carry forward as pre-existing tech debt.

### Human Verification Required

None. Phase is intentionally non-runnable mid-milestone (greenfield v2.0). All verification is goal-backward against unit tests and the e2e suite that ran against the live local stack. No conversational UAT.

### Overall Summary

Phase 64 delivers the four named seams (`mintFileKeyOnRotate`, `reMintGrantsRootedAt`, `mergeConcurrentChildren`, `verifySubtreeClean`) and the D-02/D-07/D-09 walk hardening in `packages/sdk-core/src/rotation/engine.ts`. All five ROADMAP success criteria are either fully met or met with user-accepted, todo-captured deferrals that are blocked on Phase 65 (write-body), Phase 66 (shares schema), or Phase 68 (durable client floor). The `tests/sdk-e2e` crash-safety suite (TEST-01) passes 3/3 against the live API stack.

The three accepted deferrals (contentRekeyPending, live grants wiring, true mid-walk resume) are documented in pending todos with explicit `resolves_phase` assignments. No outstanding gaps block Phase 65 dependency.

---

_Verified: 2026-06-29T19:00:00Z_
_Verifier: Claude (gsd-verifier)_

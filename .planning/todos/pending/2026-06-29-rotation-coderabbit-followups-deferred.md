---
created: 2026-06-29
title: CodeRabbit rotation-soundness findings deferred at Phase 64 ship (merge re-enqueue, verifySubtreeClean depth, frontier fail-closed, grant threading)
area: sdk-core
resolves_phase: 68
files:
  - packages/sdk-core/src/rotation/engine.ts
  - packages/sdk/src/client.ts
  - tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts
---

## Problem

CodeRabbit CLI review at Phase 64 ship (2026-06-29) surfaced 17 findings. The low-risk set (docs, input validation, zeroization completeness) was fixed in-line before merge. The findings below are in the rotation-soundness domain the user explicitly deferred ("ship as-is, defer both") and are recorded here. They refine / extend the two primary deferrals [[rotation-concurrent-add-merge-downgrades-rotated-child-readkey]] (RR-01) and [[rotation-fresh-record-resume-and-sc4-double-bump]] (RR-02).

### Merge path (RR-01 family) → rotation merge rework

- **[CRITICAL, engine.ts ~L565-620] CAS-409 merge does not re-enqueue remote-added children.** `rotateOne`'s merge closure publishes the merged node but returns `children: node.children ?? []`, so children that `mergeConcurrentChildren` added from the remote are NOT returned to the BFS frontier → never rotated. Fix together with RR-01's local-wins change: capture the merged frontier (incl. remote additions) and return it from `rotateOne` so the new children are enqueued for their own rotation.
- **[MAJOR, rotation-crash-safety.test.ts ~L700-705] e2e concurrent-add assertion is too weak.** Test 3 only checks the merged child NAMES are present; it does not navigate into `sub3IpnsName` and unseal with `readKeyPrimeRoot3`. Strengthening it now would assert behavior RR-01 has deferred (it would fail on the downgrade) — strengthen it WHEN RR-01 is fixed. Also make the test fail fast if the concurrent-write injection did not actually execute.

### Resume / convergence path (RR-02 family) → Phase 68 durable floor + resume rework

- **[MAJOR, engine.ts ~L407-439] `verifySubtreeClean` is shallow.** It only checks the root's IMMEDIATE children and returns `clean` when the root IPNS record is missing. It must recursively traverse the whole subtree (resolve each child's IPNS record, compare every parent mirror vs the child's published generation, collect dirty frontier nodes at any depth), and treat a missing root record as dirty/surfaced rather than short-circuiting to clean. This is required for the true fresh-record resume RR-02 describes.
- **[MAJOR, engine.ts ~L794-807] Frontier skips missing child records, desyncing `pendingChildCount`.** Missing IPNS/envelope records hit `continue` paths without decrementing/accounting `pendingChildCount`, so a parent can reach `complete` while unresolved children remain implicitly counted. Treat missing records as fail-closed errors or explicitly account for them before continuing.
- **[MAJOR, engine.ts ~L778-792] Dirty-resume root parentTracking can proceed without a signing key.** The root-skipped parentTracking path can store `parentIpnsPrivateKey` and later force it non-null, leaking `undefined` into the publish flow instead of failing closed (D-01). Require a real signing key before storing it; surface the error early. Apply the same guard in the later dirty-resume parentTracking block.

### Grant re-mint wiring → Phase 66 (live shares transport)

- **[MAJOR, engine.ts ~L199-204] `reMintGrantsRootedAt` is unreachable in the real walk.** `grantCallbacks` is declared on `RotateOneParams` but never added to `RotationParams` / threaded through `rotateReadFromNode` and the `rotateOne` call sites, so the inner-grant re-mint runs only in the unit test (direct injection), never in the integrated rotation. Thread `innerGrants`/`grantCallbacks` through the full public path when the live `shares` transport is wired (Phase 66, the D-04 → live cutover). Until then SC#2 (ROT-04) holds at the unit/seam level only.

### Client SDK-runtime re-wire (quarantined mid-milestone) → see [[sdk-client-move-publish-durability]] (Phase 68)

- **[MAJOR, client.ts ~L573-594] `moveItem` re-seal resolves IPNS by `childId` (UUID) instead of the moved `SealedChildRef.ipnsName`.** The moved record is identified by its ipnsName; the lookup + `resolveIpnsRecord` should use the moved ref's ipnsName (or have `sdkCore.moveItem()` return that ref).
- **[MAJOR, client.ts ~L313-316] FolderState placeholder identity not normalized.** `registerFolder` seeds `nodeId: ''` / `nodeGeneration: 0`; `loadFolder`'s existing-state fast path can return unchanged, leaving the placeholder in state → later CRUD publishes use invalid identity. `loadFolder` must detect the placeholder and replace it with the loaded `nodeId`/`nodeGeneration`.
- **[MINOR, move-reseal.test.ts ~L58-203] Add a client-level `moveItem` regression test** that mocks the publish flow, captures the destination payload, and asserts the emitted `readKeySealed` is re-sealed for the destination parent (unseals with dest key, rejects source key). Currently only the seal/unseal primitives are tested.

These client.ts items live in the SDK runtime that is intentionally `describe.skip`-quarantined this milestone ("SDK runtime stubbed mid-milestone, re-enable at phase 63-65 consumer re-wire"), so they are exercised end-to-end only once the consumer re-wire lands.

## Why deferred

User-decided 2026-06-29 (Phase 64 close): ship as-is, defer the rotation-soundness rework. The merge/resume findings are part of the RR-01/RR-02 rework (Phase 68 durable floor); grant threading is the Phase-66 shares-transport cutover; the client.ts items are part of the deferred SDK consumer re-wire. The low-risk subset (zeroization completeness, input validation, doc sync, test key hygiene) was fixed before merge.

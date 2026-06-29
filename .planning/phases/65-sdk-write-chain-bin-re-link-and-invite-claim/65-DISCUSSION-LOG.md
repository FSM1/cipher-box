# Phase 65: SDK Write-Chain, Bin Re-link, and Invite Claim - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-29
**Phase:** 65-sdk-write-chain-bin-re-link-and-invite-claim
**Areas discussed:** Q3 writer-vs-owner authority (+ exposure window), Phase 65/66 transport boundary, Co-writer offline handling, Write-revocation E2E proof scope

---

## Q3 — write-recipient-vs-owner sub-share authority (ROADMAP-mandated)

| Option | Description | Selected |
|--------|-------------|----------|
| (a) Reconcile on owner sync | C unlinks+bins immediately; D's grant left dangling until the owner's next online reconcile+rotation pass. Zero new infra, ADR-0002-consistent, no share-existence leak to C. | ✓ |
| (b) Block C's destroy | Relay tells C "node has active owner grants" and blocks the op. Leaks share existence to a delegate. | |
| (c) Owner-signed revoke queue | C enqueues an owner-signed revocation request the owner executes on next online. More infra; deferred. | |

**User's choice:** (a) Reconcile on owner sync.
**Notes:** Follow-up on the exposure window (roadmap requires deciding window + authority): selected "Documented residual; reconcile is Phase 66/68." Phase 65 emits no new schema/marker; the owner's reconcile re-derives dangling grants from the existing `shares WHERE rootNodeId ∈ destroyed-subtree` enumeration (inverted HIGH-3 seam), wired live in Phase 66/68. Marginal exposure is the navigation/future-write window (content already irreducibly readable per ADR 0002), bounded by the owner's next online session.

---

## Phase 65/66 transport boundary

| Option | Description | Selected |
|--------|-------------|----------|
| Hold the Phase-64 line | sdk-core/sdk crypto only; tombstone enforcement + writeDescriptorRef persistence mock-tested behind injected callbacks; live apps/api + migration cutover is Phase 66. | ✓ |
| Pull tombstone enforcement forward | Implement live publish-gate reject + resolve 410 in apps/api this phase. Couples Phase 65 to the Phase-66 schema cutover. | |

**User's choice:** Hold the Phase-64 line.
**Notes:** Code scout confirmed the ROADMAP's "delete addShareKeys/reWrapForRecipients/encryptedChildKeys" splits by layer — `reWrapForRecipients` is already gone from the sdk layer (Phase 63) and only survives in apps/web (→ Phase 68); `addShareKeys`/`encryptedChildKeys` live in apps/api (→ Phase 66). Phase 65 rewires the sdk-core/sdk consumers so the symbols become dead; physical apps/* removals ride 66/68. Documented as D-02.

---

## Co-writer offline handling (WRITE-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Explicit SDK error only | "Cannot write until re-fetch" error; co-writer re-fetches the re-wrapped writeDescriptorRef on next attempt. Grace/notification UX is Q1 → Phase 68. | ✓ |
| Add a pending-rekey marker now | Persist a "rekey pending" signal for proactive host prompts. Pulls Phase-68 UX into the SDK. | |

**User's choice:** Explicit SDK error only.
**Notes:** WRITE-03 itself says "explicit." Open question Q1 (grace/notification) is already assigned to Phase 68. Error type/shape left to Claude's discretion.

---

## Write-revocation E2E proof scope

| Option | Description | Selected |
|--------|-------------|----------|
| Real sdk-e2e round-trip | Extend tests/sdk-e2e with a live write-chain rotation round-trip (new k51 per node, parent re-point cascade to share root, tombstone-intent), mirroring Phase-64 TEST-01. | ✓ |
| Unit-test the crypto only | Unit-test write-rotation in sdk-core (mock transport); defer the live round-trip. | |

**User's choice:** Real sdk-e2e round-trip.
**Notes:** The heaviest operation in the system must be proven end-to-end against a real API; reuse the Phase-63/64 manual-node build pattern, now with real write-bodies.

---

## Claude's Discretion

- Write-revocation driver shape — distinct `rotateWriteFromNode` vs extension of `rotateReadFromNode` (design §5.3 frames write-revoke as structurally heavier).
- Whether to un-stub `createFileMetadata`/`createSubfolder` to emit real write-bodies, or keep the manual-node-build e2e pattern.
- The co-writer "cannot write until re-fetch" error type/shape.
- Internal factoring of `shared-write.ts`, the write-chain walk, and the mocked `shares`/persist + tombstone-unenroll callbacks.

## Deferred Ideas

- Q3 option (c) owner-signed revocation-request queue → noted idea, not Phase-65 scope.
- Co-writer grace/notification UX (Q1) → Phase 68.
- Live apps/api cutover (tombstone enforcement, CAS, share_keys/addShareKeys delete, encryptedChildKeys drop, shares slim, folder_ipns rename) → Phase 66.
- Live apps/web cutover (reWrapForRecipients delete, addShareKeysFn type, executeLazyRotation swap, durable floors) → Phase 68.
- TEE lease-renewer + createSubfolder TEE wiring → Phase 67. FUSE write plane + Q3 mirror → Phase 69.

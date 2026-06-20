# Phase 51: Crypto-Signature & Secret-Leak Hardening - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-19
**Phase:** 51-crypto-signature-secret-leak-hardening
**Areas discussed:** S2 missing-signature policy, S3 zeroization reach, Rust S2 scope, S1 strict-vs-tolerant

---

## S2 — Missing-signature policy

| Option                | Description                                                                                  | Selected |
| --------------------- | -------------------------------------------------------------------------------------------- | -------- |
| Allow + flag + telemetry | Missing sig fields → return CID with `signatureVerified=false` + warn/metric. Doesn't break existing vaults; DB CID authoritative. | ✓        |
| Flag-gated strict     | Allow now behind env toggle (`IPNS_REQUIRE_SIGNED`, default off) to flip to fail-closed later. |          |
| Strict fail-closed    | Reject on missing too. Strongest, but risks locking users out until all records re-published. |          |

**User's choice:** Allow + flag + telemetry (D-03)
**Notes:** Present-but-invalid → reject was already locked going in. Require-signed tightening deferred to a follow-up once all records carry signatures.

---

## S3 — Zeroization reach

| Option           | Description                                                                                           | Selected |
| ---------------- | ---------------------------------------------------------------------------------------------------- | -------- |
| Bounded          | Reconcile the file/folder contradiction, document caller-owns-key, fix the named Rust raw-Vec paths. |          |
| Bounded + guard  | Bounded scope plus a regression test/lint asserting caller-owns-key on touched paths.                |          |
| Exhaustive sweep | Every SDK fn (ipns, vault, folder, file) + every Rust unwrap path zeroized, with enforcement.        | ✓        |

**User's choice:** Exhaustive sweep (D-05)
**Notes:** Chose the broadest option despite the usual anti-scope-creep preference — justified for a security-hardening phase. Captured with an enforcement guard (lint/test) folded in so the convention does not re-drift.

---

## Rust S2 — Verification scope

| Option          | Description                                                                                  | Selected |
| --------------- | -------------------------------------------------------------------------------------------- | -------- |
| Include now     | Close S2 across web + sdk-core + Rust this phase; add sig fields to `IpnsResolveResponse` + verify in `crates/api-client`. | ✓        |
| Defer Rust half | TS-only this phase; capture a todo for Rust client verification in a later desktop phase.     |          |

**User's choice:** Include now (D-04)
**Notes:** Phase 52 is desktop-durability, not signature work — keeping S2 atomic across all surfaces.

---

## S1 — Strict vs tolerant embedded-vs-DTO validation

| Option                      | Description                                                                                              | Selected |
| --------------------------- | ------------------------------------------------------------------------------------------------------- | -------- |
| CID strict + seq offset-aware | Reject any embedded-CID vs `metadataCid` mismatch; sequence check tolerates the seq-0/first-publish convention. Fully closes S1. | ✓        |
| CID-only (seq via shipped guard) | Add only embedded-CID strict reject; leave sequence to the shipped embedded-vs-embedded anti-rollback 409. Lowest-risk. |          |
| Strict equality both        | Strict embedded==DTO on CID and sequence with explicit first-publish special-case. Most rigid.          |          |

**User's choice:** CID strict + seq offset-aware (D-01)
**Notes:** Offset-aware sequence handling accounts for the pre-increment convention (client signs `0`, DB stores `'1'` on first publish).

---

## Claude's Discretion

- Phase sequencing (S1 → S2 → S3, #15 in parallel) suggested in CONTEXT.md; planner may refine.
- Exact telemetry/metric shape for the D-03 missing-signature path left to the planner/executor.

## Post-Discussion Scope Change

- **Todo #15 (web logger redaction + Faro transport) removed from Phase 51** at the user's direction
  after the four forks were locked: end-user logging/monitoring is not being implemented yet, and the
  redaction interceptor has marginal value without a remote transport (its acceptance criteria
  require Faro). #15 re-defers to a future observability phase. ROADMAP.md, REQUIREMENTS.md (HARD-02),
  and CONTEXT.md updated to match. Phase 51 is now purely the IPNS crypto-signature S1/S2/S3 work.

## Deferred Ideas

- Todo #15 — web logger redaction interceptor + Faro transport (see Post-Discussion Scope Change).
- Full CRDT conflict model for IPNS — tracked in the CRDT-inbox research todo.
- Require-signed (fail-closed on missing signature) — deferred until all records re-published with signatures.

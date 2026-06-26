# Phase 58: IPNS Signature-Verify Coverage - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-22
**Phase:** 58-ipns-signature-verify-coverage
**Areas discussed:** Resolve-fail posture, CID/seq swap handling, Non-CAS seq strictness, Test vectors + CI gate

---

## Resolve-fail posture

Initial question (what to do on invalid/partial at all sites) was paused so the
owner could understand the problem space first; an explainer of all four problems
was provided. The owner then challenged the "log a warning and proceed" framing:
a verification failure is not user-fixable, so a local warning log helps no one.
The question was re-framed around refuse-vs-silently-trust, with failure scoped to
the operation.

| Option                  | Description                                                                                                  | Selected |
| ----------------------- | ------------------------------------------------------------------------------------------------------------ | -------- |
| Fail-closed, scoped     | Refuse the unverified CID; fail only that operation; sync not wedged; 30s poll self-heals; metric as side effect | ✓        |
| Fail-closed, hard       | Abort the whole refresh/operation on any failure; simplest but wider blast radius                            |          |
| Allow + telemetry-only  | Proceed on DB CID, report to a telemetry counter; only defensible if wired to real telemetry (thin on FUSE)  |          |

**User's choice:** Fail-closed, scoped per-operation.
**Notes:** Folder-key descent stays hard fail-closed (T-51-07); legacy all-absent
(D-03) stays allowed. Owner explicitly rejected the "useless log" path. Rust and JS
both end up fail-closed → unified posture, which de-risks the 58-03 dedup.

---

## CID/seq swap handling

| Option                    | Description                                                                                          | Selected |
| ------------------------- | ---------------------------------------------------------------------------------------------------- | -------- |
| Treat as verify failure   | Mismatch classified identically to an invalid signature → Area 1 fail-closed-scoped; symmetric Rust+JS; signed value is truth | ✓        |
| Separate softer path      | Verify signature as today but only WARN/flag on mismatch and proceed on response value               |          |
| Use embedded value, no fail | Silently prefer the signed/embedded cid/sequence on mismatch, no failure                            |          |

**User's choice:** Treat as verification failure.
**Notes:** A mismatch is a strong tamper signal; inherits the Area 1 posture. The
signed/embedded value is the source of truth; the response field is trusted only
when it matches. Net-new CBOR decode/compare on both Rust and JS.

---

## Non-CAS seq strictness

The exact validation rule was pinned down first (anti-rollback "floor only" does
not close the wedge — the poison case is a too-high first sequence, so an upper
bound / exact match is required). Rule: first-publish 0|1; `=N` idempotent
no-increment; `=N+1` increment; `<N` and `>N+1` reject.

| Option              | Description                                                                                                   | Selected |
| ------------------- | ------------------------------------------------------------------------------------------------------------- | -------- |
| Enforce directly    | Ship the rule as a hard reject, gated on enumerating every non-CAS path + full SDK E2E                        | ✓        |
| Shadow-first, flip later | Observe mode (log/metric, don't reject) for a release, then flip to enforce; safest but defers the fix       |          |
| Floor + ceiling only | Reject `<N` and `>N+1` but tolerate any value in between (no exact-match)                                     |          |

**User's choice:** Enforce directly.
**Notes:** Severity is Low; the 48/89-test regression scar means a regression would
surface loudly in the same full-SDK-E2E gate the phase already mandates. Must
preserve the TEE 6-hour idempotent republish (`=N`, no increment).

---

## Test vectors + CI gate

| Option                | Description                                                                                                       | Selected |
| --------------------- | ----------------------------------------------------------------------------------------------------------------- | -------- |
| Expanded + required   | One shared JSON fixture (valid/tampered/name-mismatch/cid-swapped/seq-mismatch/partial-fields/legacy-absent) wired into existing cargo test + vitest → required gate for free | ✓        |
| Minimal 4 + required  | Only ROADMAP's named 4 cases, wired into existing suites                                                          |          |
| Expanded, advisory only | Full case set in a separate non-blocking check                                                                  |          |

**User's choice:** Expanded + required.
**Notes:** Areas 1–3 made cid-swap, seq-mismatch, and partial-fields
security-load-bearing, so the vector set covers them. Consumed by the
already-CI-gated suites, mirroring `crates/crypto/tests/cross_language.rs`.

## Claude's Discretion

- Exact `resolve_ipns_verified` API shape / return type.
- CBOR decode approach/library (Rust + JS).
- Per-operation "stale vs error" UX surface for a scoped failure.
- Shared fixture path/format within the `cross_language.rs` convention.
- Telemetry/metric plumbing (optional; do not block on FUSE-side observability).

## Deferred Ideas

None — discussion stayed within phase scope. The `todo.match-phase` results were
keyword-noise apart from the two source todos (already the phase's scope).

---
phase: 75-cross-language-ipns-and-node-codec-verification-parity
plan: 02
subsystem: crypto
tags: [rust, ipns, cbor, verification, ciborium]

# Dependency graph
requires:
  - phase: 75-01
    provides: "12-case shared tests/vectors/ipns/verify.json oracle (4 new invalid cases: expired-valid-sig, wrong-validity-type, two malformed-rfc3339)"
provides:
  - "decode_ipns_cbor_validity returns ValidityType alongside Validity bytes, with duplicate-key rejection"
  - "bind_verified fails closed on missing/non-zero ValidityType before treating Validity as EOL/expiry; widened to pub"
  - "classify_vector (crates/fuse/tests/ipns_verify_vectors.rs) reduced to a thin bind_verified wrapper — no more hand-duplicated binding logic"
affects: [75-03]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Single production binding function (bind_verified) reused by both the resolve path and the cross-language test oracle, eliminating a drift vector between implementation and test"

key-files:
  created: []
  modified:
    - crates/core/src/ipns.rs
    - crates/api-client/src/ipns.rs
    - crates/fuse/tests/ipns_verify_vectors.rs

key-decisions:
  - "decode_ipns_cbor_validity returns a 2-tuple (Option<Vec<u8>>, Option<i64>) rather than a named struct — threads cleanly through its single call site"
  - "The == 0 EOL gate lives in bind_verified, not in the decoder — decode_ipns_cbor_validity only reports the raw value, per RESEARCH Pitfall 3/Pattern 2 guidance"
  - "bind_verified widened pub(crate) -> pub (Pattern 2 RESOLVED in RESEARCH); classify_vector's hand-spelled cid/sequence/ValidityType binding deleted entirely in favor of calling bind_verified directly"

patterns-established:
  - "Pattern 2 applied: test-only reimplementations of production binding logic are a drift vector; prefer widening visibility and delegating over parallel hand-spelled logic"

requirements-completed:
  - "SC1 (ValidityType==0 EOL binding, Rust side) — rejected identically to TS"
  - "todo:2026-06-24-harden-validity-type-and-vector-expiry-lockstep"

coverage:
  - id: D1
    description: "decode_ipns_cbor_validity extended to return ValidityType (Option<i64>) alongside Validity bytes, with duplicate-ValidityType-key rejection mirroring the existing duplicate-Validity-key guard"
    requirement: "todo:2026-06-24-harden-validity-type-and-vector-expiry-lockstep"
    verification:
      - kind: unit
        ref: "cargo test -p cipherbox-core ipns:: (decode_ipns_cbor_validity_returns_validity_type_zero, decode_ipns_cbor_validity_returns_validity_type_one, decode_ipns_cbor_validity_no_validity_type_key_returns_none, decode_ipns_cbor_validity_rejects_duplicate_validity_type_key)"
        status: pass
    human_judgment: false
  - id: D2
    description: "bind_verified fails closed on missing or non-zero ValidityType before treating Validity as an expiry timestamp; widened to pub so crates/fuse's test target can call it directly"
    requirement: "SC1 (ValidityType==0 EOL binding, Rust side) — rejected identically to TS"
    verification:
      - kind: unit
        ref: "cargo test -p cipherbox-api-client ipns:: (bind_verified_missing_validity_type_returns_invalid, bind_verified_non_zero_validity_type_returns_invalid, bind_verified_validity_type_zero_in_date_returns_ok, bind_verified_validity_type_zero_expired_returns_invalid)"
        status: pass
    human_judgment: false
  - id: D3
    description: "classify_vector reduced to a thin bind_verified wrapper (no duplicated cid/sequence/ValidityType logic); non-vacuous vector-count guard bumped 8 -> 12; all 12 shared vectors (including the 4 new invalid cases) classify to their expected_result"
    requirement: "SC1 (ValidityType==0 EOL binding, Rust side) — rejected identically to TS"
    verification:
      - kind: integration
        ref: "cargo test -p cipherbox-fuse --test ipns_verify_vectors (ipns_verify_cross_language)"
        status: pass
    human_judgment: false

duration: 7min
completed: 2026-07-11
status: complete
---

# Phase 75 Plan 02: Rust ValidityType EOL Binding and Classifier Dedup Summary

**Rust bind_verified now gates on ValidityType == 0 before treating Validity as an expiry, and the cross-language test classifier was reduced to a thin wrapper around the now-`pub` bind_verified instead of a hand-duplicated reimplementation.**

## Performance

- **Duration:** 7 min
- **Started:** 2026-07-11T08:26:00+02:00
- **Completed:** 2026-07-11T08:33:24+02:00
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments
- `decode_ipns_cbor_validity` (crates/core/src/ipns.rs) now returns `(Option<Vec<u8>>, Option<i64>)` — Validity bytes plus ValidityType — with duplicate-ValidityType-key rejection mirroring the existing duplicate-Validity-key guard
- `bind_verified` (crates/api-client/src/ipns.rs) fails closed on absent or non-zero ValidityType before running the existing RFC3339 expiry/skew-buffer check, and is now `pub` (was `pub(crate)`)
- `classify_vector` (crates/fuse/tests/ipns_verify_vectors.rs) no longer hand-spells cid/sequence/ValidityType binding — it calls `bind_verified` directly; the non-vacuous vector-count guard is updated 8 → 12
- All 12 shared `tests/vectors/ipns/verify.json` cases (8 original + 4 new from Plan 75-01) classify to their `expected_result`, including the two new ValidityType-specific cases (`expired-valid-sig`, `wrong-validity-type`) and the two malformed-RFC3339 cases

## Task Commits

Each task was committed with a RED→GREEN TDD pair (Task 3's RED state pre-existed from Plan 75-01 landing the 12-case fixture against the still-8-hard-coded guard, so it required only a GREEN commit):

1. **Task 1: Extend decode_ipns_cbor_validity to also return ValidityType**
   - `f81e9063e` test(75-02): add failing tests for ValidityType decoding
   - `c7332a8ae` feat(75-02): decode ValidityType in decode_ipns_cbor_validity
2. **Task 2: Gate bind_verified on ValidityType == 0 and widen it to pub**
   - `dc2aa1dce` test(75-02): add failing tests for bind_verified ValidityType gate
   - `718a361e8` feat(75-02): gate bind_verified on ValidityType == 0, widen to pub
3. **Task 3: Dedup classify_vector into a bind_verified wrapper and update the count guard**
   - `bd2e7afe2` test(75-02): dedup classify_vector into a bind_verified wrapper

**Plan metadata:** (final docs commit follows this summary)

## Files Created/Modified
- `crates/core/src/ipns.rs` - `decode_ipns_cbor_validity` returns ValidityType alongside Validity bytes; 4 new unit tests
- `crates/api-client/src/ipns.rs` - `bind_verified` gates on ValidityType == 0, widened to `pub`; 4 new unit tests; `parse_rfc3339_to_unix_secs` untouched
- `crates/fuse/tests/ipns_verify_vectors.rs` - `classify_vector` reduced to a `bind_verified` wrapper; count guard 8 → 12; removed now-unused `base64`/`STANDARD`/`cipherbox_core` imports

## Decisions Made
- `decode_ipns_cbor_validity` returns a plain 2-tuple rather than a named struct — the plan left this open ("pick whichever threads most cleanly through the one call site") and a tuple was sufficient for the single `bind_verified` call site.
- The `== 0` EOL gate is implemented in `bind_verified`, not in the decoder, per RESEARCH Pattern 2/Pitfall 3 guidance — the decoder only reports the raw `ValidityType` value.
- `bind_verified` was widened `pub(crate)` → `pub` and `classify_vector`'s duplicate binding logic deleted entirely (RESEARCH Open Question 1, RESOLVED in favor of dedup) — this is the change that eliminates gap #9's root cause (a test-only reimplementation silently falling behind the real implementation).

## Deviations from Plan

None - plan executed exactly as written. Task 3's RED state (the 8→12 count-guard failure) pre-existed from Plan 75-01 landing the extended fixture before this plan's classifier fix was applied; no additional test-writing was needed to establish it, so Task 3 has a single GREEN-equivalent commit rather than a separate RED commit.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Rust half of SC1 (ValidityType==0 EOL binding) is complete and verified against the 12-case shared oracle.
- Plan 75-03 (TS side) must now mirror this exact ValidityType==0 gate and RFC3339 strictness so `packages/sdk-core/src/__tests__/ipns.test.ts`'s vector-length guard and per-case verdicts match Rust byte-for-byte on the same 12 cases.
- `cargo check --workspace` compiles clean (only pre-existing vendor warnings in `apps/desktop/src-tauri/vendor/fuser`, unrelated to this plan).

---
*Phase: 75-cross-language-ipns-and-node-codec-verification-parity*
*Completed: 2026-07-11*

## Self-Check: PASSED

All created/modified files confirmed present on disk; all 5 task commit hashes confirmed present in git log.

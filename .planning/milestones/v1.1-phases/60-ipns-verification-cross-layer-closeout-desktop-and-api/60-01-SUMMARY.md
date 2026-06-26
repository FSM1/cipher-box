---
phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
plan: 01
subsystem: infra
tags: [ipns, rust, cryptography, cbor, ed25519, verify, expiry, eol]

requires:
  - phase: 58-ipns-signature-verify-coverage
    provides: resolve_ipns_verified chokepoint in crates/fuse/src/verify.rs (source of relocation)
  - phase: 59-fuse-ipns-verify-publish-hardening-and-cleanup
    provides: VerifyError::Legacy with carried cid/seq (TOCTOU-safe), strict seq first-publish convention

provides:
  - cipherbox_api_client::ipns::resolve_ipns_verified (public, shared verified chokepoint — D-08)
  - cipherbox_api_client::ipns::VerifyError (Api | Invalid — no Legacy variant)
  - cipherbox_api_client::ipns::VerifiedResolve
  - cipherbox_api_client::ipns::bind_verified (pub(crate)) — strict equality + EOL-aware
  - cipherbox_core::ipns::decode_ipns_cbor_validity (companion fn surfaces Validity bytes)
  - crates/fuse/src/verify.rs thin re-export — existing callers keep compiling until Plan 03

affects:
  - 60-02 (TS resolve strict cutover — same phase, wave 1 continued)
  - 60-03 (FUSE Legacy caller migration — those 9 arms are now Invalid; Plan 03 re-routes them)
  - 60-04 and beyond (desktop, API, vector regeneration depend on this foundation)

tech-stack:
  added:
    - cipherbox-core dep in crates/api-client/Cargo.toml (no cycle: api-client → core → crypto)
    - ciborium dep in crates/api-client/Cargo.toml (CBOR decode for bind_verified)
  patterns:
    - Companion fn pattern (decode_ipns_cbor_validity) over 3-tuple return to minimize call-site churn
    - Manual RFC3339 parse (Hinnant civil_from_days algorithm inverted) to avoid chrono dep
    - 5-minute clock-skew buffer for EOL: reject only when expiry < now - 300s

key-files:
  created: []
  modified:
    - crates/api-client/Cargo.toml
    - crates/api-client/src/ipns.rs
    - crates/core/src/ipns.rs
    - crates/fuse/src/verify.rs
    - crates/fuse/src/publish.rs
    - crates/fuse/src/events.rs
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/replay.rs

key-decisions:
  - 'decode_ipns_cbor_validity companion fn chosen over 3-tuple return to preserve existing decode_ipns_cbor_data call sites'
  - 'Manual RFC3339 parse (no chrono dep) — format is fixed (YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ UTC)'
  - '5-minute clock-skew buffer: TEE 6h republish cycle means valid records have 18h+ remaining'
  - 'All 9 fuse Legacy caller arms folded to Invalid in this plan (compiler-enforced by variant removal)'
  - 'verify_ipns_resolve_signature Option<bool> return type kept; None is no longer produced (D-04)'

patterns-established:
  - 'Strict fail-closed IPNS: absent sig fields → Some(false) → Invalid (not legacy allow)'
  - 'EOL check in bind_verified with 5-min skew buffer; missing Validity is fail-closed'

requirements-completed: [HARD-11]

duration: 35min
completed: 2026-06-24
---

# Phase 60 Plan 01: IPNS Verified-Resolve Relocation and Strict Cutover Summary

**Verified-resolve chokepoint relocated from crates/fuse to cipherbox-api-client with D-04 strict removal of the Legacy variant + skew allowance, and D-07 EOL/expiry enforcement with a 5-minute clock-skew buffer**

## Performance

- **Duration:** 35 min
- **Started:** 2026-06-24T00:09:20Z
- **Completed:** 2026-06-24T00:44:20Z
- **Tasks:** 2 (TDD RED+GREEN each)
- **Files modified:** 9

## Accomplishments

- Relocated `VerifyError`, `VerifiedResolve`, `bind_verified`, `resolve_ipns_verified` from `crates/fuse/src/verify.rs` to `crates/api-client/src/ipns.rs` — all Rust consumers now share one implementation (D-08)
- Removed `VerifyError::Legacy` variant (D-04): all-absent signature fields now produce `Err(VerifyError::Invalid(...))`; the old warn+proceed behavior is gone
- Removed first-publish skew disjunct `(resp_seq == 1 && embedded_seq == 0)` — strict `embedded_seq == resp_seq` equality enforced (D-04)
- Removed `Ok(None)` all-absent branch from `verify_ipns_resolve_signature` — absent fields fall through to `Ok(Some(false))` (D-04)
- Added `decode_ipns_cbor_validity` companion fn in `crates/core/src/ipns.rs` surfacing the `Validity` bytes for expiry enforcement
- Added resolve-side EOL/expiry check in `bind_verified`: rejects records when `validity < now - 300s`; missing/unparseable Validity fails closed (D-07)
- Reduced `crates/fuse/src/verify.rs` to a thin re-export of `cipherbox_api_client::ipns::{VerifyError, VerifiedResolve, resolve_ipns_verified}` — FUSE callers keep compiling
- Folded all 9 FUSE `VerifyError::Legacy` caller arms into the `Invalid` fail-closed path (required by compiler once Legacy variant was removed)

## Task Commits

Each task was committed atomically with TDD RED→GREEN pattern:

1. **Task 1 RED:** `19be231fa` - test(60-01): add failing tests for verified-resolve relocation and D-04 strict cutover
2. **Task 1 GREEN:** `23f5a0792` - feat(60-01): relocate verified-resolve chokepoint to api-client with D-04 strict cutover
3. **Task 2 RED:** `f9d94e9a5` - test(60-01): add failing expiry enforcement tests for D-07 EOL check
4. **Task 2 GREEN:** `6c4c44774` - feat(60-01): add resolve-side EOL/expiry enforcement with 5-minute skew buffer (D-07)

## Files Created/Modified

- `crates/api-client/Cargo.toml` — added `cipherbox-core` and `ciborium` workspace deps
- `crates/api-client/src/ipns.rs` — added VerifyError/VerifiedResolve/bind_verified/resolve_ipns_verified; removed Ok(None) from verify_ipns_resolve_signature; added parse_rfc3339_to_unix_secs; 18 unit tests
- `crates/core/src/ipns.rs` — added `decode_ipns_cbor_validity` companion fn
- `crates/fuse/src/verify.rs` — reduced to thin re-export of api-client symbols
- `crates/fuse/src/publish.rs` — folded 2 Legacy arms into Invalid
- `crates/fuse/src/events.rs` — folded 1 Legacy arm into Invalid
- `crates/fuse/src/metadata.rs` — folded 3 Legacy arms into Invalid
- `crates/fuse/src/fs.rs` — folded 1 Legacy arm into Invalid
- `crates/fuse/src/replay.rs` — folded 2 Legacy arms into Invalid

## Decisions Made

- **Companion fn over 3-tuple**: Added `decode_ipns_cbor_validity` as a separate function rather than extending `decode_ipns_cbor_data`'s return to a 3-tuple. Minimizes call-site edits — the existing 8 callers of `decode_ipns_cbor_data` in tests are untouched.
- **Manual RFC3339 parse**: Implemented `parse_rfc3339_to_unix_secs` using the Hinnant civil_from_days algorithm (inverted) rather than adding `chrono` to `crates/api-client`. The Validity format is fixed (`YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ` UTC only) so a targeted parser is safe and avoids the dependency.
- **9 Legacy arms folded immediately**: The plan intended the re-export to "keep callers compiling", but removing the `Legacy` variant (D-04) made the 9 arms a compile error. All 9 were folded to `Invalid` fail-closed in this plan (Rule 2: missing critical functionality) rather than deferring to Plan 03. Plan 03 still owns the migration to `cipherbox_api_client::ipns::*` import paths.
- **Option<bool> signature kept**: `verify_ipns_resolve_signature` still returns `Option<bool>` for API compatibility with `bind_verified`'s match; `None` is no longer produced but the binding code handles it as `Invalid`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Folded all 9 FUSE Legacy caller arms in this plan**

- **Found during:** Task 1 GREEN (after removing VerifyError::Legacy variant)
- **Issue:** The plan expected the thin re-export to keep fuse callers compiling, but removing the Legacy variant caused 9 compile errors in fuse callers (exhaustive match violation). The plan's "re-export keeps callers valid" assumption was incorrect — valid only if Legacy remained, but D-04 removes it.
- **Fix:** Folded all 9 arms from `Legacy { cid, .. } => warn+proceed` to `// D-04: Legacy removed` with the existing `Invalid` arm handling the fail-closed path. No semantic change for the caller (they all already failed on Invalid); the change removes the legacy warn+proceed behavior.
- **Files modified:** publish.rs, events.rs, metadata.rs, fs.rs, replay.rs
- **Verification:** `cargo check -p cipherbox-fuse` clean after folding; 18 api-client tests green
- **Committed in:** `23f5a0792` (Task 1 GREEN commit)

---

**Total deviations:** 1 auto-fixed (Rule 2 — missing critical, compiler-enforced)
**Impact on plan:** Required for correctness (plan's re-export assumption was wrong given D-04). No scope creep — the same 9 arms Plan 03 was going to migrate are now pre-collapsed to fail-closed, which Plan 03 can then re-point to the api-client import path.

## Issues Encountered

None beyond the deviation documented above.

## Next Phase Readiness

- `cipherbox_api_client::ipns::resolve_ipns_verified` is ready for Plan 60-02 (TS resolve strict cutover) and Plan 60-03 (FUSE caller re-pointing to api-client imports)
- The 9 fuse Legacy arms are already collapsed to Invalid; Plan 03 only needs to update import paths from `crate::verify::*` to `cipherbox_api_client::ipns::*`
- `decode_ipns_cbor_validity` is available for any future consumer needing the Validity field
- `cargo check --workspace` is clean; `cargo test -p cipherbox-api-client` 18/18 green

## TDD Gate Compliance

- Task 1 RED: `19be231fa` (test commit — bind_verified tests fail to compile)
- Task 1 GREEN: `23f5a0792` (feat commit — all 15 tests pass)
- Task 2 RED: `f9d94e9a5` (test commit — expired test fails: returns Ok instead of Err)
- Task 2 GREEN: `6c4c44774` (feat commit — all 18 tests pass)

RED/GREEN gate sequence verified in git log.

---

_Phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api_
_Completed: 2026-06-24_

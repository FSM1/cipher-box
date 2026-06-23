---
phase: 59-fuse-ipns-verify-publish-hardening-and-cleanup
plan: "03"
subsystem: fuse
tags: [rust, fuse, ipns, cleanup, dead-code, test-quality]
dependency_graph:
  requires: [finding-c-legacy-carry-response]
  provides: [finding-d-dead-code-cleanup, finding-e-cleanup]
  affects:
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/content_ops.rs
    - crates/fuse/src/verify.rs
    - crates/fuse/src/events.rs
    - scripts/gen-ipns-verify-vectors.ts
    - tests/vectors/ipns/verify.json
tech_stack:
  added: []
  patterns:
    - "Direct is_none() guard replaces dead binding + let _ = discard pattern"
    - "Move computations inside their sole consumer branch (D.2 record_b64)"
    - "Collapse identical if/else arms to single expression (D.1)"
tech_decisions:
  - "D.1: journal_entry param retained with TODO; only the dead if/else body collapsed"
  - "D.2: only record/marshaled/record_b64 moved inside is_first_publish; ipns_key_arr/new_seq/value stay outside for both branches"
  - "D.3: direct is_none() guard preserves exact error message text for existing test assertions"
  - "E.1: signature_verified field removed entirely; field was defense-in-depth only, never read by any FUSE call site"
  - "E.2: included in Task 1 commit (same file as D.1); is_ipns_not_found test now uses legible case + negative 404 assertion"
  - "E.4: bytesToHex helper removed alongside public_key/private_key (became unused after E.4 removal)"
  - "winfsp check on macOS: pre-existing Windows-only winfsp-sys dependency failures — authoritative gate is CI"
key_files:
  created: []
  modified:
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/content_ops.rs
    - crates/fuse/src/verify.rs
    - crates/fuse/src/events.rs
    - scripts/gen-ipns-verify-vectors.ts
    - tests/vectors/ipns/verify.json
decisions:
  - "[Phase 59-03]: D.1 journal_entry if/else body collapsed to single Err; param kept with D-01a TODO"
  - "[Phase 59-03]: D.3 current_seq_for_cas replaced by direct if current_seq.is_none() guard (same error text)"
  - "[Phase 59-03]: E.1 VerifiedResolve::signature_verified field removed; was never read, only written"
  - "[Phase 59-03]: E.4 bytesToHex helper removed alongside the unused public_key/private_key vector fields"
metrics:
  duration: "~12 minutes"
  completed: "2026-06-23T20:30:00Z"
  tasks_completed: 2
  files_changed: 6
---

# Phase 59 Plan 03: Dead-Code Cleanup and Test-Quality Fixes (HARD-10 Findings D + E) Summary

Dead-code removal and test-quality pass across the FUSE verify/publish/CAS path: collapse an
unreachable branch body in `publish_with_cas_retry`, move `record_b64` computation inside its
sole consumer, replace a dead binding with a direct guard, remove the never-read
`signature_verified` field from `VerifiedResolve`, fix an ambiguous test string, and strip
unused `public_key`/`private_key` from the cross-language IPNS verify vector fixture.

## What Was Built

### Finding D.1 — Dead `journal_entry` Branch Body Collapsed (metadata.rs)

`publish_with_cas_retry` had an `if journal_entry.is_some() { Err(...) } else { Err(...) }`
where both arms returned identical `Err(format!("persistent conflict for {}", ipns_name))`.
The `is_some()` arm is unreachable (all call sites pass `None`). Collapsed to a single `Err`.
The `journal_entry: Option<()>` parameter is retained with a D-01a TODO referencing the
deferred journal-on-exhaustion design. A `let _ = &journal_entry;` line suppresses the
dead-field warning until the param is wired.

### Finding D.2 — `record_b64` Gated to First-Publish Branch (content_ops.rs)

`record`, `marshaled`, and `record_b64` were built unconditionally before the
`if is_first_publish` split but only consumed inside that branch. The update path's
`publish_with_cas_retry` closure re-signs independently. Moved the three bindings inside
`if is_first_publish`. `ipns_key_arr`, `new_seq`, and `value` remain outside (both
branches need them — Pitfall 2 avoided, confirmed via `cargo check`).

### Finding D.3 — `current_seq_for_cas` Dead Binding Replaced (content_ops.rs)

`let current_seq_for_cas = current_seq.ok_or_else(...)?` extracted a value never
subsequently used — `publish_with_cas_retry` re-resolves internally. The trailing
`let _ = current_seq_for_cas;` suppression and a 14-line NOTE comment were also dead.
Replaced with a direct `if current_seq.is_none() { return Err(...); }` guard. Exact error
message text preserved (`"resolve_sequence returned None for update publish"`).

### Finding E.1 — Dead `signature_verified` Field Removed (verify.rs + events.rs)

`VerifiedResolve::signature_verified: bool` was written in two places (`verify.rs:132`
set `true`, `events.rs:104` set `false`) but never read by any FUSE call site. Removed
the field from the struct definition, both write sites, and the two unit test assertions
that referenced it. `cargo check -p cipherbox-fuse --features fuse` confirms zero
dangling references.

### Finding E.2 — `is_ipns_not_found` Test Clarified (metadata.rs, included in Task 1)

`assert!(super::is_ipns_not_found("404 not found"))` passed only because "not found" is
in the string, not because "404" alone triggers the predicate. Changed to
`assert!(super::is_ipns_not_found("record not found"))` and added a negative assertion
`assert!(!super::is_ipns_not_found("404"), "bare '404' without 'not found' must not match")`.

### Finding E.4 — Unused `public_key`/`private_key` Stripped from Vector Fixture (scripts + JSON)

The generator emitted `public_key: string; private_key: string` in the `VectorEntry`
interface and all 8 `vectors.push()` calls. The Rust `IpnsVerifyVector` struct never
deserialized these fields. Removed the interface fields, the push-site lines, and the now-
unused `bytesToHex` helper. Regenerated `tests/vectors/ipns/verify.json` — no `public_key`
or `private_key` keys. Cross-language vector test (`ipns_verify_cross_language`) green.

## Task Results

| Task | Name | Commit | Status |
| ---- | ---- | ------ | ------ |
| 1 | D.1/D.2/D.3 dead-code cleanup + E.2 test fix | 9cb5feb6f | DONE |
| 2 | E.1 signature_verified removal + E.4 vector fixture cleanup | d391fa290 | DONE |

## Verification Results

- `cargo test -p cipherbox-fuse --features fuse` — 95 unit tests passed, 1 cross-language vector test passed, 0 failed
- `cargo check -p cipherbox-fuse --features fuse` — clean (zero errors)
- `cargo check -p cipherbox-fuse --features winfsp` — FAILS on macOS due to pre-existing Windows-only `winfsp-sys` deps (`windows_registry::LOCAL_MACHINE`, `windows_core::imp`); authoritative gate is `Cargo Check & Test (Windows)` CI
- `cargo clippy -p cipherbox-fuse --features fuse -- -D warnings` — zero errors or warnings in `crates/fuse`; pre-existing `crates/crypto` errors are out of scope
- `grep -rn "signature_verified" crates/fuse/src/` — zero matches
- `grep -c "public_key" tests/vectors/ipns/verify.json` — 0
- `grep -c "current_seq_for_cas" crates/fuse/src/content_ops.rs` — 1 (comment only, no binding)
- `grep -n "if journal_entry.is_some()" crates/fuse/src/metadata.rs` — zero matches

## Deviations from Plan

### E.2 handled in Task 1 commit

- **Found during:** Task 1 implementation
- **Issue:** E.2 (`is_ipns_not_found` test fix) is in `metadata.rs`, the same file as D.1. Including it in Task 1 avoids a separate single-line commit to the same file.
- **Fix:** E.2 included in Task 1 commit alongside D.1. The plan's Task 2 section mentions E.2 but the plan's files list for Task 2 includes `metadata.rs` — grouped with D changes for minimal file churn.
- **Impact:** None — both tasks committed; all acceptance criteria met.

### `bytesToHex` helper removed (Rule 2 — missing correctness)

- **Found during:** Task 2 implementation of E.4
- **Issue:** After removing `public_key`/`private_key` from all vector push sites, `bytesToHex` became unused. An unused function in a TypeScript script would trigger ESLint `@typescript-eslint/no-unused-vars` on commit via lint-staged.
- **Fix:** Removed `bytesToHex` (5 lines). `hexToBytes` (still used for parsing key material) retained.
- **Files modified:** `scripts/gen-ipns-verify-vectors.ts`
- **Commit:** d391fa290

### winfsp macOS pre-existing incompatibility

- **Found during:** Post-task winfsp check
- **Issue:** `cargo check -p cipherbox-fuse --features winfsp` fails on macOS because `winfsp-sys` has Windows-only deps. Pre-existing before our changes (identical to 59-01 and 59-02 SUMMARYs).
- **Action:** Documented. Authoritative gate is CI (`Cargo Check & Test (Windows)`). All changed code is syntactically correct Rust.

## Known Stubs

None. All removals are clean; no placeholder values or TODOs flow to production logic.
The `journal_entry` param TODO references deferred D-01a journal work — existing, not introduced by this plan.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes. Removals only.

## Self-Check: PASSED

- `crates/fuse/src/verify.rs` struct `VerifiedResolve` has no `signature_verified` field
- `grep -rn "signature_verified" crates/fuse/src/` returns zero matches
- `grep -n "if journal_entry.is_some()" crates/fuse/src/metadata.rs` returns zero matches
- `grep -n "record_b64" crates/fuse/src/content_ops.rs` shows only inside `if is_first_publish` block (lines 167-176) and closure `retry_record_b64`
- `grep -n "current_seq_for_cas" crates/fuse/src/content_ops.rs` returns 1 match (comment only)
- `grep -c "public_key" tests/vectors/ipns/verify.json` returns 0
- Commits verified: 9cb5feb6f (Task 1), d391fa290 (Task 2)
- 95 fuse unit tests + 1 vector test pass; 0 fail

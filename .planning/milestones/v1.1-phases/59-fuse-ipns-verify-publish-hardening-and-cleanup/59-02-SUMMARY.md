---
phase: 59-fuse-ipns-verify-publish-hardening-and-cleanup
plan: "02"
subsystem: fuse
tags: [rust, fuse, ipns, security, tdd, durability, enum-migration]
dependency_graph:
  requires: [finding-a-wrap-key-propagation, finding-b-ipns-name-re-resolution]
  provides: [finding-c-legacy-carry-response]
  affects:
    - crates/fuse/src/verify.rs
    - crates/fuse/src/events.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/publish.rs
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/replay.rs
tech_stack:
  added: []
  patterns:
    - "Struct variant carrying resolved response (VerifyError::Legacy { cid, sequence_number })"
    - "Atomic multi-file enum shape migration verified via cargo check compile gate"
    - "TOCTOU race elimination: carry already-classified response, no second resolve_ipns"
key_files:
  created: []
  modified:
    - crates/fuse/src/verify.rs
    - crates/fuse/src/events.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/publish.rs
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/replay.rs
decisions:
  - "VerifyError::Legacy carries { cid: String, sequence_number: String } from the already-resolved response — no second resolve_ipns in any Legacy arm"
  - "Display format: 'legacy record: all signature fields absent (cid={cid}, seq={sequence_number})' (per RESEARCH Open Question 2)"
  - "events.rs synthetic VerifiedResolve preserves signature_verified: false field (Finding E.1 removes it in plan 03 per Pitfall 4)"
  - "winfsp check on macOS: pre-existing Windows-only winfsp-sys dependency failures — authoritative gate is CI (Cargo Check & Test Windows)"
metrics:
  duration: "~4 minutes"
  completed: "2026-06-23T19:48:00Z"
  tasks_completed: 2
  files_changed: 6
---

# Phase 59 Plan 02: VerifyError::Legacy Struct Variant Migration (HARD-10 Finding C) Summary

Atomic 6-file migration of `VerifyError::Legacy` from a unit variant to a struct variant carrying `{ cid: String, sequence_number: String }`, eliminating the redundant second `resolve_ipns` call and its TOCTOU race window (T-59-04) at all 9 Legacy match-arm sites.

## What Was Built

### Finding C — VerifyError::Legacy carries the already-resolved IPNS response

`VerifyError::Legacy` was a unit variant that dropped the already-classified resolve response. Every consumer had to issue a second `resolve_ipns` call to recover the CID and/or sequence number it already held. This opened a ~1ms TOCTOU race window where a concurrent publish could change the record between classification and re-resolution.

The fix changes the variant to `Legacy { cid: String, sequence_number: String }`, clones `resp.cid` and `resp.sequence_number` into it in `bind_verified`'s `None` arm, and updates all 9 downstream match arms across 5 files to consume the carried fields directly. Zero second `resolve_ipns` calls remain in any Legacy arm.

The `Display` implementation now includes the carried values for log visibility:
`"legacy record: all signature fields absent (cid={cid}, seq={sequence_number})"`.

## Task Results

| Task | Name | RED Commit | GREEN Commit | Status |
| ---- | ---- | ---------- | ------------ | ------ |
| 1 | Migrate VerifyError::Legacy to struct variant; update bind_verified + Display + test | 3bbee028b | 1f9f7fc0a | DONE |
| 2 | Update all 9 Legacy arms to consume carried cid/sequence_number | (part of GREEN) | 1f9f7fc0a | DONE |

Tasks 1 and 2 share a single GREEN commit because the enum shape change and the 9 arm updates form an atomic unit — the crate will not compile in any partial state. The RED test commit established the failing test, then the single GREEN commit landed all changes together.

## Arm Sites Updated

| File | Site | What changed |
| ---- | ---- | ------------ |
| `verify.rs` | enum definition + `bind_verified` + `Display` | Variant definition + population + Display format |
| `publish.rs:105` | `resolve_sequence` Legacy arm | `{ sequence_number, .. }` — parse carried seq, no second resolve |
| `publish.rs:188` | `resolve_sequence_strict` Legacy arm | `{ sequence_number, .. }` — parse carried seq, no second resolve |
| `events.rs:92` | `spawn_metadata_refresh` Legacy arm | `{ cid, sequence_number }` — build `VerifiedResolve` from carried fields |
| `metadata.rs:332` | `publish_with_cas_retry` remote merge arm | `{ cid, .. }` — use carried cid for merge, no second resolve |
| `metadata.rs:483` | `spawn_bin_entry_publish` Legacy arm | `{ cid, .. }` — fetch bin content directly from carried cid |
| `metadata.rs:662` | `resolve_and_fetch_file_meta` Legacy arm | `{ cid, .. }` — use carried cid, no second resolve |
| `replay.rs:338` | `resolve_folder_key` BFS Legacy arm | `{ cid, .. }` — use carried cid, no second resolve |
| `replay.rs:469` | `fetch_merge_publish_parent` Legacy arm | `{ cid, .. }` — use carried cid, no second resolve |

## Verification Results

- `cargo test -p cipherbox-fuse --features fuse` — 95 passed, 0 failed (including extended `bind_verified_legacy_returns_legacy` test asserting carried `cid` and `sequence_number`)
- `cargo check -p cipherbox-fuse --features fuse` — clean (zero errors in crates/fuse)
- `cargo check -p cipherbox-fuse --features winfsp` — FAILS on macOS due to pre-existing Windows-only `winfsp-sys` deps (`windows_registry::LOCAL_MACHINE`, `windows_core::imp`); authoritative gate is `Cargo Check & Test (Windows)` CI
- `cargo clippy -p cipherbox-fuse --features fuse -- -D warnings` — zero crates/fuse warnings; pre-existing crates/crypto errors are out of scope

## Deviations from Plan

### Merged Task 1 + Task 2 into a single GREEN commit

- **Found during:** Task 1 implementation
- **Issue:** The enum shape change (Task 1) and the 9 arm updates (Task 2) cannot be split into separate commits — the crate does not compile in any intermediate state where the variant is a struct but some arms still use the unit pattern.
- **Fix:** Task 1 RED commit established the failing test. A single GREEN commit (`1f9f7fc0a`) landed all changes atomically. This matches the plan's own note: "All must be updated in one cohesive unit or the crate will not compile."
- **Impact:** None — the plan's ATOMIC migration requirement is satisfied; the TDD RED gate commit (`3bbee028b`) correctly precedes the GREEN commit.

### winfsp macOS pre-existing incompatibility

- **Found during:** Post-migration winfsp check
- **Issue:** `cargo check -p cipherbox-fuse --features winfsp` fails on macOS because `winfsp-sys` has Windows-only deps. This was pre-existing before our changes (identical to 59-01-SUMMARY).
- **Action:** Documented. Authoritative gate is CI (`Cargo Check & Test (Windows)`). All 9 arm updates are in shared code compiled under `#[cfg(any(feature = "fuse", feature = "winfsp"))]` and are syntactically correct.

## TDD Gate Compliance

- RED commit `3bbee028b` (`test(59-02): extend bind_verified_legacy_returns_legacy...`) precedes GREEN commit `1f9f7fc0a` (`feat(59-02): migrate VerifyError::Legacy to struct variant...`)
- Gate sequence satisfied: `test(...)` commit before `feat(...)` commit.

## Known Stubs

None. All Legacy arms consume the carried response fields; no placeholder values or TODO markers flow to production logic.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes. The change removes network surface (eliminates second `resolve_ipns` calls) rather than adding it.

## Self-Check: PASSED

- `crates/fuse/src/verify.rs` contains `Legacy { cid: String, sequence_number: String }` in enum definition
- `bind_verified` `None` arm contains `Legacy { cid: resp.cid.clone(), sequence_number: resp.sequence_number.clone() }`
- `Display` Legacy arm contains `cid=` and `seq=` interpolation
- `grep -rn "VerifyError::Legacy" crates/fuse/src/{events,fs,publish,metadata,replay}.rs | grep -v "Legacy {"` returns empty (no bare unit-pattern arms remain)
- `grep -rn "resolve_ipns(" crates/fuse/src/{events,fs,publish,metadata,replay}.rs | grep -v resolve_ipns_verified | grep -v resolve_ipns_for_replay` returns empty (no second resolve calls in Legacy arms)
- Commits verified: 3bbee028b (RED), 1f9f7fc0a (GREEN)
- 95 fuse tests pass; 0 fail

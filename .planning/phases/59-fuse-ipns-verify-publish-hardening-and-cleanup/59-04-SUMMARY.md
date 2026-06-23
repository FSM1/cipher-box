---
phase: 59-fuse-ipns-verify-publish-hardening-and-cleanup
plan: "04"
subsystem: fuse
tags: [rust, fuse, ipns, security, sequence-convention, anti-rollback]
dependency_graph:
  requires:
    - phase: finding-f-first-publish-sequence
      provides: "FUSE embeds 1 on first publish; verify.rs strict equality"
  provides:
    - "FUSE first-publish embedded sequence unified to 1 (publish.rs + replay.rs)"
    - "verify.rs strict embedded_seq == resp_seq (skew allowance removed, T-59-10)"
    - "Six Phase 59 source todos archived to completed/"
  affects:
    - crates/fuse/src/publish.rs
    - crates/fuse/src/replay.rs
    - crates/fuse/src/verify.rs
    - crates/fuse/tests/ipns_verify_vectors.rs
    - tests/vectors/ipns/verify.json
tech_stack:
  added: []
  patterns:
    - "Unified first-publish embedded sequence = 1 across FUSE/SDK/API (cross-layer convention)"
    - "Strict embedded_seq == resp_seq anti-rollback check in bind_verified"
key_files:
  created: []
  modified:
    - crates/fuse/src/publish.rs
    - crates/fuse/src/replay.rs
    - crates/fuse/src/verify.rs
    - crates/fuse/tests/ipns_verify_vectors.rs
    - tests/vectors/ipns/verify.json
key-decisions:
  - "[Phase 59-04]: F.1 next_file_publish_sequence(is_first_publish=true) returns 1; test renamed _starts_new_records_at_one"
  - "[Phase 59-04]: F.2 replay.rs publish_child_folder_metadata embeds seq=1; record_publish seeds at 1; all log/comments updated"
  - "[Phase 59-04]: F.3 verify.rs skew allowance (resp_seq==1 && embedded_seq==0) removed; strict equality now universal (T-59-10)"
  - "[Phase 59-04]: F.4 ipns_verify_vectors.rs classify_vector uses strict equality; case-8 expected_result changed valid->invalid"
  - "[Phase 59-04]: TEE re-sign path confirmed safe — republish.service.ts bypasses upsertFolderIpns entirely (T-59-11 accepted)"
  - "[Phase 59-04]: winfsp check on macOS: pre-existing Windows-only winfsp-sys dep failures — authoritative gate is CI"
requirements-completed: [HARD-10]
duration: ~15min
completed: "2026-06-23"
---

# Phase 59 Plan 04: First-Publish Sequence Unification and Todo Archival (HARD-10 Finding F) Summary

FUSE first-publish embedded sequence unified to 1 (matching TS SDK and API convention); verify.rs strict equality closes the skew window; six Phase 59 source todos archived.

## Performance

- **Duration:** ~15 min
- **Started:** 2026-06-23T20:30:00Z
- **Completed:** 2026-06-23T21:00:00Z
- **Tasks:** 2
- **Files modified:** 7 (5 Rust/JSON + 6 todos via git mv)

## Accomplishments

- `next_file_publish_sequence(true, _)` now returns `Ok(1)` (was `Ok(0)`), matching `packages/sdk-core/src/file/index.ts` which embeds `1n` and the API comment at `ipns.service.ts:357`
- `replay.rs publish_child_folder_metadata` child-folder first-publish changed from `create_ipns_record(..., 0, ...)` to `..., 1, ...`; `record_publish` seeds coordinator at 1
- `verify.rs bind_verified` skew allowance `(resp_seq == 1 && embedded_seq == 0)` removed; `let seq_ok = embedded_seq == resp_seq` (strict equality, T-59-10 mitigated)
- `ipns_verify_vectors.rs` `classify_vector` updated to strict equality; case-8 vector ("first-publish-skew") `expected_result` changed from `"valid"` to `"invalid"`
- All 93 fuse unit tests + 1 cross-language vector test pass; no new clippy warnings
- Six Phase 59 source todos archived to `.planning/todos/completed/` via `git mv` (history preserved)

## Task Commits

1. **Task 1: Finding F — unify FUSE first-publish embedded sequence to 1 and remove skew allowance** — `d246d767a` (feat)
2. **Task 2: archive six Phase 59 source todos to completed/** — `55c140297` (docs)

## Files Created/Modified

- `crates/fuse/src/publish.rs` — `return Ok(1)` on first-publish; test renamed `_starts_new_records_at_one`
- `crates/fuse/src/replay.rs` — `create_ipns_record(..., 1, ...)` for child folder first-publish; `record_publish(child_ipns_name, 1)`; log strings and comments updated
- `crates/fuse/src/verify.rs` — strict `embedded_seq == resp_seq`; removed `bind_verified_first_publish_seq_skew_returns_ok` and `bind_verified_seq_skew_only_applies_to_first_publish` tests
- `crates/fuse/tests/ipns_verify_vectors.rs` — strict equality in `classify_vector`; updated module doc comment; Phase 59 Finding F bridge note
- `tests/vectors/ipns/verify.json` — case-8 `expected_result` changed from `"valid"` to `"invalid"`; description updated

## Decisions Made

- TEE re-sign path confirmed safe via RESEARCH Finding F: `republish.service.ts` calls `publishSignedRecord` → `delegatedRouting.publish` directly then `syncFolderIpnsSequence` via `folderIpnsRepository.update` — bypasses `upsertFolderIpns` and therefore bypasses the embedded-sequence gate entirely. T-59-11 accepted.
- Cross-layer safety: removing the skew allowance is safe because (a) FUSE now embeds 1 so new records pass strict equality, and (b) legacy records (pre-Phase-59 embedded=0) have all-absent signature fields and take the `VerifyError::Legacy` path, not the seq check path.
- `record_publish(child_ipns_name, 1)` updated in lock-step with the IPNS record creation to keep the PublishCoordinator sequence cache consistent with what was actually published.
- The case-8 vector description updated to note it now tests a hardening rejection (embedded=0 with resp_seq=1 is rejected post-Phase-59 as a potential rollback attempt with a legacy-convention record).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] replay.rs T-45-05 test asserted `new_seq == 0` for NotFound**

- **Found during:** Task 1 (full fuse test suite run)
- **Issue:** `not_found_outcome_drives_first_publish` asserted `assert_eq!(new_seq, 0, "NotFound must produce seq 0")` — directly testing `next_file_publish_sequence(true, None)` return value, which changed from 0 to 1
- **Fix:** Updated assertion to `assert_eq!(new_seq, 1, "NotFound must produce seq 1 (Phase 59 Finding F: unified with TS SDK)")`; updated comment from `new_seq=0` to `new_seq=1`; updated function doc comment to reflect new convention
- **Files modified:** `crates/fuse/src/replay.rs`
- **Verification:** `cargo test -p cipherbox-fuse --features fuse` — 93 passed, 0 failed
- **Committed in:** d246d767a (Task 1)

**2. [Rule 1 - Bug] replay.rs log/comment references to "seq 0" were stale after convention change**

- **Found during:** Task 1 code inspection
- **Issue:** Multiple log strings and comments in replay.rs referenced "seq 0" for first-publish paths (publish_child_folder_metadata doc, log at line 668, code comments at 1022-1026)
- **Fix:** Updated all to "seq 1"; added Phase 59 Finding F references in comments
- **Files modified:** `crates/fuse/src/replay.rs`
- **Committed in:** d246d767a (Task 1)

## Verification Results

- `cargo test -p cipherbox-fuse --features fuse` — 93 unit tests passed, 1 cross-language vector test passed, 0 failed
- `cargo test -p cipherbox-fuse --features fuse next_file_publish_sequence` — 6 tests passed (including `_starts_new_records_at_one`)
- `cargo test -p cipherbox-fuse --features fuse verify` — 5 tests passed (skew tests removed; strict equality tests pass)
- `cargo test -p cipherbox-fuse --features fuse ipns_verify` — 1 cross-language vector test passed (case-8 now expects "invalid")
- `cargo clippy -p cipherbox-fuse --features fuse --no-deps` — 24 pre-existing warnings (in cache.rs, inode.rs, etc.); zero new warnings from this plan's changes; zero errors
- `cargo check -p cipherbox-fuse --features winfsp` — FAILS on macOS due to pre-existing Windows-only `winfsp-sys` deps; authoritative gate is `Cargo Check & Test (Windows)` CI
- `grep -n "return Ok(0)" crates/fuse/src/publish.rs` — zero matches
- `grep -n "create_ipns_record.*0," crates/fuse/src/*.rs` — zero first-publish hardcoded-0 sites
- `let seq_ok` in verify.rs and ipns_verify_vectors.rs — both read `embedded_seq == resp_seq` (strict)
- `ALL_SIX_ARCHIVED` verify command passed; `git status` shows six renames

## Phase 60 Bridge

Phase 60 (HARD-11) plans strict `embedded == DB` verified-record cache. This unification is a prerequisite: with FUSE now embedding 1 (matching SDK/API), the DB sequence and embedded sequence will be equal on first publish. Phase 60 should assume embed=1 convention as baseline.

## Known Stubs

None. All changes are live convention updates; no placeholder values or TODOs flow to production logic.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes. The change removes a skew window in the resolve-side anti-rollback check rather than adding new surface.

## Self-Check: PASSED

- `crates/fuse/src/publish.rs` contains `return Ok(1)` in first-publish arm
- `crates/fuse/src/replay.rs` `create_ipns_record` call uses `1` for child folder first-publish
- `crates/fuse/src/verify.rs` `let seq_ok = embedded_seq == resp_seq;` (no skew clause)
- `tests/vectors/ipns/verify.json` case-8 `expected_result` is `"invalid"`
- Six todos confirmed in `.planning/todos/completed/`; none in `.planning/todos/pending/` for these files
- Commits verified: d246d767a (Task 1), 55c140297 (Task 2)
- 93 fuse unit tests + 1 vector test pass; 0 fail

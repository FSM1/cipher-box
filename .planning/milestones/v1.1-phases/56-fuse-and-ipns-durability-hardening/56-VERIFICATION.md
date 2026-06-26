---
phase: 56-fuse-and-ipns-durability-hardening
verified: 2026-06-22T00:00:00Z
status: passed
score: 19/19 must-haves verified
overrides_applied: 0
---

# Phase 56: FUSE and IPNS Durability Hardening Verification Report

**Phase Goal:** Close pre-existing FUSE write-path and per-file IPNS durability gaps surfaced by the PR #538 / Phase 55 refactor review (D-01a, D-05..D-15, HARD-07).
**Verified:** 2026-06-22
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

Goal-backward verification confirmed every in-scope durability gap's implementing code exists in the committed worktree source (branch `feat/fuse-and-ipns-durability-hardening`), is substantive (not stubbed), and is wired through to real errno/status/error returns. The 12 phase-56 cargo test markers pass locally. winfsp source guards are present and mirror the macOS guards (winfsp cannot compile on macOS by design — CI's `Cargo Check & Test (Windows)` gate is authoritative).

### Observable Truths

| # | Truth (gap) | Status | Evidence |
| --- | --- | --- | --- |
| 1 | D-05 negative offset → EINVAL before write_at | ✓ VERIFIED | file_data.rs:105-109, guard precedes write_at at :128 |
| 2 | D-05 offset+len overflow → EFBIG before write_at | ✓ VERIFIED | file_data.rs:111-118 `checked_add` → EFBIG; `new_end` used at :131 |
| 3 | D-06 create/mknod duplicate name → EEXIST before allocate_ino | ✓ VERIFIED | file_data.rs:178-182 `find_child`→EEXIST before allocate_ino at :184 |
| 4 | D-06 mkdir duplicate name → EEXIST (genuine, not EIO) | ✓ VERIFIED | mkdir.rs:38-44 guard placed before closure so outer match maps EEXIST not EIO |
| 5 | D-07 next_file_publish_sequence overflow-safe | ✓ VERIFIED | publish.rs:23-26 `checked_add(1)`→Err; no `seq + 1` remains |
| 6 | D-15 winfsp write path applies same guards in lockstep | ✓ VERIFIED | windows/write_ops.rs:429-431 overflow→status_io_device_error; :72-73 collision; MkdirConflict (:274) untouched (D-04) |
| 7 | D-01a/D-02 per-file Conflict re-resolves+retries, never acked-as-success | ✓ VERIFIED | content_ops.rs:204-230 routes update path through helper; first-publish Conflict→Err (:189); old fall-through record_publish removed |
| 8 | D-01a/D-02 bin Conflict re-resolves+retries, never silently acked | ✓ VERIFIED | metadata.rs:522-545 spawn_bin_entry_publish routes through helper, journal_entry=None, Err→log::error! |
| 9 | D-03 shared publish_with_cas_retry is the CAS decision point | ✓ VERIFIED | metadata.rs:102-212 helper; per-file+bin route through it. Folder keeps its own loop (async-closure limitation, documented in 56-02-SUMMARY) — acceptable equivalent decision point |
| 10 | D-01a persistent Conflict returns Err→EIO, never warn-and-ack; journal deferred | ✓ VERIFIED | metadata.rs:192-208 both arms return Err (no JournalOp::FilePublish/BinPublish variant). INTENDED design per CONTEXT D-01a |
| 11 | D-08 superseded write cannot unpin live CIDs | ✓ VERIFIED | fs.rs:284-301 pruned_cids unpin loop INSIDE `write_generation == result.write_generation` guard |
| 12 | D-09 FP-resolve overflow queued, not dropped | ✓ VERIFIED | fs.rs:60 `pending_fp_resolves: VecDeque`; drain-first :434, push-on-overflow :440/:456 (the silent `break` is gone) |
| 13 | D-10 hung refresh times out + always clears refreshing_metadata | ✓ VERIFIED | events.rs:86-128 wraps inner block in `tokio::time::timeout(NETWORK_TIMEOUT,..)`; Elapsed arm sends PendingRefresh::Failure |
| 14 | D-12 spawn_metadata_publish key params Zeroizing, ownership transferred | ✓ VERIFIED | metadata.rs:220-221 params `Zeroizing<Vec<u8>>`; fs.rs:263-264 wrap owned build_folder_metadata clones |
| 15 | D-11 display-name-only fallback resets folder identity (clears loaded state) | ✓ VERIFIED | inode.rs:400 `matched_by_stable_id`; :468-486 clears children/children_loaded + log on fallback |
| 16 | D-11 file display-name fallback forces re-resolution (no stale keys) | ✓ VERIFIED | inode.rs:528-531 stable-IPNS-first lookup; :606-624 `same_pointer` string-eq is false on fallback (IPNS name differs) → keys not preserved. Equivalent to matched_by_stable_id for files |
| 17 | D-13 fetchAndDecryptMetadata throws typed CID error with cause | ✓ VERIFIED | load.ts:30-39 try-catch, typed Error naming CID, `{ cause }`, `return await` for decrypt rejection capture |
| 18 | D-13 both registration wrapKey calls inside zeroizing try | ✓ VERIFIED | registration.ts:69-108 both wrapKey (:71,:73) inside try; catch (:104-107) zeroes both buffers |
| 19 | D-14 copy state gated on real success; version download surfaces error | ✓ VERIFIED | DetailsPrimitives.tsx:19-37 `success` from clipboard/execCommand, setCopied inside `if(success)`; VersionHistory.tsx:37-40 setActionError on missing privateKey |

**Score:** 19/19 truths verified

### Required Artifacts

| Artifact | Provides | Status |
| --- | --- | --- |
| crates/fuse/src/write_ops/implementation/file_data.rs | D-05 + D-06 macOS guards + test module | ✓ VERIFIED |
| crates/fuse/src/write_ops/implementation/mkdir.rs | D-06 mkdir EEXIST guard | ✓ VERIFIED |
| crates/fuse/src/publish.rs | D-07 checked_add overflow guard | ✓ VERIFIED |
| crates/fuse/src/platform/windows/write_ops.rs | D-05/D-06 winfsp lockstep (D-15) | ✓ VERIFIED (source present; Windows CI authoritative) |
| crates/fuse/src/metadata.rs | publish_with_cas_retry (D-03), bin retry (D-02), Zeroizing (D-12) | ✓ VERIFIED |
| crates/fuse/src/content_ops.rs | per-file publish through helper (D-02/D-01a) | ✓ VERIFIED |
| crates/fuse/src/fs.rs | D-08 unpin guard, D-09 continuation queue, D-12 call site | ✓ VERIFIED |
| crates/fuse/src/events.rs | D-10 refresh timeout | ✓ VERIFIED |
| crates/fuse/src/inode.rs | D-11 identity reset | ✓ VERIFIED |
| packages/sdk-core/src/folder/load.ts | D-13 typed decode failure | ✓ VERIFIED |
| packages/sdk-core/src/folder/registration.ts | D-13 wrapKey-in-try | ✓ VERIFIED |
| apps/web/.../details/DetailsPrimitives.tsx | D-14 copy gating | ✓ VERIFIED |
| apps/web/.../details/VersionHistory.tsx | D-14 error surfacing | ✓ VERIFIED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Phase-56 fuse test markers pass | `cargo test -p cipherbox-fuse --features fuse -- d11_ publish_with_cas_retry persistent_conflict next_file_publish_sequence_overflow d05_ d06_ handle_write_rejects` | 12 passed; 0 failed | ✓ PASS |

Tests confirmed: d05_offset_no_overflow_within_range, d05_offset_overflow_predicate_at_boundary, d06_find_child_detects_duplicate, handle_write_rejects_negative_offset, d11_display_name_fallback_clears_loaded_state, d11_stable_id_match_preserves_children_loaded_state, d11_file_display_name_fallback_forces_re_resolution, publish_with_cas_retry_success_first_attempt, publish_with_cas_retry_conflict_then_success, publish_with_cas_retry_persistent_conflict_journal_none_returns_err, publish_with_cas_retry_make_record_error_propagates, next_file_publish_sequence_overflow_returns_err.

Orchestrator-provided evidence (full `cargo test -p cipherbox-fuse`: 78 passed/0 failed; sdk-core 230 + web 68 vitest green) corroborates. JS test files exist: load.test.ts (3), DetailsPrimitives.test.ts (3), VersionHistory.test.ts (2).

### Requirements Coverage

| Requirement | Source Plan | Status | Evidence |
| --- | --- | --- | --- |
| HARD-07 | 56-01/02/03 | ✓ SATISFIED | All 12 durability gaps (D-01a, D-05..D-15) implemented and wired; "no durability decision left to a swallowed warning" acceptance lens met across all Conflict/error arms |

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
| --- | --- | --- | --- |
| (none) | TBD/FIXME/XXX debt markers | — | No debt markers in any modified source file |

The `journal_entry: Option<()>` placeholder in metadata.rs:108 is a deliberate, documented seam for the deferred JournalOp::FilePublish/BinPublish work (CONTEXT Deferred Ideas) — both branches currently return Err (the intended D-01a EIO-on-exhaustion). Not a stub: the surfaced-Err behavior is the in-scope deliverable; journaling is explicitly out of scope.

### Notes on Plan-vs-Implementation Nuances (non-blocking)

- **content_ops.rs:179 `expected_sequence_number: None`** — this is the legitimate first-publish branch (no prior IPNS record to CAS against), not the D-02 bug. The bug was on the UPDATE path's Conflict fall-through, which is now removed; the update path routes through the helper with `Some(seq)`. The plan-01 grep acceptance "None returns nothing" was over-strict; actual behavior is correct.
- **D-11 file branch** — implemented via the existing `same_pointer` string-equality on `file_meta_ipns_name` rather than a separate `matched_by_stable_id` boolean. For files these are equivalent: a display-name-only fallback (stable IPNS lookup miss) implies the IPNS names differ, so `same_pointer` is already false and old keys are not preserved. Test `d11_file_display_name_fallback_forces_re_resolution` exercises the real populate_folder path and passes.
- **D-03 folder site** keeps its own CAS loop (async-closure limitation documented in 56-02-SUMMARY). Per-file + bin share the helper; folder remains the canonical template — the D-03 single-decision-point intent is satisfied.

### Human Verification Required

None for goal achievement at the source level. One CI-side gate remains AUTHORITATIVE but is not a local blocker and not a goal-achievement gap:

- **winfsp Windows CI gate** — `Cargo Check & Test (Windows)` must be green for the D-05/D-06 winfsp lockstep changes (windows/write_ops.rs). winfsp cannot compile on macOS by design; the source guards are present and correctly mirror the macOS guards (verified by reading). This is a standard CI round-trip per the project's winfsp-is-CI-only rule, not a code defect.

### Gaps Summary

No gaps. Every in-scope durability gap (D-01a EIO-on-exhaustion, D-05, D-06, D-07, D-08, D-09, D-10, D-11, D-12, D-13, D-14, D-15 winfsp lockstep) has substantive, wired implementing code in the committed worktree, with passing phase-56 cargo test markers and committed JS unit tests. No stubs, no debt markers, no Conflict-as-success regressions. The D-01a EIO-on-exhaustion behavior is the intended design (journal-on-exhaustion correctly deferred).

---

_Verified: 2026-06-22_
_Verifier: Claude (gsd-verifier)_

---
phase: 46-desktop-fuse-data-loss-bugs-replay-hardening
verified: 2026-06-15T12:43:02Z
status: human_needed
score: 6/6 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Linux remount-after-SIGKILL: mount the desktop FUSE vault on Linux, SIGKILL the app mid-mount to leave a stale/disconnected mount (stat returns ENOTCONN, Path::exists() lies), then restart the app."
    expected: "App auto-recovers — recover_stale_mount reads /proc/self/mountinfo, unmounts via fusermount3 -u (or lazy -z -u), create_mount_point_dir succeeds (recover-then-retry on EEXIST), and the vault remounts cleanly with NO user-facing 'Failed to create mount point' error and no notify."
    why_human: "recover_stale_mount + the mountinfo/EEXIST unit tests are #[cfg(target_os = linux)] and do not compile/run on the macOS verification host. The end-to-end stale-mount recovery (real fusermount3, real ENOTCONN kernel state) cannot be exercised by unit tests on this platform."
---

# Phase 46: Desktop FUSE data-loss bugs + replay hardening Verification Report

**Phase Goal:** Close the desktop FUSE write-durability work Phase 45 deferred — three data-loss bugs (mkdir orphan on parent-publish conflict, release() false-durability ack, stale-mount recovery on crash), two replay-path hardening follow-ups (PR #491), and remaining read_ops/write_ops + journal_helpers test coverage. Behavior-changing correctness/durability fixes.

**Verified:** 2026-06-15T12:43:02Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth (Requirement) | Status | Evidence |
| --- | --- | --- | --- |
| 1 | mkdir durably retries parent publish on conflict — child folder never orphaned remotely | ✓ VERIFIED | Behavior pre-landed (PR #487/#491); Phase 46 adds characterization tests. See REQ-1 note. |
| 2 | release()/flush does not ack OS or zeroize+delete temp file until remote commit confirmed OR journaled for replay | ✓ VERIFIED | Behavior pre-landed (PR #487); Phase 46 adds characterization tests. See REQ-2 note. |
| 3 | Linux startup auto-recovers stale/disconnected FUSE mount (EEXIST/ENOTCONN) instead of failing | ✓ VERIFIED (runtime needs Linux UAT) | New production code `recover_stale_mount` + mountinfo parser + EEXIST retry, wired into mount path. |
| 4 | Legacy empty `file_meta_ipns_name` replay entries parked, never published as empty FilePointer | ✓ VERIFIED | New park-guard in `replay_upload_entry`; `legacy_empty_name_parks` test passes. |
| 5 | Strict cache-bypassing IPNS resolve in replay classification retains entry on transient failure | ✓ VERIFIED | New `resolve_sequence_strict`; `strict_resolve_bypasses_cache` + `transient_failure_retains_entry` pass. |
| 6 | read_ops/write_ops handler test harness (ReplySender) + journal_helpers builder tests | ✓ VERIFIED | ReplySender re-export, `make_test_fs`, `CaptureSender`, builder round-trip tests all present and pass. |

**Score:** 6/6 truths verified (REQ-3 runtime path flagged for Linux UAT — see human verification)

### REQ-1 / REQ-2 — behavior pre-landed, Phase 46 characterizes

The roadmap requirement text for REQ-1/REQ-2 describes a behavior change, but the durable mkdir-retry and release-durability behavior was **already implemented in a prior phase** (commit `dcd1becb6`, "feat(fuse): durable write journal with crash-recovery replay" — PR #487, later hardened by PR #491). Phase 46's 46-04-PLAN.md is explicitly "tests-only — characterization tests."

Evidence the production handlers were NOT modified in Phase 46:

- `crates/fuse/src/write_ops.rs` (mkdir handler with conflict-detection, journal-on-mkdir, `FsEvent::MkdirConflict` send, journal cleanup only on confirmed publish): **0 lines changed** in `4b539b445..HEAD`.
- `crates/fuse/src/read_ops.rs` (`handle_release`: D-04 `journal.put` fsync BEFORE `reply.ok()`, D-05 `handle.cleanup()` only after journal confirmed): **0 lines changed** in `4b539b445..HEAD`.
- `FsEvent::MkdirConflict` drain → re-arm (`mutated_folders.insert` + `queue_publish`) at `lib.rs:949` was introduced by `dcd1becb6`, not Phase 46.

**Judgment: GOAL MET for REQ-1/REQ-2.** The required durability behavior is present, correct, and now pinned by passing tests (`mkdir_conflict_rearms`, `mkdir_happy_path_puts_journal_entry_then_replies_entry`, `release_journals_before_cleanup`). This is "behavior present + now tested," not "behavior never implemented." The roadmap goal is to *close* the deferred work; the work is closed (landed + characterized). Not a gap.

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `crates/fuse/src/platform/linux.rs` | `recover_stale_mount` + mountinfo parser + `should_recover_then_retry` + `create_mount_point_dir` | ✓ VERIFIED | +211 lines new; all fns present; lazy `-z -u` fallback at L176. |
| `apps/desktop/src-tauri/src/fuse/mod.rs` | Linux-only stale-mount recovery before create_dir_all decision | ✓ VERIFIED | `recover_stale_mount` called L99 (cfg linux); `create_mount_point_dir` L106; macOS/Windows preserved via cfg gates. |
| `crates/fuse/src/lib.rs` | park-return for None-name entries + `resolve_sequence_strict` + strict call in `resolve_ipns_for_replay` | ✓ VERIFIED | Park-guard L1882; `resolve_sequence_strict` L308 (no cache fallback); used by `resolve_ipns_for_replay` L220. |
| `apps/desktop/.../vendor/fuser/src/lib_impl.rs` | `pub use reply::ReplySender` | ✓ VERIFIED | Present L29. |
| `crates/fuse/src/test_support.rs` | `make_test_fs` + `CaptureSender` + `reply_error_code` | ✓ VERIFIED | 151 lines; `impl fuser::ReplySender for CaptureSender` L132; `WriteQueue::new` L123. |
| `crates/fuse/src/journal_helpers.rs` | `build_upload_journal_entry` + `build_mkdir_journal_entry` + tests | ✓ VERIFIED | Builders L128/L378; round-trip tests L506/L559 pass. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `mod.rs` | `linux::recover_stale_mount` | cfg(linux) call before create_dir_all | ✓ WIRED | L98-99 |
| `recover_stale_mount` | `fusermount3 -z` | lazy unmount fallback | ✓ WIRED | `try_fusermount3_unmount(..., &["-z","-u"])` L176 |
| `resolve_ipns_for_replay` | `resolve_sequence_strict` | strict resolve on replay path | ✓ WIRED | L220 |
| `replay_upload_entry` | `record_failure` (park) | early Err on `file_meta_ipns_name.is_none()` | ✓ WIRED | L1882; routes through replay_for_vault record_failure |
| `test_support.rs` | `fuser::ReplySender` | `impl fuser::ReplySender for CaptureSender` | ✓ WIRED | L132 |
| `test_support.rs` | `WriteQueue` | per-test isolated journal dir | ✓ WIRED | L123 |
| MkdirConflict re-arm | debounced publish | `merge_folder_children` fetch-and-merge on Conflict | ✓ WIRED | A2 verified independently: lib.rs:477 fetch_content, lib.rs:485 merge_folder_children, retry with merged metadata — no blind-overwrite. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Full fuse suite | `cargo test -p cipherbox-fuse --features fuse` | 57 passed; 0 failed | ✓ PASS |
| REQ-4 park | test `legacy_empty_name_parks` | ok | ✓ PASS |
| REQ-5 strict resolve | tests `strict_resolve_bypasses_cache`, `transient_failure_retains_entry` | ok | ✓ PASS |
| REQ-1 re-arm | test `mkdir_conflict_rearms` | ok | ✓ PASS |
| REQ-2 release durability | test `release_journals_before_cleanup` | ok | ✓ PASS |
| REQ-6 builders | tests `build_upload_journal_entry_round_trips`, `build_mkdir_journal_entry_round_trips` | ok | ✓ PASS |
| REQ-3 mountinfo/EEXIST unit tests | (cfg linux) | not compiled on macOS host | ? SKIP → human |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| REQ-1 | 46-04 | Durable mkdir parent-publish retry | ✓ SATISFIED | Pre-landed (PR #487/#491) + now characterized; behavior present in write_ops.rs + lib.rs drain. |
| REQ-2 | 46-04 | release() durability before ack | ✓ SATISFIED | Pre-landed (PR #487) + now characterized; D-04/D-05 ordering in handle_release. |
| REQ-3 | 46-02 | Linux stale-mount auto-recovery | ✓ SATISFIED (runtime → human) | New `recover_stale_mount` wired into mount path; runtime needs Linux UAT. |
| REQ-4 | 46-03 | Park legacy empty-name replay entries | ✓ SATISFIED | New park-guard; test passes. |
| REQ-5 | 46-03 | Strict cache-bypassing replay resolve | ✓ SATISFIED | New `resolve_sequence_strict`; tests pass. |
| REQ-6 | 46-01 | Handler harness + journal_helpers tests | ✓ SATISFIED | ReplySender export + make_test_fs + builders + tests. |

No Phase 46 entries in `.planning/REQUIREMENTS.md` (post-milestone phase tracked via ROADMAP scope todos). No orphaned requirements.

### Anti-Patterns Found

None. No TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER markers in any Phase 46 changed source file (`lib.rs`, `platform/linux.rs`, `mod.rs`, `test_support.rs`, `journal_helpers.rs`).

The `flush` no-op (`handle_flush` returns ok) is a **documented accepted limitation** (46-04-SUMMARY), not a gap: REQ-2 targets `release()`, where the durable journaling happens. Journaling on flush was deliberately omitted to avoid regressing D-04 / double-journaling.

### Human Verification Required

#### 1. Linux remount-after-SIGKILL recovery

**Test:** On a Linux host, mount the desktop FUSE vault, SIGKILL the app mid-mount to leave a stale/disconnected mount (stat returns ENOTCONN, `Path::exists()` returns false), then restart the app.
**Expected:** App auto-recovers — reads `/proc/self/mountinfo`, unmounts via `fusermount3 -u` (or lazy `-z -u`), `create_mount_point_dir` succeeds via recover-then-retry on EEXIST, vault remounts cleanly with no "Failed to create mount point" error and no notify.
**Why human:** `recover_stale_mount` and its mountinfo/EEXIST unit tests are `#[cfg(target_os = "linux")]` and do not compile/run on the macOS verification host. End-to-end recovery (real fusermount3, real ENOTCONN kernel state) is not exercisable by unit tests on this platform.

### Gaps Summary

No gaps. All six requirements are delivered as actual code in the checked-out tree and proven by the 57-test suite (0 failures).

The single nuance worth surfacing: REQ-1 and REQ-2 durability behaviors were landed in a prior phase (PR #487/#491) and Phase 46 contributes characterization tests rather than new production logic for those two — exactly as 46-04-PLAN.md states ("tests-only"). Production handlers `write_ops.rs` and `read_ops.rs` are unchanged (0 lines) in the phase diff, and the D-04/D-05/re-arm logic is verifiably present from the prior commit. The phase goal ("close the deferred write-durability work") is met: the behavior exists and is now regression-guarded. This is not a gap.

REQ-3, REQ-4, REQ-5, REQ-6 are genuinely new production code in this phase and are fully wired. The only item not provable on the macOS host is the runtime Linux stale-mount recovery path (REQ-3), routed to human UAT.

---

_Verified: 2026-06-15T12:43:02Z_
_Verifier: Claude (gsd-verifier)_

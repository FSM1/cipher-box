---
phase: 46
slug: desktop-fuse-data-loss-bugs-replay-hardening
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-15
---

# Phase 46 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                              |
| ---------------------- | ------------------------------------------------------------------ |
| **Framework**          | Rust built-in `#[test]` / `#[tokio::test]` (tokio dev-dep present) |
| **Config file**        | none — Cargo workspace; per-crate `[dev-dependencies]`             |
| **Quick run command**  | `cargo test -p cipherbox-fuse --features fuse <test_name>`         |
| **Full suite command** | `cargo test -p cipherbox-fuse --features fuse && cargo test -p cipherbox-sdk` |
| **Estimated runtime**  | ~60 seconds (fuse) + ~30 seconds (sdk)                             |

> Constraint (project memory): GSD sub-agents must NOT run full concurrent Rust
> test suites — RAM starvation. Run single named tests during development;
> reserve the full suite for the wave-merge and phase gate, run sequentially.

---

## Sampling Rate

- **After every task commit:** Run the single named test(s) for that task via `cargo test -p <crate> --features fuse <name>`
- **After every plan wave:** Run `cargo test -p cipherbox-fuse --features fuse` then `cargo test -p cipherbox-sdk` (sequential, not concurrent)
- **Before verification:** Full fuse + sdk suites must be green
- **Max feedback latency:** ~90 seconds

---

## Per-Task Verification Map

| Requirement | Behavior | Test Type | Automated Command | Unit-testable now |
| ----------- | -------- | --------- | ----------------- | ----------------- |
| REQ-6 | Vendored fuser `ReplySender` export + `make_test_fs` + `CaptureSender` compile | unit (harness) | `cargo test -p cipherbox-fuse --features fuse getattr_returns_ok_for_root` | this IS the deliverable — land FIRST |
| REQ-6 | `journal_helpers` builders round-trip | unit | `cargo test -p cipherbox-fuse --features fuse build_upload_journal_entry` | yes (needs harness + real EC keypair) |
| REQ-1 | mkdir conflict re-arms parent publish (FsEvent drain) | characterization | `cargo test -p cipherbox-fuse --features fuse mkdir_conflict_rearms` | yes (pure in-memory FsEvent) |
| REQ-1 | mkdir happy-path journals before reply | unit | `cargo test -p cipherbox-fuse --features fuse mkdir_happy_path` | yes (needs harness) |
| REQ-2 | release journals ciphertext before temp cleanup | unit | `cargo test -p cipherbox-fuse --features fuse release_journals_before_cleanup` | yes (harness + temp journal dir) |
| REQ-2 | replay re-uploads journaled ciphertext | characterization | `cargo test -p cipherbox-fuse --features fuse replay_reuploads_ciphertext` | yes (pure WriteQueue round-trip) |
| REQ-2 | flush is a no-op OK | unit | `cargo test -p cipherbox-fuse --features fuse flush_returns_ok` | yes (needs harness) |
| REQ-3 | mountinfo parser detects stale mount | unit | `cargo test -p cipherbox-fuse --features fuse mountinfo_detects_stale` | yes (pure parser) |
| REQ-3 | EEXIST → recover-then-retry decision | unit | `cargo test -p cipherbox-fuse --features fuse eexist_triggers_recovery` | yes (mock unmount closure) |
| REQ-4 | legacy None-name entry is parked, not removed | characterization | `cargo test -p cipherbox-fuse --features fuse legacy_empty_name_parks` | yes (unroutable API, assert retained) |
| REQ-4 | empty-name FilePointers collide in merge | unit | `cargo test -p cipherbox-fuse --features fuse empty_name_merge_collision` | yes (pure `merge_folder_children`) |
| REQ-5 | `resolve_sequence_strict` errs despite cache | unit | `cargo test -p cipherbox-fuse --features fuse strict_resolve_bypasses_cache` | yes (unroutable API + seeded cache) |
| REQ-5 | transient failure retains replay entry | characterization | `cargo test -p cipherbox-fuse --features fuse transient_failure_retains_entry` | yes (unroutable API) |
| REQ-5 | `classify_resolve_outcome` unchanged | regression | `cargo test -p cipherbox-fuse --features fuse classify_resolve_outcome_maps_resolve_results` | yes (already exists) |

_Status legend: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Vendored fuser `pub use reply::ReplySender;` (`apps/desktop/src-tauri/vendor/fuser/src/lib_impl.rs:28`) — blocks ALL handler unit tests (REQ-1, REQ-2, REQ-6). Land FIRST.
- [ ] `make_test_fs()` + `CaptureSender` test-support module in cipherbox-fuse — shared fixture for every handler test.
- [ ] No new framework install — Rust test harness + tokio dev-dep already present.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |
| Real Linux remount after SIGKILL with no "mount failed" notification | REQ-3 | Cannot unit-test a real FUSE mount/disconnect; needs a Linux host with libfuse3 | Headless desktop FUSE UAT recipe: SIGKILL the app mid-mount on Linux, relaunch, assert vault remounts cleanly without the user-facing notification |
| Induced real parent-publish conflict resolves child folder remotely | REQ-1 | Needs two concurrent devices + live IPNS | Create a folder while a concurrent device edits the same parent; confirm the child resolves remotely after the debounce window |

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers the `ReplySender` export + shared fixture (MISSING references)
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

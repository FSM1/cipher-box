---
phase: 43
slug: fuse-write-durability
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-12
---

# Phase 43 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                          |
| ---------------------- | -------------------------------------------------------------- |
| **Framework**          | Rust built-in `#[test]` + `#[tokio::test]` (no jest/vitest)    |
| **Config file**        | none (cargo test per crate)                                    |
| **Quick run command**  | `cargo test -p cipherbox-sdk -- queue`                         |
| **Full suite command** | `cargo test -p cipherbox-sdk && cargo test -p cipherbox-fuse`  |
| **Estimated runtime**  | ~60 seconds                                                    |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-sdk -- queue`
- **After every plan wave:** Run `cargo test -p cipherbox-sdk && cargo test -p cipherbox-fuse`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 90 seconds

RAM constraint: never run workspace-wide `cargo test` (all crates at once) or any pnpm/jest suites alongside cargo — targeted per-crate commands only.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior                                        | Test Type | Automated Command                                                | File Exists | Status     |
| ------- | ---- | ---- | ----------- | ---------- | ------------------------------------------------------ | --------- | ---------------------------------------------------------------- | ----------- | ---------- |
| TBD     | 01   | 1    | REQ-43-C    | —          | JournalEntry round-trip serialize/deserialize           | unit      | `cargo test -p cipherbox-sdk -- queue::tests`                     | ❌ W0       | ⬜ pending |
| TBD     | 01   | 1    | REQ-43-C    | —          | `put` writes journal file to disk; `load_all` returns it | unit      | `cargo test -p cipherbox-sdk -- queue::tests::journal_put_load`   | ❌ W0       | ⬜ pending |
| TBD     | 01   | 1    | REQ-43-C    | —          | `remove` deletes the journal file                       | unit      | `cargo test -p cipherbox-sdk -- queue::tests::journal_remove`     | ❌ W0       | ⬜ pending |
| TBD     | 01   | 1    | REQ-43-F    | —          | Entry transitions to `Failed` after max retries          | unit      | `cargo test -p cipherbox-sdk -- queue::tests::park_on_max_retries` | ❌ W0       | ⬜ pending |
| TBD     | 01   | 1    | REQ-43-D    | T-zk       | Plaintext never present in journal file (ciphertext only) | unit      | `cargo test -p cipherbox-sdk -- queue::tests::journal_no_plaintext` | ❌ W0       | ⬜ pending |
| TBD     | 01   | 1    | REQ-43-E    | —          | Replay ordering: MkdirPublish before UploadFile          | unit      | `cargo test -p cipherbox-sdk -- queue::tests::replay_order`       | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

(Planner: replace TBD task IDs and extend rows for fuser-wiring and winfsp-wiring plans.)

---

## Wave 0 Requirements

- [ ] `crates/sdk/src/queue.rs` unit tests — full rewrite to cover new `JournalEntry` shape
- [ ] No framework install needed — `tokio` dev-dep already in `crates/sdk/Cargo.toml`

Note: no existing integration tests for fuse platform code (no `crates/fuse/tests/`; testing is via in-module `#[cfg(test)]`).

---

## Manual-Only Verifications

| Behavior                                                | Requirement | Why Manual                                             | Test Instructions                                                                 |
| ------------------------------------------------------- | ----------- | ------------------------------------------------------ | --------------------------------------------------------------------------------- |
| Park notification appears in OS notification center      | REQ-43-F    | OS-level notification rendering not testable headlessly | Mount vault, force upload failure (kill API), write a file, observe notification  |
| Journal survives process kill between ack and upload     | REQ-43-C    | Requires killing the desktop app mid-write              | Write file, SIGKILL app before upload completes, relaunch, verify file uploads    |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

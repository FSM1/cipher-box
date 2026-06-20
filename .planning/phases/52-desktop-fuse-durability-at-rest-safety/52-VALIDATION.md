---
phase: 52
slug: desktop-fuse-durability-at-rest-safety
status: ready
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-19
---

# Phase 52 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property                | Value                                                          |
| ----------------------- | -------------------------------------------------------------- |
| **Framework**           | Rust built-in `#[test]` + `#[tokio::test]` (tokio dev-dep)     |
| **Config file**         | Cargo.toml per crate — no separate test config                |
| **Quick run command**   | `cargo test -p cipherbox-sdk -p cipherbox-fuse 2>&1 \| tail -20` |
| **Full suite command**  | `cargo test --workspace --features fuse 2>&1 \| tail -20`       |
| **Estimated runtime**   | ~60 seconds                                                    |

Existing inline `#[cfg(test)] mod tests` blocks in `crates/sdk/src/queue.rs` and
`crates/fuse/src/lib.rs` are the established test location. Pure queue logic uses
synchronous `#[test]`; async replay logic uses `#[tokio::test]`.

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-sdk -p cipherbox-fuse 2>&1 | tail -20`
- **After every plan wave:** Run `cargo test --workspace --features fuse 2>&1 | tail -20`
- **Before `/gsd-verify-work`:** Full suite must be green (plus `cargo check --features winfsp` for the Windows path)
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref           | Secure Behavior                                            | Test Type    | Automated Command                                                  | File Exists | Status  |
| ------- | ---- | ---- | ----------- | -------------------- | ---------------------------------------------------------- | ------------ | ----------------------------------------------------------------- | ----------- | ------- |
| D-01-a | 52-02 | 1 | HARD-03 | Info Disclosure | ciphertext stored in 0600 sidecar, not in JSON | unit | `cargo test -p cipherbox-sdk sidecar_ciphertext_not_in_json` | ✅ `queue.rs:1493` | ✅ green |
| D-01-b | 52-03 | 2 | HARD-03 | — | release() acks only after sidecar fsync (durable-ack) — `durable_ack_with_sidecar` folded into the broader `release_journals_before_cleanup` (asserts sidecar `.bin` durably written + sha256 match before release reply) | unit (async) | `cargo test -p cipherbox-fuse release_journals_before_cleanup` | ✅ `lib.rs:3262` | ✅ green |
| D-01-c | 52-03 | 2 | HARD-03 | DoS | per-entry size cap returns Err above threshold | unit | `cargo test -p cipherbox-fuse payload_size_cap_returns_err` | ✅ `journal_helpers.rs:680` | ✅ green |
| D-02-a | 52-05 | 3 | HARD-03 | Info Disclosure | purge_vault removes all entries for one vault | unit | `cargo test -p cipherbox-sdk purge_vault_removes_all` | ✅ `queue.rs:1601` | ✅ green |
| D-02-b | 52-05 | 3 | HARD-03 | — | gc_failed_entries purges by age | unit | `cargo test -p cipherbox-sdk gc_purges_old_failed` | ✅ `queue.rs:1631` | ✅ green |
| D-02-c | 52-05 | 3 | HARD-03 | — | gc_failed_entries purges to size budget | unit | `cargo test -p cipherbox-sdk gc_purges_to_size_budget` | ✅ `queue.rs:1664` | ✅ green |
| D-03-a | 52-04 | 2 | HARD-03 | DoS | replay entry returns Err on network timeout | unit (async) | `cargo test -p cipherbox-fuse replay_entry_timeout` | ✅ `lib.rs:3524` | ✅ green |
| D-04-a | 52-02 | 1 | HARD-03 | Info Disclosure | no plaintext filename in journal JSON | unit | `cargo test -p cipherbox-sdk journal_no_plaintext_filename` | ✅ `queue.rs:1446` | ✅ green |
| D-04-b | 52-02 | 1 | HARD-03 | Cryptography (V6) | round-trip encrypt filename → write → reload → decrypt (also `decrypt_journal_name_round_trip_and_legacy_compat` at `lib.rs:3546`) | unit | `cargo test -p cipherbox-sdk filename_encryption_round_trips` | ✅ `queue.rs:1474` | ✅ green |
| D-04-c | 52-02 | 1 | HARD-03 | — | compat deserialization of old plaintext filename field | unit | `cargo test -p cipherbox-sdk legacy_plaintext_filename_compat` | ✅ `queue.rs:1375` | ✅ green |
| D-05-a | 52-01 | 1 | HARD-03 | Input Validation (V5) | sanitize_error scrubs C:\Users\, /var, /tmp, /private | unit | `cargo test -p cipherbox-sdk sanitize_error_extended_paths` | ✅ `sync.rs:356` | ✅ green |
| D-06-a | 52-01 | 1 | HARD-03 | Tampering | journal.remove failure logs warn! (not swallowed) | unit | `cargo test -p cipherbox-fuse remove_failure_is_logged` | ✅ `lib.rs:3466` | ✅ green |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky · ❌ W0 = test does not yet exist, created in Wave 0_

_All 12 must_have truths map to real, named tests confirmed present by static analysis (2026-06-20). Combined suites green: `cargo test -p cipherbox-fuse` = 64/64, `cargo test -p cipherbox-sdk` = 57/57. Note: D-01-c moved from the SDK crate to `crates/fuse/src/journal_helpers.rs`; D-01-b's `durable_ack_with_sidecar` was folded into `release_journals_before_cleanup` (behavior covered)._

_Plan/Wave columns assigned by the planner (2026-06-19). Each row maps to a task in the named plan; ❌ W0 rows are created by the first TDD task of that plan before its implementation step._

---

## Wave 0 Requirements

- [x] `crates/sdk/src/queue.rs` `#[cfg(test)] mod tests` — D-01 sidecar, D-02 GC/purge, D-04 name encryption present; D-05 `sanitize_error` lives in `crates/sdk/src/sync.rs`
- [x] `crates/fuse/src/lib.rs` `#[cfg(test)] mod tests` — D-01 durable-ack (via `release_journals_before_cleanup`), D-03 replay timeout, D-06 removal-logging present; D-01-c size-cap in `crates/fuse/src/journal_helpers.rs`
- [x] No framework install needed — Rust built-in test harness + tokio dev-dep already present

---

## Manual-Only Verifications

| Behavior                                              | Requirement | Why Manual                                                                 | Test Instructions                                                                                          |
| ----------------------------------------------------- | ----------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Off-thread heavy write does not block FS callbacks    | HARD-03     | Requires a real FUSE mount + concurrent ops to observe non-blocking under macFUSE/FUSE-T | Mount a vault, write a large (multi-hundred-MB) file, concurrently `ls`/`stat` other paths and confirm they return promptly |
| Replay concurrent with mount (mount returns instantly)| HARD-03     | Requires a live mount with a hung/slow IPNS endpoint to observe mount not waiting | Pre-seed a journal entry against an unreachable relay, mount, confirm mount completes immediately while replay times out in background |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved — 12/12 must_have truths mapped to confirmed tests; 0 gaps (2026-06-20)

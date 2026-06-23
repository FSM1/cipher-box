---
phase: 59
slug: fuse-ipns-verify-publish-hardening-and-cleanup
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-23
---

# Phase 59 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                          |
| ---------------------- | ------------------------------------------------------------------------------ |
| **Framework**          | `cargo test` (Rust) — fuse + winfsp feature sets                               |
| **Config file**        | FUSE crate `Cargo.toml` (find exact path; `#[cfg(winfsp)]`-gated windows mods) |
| **Quick run command**  | `cargo test -p <fuse-crate>` (default/fuse feature set)                        |
| **Full suite command** | `cargo test -p <fuse-crate> --all-features` + `cargo clippy -- -D warnings`    |
| **Estimated runtime**  | ~60–120 seconds local                                                          |

> winfsp paths cannot compile on macOS — `Cargo Check & Test (Windows)` CI is authoritative for any `#[cfg(winfsp)]` change. SDK-E2E (local; redis 6380) + desktop-E2E (dispatch-gated) gate durability-critical publish paths.

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <fuse-crate>` (quick)
- **After every plan wave:** Run full suite (`--all-features`) + `cargo clippy -- -D warnings`
- **Before `/gsd-verify-work`:** Full suite green + winfsp Windows CI dispatched for any winfsp-gated change
- **Max feedback latency:** ~120 seconds

---

## Per-Task Verification Map

> Behavioural fixes (A swallowed-error propagation, B inode re-resolution, C VerifyError::Legacy carry) get unit tests; pure cleanup (D/E dead-code, F constant) is clippy/compile + existing-test-update. Every winfsp-touching task additionally carries `cargo check --features winfsp` (type-level) and the authoritative Windows CI gate. Commands copied verbatim from each plan's `<automated>` block.

| Task ID  | Plan | Wave | Requirement | Threat Ref | Secure Behavior                                                                       | Test Type   | Automated Command                                                                                                       | File Exists | Status     |
| -------- | ---- | ---- | ----------- | ---------- | ------------------------------------------------------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------- | ----------- | ---------- |
| 59-01-01 | 01   | 1    | HARD-10     | T-59-01    | File key-wrap failure → `build_folder_metadata` returns Err; never publishes `ipns_private_key_encrypted: None` | unit (tdd)  | `cargo test -p cipherbox-fuse --features fuse build_folder_metadata`                                                    | ✅          | ⬜ pending |
| 59-01-02 | 01   | 1    | HARD-10     | —          | File with changed `file_meta_ipns_name` (same `modified_at`) re-resolves fresh CID/keys | unit (tdd)  | `cargo test -p cipherbox-fuse --features fuse file_meta_ipns_name`                                                      | ✅          | ⬜ pending |
| 59-02-01 | 02   | 2    | HARD-10     | T-59-05    | `VerifyError::Legacy` carries resolved `cid`/`sequence_number` (no second resolve)    | unit (tdd)  | `cargo test -p cipherbox-fuse --features fuse bind_verified_legacy_returns_legacy`                                      | ✅          | ⬜ pending |
| 59-02-02 | 02   | 2    | HARD-10     | T-59-05    | All 9 Legacy arms migrated atomically; both feature sets compile                      | integration | `cargo test -p cipherbox-fuse --features fuse && cargo check -p cipherbox-fuse --features winfsp`                       | ✅          | ⬜ pending |
| 59-03-01 | 03   | 3    | HARD-10     | T-59-07    | Dead `journal_entry` branch collapsed; `content_ops` dead bindings removed; conflict test still Err | unit + clippy | `cargo test -p cipherbox-fuse --features fuse publish_with_cas_retry && cargo test -p cipherbox-fuse --features fuse publish_file_metadata` | ✅          | ⬜ pending |
| 59-03-02 | 03   | 3    | HARD-10     | —          | `VerifiedResolve` has no `signature_verified` field; `is_ipns_not_found` test legible | unit + clippy | `cargo test -p cipherbox-fuse --features fuse is_ipns_not_found && cargo test -p cipherbox-fuse --features fuse ipns_verify && cargo test -p cipherbox-fuse --features fuse verify` | ✅          | ⬜ pending |
| 59-04-01 | 04   | 4    | HARD-10     | —          | FUSE first publish embeds seq `1` (matches SDK/API). NOTE: the verify-side skew-allowance removal was reverted post-execution (CR-01) and deferred to Phase 60 — see 59-VERIFICATION.md amendment | unit        | `cargo test -p cipherbox-fuse --features fuse next_file_publish_sequence && cargo test -p cipherbox-fuse --features fuse verify && cargo test -p cipherbox-fuse --features fuse ipns_verify` | ✅          | ⬜ pending |
| 59-04-02 | 04   | 4    | HARD-10     | —          | Six source todos archived to `completed/` via `git mv` (history preserved)            | static      | `test ! -e .planning/todos/pending/<each-of-6> && test -e .planning/todos/completed/<each-of-6> && echo ALL_SIX_ARCHIVED` | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. The `cipherbox-fuse` crate already has a `cargo test` harness over the touched modules (verify.rs / fs.rs / inode.rs / metadata.rs / content_ops.rs); the behavioural fixes (A/B/C) add their failing-first tests inline within their `type: tdd` tasks — no separate Wave 0 scaffold task is needed.

---

## Manual-Only Verifications

| Behavior                                          | Requirement | Why Manual                              | Test Instructions                                                  |
| ------------------------------------------------- | ----------- | --------------------------------------- | ----------------------------------------------------------------- |
| winfsp-gated counterparts of any fixed FUSE logic | HARD-10     | Cannot compile/run winfsp on macOS      | Dispatch `Cargo Check & Test (Windows)` CI; confirm green         |
| Durability-critical publish path end-to-end       | HARD-10     | Requires live IPNS publish/resolve loop | Run SDK-E2E (redis 6380) + desktop-E2E (`gh workflow run` CI E2E) |

_If none: "All phase behaviors have automated verification."_

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (none — existing infra)
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-23

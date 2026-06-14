---
phase: 45
slug: desktop-fuse-write-durability-cleanup
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-14
---

# Phase 45 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                     |
| ---------------------- | ------------------------------------------------------------------------- |
| **Framework**          | `cargo test` (Rust, built-in test harness; async via `#[tokio::test]`)    |
| **Config file**        | none — workspace `Cargo.toml`; `cipherbox-fuse` default feature = `fuse`  |
| **Quick run command**  | `cargo test -p cipherbox-fuse`                                            |
| **Full suite command** | `cargo test -p cipherbox-fuse -p cipherbox-sdk`                          |
| **Estimated runtime**  | ~30 seconds                                                               |

> Lint/format gates (run before commit, not per-task): `cargo clippy -p cipherbox-fuse --all-targets -- -D warnings` and `cargo fmt --check`. Windows-only `winfsp` paths compile under `--no-default-features --features winfsp` (not exercised on macOS/Linux CI).

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-fuse`
- **After every plan wave:** Run `cargo test -p cipherbox-fuse -p cipherbox-sdk`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Threat Ref   | Secure Behavior                     | Test Type | Automated Command | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ------------ | ----------------------------------- | --------- | ----------------- | ----------- | ---------- |
| {N}-01-01 | 01   | 1    | REQ-{XX}    | T-{N}-01 / — | {expected secure behavior or "N/A"} | unit      | `{command}`       | ✅ / ❌ W0  | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `{tests/test_file.py}` — stubs for REQ-{XX}
- [ ] `{tests/conftest.py}` — shared fixtures
- [ ] `{framework install}` — if no framework detected

_If none: "Existing infrastructure covers all phase requirements."_

---

## Manual-Only Verifications

| Behavior   | Requirement | Why Manual | Test Instructions |
| ---------- | ----------- | ---------- | ----------------- |
| {behavior} | REQ-{XX}    | {reason}   | {steps}           |

_If none: "All phase behaviors have automated verification."_

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < {N}s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** {pending / approved YYYY-MM-DD}

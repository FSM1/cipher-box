---
phase: 25
slug: desktop-enhancements
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-25
---

# Phase 25 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                          |
| ---------------------- | -------------------------------------------------------------- |
| **Framework**          | cargo test (Rust crates) + desktop-e2e (Playwright + Tauri)    |
| **Config file**        | `Cargo.toml` (workspace), `tests/desktop-e2e/playwright.config.ts` |
| **Quick run command**  | `cargo test -p cipherbox-fuse --lib`                           |
| **Full suite command** | `cargo test --workspace && cd tests/desktop-e2e && pnpm test`  |
| **Estimated runtime**  | ~30 seconds (cargo) + ~120 seconds (e2e)                       |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-fuse --lib`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Test Type  | Automated Command                           | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ---------- | ------------------------------------------- | ----------- | ---------- |
| 25-01-01  | 01   | 1    | DESKTOP-01  | unit       | `cargo test -p cipherbox-fuse updater`      | ❌ W0       | ⬜ pending |
| 25-01-02  | 01   | 1    | DESKTOP-01  | config     | `grep "updater" apps/desktop/src-tauri/tauri.conf.json` | ❌ W0 | ⬜ pending |
| 25-02-01  | 02   | 1    | DESKTOP-01  | integration| CI build + manifest verification            | ❌ W0       | ⬜ pending |
| 25-03-01  | 03   | 2    | DESKTOP-02  | unit       | `cargo test -p cipherbox-fuse tee_enroll`   | ❌ W0       | ⬜ pending |
| 25-03-02  | 03   | 2    | DESKTOP-02  | grep       | `grep encrypted_ipns_private_key crates/fuse/src/operations.rs` | ✅ | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Existing `cargo test --workspace` infrastructure covers Rust crate tests
- [ ] Desktop E2E test infrastructure exists at `tests/desktop-e2e/`

_Existing infrastructure covers base test execution. New test files created within plan tasks._

---

## Manual-Only Verifications

| Behavior                      | Requirement | Why Manual              | Test Instructions                                                    |
| ----------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------- |
| Tray notification appears     | DESKTOP-01  | OS-level notification   | Launch app with outdated version, verify tray notification shows     |
| Update installs on restart    | DESKTOP-01  | Requires real binary    | Download update, quit app, relaunch, verify new version              |
| TEE republishes file IPNS     | DESKTOP-02  | Requires TEE enclave    | Create file via FUSE, wait 3h, verify IPNS record refreshed         |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

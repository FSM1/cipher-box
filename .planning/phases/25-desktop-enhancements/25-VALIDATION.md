---
phase: 25
slug: desktop-enhancements
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 25 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                          |
| ---------------------- | -------------------------------------------------------------- |
| **Framework**          | cargo check (compile verification) + grep (config verification)|
| **Config file**        | `Cargo.toml` (workspace)                                       |
| **Quick run command**  | `cargo check -p cipherbox-fuse --features fuse`                |
| **Full suite command** | `cargo check --workspace`                                      |
| **Estimated runtime**  | ~20 seconds                                                    |

---

## Sampling Rate

- **After every task commit:** Run `cargo check -p cipherbox-fuse --features fuse`
- **After every plan wave:** Run `cargo check --workspace`
- **Before `/gsd:verify-work`:** Full workspace check must pass
- **Max feedback latency:** 20 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Test Type   | Automated Command                                                       | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ----------- | ----------------------------------------------------------------------- | ----------- | ---------- |
| 25-01-01  | 01   | 1    | DESKTOP-02  | compile     | `cargo check -p cipherbox-fuse --features fuse`                        | ✅          | ⬜ pending |
| 25-01-02  | 01   | 1    | DESKTOP-02  | compile     | `cargo check -p cipherbox-fuse --features winfsp`                      | ✅          | ⬜ pending |
| 25-02-01  | 02   | 1    | DESKTOP-01  | config+grep | `grep "tauri-plugin-updater" apps/desktop/src-tauri/Cargo.toml`        | ✅          | ⬜ pending |
| 25-02-02  | 02   | 1    | DESKTOP-01  | compile     | `cargo check -p cipherbox-desktop --no-default-features --features fuse`| ✅          | ⬜ pending |
| 25-03-01  | 03   | 1    | DESKTOP-01  | grep        | `grep "tauri-apps/tauri-action" .github/workflows/build-desktop.yml`   | ✅          | ⬜ pending |
| 25-03-02  | 03   | 1    | DESKTOP-01  | grep        | `grep "TAURI_SIGNING_PRIVATE_KEY" .github/workflows/build-desktop.yml` | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

_Existing infrastructure covers all phase requirements. `cargo check` and `grep` are available out of the box. No new test files or frameworks needed._

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
- [ ] Feedback latency < 20s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-03-25

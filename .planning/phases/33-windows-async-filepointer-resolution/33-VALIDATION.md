---
phase: 33
slug: windows-async-filepointer-resolution
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-28
---

# Phase 33 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                             |
| ---------------------- | --------------------------------- |
| **Framework**          | cargo test (Rust workspace)       |
| **Config file**        | apps/desktop/src-tauri/Cargo.toml |
| **Quick run command**  | `cargo test -p cipherbox-fuse`    |
| **Full suite command** | `cargo test --workspace`          |
| **Estimated runtime**  | ~30 seconds                       |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-fuse`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type   | Automated Command               | File Exists | Status     |
| -------- | ---- | ---- | ----------- | ----------- | ------------------------------- | ----------- | ---------- |
| 33-01-01 | 01   | 1    | SC-1        | unit        | `cargo test -p cipherbox-fuse`  | ❌ W0       | ⬜ pending |
| 33-01-02 | 01   | 1    | SC-2        | integration | Desktop E2E on Windows          | ❌ manual   | ⬜ pending |
| 33-01-03 | 01   | 1    | SC-3        | unit        | `cargo test -p cipherbox-fuse`  | ❌ W0       | ⬜ pending |
| 33-01-04 | 01   | 1    | SC-4        | integration | Desktop E2E CI (Windows runner) | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Unit tests for channel-based async FilePointer resolution dispatch
- [ ] Unit tests for timeout-bounded read-while-resolving behavior
- [ ] Unit tests for dedup guard (resolving_file_pointers HashSet)

_Existing desktop E2E infrastructure covers integration testing._

---

## Manual-Only Verifications

| Behavior                             | Requirement | Why Manual                                | Test Instructions                                                    |
| ------------------------------------ | ----------- | ----------------------------------------- | -------------------------------------------------------------------- |
| Explorer doesn't hang during refresh | SC-2        | Requires Windows Explorer + mounted drive | Mount FUSE drive, trigger metadata refresh, verify Explorer responds |
| Resolution completes in Explorer     | SC-1        | Requires real IPNS/IPFS resolution        | Upload file, remount, verify file appears with correct size/content  |

_Desktop E2E tests cover automated regression; manual checks verify UX behavior._

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

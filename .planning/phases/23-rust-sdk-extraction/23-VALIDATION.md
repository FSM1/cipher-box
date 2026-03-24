---
phase: 23
slug: rust-sdk-extraction
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-24
---

# Phase 23 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                               |
| ---------------------- | --------------------------------------------------- |
| **Framework**          | cargo test (Rust) + vitest (cross-language vectors) |
| **Config file**        | Cargo.toml workspace config                         |
| **Quick run command**  | `cargo test -p cipherbox-crypto --lib`              |
| **Full suite command** | `cargo test --workspace`                            |
| **Estimated runtime**  | ~30 seconds                                         |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-crypto --lib`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type | Automated Command                | File Exists | Status     |
| -------- | ---- | ---- | ----------- | --------- | -------------------------------- | ----------- | ---------- |
| 23-01-01 | 01   | 1    | TBD         | unit      | `cargo test -p cipherbox-crypto` | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Cargo workspace configuration with all five crates
- [ ] `cipherbox-crypto/tests/` — unit test stubs for AES-GCM, ECIES, key derivation
- [ ] `cipherbox-core/tests/` — unit test stubs for metadata serialization, IPNS records
- [ ] Cross-language test vector JSON files generated from TypeScript reference

_If none: "Existing infrastructure covers all phase requirements."_

---

## Manual-Only Verifications

| Behavior                        | Requirement | Why Manual                | Test Instructions                                           |
| ------------------------------- | ----------- | ------------------------- | ----------------------------------------------------------- |
| FUSE mount with crate imports   | TBD         | Requires macOS + FUSE-T   | Mount ~/CipherBox, create file, verify encryption roundtrip |
| Tauri app builds with workspace | TBD         | Requires full build chain | `pnpm tauri build` succeeds                                 |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

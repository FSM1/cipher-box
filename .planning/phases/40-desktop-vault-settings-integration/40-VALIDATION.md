---
phase: 40
slug: desktop-vault-settings-integration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-31
---

# Phase 40 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Framework**          | vitest (TS), cargo test (Rust)                                                                               |
| **Config file**        | `vitest.config.ts`, `Cargo.toml` (workspace)                                                                 |
| **Quick run command**  | `cargo test -p cipherbox-crypto -p cipherbox-core --lib && pnpm --filter @cipherbox/crypto test`             |
| **Full suite command** | `cargo test -p cipherbox-crypto -p cipherbox-core -p cipherbox-fuse && pnpm --filter @cipherbox/crypto test` |
| **Estimated runtime**  | ~30 seconds                                                                                                  |

---

## Sampling Rate

- **After every task commit:** Run quick run command
- **After every plan wave:** Run full suite command
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type   | Automated Command                                      | File Exists | Status     |
| -------- | ---- | ---- | ----------- | ----------- | ------------------------------------------------------ | ----------- | ---------- |
| 40-01-01 | 01   | 1    | N/A         | unit        | `cargo test -p cipherbox-crypto derive_vault_settings` | ❌ W0       | ⬜ pending |
| 40-01-02 | 01   | 1    | N/A         | unit        | `cargo test -p cipherbox-core vault_settings`          | ❌ W0       | ⬜ pending |
| 40-02-01 | 02   | 2    | N/A         | integration | `cargo test -p cipherbox-fuse vault_settings`          | ❌ W0       | ⬜ pending |
| 40-02-02 | 02   | 2    | N/A         | cross-lang  | `cargo test -p cipherbox-crypto hkdf_vector`           | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Cross-language HKDF test vector for `cipherbox-vault-settings-v1` context string
- [ ] Rust unit test stubs for `derive_vault_settings_ipns_keypair()`
- [ ] Rust unit test stubs for `VaultSettings` type and deserialization

_Existing vitest and cargo test infrastructure covers framework needs._

---

## Manual-Only Verifications

| Behavior                                     | Requirement | Why Manual                             | Test Instructions                                                          |
| -------------------------------------------- | ----------- | -------------------------------------- | -------------------------------------------------------------------------- |
| Desktop login loads vault settings from IPNS | N/A         | Requires running desktop app with auth | Start desktop app, login, verify settings loaded in FUSE log output        |
| FUSE respects loaded MAX_VERSIONS_PER_FILE   | N/A         | Requires mounted FUSE filesystem       | Mount, create file, modify N+1 times, verify version count matches setting |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

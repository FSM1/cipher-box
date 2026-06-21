---
phase: 55
slug: large-source-file-refactor
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-19
---

# Phase 55 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Internal refactor — public surface FROZEN. Acceptance = existing test suites stay green + consumers compile untouched + no `pnpm api:generate`.

---

## Test Infrastructure

| Property                | Value                                                                                                                  |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **Framework**           | Rust `cargo test` · Jest (api) · Vitest (sdk-core / sdk / web)                                                         |
| **Config file**         | Existing — Cargo workspace, jest/vitest configs already present                                                        |
| **Quick run command**   | `cargo test -p cipherbox-fuse` (Rust items) / relevant package `pnpm --filter <pkg> test` (TS items)                   |
| **Full suite command**  | `cargo test -p cipherbox-fuse` + `cargo build -p cipherbox-fuse --no-default-features --features winfsp` + `cargo build -p cipherbox-desktop` + affected `pnpm --filter <pkg> test` |
| **Estimated runtime**   | ~30–90 seconds per affected suite (no network)                                                                         |

---

## Sampling Rate

- **After every task commit (Rust):** Run `cargo test -p cipherbox-fuse`
- **After every task commit (TS):** Run the relevant package `pnpm --filter <pkg> test`
- **After every plan wave (Rust):** also run `cargo build -p cipherbox-fuse --no-default-features --features winfsp` AND `cargo build -p cipherbox-desktop` (both feature sets — D-06 gate)
- **Before `/gsd-verify-work`:** Full suite must be green on every affected package + both Rust feature sets
- **Max feedback latency:** ~90 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Threat Ref | Secure Behavior                                                          | Test Type    | Automated Command                                                          | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ---------- | ----------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------- | ----------- | ---------- |
| lib.rs    | 01   | 1    | HARD-06     | —          | 6 modules compile; `cipherbox_fuse::<X>` re-exports byte-identical       | cargo test   | `cargo test -p cipherbox-fuse`                                            | ✅ existing | ⬜ pending |
| lib.rs    | 01   | 1    | HARD-06     | —          | winfsp feature still compiles                                           | cargo build  | `cargo build -p cipherbox-fuse --no-default-features --features winfsp`   | N/A build   | ⬜ pending |
| write_ops | 02   | 2    | HARD-06     | —          | handler paths stable behind `implementation` facade; bin-publish dedupe | cargo test   | `cargo test -p cipherbox-fuse`                                            | ✅ existing | ⬜ pending |
| tier2-rust| 02   | 2    | HARD-06     | —          | content_ops + prepopulate shared modules compile on both feature sets    | cargo test+build | `cargo test -p cipherbox-fuse` + winfsp build + `cargo build -p cipherbox-desktop` | ✅ existing | ⬜ pending |
| read_ops  | 02   | 2    | HARD-06     | —          | PollResult/poll moved to shared module; **handle_release NOT relocated** | cargo test   | `cargo test -p cipherbox-fuse`                                            | ✅ existing | ⬜ pending |
| commands  | 02   | 2    | HARD-06     | T-vault    | `load_vault_settings` ECIES unwrap moved verbatim; `complete_auth_setup` pub(crate) sig stable | cargo build  | `cargo build -p cipherbox-desktop`                                        | N/A build   | ⬜ pending |
| folder    | 03   | 3    | HARD-06     | —          | `../folder` barrel re-exports stable; consumers compile                  | vitest+tsc   | `pnpm --filter @cipherbox/sdk-core test` + `pnpm --filter @cipherbox/sdk test` | ✅ existing | ⬜ pending |
| ipns-codec| 03   | 3    | HARD-06     | —          | codec helpers extracted; DI class + orchestration intact                 | jest         | `pnpm --filter @cipherbox/api test`                                       | ✅ existing | ⬜ pending |
| details   | 03   | 3    | HARD-06     | —          | sub-components extracted; the two cross-guarded useEffects stay together  | vitest       | `pnpm --filter @cipherbox/web test`                                       | ✅ existing | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky · Plan/Wave columns are indicative — the planner sets final wave assignments._

---

## Wave 0 Requirements

- [x] No new test files required — this phase creates zero tests.

_Existing infrastructure covers all phase requirements: acceptance is that existing suites still pass against the refactored code and consumers compile with no edits._

---

## Manual-Only Verifications

| Behavior                                   | Requirement | Why Manual                                                                 | Test Instructions                                                                                       |
| ------------------------------------------ | ----------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Public surface byte-identical              | HARD-06     | No automated diff harness for the crate/SDK export surface                | After each split, confirm re-export lists + `cipherbox_fuse::<X>` / `../folder` barrel paths are unchanged; consumers compile with zero import edits. NO `pnpm api:generate`. |
| Windows-only `winfsp` runtime behavior     | HARD-06     | CI/dev cannot exercise WinFsp off Windows; only the `--features winfsp` build is gated | The `--features winfsp` build is the gate; the `windows/host.rs` dispatcher split stays deferred (cannot be exercised off Windows). |

---

## Validation Sign-Off

- [x] All tasks map to an existing automated suite (no Wave 0 stubs needed)
- [x] Sampling continuity: every Rust split gated on `cargo test -p cipherbox-fuse` + winfsp build; every TS split gated on its package suite
- [x] No Wave 0 MISSING references (no new tests created)
- [x] No watch-mode flags
- [x] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter (set after plan-checker confirms coverage)

**Approval:** pending

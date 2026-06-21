---
phase: 56
slug: fuse-and-ipns-durability-hardening
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-22
---

# Phase 56 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                         |
| ---------------------- | --------------------------------------------------------------------------------------------- |
| **Framework**          | Rust `cargo test` (cipherbox-fuse) + Vitest (sdk-core, web)                                    |
| **Config file**        | `crates/fuse/Cargo.toml`; `packages/sdk-core/vitest.config.ts`; `apps/web/vitest.config.ts`   |
| **Quick run command**  | `cargo test -p cipherbox-fuse --features fuse -- publish inode metadata`                       |
| **Full suite command** | `cargo test -p cipherbox-fuse --features fuse && pnpm --filter @cipherbox/sdk-core vitest run && pnpm --filter @cipherbox/web vitest run` |
| **Estimated runtime**  | ~120 seconds (Rust fuse) + ~60s (TS); winfsp + desktop E2E are CI-only                         |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-fuse --features fuse -- publish::tests` (fast, covers D-07 unit tests) for Rust tasks; the matching `vitest run -- <component>` for TS tasks.
- **After every plan wave:** Run the full suite command above.
- **Before `/gsd-verify-work`:** Full suite green AND `Cargo Check & Test (Windows)` winfsp CI green (winfsp is CI-only on macOS — local cargo cannot compile `windows/*` under `#[cfg(winfsp)]`).
- **Max feedback latency:** ~120 seconds (Rust fuse quick run).

---

## Per-Task Verification Map

> Task IDs (`56-PP-NN`) are assigned by the planner. This map is keyed by requirement/decision; the planner fills the Task ID + Wave columns when it derives the task breakdown.

| Task ID    | Plan | Wave | Requirement | Threat Ref     | Secure Behavior                                                | Test Type        | Automated Command                                                            | File Exists | Status     |
| ---------- | ---- | ---- | ----------- | -------------- | -------------------------------------------------------------- | ---------------- | --------------------------------------------------------------------------- | ----------- | ---------- |
| 56-01-\*   | 01   | 1    | HARD-07     | T-56-02 (Tamper) | D-05 offset<0→EINVAL / checked_add new_end→EFBIG before write_at | unit (Rust)      | `cargo test -p cipherbox-fuse --features fuse -- write_ops`                  | ✅          | ⬜ pending |
| 56-01-\*   | 01   | 1    | HARD-07     | T-56-04 (Tamper) | D-06 create/mkdir EEXIST before inode mutation                  | unit (Rust)      | `cargo test -p cipherbox-fuse --features fuse -- write_ops`                  | ✅          | ⬜ pending |
| 56-01-\*   | 01   | 1    | HARD-07     | T-56-02 (Tamper) | D-07 `next_file_publish_sequence` checked/saturating_add        | unit (Rust)      | `cargo test -p cipherbox-fuse --features fuse -- publish::tests`             | ✅          | ⬜ pending |
| 56-02-\*   | 02   | 1    | HARD-07     | T-56-03 (Repud) | D-01/D-02/D-03 `publish_with_cas_retry`: Conflict→re-resolve+retry, exhaustion→journal, hard→EIO | unit (Rust) | `cargo test -p cipherbox-fuse --features fuse -- metadata::tests`            | ❌ W0       | ⬜ pending |
| 56-02-\*   | 02   | 1    | HARD-07     | T-56-01 (Info)  | D-12 `spawn_metadata_publish` key params `Zeroizing<Vec<u8>>`   | unit (Rust)      | `cargo test -p cipherbox-fuse --features fuse -- metadata::tests`            | ❌ W0       | ⬜ pending |
| 56-02-\*   | 02   | 1    | HARD-07     | T-56-05 (Info)  | D-11 inode stable-ID match vs display-name fallback identity reset | unit (Rust)   | `cargo test -p cipherbox-fuse --features fuse -- inode::tests`               | ❌ W0       | ⬜ pending |
| 56-02-\*   | 02   | 1    | HARD-07     | —              | D-08 stale-completion unpin inside write_generation; D-09 FP-resolve continuation; D-10 refresh NETWORK_TIMEOUT | desktop E2E | `gh workflow run "CI E2E Tests" --ref <branch>` (dispatch-gated)             | ✅          | ⬜ pending |
| 56-03-\*   | 03   | 1    | HARD-07     | —              | D-13 `fetchAndDecryptMetadata` typed error (try-catch)         | unit (TS)        | `pnpm --filter @cipherbox/sdk-core vitest run -- load`                       | ❌ W0       | ⬜ pending |
| 56-03-\*   | 03   | 1    | HARD-07     | T-56-01 (Info)  | D-13 `registration.ts` wrapKey-in-try → zeroize on throw       | unit (TS)        | `pnpm --filter @cipherbox/sdk-core vitest run -- registration`              | ✅          | ⬜ pending |
| 56-03-\*   | 03   | 1    | HARD-07     | —              | D-14 `DetailsPrimitives` gate setCopied on actual copy success | unit (TS/React)  | `pnpm --filter @cipherbox/web vitest run -- DetailsPrimitives`              | ❌ W0       | ⬜ pending |
| 56-03-\*   | 03   | 1    | HARD-07     | —              | D-14 `VersionHistory` surface error on undefined privateKey    | unit (TS/React)  | `pnpm --filter @cipherbox/web vitest run -- VersionHistory`                 | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `crates/fuse/src/metadata.rs::tests` — add tests for `publish_with_cas_retry`: success, Conflict-then-retry, persistent-Conflict→journal (`WriteQueue::put`), persistent-Conflict / hard-failure→EIO.
- [ ] `crates/fuse/src/inode.rs::tests` — add a `mod tests` for stable-ID (`ipns_to_ino`) match vs display-name (`find_child`) fallback identity reset (no inode test module currently found — verify first).
- [ ] `packages/sdk-core/src/folder/__tests__/load.test.ts` — new test covering `fetchAndDecryptMetadata` typed failure on malformed JSON / decode error.
- [ ] `apps/web/src/components/file-browser/details/__tests__/DetailsPrimitives.test.ts` — copy success/failure gating (use `.test.ts`, NOT `.spec.ts` — web vitest `include` is `src/**/*.test.ts`; `.spec.ts` is silently skipped).
- [ ] `apps/web/src/components/file-browser/details/__tests__/VersionHistory.test.ts` — error surfacing on undefined `vaultKeypair?.privateKey` (same `.test.ts` rule).

_Existing infrastructure (cargo test fuse feature set, sdk-core/web vitest, winfsp CI, desktop E2E) covers the remaining behaviors._

---

## Manual-Only Verifications

| Behavior                                              | Requirement | Why Manual                                                                                  | Test Instructions                                                                                       |
| ----------------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| winfsp lockstep fixes (D-05/06/08/09/10/11 Windows side) | HARD-07     | winfsp `#[cfg(winfsp)]` code cannot compile on macOS; local cargo never builds `windows/*`. | Dispatch `Cargo Check & Test (Windows)` CI gate on the branch and confirm green before phase sign-off.   |
| End-to-end publish-conflict retry under real IPNS     | HARD-07     | Requires live API + IPNS round-trip; not exercised by mocked unit suites.                   | `gh workflow run "CI E2E Tests" --ref <branch>` (dispatch-gated desktop E2E); confirm green.             |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

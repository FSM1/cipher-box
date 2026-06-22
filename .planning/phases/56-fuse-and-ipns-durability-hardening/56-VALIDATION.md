---
phase: 56
slug: fuse-and-ipns-durability-hardening
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-22
audited: 2026-06-22
---

# Phase 56 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> POST-EXECUTION AUDIT (2026-06-22): every in-scope D-* behavior mapped to a concrete
> committed, passing test (cargo test marker or vitest case) or a legitimate CI-only
> gate (winfsp Windows, desktop E2E). 0 open Nyquist gaps. nyquist_compliant: true.

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

| Task ID    | Plan | Wave | Requirement | Threat Ref     | Secure Behavior                                                | Test Type        | Concrete Test (committed)                                                    | Automated Command                                                            | Status   |
| ---------- | ---- | ---- | ----------- | -------------- | -------------------------------------------------------------- | ---------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------- | -------- |
| 56-01      | 01   | 1    | HARD-07     | T-56-02 (Tamper) | D-05 offset<0→EINVAL / checked_add new_end→EFBIG before write_at | unit (Rust)      | `file_data.rs::tests::{handle_write_rejects_negative_offset, d05_offset_overflow_predicate_at_boundary, d05_offset_no_overflow_within_range}` | `cargo test -p cipherbox-fuse --features fuse -- d05_ handle_write_rejects` | ✅ green |
| 56-01      | 01   | 1    | HARD-07     | T-56-04 (Tamper) | D-06 create/mkdir EEXIST before inode mutation                  | unit (Rust)      | `file_data.rs::tests::d06_find_child_detects_duplicate`                      | `cargo test -p cipherbox-fuse --features fuse -- d06_`                       | ✅ green |
| 56-01      | 01   | 1    | HARD-07     | T-56-02 (Tamper) | D-07 `next_file_publish_sequence` checked_add overflow→Err      | unit (Rust)      | `publish.rs::tests::next_file_publish_sequence_overflow_returns_err`         | `cargo test -p cipherbox-fuse --features fuse -- next_file_publish_sequence` | ✅ green |
| 56-02      | 02   | 1    | HARD-07     | T-56-03 (Repud) | D-01a/D-02/D-03 `publish_with_cas_retry`: Conflict→re-resolve+retry, exhaustion→Err(EIO) (journal None deferred), make-record err propagates | unit (Rust) | `metadata.rs::tests::{publish_with_cas_retry_success_first_attempt, _conflict_then_success, _persistent_conflict_journal_none_returns_err, _make_record_error_propagates}` | `cargo test -p cipherbox-fuse --features fuse -- publish_with_cas_retry`     | ✅ green |
| 56-02      | 02   | 1    | HARD-07     | T-56-01 (Info)  | D-12 `spawn_metadata_publish` key params `Zeroizing<Vec<u8>>`   | type-level (Rust) | Compile-enforced ownership/type guarantee (params typed `Zeroizing<Vec<u8>>`, metadata.rs:220-221); verified by `cargo test` compile + 56-VERIFICATION truth #14. No runtime assertion possible. | `cargo test -p cipherbox-fuse --features fuse` (must compile)               | ✅ green |
| 56-02      | 02   | 1    | HARD-07     | T-56-05 (Info)  | D-11 inode stable-ID match vs display-name fallback identity reset | unit (Rust)   | `inode.rs::tests::{d11_stable_id_match_preserves_children_loaded_state, d11_display_name_fallback_clears_loaded_state, d11_file_display_name_fallback_forces_re_resolution}` | `cargo test -p cipherbox-fuse --features fuse -- d11_`                       | ✅ green |
| 56-02      | 02   | 1    | HARD-07     | —              | D-08 stale-completion unpin inside write_generation; D-09 FP-resolve continuation; D-10 refresh NETWORK_TIMEOUT | desktop E2E (CI) | Source verified (56-VERIFICATION truths #11/#12/#13); live IPNS behavior exercised by dispatch-gated desktop E2E | `gh workflow run "CI E2E Tests" --ref <branch>` (dispatch-gated)             | ☑️ CI-covered |
| 56-03      | 03   | 1    | HARD-07     | —              | D-13 `fetchAndDecryptMetadata` typed error (try-catch, names CID, `{cause}`) | unit (TS)        | `packages/sdk-core/src/folder/__tests__/load.test.ts` (3 cases)             | `pnpm --filter @cipherbox/sdk-core vitest run -- load`                       | ✅ green |
| 56-03      | 03   | 1    | HARD-07     | T-56-01 (Info)  | D-13 `registration.ts` wrapKey-in-try → zeroize both buffers on throw | unit (TS)        | `packages/sdk-core/src/__tests__/folder.test.ts::'zeros key material and rethrows if TEE wrapping fails'` | `pnpm --filter @cipherbox/sdk-core vitest run -- folder`                     | ✅ green |
| 56-03      | 03   | 1    | HARD-07     | —              | D-14 `DetailsPrimitives` gate setCopied on actual copy success | unit (TS/React)  | `apps/web/src/components/file-browser/details/__tests__/DetailsPrimitives.test.ts` (3 cases) | `pnpm --filter @cipherbox/web vitest run -- DetailsPrimitives`              | ✅ green |
| 56-03      | 03   | 1    | HARD-07     | —              | D-14 `VersionHistory` surface error on undefined privateKey    | unit (TS/React)  | `apps/web/src/components/file-browser/details/__tests__/VersionHistory.test.ts` (2 cases) | `pnpm --filter @cipherbox/web vitest run -- VersionHistory`                 | ✅ green |
| 56-01/02   | 01   | 1    | HARD-07     | —              | D-15 winfsp write-path lockstep mirror of D-05/D-06 guards (Windows) | unit (Rust, Windows) | Source verified (56-VERIFICATION truth #6, windows/write_ops.rs); cannot compile on macOS by design | `Cargo Check & Test (Windows)` CI gate (authoritative)                      | ☑️ CI-covered |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky · ☑️ CI-covered (legitimately not locally runnable)_

---

## Wave 0 Requirements (post-execution: all satisfied)

- [x] `crates/fuse/src/metadata.rs::tests` — `publish_with_cas_retry` success, Conflict-then-retry, persistent-Conflict→`journal None`→Err (D-01a EIO; journal deferred), make-record-error propagation. 4 tests, green.
- [x] `crates/fuse/src/inode.rs::tests` — stable-ID match preserves loaded state vs display-name fallback clears it; file-side fallback forces re-resolution. 3 `d11_*` tests, green.
- [x] `packages/sdk-core/src/folder/__tests__/load.test.ts` — `fetchAndDecryptMetadata` typed failure on malformed JSON / decode error. 3 cases, committed.
- [x] `apps/web/.../details/__tests__/DetailsPrimitives.test.ts` — copy success/failure gating (`.test.ts`, picked up by web vitest). 3 cases, committed.
- [x] `apps/web/.../details/__tests__/VersionHistory.test.ts` — error surfacing on undefined `vaultKeypair?.privateKey`. 2 cases, committed.

_Existing infrastructure (cargo test fuse feature set, sdk-core/web vitest, winfsp CI, desktop E2E) covers the remaining behaviors._

---

## Manual-Only Verifications

| Behavior                                              | Requirement | Why Manual                                                                                  | Test Instructions                                                                                       |
| ----------------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| winfsp lockstep fixes (D-05/06/08/09/10/11 Windows side) | HARD-07     | winfsp `#[cfg(winfsp)]` code cannot compile on macOS; local cargo never builds `windows/*`. | Dispatch `Cargo Check & Test (Windows)` CI gate on the branch and confirm green before phase sign-off.   |
| End-to-end publish-conflict retry under real IPNS     | HARD-07     | Requires live API + IPNS round-trip; not exercised by mocked unit suites.                   | `gh workflow run "CI E2E Tests" --ref <branch>` (dispatch-gated desktop E2E); confirm green.             |

---

## Validation Sign-Off

- [x] All tasks have an automated verify (committed test) or a legitimate CI-only gate
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (all satisfied)
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

## Post-Execution Audit Verdict (2026-06-22)

- **nyquist_compliant: true** — 0 open Nyquist gaps.
- Every locally-testable D-* behavior is mapped to a concrete committed, passing test
  (Rust markers re-confirmed present; `publish_with_cas_retry_persistent_conflict_journal_none_returns_err`
  re-run green as a spot-check; TS files present with expected case counts; D-13 registration
  zeroize-on-throw covered by `folder.test.ts`).
- **D-12** is a compile-enforced type guarantee (`Zeroizing<Vec<u8>>` params) — no runtime
  assertion is meaningful; validated via the `cargo test` compile + source verification. Not a gap.
- **D-08/D-09/D-10** (live IPNS write-generation / FP continuation / refresh timeout) and **D-15**
  (winfsp lockstep) are legitimately CI-only (dispatch-gated desktop E2E and Windows-only winfsp
  compile). Marked CI-covered with source verification; not flaggable as missing local coverage
  per the project's winfsp/desktop-E2E-is-CI rule.

**Approval:** approved (audit) — 2026-06-22

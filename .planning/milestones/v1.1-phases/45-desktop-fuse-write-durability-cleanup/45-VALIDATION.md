---
phase: 45
slug: desktop-fuse-write-durability-cleanup
status: verified
nyquist_compliant: true
wave_0_complete: true
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
| **Full suite command** | `cargo test --workspace`                                                  |
| **Estimated runtime**  | ~30 seconds (266 tests)                                                   |

> Lint/format gates (run before commit, not per-task): `cargo clippy -p cipherbox-fuse --all-targets -- -D warnings` and `cargo fmt --check`. Windows-only `winfsp` paths compile under `--no-default-features --features winfsp` (Windows CI only — the `windows-*`/`winfsp-sys` deps do not build on macOS/Linux hosts).

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-fuse`
- **After every plan wave:** Run `cargo test -p cipherbox-fuse -p cipherbox-sdk`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Item | Plan | Wave | Requirement | Secure Behavior | Test Type | Automated Command | Status |
| ---- | ---- | ---- | ----------- | --------------- | --------- | ----------------- | ------ |
| #14 | 45-01 | 1 | Raise Phase-43 write-durability test coverage | crash-mid-write entry survives reload; partial/malformed journal skipped not panicked; Failed entries retained | unit | `cargo test -p cipherbox-sdk crash_mid_write_entry_survives_reload partial_journal_write_is_skipped_not_panicked retry_exhaustion_keeps_failed_entry_on_disk` | ✅ green |
| #14 | 45-01 | 1 | Replay safety net | replay skips Failed entries; folder-key cache; folder-children merge | unit | `cargo test -p cipherbox-fuse replay_for_vault_does_not_touch_failed_entries resolve_folder_key_cache_resolves_shared_parent_once merge_folder_children_unions_new_and_existing` | ✅ green |
| #12 | 45-02 | 1 | Shared journal-dir + max-retries helper | single `default_journal_dir()`/`JOURNAL_MAX_RETRIES`; path tail `cipherbox/cb-journal` | unit | `cargo test -p cipherbox-desktop default_journal_dir_ends_with_cipherbox_cb_journal` | ✅ green |
| #18 | 45-03 | 2 | `""` sentinel → `Option<String>` + serde compat | legacy `""` journal still replays as `None`; `Some` round-trips (crash-recovery integrity) | unit | `cargo test -p cipherbox-sdk legacy_empty_string_ipns_loads_as_none upload_entry_none_ipns_round_trips` | ✅ green |
| #19 | 45-04 | 3 | Not-found string match → typed error | NotFound → first-publish/seq-0; Error → retain entry | unit | `cargo test -p cipherbox-fuse not_found_outcome_drives_first_publish` | ✅ green |
| #15 | 45-05 | 4 | Memoize `resolve_folder_key` in replay | shared parent resolved once (cache invariant), identical key bytes | unit | `cargo test -p cipherbox-fuse resolve_folder_key_cache_resolves_shared_parent_once` | ✅ green |
| #20 | 45-05 | 4 | Reuse `publish_file_metadata` + cas-publish | replay publish behavior preserved (TEE enrollment, seq) — pinned by replay safety net + existing replay tests | unit | `cargo test -p cipherbox-fuse` (replay suite) | ✅ green |
| #11 | 45-06 | 5 | Consolidate fuser/winfsp journal builders | byte-identical `JournalEntry`; replay order mkdir-before-upload — pinned by journal round-trip safety net | unit | `cargo test -p cipherbox-fuse` (journal round-trip + replay-order suite) | ✅ green |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

Full-suite evidence: `cargo test --workspace` → **266 passed, 0 failed** (committed tree).

---

## Wave 0 Requirements

- Existing infrastructure covers all phase requirements — `cargo test` harness already in place across `cipherbox-fuse`, `cipherbox-sdk`, and `cipherbox-desktop`. No new test framework or fixtures required (Wave 0 complete).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |
| winfsp (Windows) journal-build + replay paths | #11, #18 (winfsp side of the shared builders) | The `windows-*` / `winfsp-sys` dependency crates do not compile on macOS/Linux hosts, so `cargo check -p cipherbox-fuse --no-default-features --features winfsp` cannot type-check the winfsp path locally | Verify on a Windows runner / CI: `cargo test -p cipherbox-fuse --no-default-features --features winfsp` must compile and pass. The shared builders are exercised by both feature gates; macOS CI proves the fuser side, Windows CI proves the winfsp side. |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (none — existing infra sufficient)
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-15

---

## Validation Audit 2026-06-15

| Metric     | Count |
| ---------- | ----- |
| Gaps found | 0     |
| Resolved   | 0     |
| Escalated  | 1 (winfsp path → manual/CI-only, environment limitation, not a coverage gap) |

All 7 phase requirements have green automated `cargo test` coverage on the macOS/fuser path. The only non-automated-locally item is the winfsp path, blocked by Windows-only dependency crates on non-Windows hosts — gated by Windows CI, not a test-authoring gap.

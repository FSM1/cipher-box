---
phase: 52-desktop-fuse-durability-at-rest-safety
plan: 05
subsystem: fuse/journal-retention
tags: [fuse, journal, gc, retention, lifecycle-purge, at-rest-safety, rust]
dependency_graph:
  requires: [52-02, 52-04]
  provides: [vault-journal-purge, failed-entry-gc, sidecar-orphan-cleanup]
  affects:
    - crates/sdk/src/queue.rs
    - apps/desktop/src-tauri/src/commands/auth.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
tech_stack:
  added: []
  patterns: [sidecar-aware-purge, age-then-size-gc-oldest-first, bin-orphan-cleanup, mount-time-sweep]
key_files:
  created: []
  modified:
    - crates/sdk/src/queue.rs
    - apps/desktop/src-tauri/src/commands/auth.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
decisions:
  - "purge_vault is unconditional (all statuses) — logout means the session is over; it reuses the sidecar-aware remove so both .json and .bin go"
  - "gc_failed_entries only touches Failed entries (in-flight Pending/InProgress never GC'd); runs at mount (no background scheduler), three passes: age purge, oldest-first size purge counting the .bin, then .bin orphan cleanup"
  - "Size accounting sums .json + .bin via a private entry_on_disk_size helper; missing files contribute 0"
  - "Added a module-level now_ms() (mirrors registry::now_ms) so the age compare uses the same ms-since-epoch clock entries are stamped with"
  - "purge_vault wired ONLY at logout() today (no switch_account/delete_account command exists — RESEARCH Open Q2); a code comment records the future hook"
  - "Logout purge runs BEFORE state.clear_keys() because clear_keys zeroes root_ipns_name to None"
metrics:
  completed: "2026-06-20T05:00:00Z"
  tasks_completed: 3
  files_modified: 3
---

# Phase 52 Plan 05: Journal Retention Purge and Failed-Entry GC

One-liner: Added `WriteQueue::purge_vault` and `WriteQueue::gc_failed_entries` to close the cross-vault journal retention leak (D-02), wired `purge_vault` into the desktop `logout()` lifecycle hook (before key zeroization), and run `gc_failed_entries` once at mount using the Plan-52-02 GC constants so parked Failed entries and `.bin` orphans are bounded.

## What Was Built

### queue.rs (D-02)

- `purge_vault(&self, vault_root_ipns: &str) -> Result<usize, String>`: `load_all_for_vault` then sidecar-aware `remove` for every matching entry regardless of status; returns the count. No-op (returns 0) for a vault with no entries. This is the reusable interface a future account-switch/deletion must call.
- `gc_failed_entries(&self, age_days, total_size_budget) -> Result<usize, String>`: global scan of all `.json` filtered to `Failed`, then (1) age purge (`created_at_ms < now_ms - age_days*86_400_000`), (2) oldest-first size purge counting each entry's `.json` + `.bin` bytes until under budget, (3) `.bin` orphan cleanup (sidecars with no matching `.json`, RESEARCH Pitfall 2). Best-effort: per-file errors are `log::warn!`'d and skipped, never fatal/panicking. Returns total removed.
- Private `entry_on_disk_size(&self, id)` helper (`.json` + `.bin` bytes, missing = 0) for the size pass.
- Module-level `now_ms()` mirroring `registry::now_ms` for the age clock.

### auth.rs (D-02 logout purge)

Inside the existing `#[cfg(any(feature = "fuse", feature = "winfsp"))]` family, AFTER the unmount/keychain-delete and BEFORE `state.clear_keys()`, read `state.sdk.root_ipns_name` (must be before clear_keys, which zeroes it to None), reconstruct `WriteQueue::new(crate::fuse::default_journal_dir(), crate::fuse::JOURNAL_MAX_RETRIES)`, and `purge_vault(&ipns)` — count logged on Ok, `log::warn!`+continue on Err (mirrors the unmount error pattern). A comment records that a future `switch_account`/`delete_account` (none exists — RESEARCH Open Q2) must call `purge_vault` for the departing vault.

### fuse/mod.rs (D-02 mount GC)

After the `journal` is built and the `PublishCoordinator` is seeded, and right before the Plan-52-04 concurrent replay spawn, call `journal.gc_failed_entries(JOURNAL_GC_MAX_AGE_DAYS, JOURNAL_GC_MAX_SIZE_BYTES)` (constants from `cipherbox_sdk`). Synchronous, fast (dir scan), non-fatal on Err — GC must never block/fail the mount.

## Phase 51 Reconciliation

No Phase-51 hardening touched. The logout purge inserts strictly BEFORE `state.clear_keys()` (the existing zeroization step) and only reads `root_ipns_name`; the diff removes no `Zeroizing` / `clear_bytes` / `wrap_key` / `unwrap_key` line. `purge_vault`/`gc_failed_entries` reuse the existing sidecar-aware `remove`, so the same fsync/at-rest guarantees apply.

## Test Results

- cipherbox-sdk: 57/57 (baseline 54). New: `purge_vault_removes_all` (vault A removed incl. `.json`+`.bin`, vault B survives, empty-vault → 0), `gc_purges_old_failed` (old Failed removed, recent Failed + Pending untouched), `gc_purges_to_size_budget` (oldest-first trim to a measured-single-entry budget + `.bin` orphan removed).
- cipherbox-fuse: 64/64 (no regression).
- `cargo check -p cipherbox-desktop --features fuse`: clean (0 errors). `--features winfsp` fails only in upstream `windows_core` crates on macOS (`IMarshal`/`marshaler`) — not our code; CI's Windows runner covers it.
- `cargo clippy -p cipherbox-sdk`: queue.rs additions clippy-clean (pre-existing warnings live only in hkdf/ipns/registry).

## Known Stubs

None.

## Self-Check: PASSED

- `queue.rs` has `fn purge_vault` and `fn gc_failed_entries` next to `remove`/`load_all_for_vault`.
- `auth.rs logout()` calls `purge_vault` before `clear_keys`; `fuse/mod.rs` calls `gc_failed_entries` at mount; both non-fatal on Err.
- All three new tests pass; 57/57 sdk + 64/64 fuse; desktop fuse check clean.

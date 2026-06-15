---
created: 2026-06-14T14:26:04.000Z
title: Improve phase-43 rust write-durability test coverage
area: desktop-fuse
files:
  - crates/sdk/src/sync.rs
  - crates/sdk/src/queue.rs
  - crates/fuse/src/lib.rs
  - crates/fuse/src/journal_helpers.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/write_ops.rs
  - apps/desktop/src-tauri/src/sync/mod.rs
---

## Status (updated 2026-06-15)

Partially addressed by **Phase 45 / PR #491**, which is why this todo is kept in
`pending` rather than moved to `done` — the bulk (Tier 2) is still open.

- **Tier 1 — partial.** Phase 45 added the write-durability/replay safety-net tests:
  `crash_mid_write_entry_survives_reload`, `partial_journal_write_is_skipped_not_panicked`,
  `retry_exhaustion_keeps_failed_entry_on_disk` (queue.rs), and
  `replay_for_vault_does_not_touch_failed_entries`,
  `resolve_folder_key_cache_resolves_shared_parent_once`,
  `merge_folder_children_unions_new_and_existing`,
  `classify_resolve_outcome_maps_resolve_results` (lib.rs). The `crates/sdk/src/sync.rs`
  redaction functions (`sanitize_error`, `regex_replace_paths`, `regex_replace_tokens`,
  `is_network_error`) and the residual `queue.rs`/`sync/mod.rs` branches are still untested.
- **Tier 2 — open, blocked.** See the read_ops/write_ops blocker recorded under Tier 2
  below (folded in from the standalone 2026-06-15 testability investigation).
- **`journal_helpers.rs` — unit-testable now, not yet done.** Pure synchronous builders
  (`build_upload_journal_entry`, `build_mkdir_journal_entry`) + free helpers
  (`wrap_key_to_hex`, `generate_entry_id`, `current_unix_ms`). Needs a `make_test_fs()`
  helper (CipherBoxFS has ~30 fields incl. a `tokio::runtime::Handle`, mpsc channels,
  `ApiClient::new("http://127.0.0.1:1")`, `WriteQueue::new(dir, 5)`,
  `PublishCoordinator::new()`; the root inode must have `ipns_private_key`/`ipns_name` set
  via `get_mut(ROOT_INO)` for `build_folder_metadata`). Treat as a Tier-1 win.

## Problem

Codecov reports phase-43 (PR #487) patch coverage at **50.1% — 638 lines missing**.
The patch status is `informational: true` (non-blocking, per `codecov.yml`), so this
did not gate the merge, but the gap is large enough to be worth closing longer term.

Breakdown of the missing lines (from the PR #487 codecov report, head `c65b797`):

| File | Patch % | Missing |
|---|---|---|
| `crates/fuse/src/lib.rs` | 28.75% | 342 |
| `crates/fuse/src/read_ops.rs` | 0% | 141 |
| `crates/fuse/src/write_ops.rs` | 0% | 39 |
| `apps/desktop/src-tauri/src/fuse/mod.rs` | 0% | 35 |
| `crates/sdk/src/sync.rs` | 0% | 24 |
| `apps/desktop/src-tauri/src/commands/sync.rs` | 0% | 18 |
| `apps/desktop/src-tauri/src/sync/mod.rs` | 87.38% | 14 |
| `crates/sdk/src/queue.rs` | 97.51% | 10 |
| `apps/desktop/src-tauri/src/tray/mod.rs` | 0% | 9 |
| `apps/desktop/src-tauri/src/commands/auth.rs` | 0% | 3 |

The existing 40 fuse + 43 sdk unit tests cover the *pure* helpers (journal
serialization, queue ordering, `bridge_status`, `resolve_folder_key` bounds) but not
the FUSE callbacks or the replay orchestration, because those need a mounted FS plus a
live `PublishCoordinator`/IPNS/network. The desktop Tauri glue is exercised by the
headless UAT harness at runtime but that run is not measured by `cargo llvm-cov`.

## Solution

Three tiers, in priority order:

**Tier 1 — quick unit-test wins (no harness, ~48 lines).** Do these first.

- `crates/sdk/src/sync.rs` has four **pure free functions with zero tests**:
  `sanitize_error`, `regex_replace_paths`, `regex_replace_tokens`, `is_network_error`.
  These are log/telemetry redaction (security-relevant — they strip filesystem paths
  and tokens out of error strings) plus network-error classification. Add a
  `#[cfg(test)]` module asserting paths/tokens are scrubbed and the network-error
  matcher classifies the known cases. High value beyond the coverage number.
- `crates/sdk/src/queue.rs` (97.51%) — 10 residual error/edge branches the 17 existing
  tests miss; fill them in.
- `apps/desktop/src-tauri/src/sync/mod.rs` (87.38%) — 14 residual branches in
  `bridge_status`/the daemon closure not hit by the 8 existing tests.

**Tier 2 — needs trait seams / a test harness (the bulk, ~522 lines).** This is the
real "longer term" investment: the FUSE release/write callbacks
(`read_ops.rs`/`write_ops.rs`) and the replay orchestration in `lib.rs`
(`replay_for_vault`, `replay_upload_entry`, the CAS-publish tail, the full
`resolve_folder_key` walk) only run against a mounted FS + live coordinator. To unit
-test them, inject the SDK client / `PublishCoordinator` / journal behind traits so the
orchestration runs over mocks. This is **directly enabled by the two related deferred
refactors** — once the write/replay logic is a pure `CipherBoxFS` method over injected
deps, it is mockable in one place instead of two:
  - [[2026-06-14-consolidate-fuser-and-winfsp-journal-write-paths]]
  - [[2026-06-14-reuse-publish-file-metadata-and-cas-publish-in-replay]]
  Sequence Tier 2 *after* those land.

**Tier 2 blocker — `fuser` reply objects can't be constructed in tests (folded in from
the 2026-06-15 testability investigation).** Every `read_ops.rs`/`write_ops.rs` handler
consumes a concrete `fuser::Reply*` value. The only constructor is
`Reply::new(unique, sender)` where `sender: impl ReplySender` — and in our vendored fuser
(`apps/desktop/src-tauri/vendor/fuser`, wired via the workspace
`[patch.crates-io] fuser = { path = ... }`) `mod reply;` is private and the crate root
re-exports only the `Reply` trait + concrete reply types; **`ReplySender` is not exported**
(`lib_impl.rs:28`). So `cipherbox-fuse` cannot implement a capturing sender, and the reply
objects can't be built in a unit test. Three ways forward:

- **Option A (lowest-touch real coverage):** add one line to the vendored fuser
  (`pub use reply::ReplySender;`), write a channel-backed capture sender in cipherbox-fuse
  test support, and unit-test the metadata-only handlers (getattr, access, lookup incl.
  "."/"..", setattr truncate, create, unlink, rmdir, rename, flush, xattr, mkdir
  happy-path). Reply wire format: out-header is `len:u32 LE | error:i32 LE | unique:u64 LE`,
  `error == 0` success / `-errno` on error. Leave the blocking-network `handle_read`/
  `handle_open` paths to E2E.
- **Option B:** the trait-seam refactor described above (decouple handlers from reply
  emission), then unit-test the pure cores.
- **Option C:** cover via a real mounted FUSE mount (headless desktop FUSE UAT recipe) —
  integration coverage, not unit patch-coverage.

**Tier 3 — realistically UAT-covered, do NOT chase with unit tests (~65 lines).** The
Tauri glue (`apps/desktop/src-tauri/src/fuse/mod.rs`, `commands/sync.rs`,
`tray/mod.rs`, `commands/auth.rs`) is `#[tauri::command]` handlers + mount wiring
already exercised by the headless desktop UAT harness; codecov just doesn't see that
run. Either accept the gap or, if it must count, explore feeding the UAT run's
coverage into `cargo llvm-cov` — but don't write contrived unit tests for AppHandle
glue. `log()` this as a known, accepted gap rather than silently leaving it red.

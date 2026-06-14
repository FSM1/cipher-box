---
created: 2026-06-14T14:26:04.000Z
title: Improve phase-43 rust write-durability test coverage
area: desktop-fuse
files:
  - crates/sdk/src/sync.rs
  - crates/sdk/src/queue.rs
  - crates/fuse/src/lib.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/write_ops.rs
  - apps/desktop/src-tauri/src/sync/mod.rs
---

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

**Tier 3 — realistically UAT-covered, do NOT chase with unit tests (~65 lines).** The
Tauri glue (`apps/desktop/src-tauri/src/fuse/mod.rs`, `commands/sync.rs`,
`tray/mod.rs`, `commands/auth.rs`) is `#[tauri::command]` handlers + mount wiring
already exercised by the headless desktop UAT harness; codecov just doesn't see that
run. Either accept the gap or, if it must count, explore feeding the UAT run's
coverage into `cargo llvm-cov` — but don't write contrived unit tests for AppHandle
glue. `log()` this as a known, accepted gap rather than silently leaving it red.

---
phase: 43-fuse-write-durability
plan: "08"
subsystem: sdk-sync
tags:
  - cr-07
  - write-queue
  - sync-daemon
  - write-parked
dependency_graph:
  requires:
    - 43-05  # WriteQueue::default removal
    - 43-06  # record_failure wiring in upload paths
    - 43-07  # record_failure wiring in mkdir paths
  provides:
    - real cb-journal WriteQueue injected into SyncDaemon
    - sync_cycle emits WriteParked from on-disk Failed counts
    - full retry-to-park-to-notification pipeline is live
  affects:
    - crates/sdk/src/sync.rs
    - crates/sdk/src/client.rs
    - apps/desktop/src-tauri/src/sync/mod.rs
    - apps/desktop/src-tauri/src/commands/sync.rs
tech_stack:
  added: []
  patterns:
    - inject WriteQueue at construction (no default/default-impl)
    - journal-count observation in sync_cycle (read-only, never drain)
    - neutral count-only notification copy (ZK-safe, no file names)
key_files:
  created: []
  modified:
    - crates/sdk/src/sync.rs
    - crates/sdk/src/client.rs
    - apps/desktop/src-tauri/src/sync/mod.rs
    - apps/desktop/src-tauri/src/commands/sync.rs
decisions:
  - emit WriteParked and return (no Idle) when failed > 0; emit Idle when failed == 0
    to avoid status flap from pending-only transient retries
  - journal read errors in sync_cycle are logged as warn and fall through to Idle
    (T-43-33 accept — cost is negligible; errors must never fail the cycle)
  - WriteQueue::new(..., 5) mirrors the FUSE mount's max_retries to keep behavior consistent
metrics:
  duration: "~5 minutes"
  completed_date: "2026-06-13"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 4
---

# Phase 43 Plan 08: Desktop Wires Real WriteQueue into SyncDaemon Summary

One-liner: `SyncDaemon` now takes the real cb-journal `WriteQueue` at construction and
emits `SyncStatus::WriteParked` from on-disk `Failed` counts each sync cycle, making
the 43-04 tray-notification bridge reachable in production (CR-07 end-to-end closure).

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | SyncDaemon takes the real journal and emits WriteParked | d5cae52fc | crates/sdk/src/sync.rs, crates/sdk/src/client.rs |
| 2 | Desktop wires the cb-journal WriteQueue into the daemon | 0d4cc08c4 | apps/desktop/src-tauri/src/sync/mod.rs, apps/desktop/src-tauri/src/commands/sync.rs |

## What Was Built

### Task 1: SyncDaemon WriteQueue injection and WriteParked emission

`SyncDaemon::new` now accepts a `write_queue: WriteQueue` parameter stored directly
on the struct. The `WriteQueue::default()` call is gone (the `Default` impl was
removed in 43-05, so this was required to compile).

In `sync_cycle`, after a successful poll the daemon reads the current vault's
root IPNS name from `KeyState`, calls `self.write_queue.load_all_for_vault(&root_ipns_name)`,
counts `Failed` and `Pending/InProgress` entries, and:

- `failed > 0`: emits `SyncStatus::WriteParked { pending, failed }` and returns
  (no subsequent `Idle` this cycle — parked state is the user-visible status).
- `failed == 0`: emits `Idle` as before (avoids status flap from transient retries).
- `root_ipns_name` is `None`: skips journal check, falls through to `Idle`.
- `load_all_for_vault` returns `Err`: logs `warn` and falls through to `Idle` (never
  fails the cycle — T-43-33 accepted threat).

`CipherBoxSdkClient::start_sync` also updated to accept and forward `WriteQueue`.

### Task 2: Desktop cb-journal path wiring

`create_sync_daemon` in `sync/mod.rs` gains a `write_queue: cipherbox_sdk::WriteQueue`
parameter forwarded verbatim to `SyncDaemon::new`. The existing `WriteParked` to
`send_write_parked_notification` bridge (built in 43-04) is unchanged.

`start_sync_daemon` in `commands/sync.rs` constructs the `WriteQueue` using the same
path resolution as the FUSE mount:

```
dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("cipherbox").join("cb-journal")
```

with `max_retries = 5` (matching the FUSE mount). This guarantees the daemon reads
the same on-disk entries the FUSE layer writes.

## End-to-End Pipeline Status (CR-07)

After this plan and its predecessors:

1. FUSE `release()` writes `JournalEntry` with fsync barrier (43-01/43-02)
2. Background upload attempts call `record_failure` on error (43-06/43-07)
3. After `max_retries` exhausted, entry transitions to `Failed` on disk (43-05 schema)
4. `sync_cycle` reads `Failed` count via `load_all_for_vault` — **this plan**
5. Emits `SyncStatus::WriteParked` — **this plan**
6. Bridge in `sync/mod.rs` fires OS notification with neutral count-only copy (43-04)

The full pipeline is now live end-to-end.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] CipherBoxSdkClient::start_sync also called SyncDaemon::new**

- **Found during:** Task 1 (`cargo check` after initial edit)
- **Issue:** `crates/sdk/src/client.rs` calls `SyncDaemon::new` with 4 args; the new
  signature requires 5. Plan only mentioned `sync.rs` as the file to modify.
- **Fix:** Added `write_queue: WriteQueue` parameter to `start_sync` and forwarded it
  to `SyncDaemon::new` in `client.rs`.
- **Files modified:** `crates/sdk/src/client.rs`
- **Commit:** d5cae52fc (included in Task 1 commit)

**2. [Rule 3 - Blocking] Worktree had no node_modules; pre-commit hook failed**

- **Found during:** Task 1 commit
- **Issue:** `pnpm lint-staged` invoked by `.husky/pre-commit` could not resolve
  `lint-staged` because the worktree has no `node_modules/` directory.
- **Fix:** Created a temporary symlink `worktree/node_modules -> main-repo/node_modules`
  before each commit, removed it after. Staged `.rs` files matched no lint-staged task
  so the hook passed cleanly.
- **Files modified:** none (symlink created/removed transiently)

## Known Stubs

None.

## Threat Flags

No new network endpoints, auth paths, or trust-boundary surface introduced.
The threat register entries T-43-31/T-43-32/T-43-33 from the plan are fully mitigated:

- T-43-31 (dead WriteParked pipeline): mitigated — pipeline is now live.
- T-43-32 (notification copy): unchanged neutral-copy bridge from 43-04.
- T-43-33 (journal read cost): accepted — errors are non-fatal, logged only.

## Self-Check

### Post-Review Resolution

The phase-43 code review (`43-REVIEW.md`) flagged 8 critical findings (CR-01..CR-08)
on 2026-06-12, including CR-07 which this plan addresses. As of 2026-06-14, all 8
criticals were verified resolved via a code cross-check against the current
implementation and a CodeRabbit re-review. See the "Post-Review Resolution
(2026-06-14)" section in `43-REVIEW.md` for the per-finding status and commits.

The Self-Check below predates that reconciliation; it confirms this plan's own
deliverables, and the resolution note above closes the gap against the review's
critical findings.

---

Checking created files exist...
- `.planning/phases/43-fuse-write-durability/43-08-SUMMARY.md`: this file (FOUND)

Checking commits exist...
- d5cae52fc: FOUND
- 0d4cc08c4: FOUND

## Self-Check: PASSED

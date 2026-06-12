---
phase: 43-fuse-write-durability
plan: "06"
subsystem: fuse-write
tags:
  - rust
  - fuse
  - journal
  - durability
  - gap-closure

dependency_graph:
  requires:
    - phase: 43-05
      provides: parent_ipns_key_hex field in JournalOp, user-wrapped child IPNS key in MkdirPublish
  provides:
    - handle_release Err arm replies EIO and returns instead of acking success
    - journal entry removal gated on replay instead of premature in-thread remove
    - record_failure called on background upload failure to drive park pipeline
    - write_ops child_ipns_key_hex and parent_ipns_key_hex confirmed user-wrapped
  affects:
    - crates/fuse/src/read_ops.rs

tech_stack:
  added: []
  patterns:
    - EIO reply-and-return on prepare failure prevents silent data loss
    - Replay-only journal cleanup removes premature orphan window
    - JournalEntry snapshot carried into spawn closure for record_failure

key_files:
  created: []
  modified:
    - crates/fuse/src/read_ops.rs

key_decisions:
  - 'CR-08 mechanism b chosen: replay is the authoritative journal cleanup path; in-thread journal.remove removed entirely. The debounced publisher has no journal knowledge so threading through UploadComplete (mechanism a) would require modifying lib.rs outside this plan scope. Replay already_present check on next mount removes entries whose parent publish is confirmed.'
  - 'CR-07 record_failure wired via JournalEntry snapshot field added to UploadSpawnParams struct. Snapshot cloned before journal.put so the persisted-at-creation state is what gets transitioned on failure.'
  - 'Task 3 write_ops.rs changes confirmed already done by plan 43-05 deviation 4; no new modifications needed in this plan.'

requirements-completed:
  - 2026-06-11-fuse-release-data-loss-before-remote-commit
  - 2026-06-11-fuse-mkdir-parent-publish-orphan

duration: ~25min
completed: 2026-06-13
---

# Phase 43 Plan 06: FUSE Write-Side Gap Closure Summary

**handle_release now replies EIO on prepare failure and calls record_failure on background upload failure; journal entry removal deferred to replay so no orphan window between upload success and parent pointer publish**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-06-13T00:00:00Z
- **Completed:** 2026-06-13T00:25:00Z
- **Tasks:** 3 (Tasks 1/2 committed together; Task 3 was already done by 43-05 deviation 4)
- **Files modified:** 1

## Accomplishments

- CR-04: `prepare_result` Err arm now calls `reply.error(libc::EIO); return` — the trailing `reply.ok()` is no longer reachable from the failure path, closing the silent data-loss window where the OS was acked after a journal fsync failure
- CR-08: removed `spawn_journal.remove(&journal_entry_id)` from the background upload thread; replay on the next mount is the authoritative cleanup path, eliminating the irrecoverable orphan window between `upload_content` success and the debounced parent-pointer publish
- CR-07: `spawn_journal.record_failure(&journal_entry_snapshot, &e)` called in the background failure arm; a `JournalEntry` clone is carried into the spawn closure via a new `journal_entry_snapshot` field in `UploadSpawnParams`; retries increment and the entry parks as Failed after `max_retries`
- CR-03 / CR-01 write-side: confirmed correct in `write_ops.rs` — `child_ipns_key_hex` is user-ECIES-wrapped and `parent_ipns_key_hex` is set; these were fixed by plan 43-05 deviation 4

## Task Commits

1. **Tasks 1, 2, 3: CR-04/CR-08/CR-07 in handle_release; CR-03/CR-01 write-side confirmed** - `4e8c480` (fix)

## Files Created/Modified

- `crates/fuse/src/read_ops.rs` — CR-04 EIO reply on prepare failure; CR-08 journal.remove removed from background thread; CR-07 record_failure wired; journal_entry_snapshot field added to UploadSpawnParams

## Decisions Made

### CR-08 Mechanism Choice

The plan offered two mechanisms for gating journal removal on confirmed parent pointer publish:

- Mechanism (a): thread `journal_entry_id` through `UploadComplete` struct so the debounced publisher removes the entry on parent-publish success
- Mechanism (b): remove the in-thread `journal.remove` entirely and use replay as authoritative cleanup

**Chose mechanism (b).** Mechanism (a) requires modifying `UploadComplete` and `flush_publish_queue` in `crates/fuse/src/lib.rs`, which is not a declared file for this plan and is a more invasive change. Mechanism (b) is simpler, correct, and already supported by the replay idempotency logic from plan 43-05: `replay_upload_entry` returns Ok when the child is already present in parent metadata, and the replay caller removes the entry on Ok return.

## Deviations from Plan

### No new deviations

Task 3 changes to `write_ops.rs` (CR-03 user-wrapped child IPNS key and CR-01 parent IPNS key) were already implemented by plan 43-05 deviation 4. No modification was needed.

The write_ops.rs changes were verified by inspecting the file and confirmed correct:

- `child_ipns_key_hex: child_ipns_key_hex_user_wrapped` (user-ECIES-wrapped, not TEE-wrapped)
- `parent_ipns_key_hex: parent_ipns_key_hex_for_journal` (user-ECIES-wrapped parent key)

## Known Stubs

None.

## Threat Surface Scan

No new network endpoints or auth paths. Threat mitigations implemented:

| Flag | File | Description |
| ---- | ---- | ----------- |
| T-43-22 closed | crates/fuse/src/read_ops.rs | EIO reply on prepare failure; no OS ack after journal fsync failure |
| T-43-23 closed | crates/fuse/src/read_ops.rs | journal.remove no longer called before parent pointer published |
| T-43-24 confirmed | crates/fuse/src/write_ops.rs | child_ipns_key_hex is user-ECIES-wrapped per 43-05 deviation 4 |
| T-43-25 confirmed | crates/fuse/src/read_ops.rs write_ops.rs | parent_ipns_key_hex is user-ECIES-wrapped in both fuser callbacks |
| T-43-26 closed | crates/fuse/src/read_ops.rs | record_failure now called on background upload failure |

## Self-Check: PASSED

- `crates/fuse/src/read_ops.rs` exists and contains all required changes
- Commit `4e8c480` exists in git log
- `cargo check -p cipherbox-fuse` reported zero errors
- `grep -n "reply.error(libc::EIO)" read_ops.rs` matches line 1003 in handle_release Err arm
- `grep -n "record_failure" read_ops.rs` matches line 983 production call
- No `let _ = spawn_journal.remove` remaining in the background upload thread
- `write_ops.rs` confirmed with user-wrapped keys for both child_ipns_key_hex and parent_ipns_key_hex

_Phase: 43-fuse-write-durability_
_Completed: 2026-06-13_

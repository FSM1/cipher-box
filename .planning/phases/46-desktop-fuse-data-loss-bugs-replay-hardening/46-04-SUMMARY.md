---
phase: 46-desktop-fuse-data-loss-bugs-replay-hardening
plan: 04
subsystem: desktop-fuse
tags: [fuse, testing, journal, durability, mkdir, release, replay, A2]
requires: [46-01, 46-03]
provides:
  - REQ-1 mkdir characterization tests (journal-before-reply + conflict re-arm)
  - REQ-2 release/replay characterization tests (journal-before-cleanup + ciphertext recovery)
  - Open Question A2 verification finding (RESOLVED)
affects:
  - crates/fuse/src/lib.rs
tech-stack:
  added: []
  patterns:
    - characterization tests that lock in already-correct D-04 ordering and the mkdir re-arm
    - real secp256k1 keypair via ecies dev-dep for handlers that ECIES-wrap keys
    - per-test isolated journal dir (reused from 46-01 test_support)
key-files:
  created:
    - .planning/phases/46-desktop-fuse-data-loss-bugs-replay-hardening/46-04-SUMMARY.md
  modified:
    - crates/fuse/src/lib.rs
decisions:
  - Tests-only plan; no production rewrites (REQ-1/REQ-2 already implemented by Phase 43/45)
  - flush left a no-op (already covered by flush_returns_ok from 46-01); not journalled on flush to avoid regressing D-04
  - replay test owns its journal dir directly (WriteQueue.journal_dir is pub(crate) to the sdk crate, not reachable from fuse)
metrics:
  duration: ~15m
  completed: 2026-06-15
---

# Phase 46 Plan 04: REQ-1/REQ-2 Characterization Tests + A2 Verification Summary

This is a tests-plus-verification plan. REQ-1 (mkdir durable conflict retry) and
REQ-2 (release durability) are ALREADY IMPLEMENTED in the current tree by Phase
43/45. This plan adds characterization tests that lock in the correct behavior
(and would fail on a future regression) and resolves Open Question A2. No
production code was rewritten.

## What Was Built

All additions live in a new `#[cfg(all(test, feature = "fuse"))] mod
durability_characterization_tests` block appended to `crates/fuse/src/lib.rs`.
The harness from 46-01 (`make_test_fs`, `make_test_fs_with_keypair`,
`CaptureSender`, `reply_error_code`, `make_isolated_journal_dir`) is reused; none
of it was redefined.

### Task 1: REQ-1 mkdir characterization tests

- `mkdir_happy_path_puts_journal_entry_then_replies_entry`
  (`#[tokio::test(flavor = "multi_thread")]`, real EC keypair). Calls
  `handle_mkdir` for a new child under `ROOT_INO`. Asserts: (1) the root inode's
  children now contain the new child named `newdir`, (2) a `MkdirPublish` journal
  entry exists on disk via `load_all_for_vault`, (3) `reply_error_code == 0`. The
  detached publish targets 127.0.0.1:1 and fails harmlessly; the entry is
  retained (D-11b), so journal emptiness is never asserted.
- `mkdir_conflict_rearms` (`make_test_fs`, pure in-memory). Sends
  `FsEvent::MkdirConflict { parent_ino }` on the upload channel, drains via
  `drain_upload_completions`, asserts `parent_ino` is in BOTH `mutated_folders`
  and `publish_queue`. Locks in the re-arm at `lib.rs:949-955`.

### Task 2: REQ-2 release / replay characterization tests

- `release_journals_before_cleanup`
  (`#[tokio::test(flavor = "multi_thread")]`, real EC keypair). Creates a file
  via `handle_create`, writes bytes into its temp file, calls `handle_release`.
  Asserts: (1) an `UploadFile` journal entry exists with non-empty
  `ciphertext_b64`, (2) the temp file path no longer exists (`handle.cleanup`
  ran, `read_ops.rs:882`), (3) `reply_error_code == 0`, and after a brief drain
  the entry is STILL present (the 127.0.0.1:1 failure calls `record_failure`,
  which retains it). This is the D-04 journal-before-cleanup ordering lock.
- `replay_reuploads_ciphertext` (pure, no network). Builds a
  `JournalOp::UploadFile` with a known `ciphertext_b64`, `put`s it to an isolated
  dir, then a fresh `WriteQueue::new` over the same dir + `load_all_for_vault`
  reloads it; asserts the reloaded `ciphertext_b64` base64-decodes to the exact
  original ciphertext bytes.

The flush-before-release window (Open Question 2) was left as a documented
accepted limitation: `flush` stays a no-op (already covered by `flush_returns_ok`
from 46-01). Journaling on flush was deliberately NOT added, since it risks
regressing D-04 / double-journaling.

### Task 3: A2 verification (READ-ONLY)

See the A2 finding below. No production code was changed by this task.

## A2 Finding: RESOLVED

Open Question A2: when the `MkdirConflict` re-arm causes the debounced publisher
to republish the parent, does that publish FETCH-AND-MERGE remote parent children
(preserving a concurrent remote edit) or BLIND-OVERWRITE with local state only?

Verdict: A2 RESOLVED — the debounced parent republish fetch-and-merges. No
clobber risk; REQ-1 is fully closed.

Path traced:

1. `drain_upload_completions` handles `FsEvent::MkdirConflict` by calling
   `queue_publish(parent_ino, false)` then `flush_publish_queue`
   (`lib.rs:949-958`).
2. `flush_publish_queue` (`lib.rs:976-1009`) builds parent metadata via
   `build_folder_metadata(folder_ino)` and calls `spawn_metadata_publish(...)`
   (`lib.rs:992-1001`).
3. `spawn_metadata_publish` (`lib.rs:407`) first attempts the publish with the
   local metadata and an `expected_sequence_number`. On
   `PublishResult::Conflict` (`lib.rs:462`) it resolves the fresh sequence,
   `resolve_ipns` + `fetch_content` + `decrypt_metadata_from_ipfs_public` the
   remote parent, and calls `merge_folder_children(&metadata, remote_metadata)`
   at `lib.rs:485`, then retries the publish with the MERGED metadata.

The merge function is `merge_folder_children` (defined at `lib.rs:360`), invoked
from `spawn_metadata_publish` at `lib.rs:485`. So a concurrent remote edit to the
parent folder's children is preserved through the conflict-driven retry. There is
no blind-overwrite on the re-arm path.

## Test Results

All four named tests pass when run individually under the RAM constraint:

```text
test durability_characterization_tests::mkdir_happy_path_puts_journal_entry_then_replies_entry ... ok
test durability_characterization_tests::mkdir_conflict_rearms ... ok
test durability_characterization_tests::release_journals_before_cleanup ... ok
test durability_characterization_tests::replay_reuploads_ciphertext ... ok
```

`git diff --stat crates/fuse/src/write_ops.rs crates/fuse/src/read_ops.rs` is
EMPTY — production durability code is untouched. No bare `cargo test` was run.

## Deviations from Plan

- The plan suggested reading `fs.journal.journal_dir` in
  `replay_reuploads_ciphertext`. That field is `pub(crate)` to the
  `cipherbox_sdk` crate and is not reachable from `cipherbox-fuse`, so the test
  instead owns its own isolated dir via `make_isolated_journal_dir()` and builds
  both the `put` and reload `WriteQueue` over it. The round-trip assertion is
  unchanged.

## Threat Model Compliance

- T-46-09 (release D-04 ordering): `release_journals_before_cleanup` asserts the
  journal entry with non-empty ciphertext exists AND the temp file is gone after
  release; a future reorder of `reply.ok()` ahead of `journal.put`, or temp-file
  deletion before journalling, would fail the test.
- T-46-10 (debounced parent republish A2): verified fetch-and-merge via
  `merge_folder_children` (`lib.rs:485`); no clobber risk.
- T-46-08 (test fixtures): tests use a real EC keypair only to wrap keys; the
  journal holds ciphertext + ECIES-wrapped keys; isolated temp dirs; no raw
  plaintext keys constructed.

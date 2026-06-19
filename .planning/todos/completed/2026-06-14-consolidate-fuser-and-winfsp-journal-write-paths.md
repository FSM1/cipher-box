---
created: 2026-06-14T12:37:25.820Z
title: Consolidate fuser and winfsp journal write paths
area: desktop-fuse
files:
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/write_ops.rs
  - crates/fuse/src/lib.rs
---

## Problem

The fuser release path (`crates/fuse/src/read_ops.rs`) and the winfsp cleanup path
(`crates/fuse/src/platform/windows/write_ops.rs`) carry ~150 lines of near-identical
code: the local `UploadSpawnParams` struct, the prepare closure that builds the
`UploadFile`/`MkdirPublish` journal entry, the `journal.put` + deferred-mutation
sequence, and the spawn-upload closure. The mkdir journal-entry construction is
similarly duplicated between `write_ops.rs` and the winfsp `write_ops.rs`.

The two copies have already begun to drift (CR-04/CR-05/CR-07 fixes had to be applied
twice; the fuser struct briefly carried a dead `journal_entry_id` field the winfsp one
did not). Every future change to journal-entry shape, the D-04 fsync-before-ack
ordering, or the D-05 plaintext handling must be made twice and kept in sync by hand.

Flagged as the #1 item by all four agents in the phase-43 `/simplify` review and
deferred from the cleanup pass (commit a1ec69f1b) as too large/risky for that pass.

## Solution

Lift the platform-independent core into shared `CipherBoxFS` methods in
`crates/fuse/src/lib.rs` (or a `write_common` module), e.g.
`build_upload_journal_entry(...) -> Result<(JournalEntry, UploadSpawnParams), String>`,
`build_mkdir_journal_entry(...) -> JournalEntry`, and a `spawn_upload(params)`. The
platform layers keep only what genuinely differs: the reply/cleanup ordering
(`reply.ok()` / `reply.error(EIO)` on fuser vs. WinFsp's void `Cleanup`).

Constraints: this is the most security-sensitive path — the D-04 fsync-before-ack and
D-05 plaintext-zeroize ordering MUST be preserved exactly, and the deferred-mutation
ordering (CR-04) must stay after `journal.put`. The winfsp half is not locally
compilable on macOS, so verify via the winfsp CI gate (`cargo check --features winfsp`)
and the desktop E2E. Pairs naturally with the Option<String> key helper and the
created_at/now_ms helpers.

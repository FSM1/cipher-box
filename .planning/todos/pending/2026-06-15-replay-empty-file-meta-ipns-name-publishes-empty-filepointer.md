---
created: 2026-06-15
title: Park legacy empty file_meta_ipns_name replay entries instead of empty FilePointer
area: fuse
files:
  - crates/fuse/src/lib.rs:1825
---

## Problem

In `replay_upload_entry` (crates/fuse/src/lib.rs ~line 1825), when `file_meta_ipns_name`
is `None` (a legacy pre-Phase-45 journal entry that stored the `""` sentinel), Step 3
skips the per-file metadata IPNS publish, but Step 4 still builds a parent `FolderChild::File`
`FilePointer` whose `file_meta_ipns_name` is `""` (via `unwrap_or_default()`) and id
`replay-`. `replay_for_vault` then treats the entry as published and removes it from the
journal. The uploaded content CID ends up with **no resolvable per-file metadata record**,
and multiple legacy empty-name entries can collide under `merge_folder_children`'s
IPNS-key merge semantics (all keyed on the empty name).

This is **pre-existing** behavior, explicitly preserved: the code carries the comment
"an empty string preserves the pre-Phase-45 behavior where files without a per-file IPNS
name are still merged into the parent via their FilePointer entry." Phase 45 (#18) changed
the `""` sentinel to `Option<String>` but kept this replay behavior identical (verified as
no-behavior-change). Flagged by CodeRabbit on PR #491 (tagged "Heavy lift") and deferred as
out of scope for that cleanup phase.

## Solution

TBD — for the `file_meta_ipns_name == None` legacy case, either:

- Park / return an error for the entry (retain in journal) rather than publishing an empty
  `FilePointer`, so it is never marked successfully replayed without a real metadata record; OR
- Have replay mint a fresh per-file IPNS name + key for the legacy entry so it gets a real,
  resolvable metadata record before building the FilePointer.
- Needs care: decide what should happen to already-published empty-locator FilePointers
  from past replays, and add tests for the legacy-empty-name path + the multi-entry
  merge-collision case. This is a crash-recovery behavior change — out of any
  no-behavior-change phase; plan it as its own bug-fix work.

Source: CodeRabbit review on PR #491 (thread on crates/fuse/src/lib.rs:1837).

---
phase: 43-fuse-write-durability
plan: "05"
subsystem: fuse-replay
tags:
  - rust
  - fuse
  - replay
  - journal
  - durability
  - gap-closure
  - tdd
dependency_graph:
  requires:
    - cipherbox-sdk::WriteQueue (43-01)
    - crates/fuse/src/lib.rs replay skeleton (43-02/03/04)
  provides:
    - JournalOp::UploadFile.parent_ipns_key_hex
    - JournalOp::MkdirPublish.parent_ipns_key_hex
    - JournalOp::MkdirPublish.child_ipns_key_hex (user-wrapped, not TEE-wrapped)
    - fetch_merge_publish_parent with actual IPNS publish (CR-01)
    - replay_upload_entry with ecies::unwrap_key before [u8;32] cast (CR-02)
    - replay_mkdir_entry stores user-wrapped child key (CR-03)
    - ordered_for_replay sorts by created_at_ms (WR-01)
    - resolve_folder_key BFS descent (WR-02)
    - put() atomic 0o600 at create + parent dir fsync (WR-03)
    - WriteQueue::default removed (WR-09)
  affects:
    - crates/sdk/src/queue.rs
    - crates/sdk/src/sync.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/src/write_ops.rs
    - crates/fuse/src/platform/windows/write_ops.rs
tech_stack:
  added: []
  patterns:
    - BFS descent for nested folder resolution
    - ECIES unwrap before IPNS key cast
    - CAS-publish with expected_sequence_number
    - atomic 0o600 via OpenOptionsExt::mode at create time
    - parent dir fsync after put/remove
    - atomic counter for test temp dir isolation
decisions:
  - parent_ipns_key_hex is user-ECIES-wrapped (not TEE-wrapped, not raw) per D-04 zero-knowledge family
  - fetch_merge_publish_parent returns Err on Conflict so entry is retained — never removed without confirmed publish
  - unpin_content called only after PublishResult::Success on the pre-merge CID (T-43-19)
  - resolve_folder_key returns only the folder key; IPNS key comes from journaled parent_ipns_key_hex in both replay functions
  - SyncDaemon.write_queue field removed (FUSE layer owns drain per 43-01; 43-08 will rewire daemon)
  - BFS depth cap 32 prevents infinite loops/excessive network calls
  - Test temp dir uses atomic counter to avoid parallel test collision
key_files:
  created: []
  modified:
    - crates/sdk/src/queue.rs
    - crates/sdk/src/sync.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/src/write_ops.rs
    - crates/fuse/src/platform/windows/write_ops.rs
metrics:
  duration: ~45min
  completed: 2026-06-12
  tasks: 3
  files: 6
---

# Phase 43 Plan 05: Replay Correctness Gap Closure Summary

Closes foundational replay-correctness gaps CR-01, CR-02, CR-03 plus WR-01, WR-02, WR-03 (partial), and WR-09. The root defect — parent IPNS private key was never journaled, so replay returned Ok without publishing — is now closed.

## What Was Built

### Journal Schema Changes (crates/sdk/src/queue.rs)

Added `parent_ipns_key_hex: String` field to both `JournalOp::UploadFile` and `JournalOp::MkdirPublish`. The field stores the user-ECIES-wrapped parent IPNS private key, unwrappable only with the user's private key at replay time. Never raw, never TEE-wrapped (D-04 zero-knowledge family, CR-01).

`JournalOp::MkdirPublish.child_ipns_key_hex` doc comment updated: now explicitly stores the user-ECIES-wrapped child IPNS key (CR-03). The write side (write_ops.rs) was updated to journal `wrap_key(&child_ipns_key, &user_public_key)` instead of `encrypted_ipns_for_tee`.

`ordered_for_replay` now sorts each group ascending by `created_at_ms` before returning (WR-01). The previous implementation preserved insertion order which was filesystem read_dir order (non-deterministic).

`put()` sets 0o600 atomically at create time via `OpenOptionsExt::mode(0o600)` (WR-03a — no readable window). After the file fsync, `put()` and `remove()` both open the parent journal directory and call `sync_all()` so new/removed dirents are durable on crash (WR-03b).

`impl Default for WriteQueue` removed (WR-09). `SyncDaemon.write_queue` field and `write_queue_mut()` accessor removed — FUSE layer owns drain per Plan 43-01 SUMMARY.

### Replay Core Changes (crates/fuse/src/lib.rs)

`fetch_merge_publish_parent` now accepts the unwrapped parent IPNS private key (`&[u8]`) and actually signs and publishes the IPNS record (CR-01). Implementation mirrors the live mkdir parent-publish path from write_ops.rs:

- Casts unwrapped key to `[u8;32]`, builds value `/ipfs/{merged_cid}`
- Calls `cipherbox_core::create_ipns_record` then `cipherbox_api_client::ipns::publish_ipns`
- On `PublishResult::Success`: calls `coordinator.record_publish` then unpins the OLD CID
- On `PublishResult::Conflict`: returns `Err` so the journal entry is retained for next mount

The unconditional `unpin_content(&resolve.cid)` (T-43-19: unpinned live CID before publish) is removed. The phantom `coordinator.record_publish` for an unpublished record (IN-06) is removed.

`replay_mkdir_entry` and `replay_upload_entry` now accept `parent_ipns_key_hex: &str`, hex-decode it, and call `cipherbox_crypto::ecies::unwrap_key` to get the raw bytes passed to `fetch_merge_publish_parent`. Returns `Err` on empty or malformed key (T-43-20 — never panics).

`replay_upload_entry` CR-02 fix: ecies-unwraps the file IPNS key before the `[u8;32]` cast. The journaled `file_ipns_key_hex` is stored AS-IS into `FilePointer.ipns_private_key_encrypted` without re-wrapping (double-wrap removed).

`replay_mkdir_entry` CR-03 fix: `child_ipns_key_hex` is now the user-ECIES-wrapped key from the journal (write side fixed in write_ops.rs). Written directly into `FolderEntry.ipns_private_key_encrypted` — no re-wrap.

`resolve_folder_key` replaced with a bounded BFS descent (WR-02). Starts from root, expands folder children level by level, decrypting each layer's metadata with the just-unwrapped folder key. Capped at depth 32. Returns only the folder (AES) key; the IPNS signing key comes from `parent_ipns_key_hex` in the journal.

### Write Side Changes

`crates/fuse/src/read_ops.rs`: `UploadFile` journal entry now includes `parent_ipns_key_hex` built by resolving the parent inode's `ipns_private_key` and wrapping with `fs.public_key`.

`crates/fuse/src/write_ops.rs`: `MkdirPublish` journal entry includes `parent_ipns_key_hex` (user-wrapped `parent_ipns_key` from `build_folder_metadata`) and `child_ipns_key_hex` (user-wrapped `ipns_private_key`, not TEE-wrapped).

`crates/fuse/src/platform/windows/write_ops.rs`: Same fixes as write_ops.rs applied to the WinFsp cleanup path.

## TDD Gate Compliance

| Gate | Commit | Notes |
| ---- | ------ | ----- |
| RED | 7127cbb72 | 4 new tests added; fail to compile (fields missing) |
| GREEN | 0b8545bad | 18 tests pass; schema + implementation added |

## Test Results

```
cargo test -p cipherbox-sdk -- queue: 18 passed
cargo check -p cipherbox-fuse: 0 errors
```

New tests added:

- `upload_entry_parent_ipns_key_hex_round_trips` — CR-01 field survives serde
- `mkdir_entry_parent_ipns_key_hex_round_trips` — same for MkdirPublish
- `replay_order_sorts_by_created_at_within_group` — WR-01 deterministic ordering
- `journal_no_plaintext_with_parent_ipns_key` — D-05 no raw key bytes in JSON

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed parallel test temp dir collision**

- Found during: GREEN verification (intermittent `journal_remove` failure)
- Issue: `make_temp_queue()` used `subsec_nanos + tid.len()` which produced the same suffix when tests ran concurrently (tid.len() is always ~12; subsec_nanos collision on fast hardware)
- Fix: Changed to atomic monotonic counter plus thread ID numeric part
- Files modified: `crates/sdk/src/queue.rs`
- Commit: 62e119a91

**2. [Rule 3 - Blocking] Removed SyncDaemon.write_queue field using WriteQueue::default()**

- Found during: GREEN implementation (compile error after removing Default impl)
- Issue: `sync.rs` field `write_queue: WriteQueue` initialized via `WriteQueue::default()` in `SyncDaemon::new`. Only other reference was `write_queue_mut()` accessor with no callers
- Fix: Removed the field, the accessor, and the `use crate::queue::WriteQueue` import from sync.rs (FUSE layer owns drain per 43-01 SUMMARY)
- Files modified: `crates/sdk/src/sync.rs`
- Commit: 0b8545bad

**3. [Rule 3 - Blocking] Removed /// doc comments from function parameters**

- Found during: Task 2 cargo check
- Issue: Rust does not allow `///` doc comments on function parameters; 7 errors
- Fix: Converted to inline `//` comments above the parameter
- Files modified: `crates/fuse/src/lib.rs`
- Commit: 4bc1a0278

**4. [Rule 2 - Missing Critical] Fixed CR-03 on write side in same plan**

- Found during: Task 2 implementation
- Issue: Plan said 43-06 would fix `write_ops.rs:525` (TEE-wrapped key journaled), but fixing `replay_mkdir_entry` to write the key as-is is only correct if the write side already journals the user-wrapped form
- Fix: Added `child_ipns_key_hex_user_wrapped = wrap_key(&ipns_private_key, &fs.public_key)` in both `write_ops.rs` and `windows/write_ops.rs` MkdirPublish journal entries
- Files modified: `crates/fuse/src/write_ops.rs`, `crates/fuse/src/platform/windows/write_ops.rs`
- Commit: 4bc1a0278

## Known Stubs

None. All CR-01/02/03, WR-01/02/03/09 are fully implemented. `fetch_merge_publish_parent` now performs a confirmed IPNS publish.

Remaining gaps from the VERIFICATION report that are out of scope for this plan:

- CR-04 (read_ops.rs error path acks reply.ok on journal failure) — scoped to 43-06
- CR-05 (Windows UploadSpawnParams wrong types) — scoped to 43-07
- CR-06 (Windows mount never calls replay_for_vault) — scoped to 43-07
- CR-07 (record_failure has no production callers) — scoped to 43-08
- CR-08 (journal entry removed before parent pointer confirmed) — scoped to 43-06

## Threat Surface Scan

No new network endpoints or auth paths. Threat register mitigations implemented:

- T-43-17: `parent_ipns_key_hex` is user-ECIES-wrapped; journal file 0o600 at create
- T-43-18: CAS publish with `expected_sequence_number`; Conflict returns Err, entry retained
- T-43-19: Removed unconditional `unpin_content(&resolve.cid)`; only unpins after Success
- T-43-20: hex::decode and ecies::unwrap_key both return Err on malformed key; entry retained
- T-43-21: Removed phantom `coordinator.record_publish` for unpublished records

## Self-Check: PASSED

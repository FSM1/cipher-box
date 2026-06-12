---
phase: 43-fuse-write-durability
plan: "02"
subsystem: fuse
tags:
  - rust
  - fuse
  - write-journal
  - durability
  - data-loss-fix
dependency_graph:
  requires:
    - cipherbox-sdk::WriteQueue (from plan 43-01)
    - cipherbox-sdk::JournalEntry
    - cipherbox-sdk::JournalOp
    - cipherbox-sdk::JournalEntryStatus
  provides:
    - FsEvent enum (UploadComplete, MkdirConflict variants)
    - CipherBoxFS.journal field
    - handle_release journal-fsync-before-ack ordering
    - handle_mkdir journal-fsync-before-reply + conflict retry signal
  affects:
    - crates/fuse/src/lib.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/src/write_ops.rs
    - crates/fuse/Cargo.toml
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
    - crates/fuse/src/platform/windows/write_ops.rs
    - crates/sdk/src/queue.rs
tech_stack:
  added:
    - cipherbox-sdk dependency in cipherbox-fuse Cargo.toml
  patterns:
    - FsEvent enum wrapping channel message types (replaces bare UploadComplete channel)
    - journal-fsync-before-ack ordering in FUSE release/mkdir callbacks
    - spawn-after-ack pattern with UploadSpawnParams struct
    - conflict retry via mpsc FsEvent::MkdirConflict signal
key_files:
  created: []
  modified:
    - crates/fuse/src/lib.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/src/write_ops.rs
    - crates/fuse/Cargo.toml
    - crates/sdk/src/queue.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
    - crates/fuse/src/platform/windows/write_ops.rs
decisions:
  - journal field injected into CipherBoxFS struct so all FUSE callbacks reach it as fs.journal without going through Tauri APIs (A3 constraint preserved)
  - WriteQueue Clone derive added so journal handle can be moved into background upload thread closure
  - journal_dir uses dirs::data_local_dir().join("cipherbox/cb-journal") for stable cross-remount persistence; falls back to temp_dir if data_local_dir unavailable
  - UploadSpawnParams struct used to separate prepare-and-journal phase from spawn phase so handle.cleanup() can run before reply.ok() without borrow issues
  - parent_ino_for_conflict captured before spawn closure via let binding so u64 is Copy-moved into the FsEvent::MkdirConflict send
metrics:
  duration: 50min
  completed: 2026-06-12
  tasks: 3
  files: 8
---

# Phase 43 Plan 02: FUSE Write Durability — fuser Callback Wiring Summary

Wired the durable journal from Plan 43-01 into the shared fuser callback path used by macOS and Linux. Reordered handle_release to journal-fsync-before-ack (D-04), moved plaintext cleanup before OS ack (D-05), journaled MkdirPublish before reply.entry (D-04), and replaced the false "debounced publish will retry" warning with an actual FsEvent::MkdirConflict retry signal (D-11a/b).

## What Was Built

### Task 1: FsEvent enum + journal field + MkdirConflict drain arm

`crates/fuse/src/lib.rs`:

- New `pub enum FsEvent` with variants `UploadComplete(UploadComplete)` and `MkdirConflict { parent_ino: u64 }` near `UploadComplete` struct (line 111)
- `upload_rx`/`upload_tx` channel type changed from `mpsc::*<UploadComplete>` to `mpsc::*<FsEvent>`
- `pub journal: cipherbox_sdk::WriteQueue` field added to `CipherBoxFS` struct
- `drain_upload_completions` updated to match on `FsEvent`; new `MkdirConflict` arm inserts `parent_ino` into `mutated_folders` and calls `queue_publish(parent_ino, false)` (D-11a)
- All `upload_tx.send(UploadComplete {...})` call sites updated to `FsEvent::UploadComplete(...)` in `read_ops.rs` and `platform/windows/write_ops.rs`

`crates/fuse/Cargo.toml`:

- Added `cipherbox-sdk = { workspace = true }` dependency

`apps/desktop/src-tauri/src/fuse/mod.rs` and `windows/mod.rs`:

- Channel construction updated to `mpsc::channel::<cipherbox_fuse::FsEvent>()`
- Journal dir created at `dirs::data_local_dir()/cipherbox/cb-journal` with `0o700` permissions
- `journal` field injected into `CipherBoxFS { ... }` struct literal

### Task 2: handle_release reordering (D-04, D-05)

`crates/fuse/src/read_ops.rs`:

New operation order in `handle_release`:

1. Encrypt + wrap_key + clear_bytes (unchanged)
2. Build `JournalEntry` with `JournalOp::UploadFile` using stable IPNS names (`file_meta_ipns_name`, `parent_folder_ipns_name`) — never inode numbers (D-02)
3. `fs.journal.put(&journal_entry)` — fsync to disk (D-04 barrier)
4. `handle.cleanup()` — zeroize+delete plaintext temp file immediately after fsync (D-05)
5. `reply.ok()` — OS acked only after local durability is confirmed
6. `std::thread::spawn(...)` — background upload; calls `journal.remove` on confirmed success; does NOT remove on failure (D-09 replay path)

`ciphertext_b64` is base64-encoded ciphertext; only ciphertext-layer data in journal entry (zero-knowledge compliance).

`UploadSpawnParams` struct was introduced to cleanly separate the prepare+journal phase from the spawn phase (see Deviations).

`crates/sdk/src/queue.rs`:

- `#[derive(Clone)]` added to `WriteQueue` so journal handles can be moved into background thread closures

### Task 3: handle_mkdir wiring (D-04, D-11a, D-11b)

`crates/fuse/src/write_ops.rs`:

- After `build_folder_metadata(parent)` and before `std::thread::spawn`: build `JournalEntry` with `JournalOp::MkdirPublish { child_ipns_name, child_folder_key_hex, child_ipns_key_hex, parent_folder_ipns_name, name, created_at_ms }` (all hex-encoded ECIES-wrapped keys — no raw key material, D-05)
- `fs.journal.put(&mkdir_journal_entry)` fsyncs before the closure returns — `reply.entry()` fires after the outer closure returns, so the fsync barrier precedes the OS ack (D-04)
- Parent-publish success branch: `journal_for_mkdir.remove(&mkdir_journal_entry_id)` called after coordinator records publish (D-11b)
- Conflict arm replacement: old false "Debounced publish will retry" comment and warn-only body replaced with `upload_tx.send(crate::FsEvent::MkdirConflict { parent_ino })` (D-11a); journal entry is NOT removed on conflict

### Key line ordering (for Plan 43-03 Windows mirror)

`handle_release` ordering:

```
journal.put (line 844)       <-- fsync barrier
handle.cleanup (line 892)    <-- plaintext deleted
reply.ok (line 894)          <-- OS acked
std::thread::spawn (line 904) <-- upload started
spawn_journal.remove (line 943, inside thread)  <-- removed on success
```

`handle_mkdir` ordering:

```
build_folder_metadata (line ~509)
fs.journal.put (line 534)       <-- fsync barrier inside closure
std::thread::spawn (line 548)   <-- upload thread
reply.entry (line 655)          <-- OS acked (closure returned Ok)
journal_for_mkdir.remove (line 628, inside thread)  <-- removed on success
upload_tx.send MkdirConflict (line 639, inside thread)  <-- conflict retry signal
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] cipherbox-sdk not a dep of cipherbox-fuse**

- Found during: Task 1 compile
- Issue: `cipherbox_sdk::WriteQueue` type not resolvable; crates/fuse/Cargo.toml lacked the dependency
- Fix: Added `cipherbox-sdk = { workspace = true }` to Cargo.toml
- Files modified: `crates/fuse/Cargo.toml`
- Commit: a3729f529

**2. [Rule 3 - Blocking] WriteQueue not Clone**

- Found during: Task 2 implementation
- Issue: Background upload thread closure requires `WriteQueue` to be moved in; struct had no Clone impl
- Fix: Added `#[derive(Clone)]` to `WriteQueue` in `crates/sdk/src/queue.rs` (both fields `PathBuf` and `u32` are Clone)
- Files modified: `crates/sdk/src/queue.rs`
- Commit: eb6a8ff61

**3. [Rule 2 - Missing critical] Windows channel type update required for compilation**

- Found during: Task 1 (channel type change propagation)
- Issue: Windows write_ops.rs send site and windows/mod.rs channel construction used the old `UploadComplete` type which would cause type mismatch errors on Windows builds
- Fix: Updated `platform/windows/write_ops.rs` send to `FsEvent::UploadComplete(...)` and `windows/mod.rs` channel to `mpsc::channel::<cipherbox_fuse::FsEvent>()`; injected journal into Windows CipherBoxFS construction
- Files modified: `crates/fuse/src/platform/windows/write_ops.rs`, `apps/desktop/src-tauri/src/fuse/windows/mod.rs`
- Commit: a3729f529

**4. [Rule 1 - Bug] encrypted_folder_key_hex moved before journal entry use**

- Found during: Task 3 compile
- Issue: `encrypted_folder_key_hex` was moved into `InodeKind::Folder { encrypted_folder_key: encrypted_folder_key_hex }` at line 470; journal entry at line 522 tried to use it after the move
- Fix: Added `let encrypted_folder_key_hex_for_journal = encrypted_folder_key_hex.clone();` before the move; used the clone in the journal entry
- Files modified: `crates/fuse/src/write_ops.rs`
- Commit: 9a85d9360

## Known Stubs

None. All journal wiring is fully implemented. Plan 43-03 (Windows WinFsp path) will mirror the same ordering for the Windows-specific `handle_cleanup` release path; Plan 43-04 (drain owner) will call `record_failure` on upload error to transition to `WriteParked`.

## Threat Surface Scan

No new network endpoints or auth paths introduced. Threat register mitigations implemented:

- T-43-05 (Repudiation/Data loss): `fs.journal.put` precedes `reply.ok()` in handle_release — verified by line numbers (844 < 894)
- T-43-06 (Information Disclosure): `handle.cleanup()` at line 892 before `reply.ok()` at 894 — plaintext temp deleted before OS ack
- T-43-07 (Data loss / mkdir orphan): MkdirPublish journaled at line 534 before `reply.entry()` at 655; `FsEvent::MkdirConflict` signal at 639 triggers live-session retry; journal entry cleared only on success (628)
- T-43-08 (Tampering / stale upload): `write_generation` captured at line 759-761 (unchanged); drain guard in `lib.rs:659-662` checks `inode.write_generation == result.write_generation` before applying CID update

## Self-Check: PASSED

---
phase: 52-desktop-fuse-durability-at-rest-safety
plan: 03
subsystem: fuse/write-path
tags: [fuse, journal, sidecar, durable-ack, name-encryption, size-cap, rust]
dependency_graph:
  requires: [52-02]
  provides: [size-cap-guard, filename-encryption-write, off-thread-durable-ack]
  affects:
    - crates/fuse/src/journal_helpers.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/Cargo.toml
    - crates/fuse/src/lib.rs
tech_stack:
  added: [sha2-dep-fuse]
  patterns: [off-thread-std-thread-recv_timeout, ecies-filename-encryption, sha256-sidecar-hash]
key_files:
  created: []
  modified:
    - crates/fuse/src/journal_helpers.rs
    - crates/fuse/src/read_ops.rs
    - crates/fuse/Cargo.toml
    - crates/fuse/src/lib.rs
decisions:
  - "Size cap checked FIRST (before key gen) so the EIO-reject path has nothing to zeroize"
  - "Filename/dir-name encryption uses ecies::wrap_key directly with ?-propagation (a failed name encrypt FAILS the write; unlike key wrapping it does not fall back to empty string)"
  - "Durable-ack uses std::thread::spawn + std::sync::mpsc recv_timeout, NOT rt.block_on — put_with_sidecar is synchronous, and recv_timeout works whether or not the caller is inside a tokio runtime (rt.block_on panics with nested-runtime inside #[tokio::test])"
  - "NETWORK_TIMEOUT made pub(crate) so read_ops can use NETWORK_TIMEOUT * 18 for the bounded recv"
metrics:
  completed: "2026-06-20T01:30:00Z"
  tasks_completed: 2
  files_modified: 4
---

# Phase 52 Plan 03: Write-Side Size Cap, Filename Encryption, Off-Thread Durable-Ack

One-liner: Enforced the per-entry size cap and ECIES-encrypted the filename/dir-name in `build_upload_journal_entry`/`build_mkdir_journal_entry`, and moved the heavy ciphertext-sidecar write + fsync off the FUSE callback thread onto a separate OS thread while preserving the Phase-43 durable-ack contract via a bounded `recv_timeout` the callback blocks on before `reply.ok()`.

## What Was Built

### journal_helpers.rs (D-01 write side, D-04)

- Size cap: immediately after `read_all()`, reject files where `plaintext.len() > cipherbox_sdk::MAX_JOURNAL_PAYLOAD_BYTES` with an `Err` (so the release path replies EIO). Checked before any key generation, so nothing sensitive is in memory on the reject path.
- Sidecar fields: compute `entry_id` up-front, `sidecar_path = self.journal.sidecar_path_for(&entry_id)`, and `sidecar_sha256 = SHA-256(ciphertext)`; the `UploadFile` entry now carries these instead of `ciphertext_b64`. The in-memory `ciphertext` is still returned in `UploadJournalResult` for the live upload thread (unchanged).
- Filename encryption: `filename_encrypted_hex = hex(ecies::wrap_key(file_name, public_key))` with `?` propagation (a failed encrypt fails the write).
- Mkdir name encryption: same treatment for `name_encrypted_hex` in `build_mkdir_journal_entry`.

### read_ops.rs (D-01 durable-ack)

The release durability step was restructured into three stages: (1) build entry (size cap + sidecar + name encrypt, no mutations), (2) spawn the synchronous `put_with_sidecar` on a separate OS thread + block the callback thread on a BOUNDED `recv_timeout(NETWORK_TIMEOUT * 18)`, (3) only on durable Ok apply the inode mutations / pending_content / queue_publish, then `reply.ok()` and spawn the background upload. Any durability failure/timeout replies EIO with no inode mutation (CR-04 preserved — Pitfall 1 false-ack avoided).

### Cargo.toml / lib.rs

- Added `sha2 = { workspace = true }` to the fuse crate.
- Made `NETWORK_TIMEOUT` `pub(crate)` so read_ops can reference it.

## Critical Reconciliation (nested-runtime)

The plan specified `fs.rt.block_on(tokio::time::timeout(NETWORK_TIMEOUT * 18, oneshot_rx))`. That panics with "Cannot start a runtime from within a runtime" when the release handler is driven from inside a tokio runtime (every `#[tokio::test]`, and any caller already on a runtime thread). Switched to `std::thread::spawn` + `std::sync::mpsc::Receiver::recv_timeout`, which is runtime-agnostic and equally correct: `put_with_sidecar` is synchronous so no tokio task is needed, and the bound is identical (`NETWORK_TIMEOUT * 18 ≈ 180s`). This is what makes `release_journals_before_cleanup` pass (it would otherwise panic).

## Phase 51 Reconciliation

The Phase-51 `clear_bytes`-on-every-fallible-path zeroization in `build_upload_journal_entry` is preserved untouched — the new size-cap guard is inserted ABOVE the key generation, so it cannot leak the file key (none exists yet at that point). `cipherbox_crypto::ecies::wrap_key` (used for filename encryption) is the same hardened API.

## Test Results

- cipherbox-fuse: 64/64 (baseline 60). `payload_size_cap_returns_err` (cap boundary + message), and the migrated `build_upload_journal_entry_round_trips` (asserts sidecar fields + sidecar_sha256 == SHA-256(ciphertext) + encrypted filename) and `build_mkdir_journal_entry_round_trips` (encrypted name, not plaintext) all green.
- `release_journals_before_cleanup` now asserts the sidecar `.bin` exists and its bytes hash to the recorded `sidecar_sha256` BEFORE the OS ack (durable-ack-with-sidecar evidence).

## Known Stubs

None.

## Self-Check: PASSED

- `journal_helpers.rs` contains `MAX_JOURNAL_PAYLOAD_BYTES`, `sidecar_path`, `sidecar_sha256`, `filename_encrypted_hex`, `name_encrypted_hex`; no `ciphertext_b64`/`base64` remains.
- `read_ops.rs` writes the sidecar off-thread and blocks on a bounded `recv_timeout` before `reply.ok()`.
- 64/64 fuse tests pass; no warnings.

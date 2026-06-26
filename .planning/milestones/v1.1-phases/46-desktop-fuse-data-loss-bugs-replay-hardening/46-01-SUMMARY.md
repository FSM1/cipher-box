---
phase: 46-desktop-fuse-data-loss-bugs-replay-hardening
plan: 01
subsystem: desktop-fuse
tags: [fuse, testing, harness, journal, vendored-fuser]
requires: []
provides:
  - fuser::ReplySender re-export from vendored fuser
  - crate::test_support harness (make_test_fs / make_test_fs_with_keypair / CaptureSender / reply_error_code / make_isolated_journal_dir)
  - sample handler tests and journal_helpers builder round-trip tests
affects:
  - apps/desktop/src-tauri/vendor/fuser/src/lib_impl.rs
  - crates/fuse/src/lib.rs
  - crates/fuse/src/test_support.rs
  - crates/fuse/src/journal_helpers.rs
tech-stack:
  added: []
  patterns:
    - per-test isolated journal dir keyed by process id plus monotonic counter
    - CaptureSender decodes the 16-byte fuse_out_header error field at offset 4
    - real secp256k1 keypair via ecies dev-dep for ECIES wrap round-trips
key-files:
  created:
    - crates/fuse/src/test_support.rs
  modified:
    - apps/desktop/src-tauri/vendor/fuser/src/lib_impl.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/journal_helpers.rs
decisions:
  - Test modules feature-gated on fuse so crate::test_support is in scope
  - Upload builder test uses an absent inode (ino 4242) to exercise the new-file path
  - Mkdir builder test calls the builder with a fresh child ino without inserting it; the builder only reads the parent
metrics:
  duration: ~12m
  completed: 2026-06-15
---

# Phase 46 Plan 01: FUSE Handler Test Harness Summary

REQ-6 test infrastructure that unblocks unit testing of FUSE handlers and journal builders: a one-line vendored-fuser `ReplySender` re-export, a `make_test_fs()` / `CaptureSender` harness, and sample handler plus journal-builder round-trip tests using a real EC keypair.

## What Was Built

### Task 1: vendored fuser ReplySender re-export

Added exactly one line `pub use reply::ReplySender;` after line 28 of `apps/desktop/src-tauri/vendor/fuser/src/lib_impl.rs`. This surfaces only the trait name; `mod reply;` stays private. The FUSE-T `channel.rs` patch was not touched (verified empty diff across all three commits).

### Task 2: test_support harness module

Created `crates/fuse/src/test_support.rs` gated `#[cfg(all(test, feature = "fuse"))]`, declared as a private module in `lib.rs` under the same gate. Provides:

- `make_test_fs()` and `make_test_fs_with_keypair(private_key, public_key)` — build the full 29-field `CipherBoxFS` literal with a per-test isolated journal dir created before `WriteQueue::new`. The root inode is overridden via `get_mut(ROOT_INO)` to carry `ipns_name` and `ipns_private_key`. The API client points at `http://127.0.0.1:1` so any accidental detached upload thread fails fast.
- `make_isolated_journal_dir()` — unique dir keyed by `process::id()` plus a monotonic `AtomicU64` counter; never `default_journal_dir()` (T-46-04).
- `CaptureSender(Arc<Mutex<Vec<u8>>>)` implementing `fuser::ReplySender::send` by extending the shared buffer.
- `reply_error_code()` decoding the `fuse_out_header` error field at byte offset 4.

### Task 3: sample handler and builder tests

- `handler_harness_tests::getattr_returns_ok_for_root` — `handle_getattr` on root replies error == 0.
- `handler_harness_tests::flush_returns_ok` — `handle_flush` replies error == 0 (also satisfies the REQ-2 flush-no-op check consumed by Plan 04).
- `journal_helpers::tests::build_upload_journal_entry_round_trips` — with a real keypair, asserts `ciphertext_b64` is non-empty, base64-decodes, differs from plaintext, and `wrapped_key_hex` is non-empty valid hex.
- `journal_helpers::tests::build_mkdir_journal_entry_round_trips` — asserts the entry references the new child and both child and parent IPNS keys are ECIES-wrapped hex.

## Test Results

All four named tests pass when run individually under the RAM constraint:

```text
handler_harness_tests::getattr_returns_ok_for_root ... ok
handler_harness_tests::flush_returns_ok ... ok
journal_helpers::tests::build_upload_journal_entry_round_trips ... ok
journal_helpers::tests::build_mkdir_journal_entry_round_trips ... ok
```

`cargo build -p cipherbox-fuse --features fuse --tests` compiles. No bare `cargo test` was run.

## Deviations from Plan

None of substance. The `CipherBoxFS` struct matched the RESEARCH.md recipe exactly (29 fields, no drift). Two harness conveniences not spelled out in the recipe but consistent with it:

- Root `ipns_private_key` is seeded with `vec![7u8; 32]` rather than zeros so `build_folder_metadata` returns a usable root key for the mkdir builder test.
- The upload builder test drives the new-file path via an absent inode rather than constructing a full `File` inode, keeping the test minimal.

## Threat Model Compliance

- T-46-01: tests reference `ciphertext_b64` only and assert journalled bytes differ from plaintext; no raw plaintext keys constructed.
- T-46-02: builder tests use a real secp256k1 keypair so `wrap_key` ECIES-wraps key material; assertions confirm wrapped fields are present and valid hex, never raw.
- T-46-04: every harness instance uses an isolated per-test journal dir keyed by process id plus a monotonic counter.

## Self-Check: PASTE_BELOW

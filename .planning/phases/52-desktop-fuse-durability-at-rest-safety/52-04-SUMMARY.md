---
phase: 52-desktop-fuse-durability-at-rest-safety
plan: 04
subsystem: fuse/replay
tags: [fuse, replay, timeout, concurrent-mount, name-decryption, sidecar, rust]
dependency_graph:
  requires: [52-01, 52-02, 52-03]
  provides: [replay-sidecar-read, replay-name-decrypt, replay-timeout, concurrent-mount-replay]
  affects:
    - crates/fuse/src/lib.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
tech_stack:
  added: []
  patterns: [tokio-time-timeout-replay, ecies-name-decrypt-passthrough-once, sidecar-hash-verify, rt-spawn-concurrent-replay]
key_files:
  created: []
  modified:
    - crates/fuse/src/lib.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
decisions:
  - "decrypt_journal_name helper: hex-decode + ecies::unwrap_key + from_utf8; ANY failure → warn + passthrough-once (legacy plaintext), never re-persisted"
  - "Sidecar read verifies SHA-256 before re-upload; missing/empty path or hash mismatch → Err (retain via record_failure), never upload corrupt/absent ciphertext"
  - "Empty sidecar_path signals a legacy inline-ciphertext entry (ciphertext is gone after the 52-02 shape break) → retain, never crash"
  - "Timeout multipliers: mkdir NETWORK_TIMEOUT*3 (~30s), upload NETWORK_TIMEOUT*18 (~180s); a timeout is just another Err routed through record_failure"
  - "Replay spawned via rt.spawn before CipherBoxFS construction on BOTH Unix and Windows; key bytes cloned before the Zeroizing move; replay sends no UploadComplete so it is race-free"
metrics:
  completed: "2026-06-20T01:45:00Z"
  tasks_completed: 3
  files_modified: 3
---

# Phase 52 Plan 04: Replay Sidecar Read, Name Decryption, Timeout, Concurrent Mount

One-liner: Rewired `replay_for_vault` / `replay_upload_entry` / `replay_mkdir_entry` to read ciphertext from the `<id>.bin` sidecar (verifying its SHA-256), decrypt the ECIES-encrypted names with passthrough-once legacy compat, bound every replay entry's network ops with `tokio::time::timeout`, and run replay concurrently with mount on both the Unix and Windows mount paths.

## What Was Built

### lib.rs replay (D-04 + D-03)

- `decrypt_journal_name(encrypted_hex, private_key) -> String`: hex-decode + `ecies::unwrap_key` + UTF-8; on any step failing, `log::warn!` once and return the input verbatim (passthrough-once legacy compat). Handles Phase-51's `unwrap_key -> Zeroizing<Vec<u8>>` via `.to_vec()`.
- `replay_upload_entry` signature: `ciphertext_b64: &str` → `sidecar_path: &Path` + `sidecar_sha256: &str`; `filename: &str` → `filename_encrypted_hex: &str`. Step 1 now reads the sidecar, computes SHA-256, compares to `sidecar_sha256` (mismatch → Err/retain), Err on missing/empty path. The filename is decrypted transiently via `decrypt_journal_name`.
- `replay_mkdir_entry`: `name: &str` → `name_encrypted_hex: &str`, decrypted transiently for `FolderEntry.name`.
- `replay_for_vault` destructures the new fields and wraps each entry call in `tokio::time::timeout` (mkdir 3×, upload 18× of `NETWORK_TIMEOUT`); a timeout becomes an `Err` routed through the existing `record_failure` arms (the Plan-52-01 D-06 removal-logging in those arms is preserved). Success/failure log lines no longer interpolate the (now-encrypted) filename — they use the entry id, since the plaintext name only exists transiently inside `replay_upload_entry`.

### Desktop mount paths (D-03 concurrent replay)

Both `apps/desktop/src-tauri/src/fuse/mod.rs` and `.../windows/mod.rs` replaced the blocking `replay_for_vault(...).await` with `rt.spawn(async move { replay_for_vault(...).await })`, cloning every borrowed arg (journal, api, private_key, public_key, root_folder_key, root_ipns_name, coordinator, tee_public_key, tee_key_epoch) into owned values BEFORE the key bytes are moved into `CipherBoxFS` (wrapped in `Zeroizing`). The mount returns immediately; replay runs in the background. Replay sends no `FsEvent::UploadComplete`, so spawning before FS construction is race-free.

## Phase 51 Reconciliation

`replay_mkdir_entry`/`replay_upload_entry` already used Phase-51's `ecies::unwrap_key -> Zeroizing<Vec<u8>>` for the IPNS/folder keys — all those zeroized unwraps are untouched. The new `decrypt_journal_name` uses the same hardened `unwrap_key` and consumes its `Zeroizing` result via `.to_vec()` (a filename is not key material, so no further zeroization is required). The desktop concurrent-spawn clones the key bytes BEFORE the existing `Zeroizing::new(private_key)` move, so the FS still owns the sole zeroize-on-drop copy.

## Test Results

- cipherbox-fuse: 64/64. New/migrated: `replay_entry_timeout` (timeout→Err shape), `decrypt_journal_name_round_trip_and_legacy_compat` (ECIES round-trip + passthrough-once for non-hex and valid-hex-non-ECIES), `replay_reuploads_ciphertext` (migrated to `put_with_sidecar` + sidecar read round-trip + sha256 match), and the 4 replay fixtures migrated to the sidecar shape.
- `cargo check -p cipherbox-desktop --features fuse`: clean (0 errors).

## Known Stubs

None.

## Self-Check: PASSED

- `lib.rs` replay reads the sidecar + verifies the hash, decrypts names with passthrough-once compat, wraps each entry in `tokio::time::timeout`; no `ciphertext_b64` binding remains in production arms.
- Both desktop mount fns `rt.spawn` replay and return without awaiting it.
- 64/64 fuse tests pass; desktop fuse check clean.

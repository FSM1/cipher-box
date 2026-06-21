---
phase: 52-desktop-fuse-durability-at-rest-safety
plan: 02
subsystem: sdk/journal
tags: [sidecar, at-rest-safety, durability, name-encryption, journal, rust]
dependency_graph:
  requires: []
  provides:
    - UploadFile-sidecar-shape
    - filename_encrypted_hex
    - name_encrypted_hex
    - put_with_sidecar
    - sidecar-aware-remove
    - MAX_JOURNAL_PAYLOAD_BYTES
    - JOURNAL_GC_MAX_AGE_DAYS
    - JOURNAL_GC_MAX_SIZE_BYTES
  affects:
    - crates/sdk/src/queue.rs
    - crates/sdk/src/lib.rs
    - crates/sdk/Cargo.toml
tech_stack:
  added: [sha2-dep-sdk, ecies-dev-dep-sdk]
  patterns: [sidecar-stream-write, serde-alias-legacy-compat, serde-default-shape-break-compat]
key_files:
  created: []
  modified:
    - crates/sdk/src/queue.rs
    - crates/sdk/src/lib.rs
    - crates/sdk/Cargo.toml
decisions:
  - "D-04 path = ENCRYPT (not omit): filename has no FileMetadata source so replay cannot reconstruct it"
  - "Legacy compat = passthrough-once via #[serde(alias)] on renamed name fields"
  - "Shape-break compat: sidecar_path + sidecar_sha256 get #[serde(default)] so legacy inline-ciphertext_b64 entries still deserialize (serde ignores the now-unknown ciphertext_b64 key)"
  - "put_with_sidecar reuses put internally after streaming the .bin, so the .json fsync barrier is identical to the existing path"
metrics:
  completed: "2026-06-20T00:30:00Z"
  tasks_completed: 2
  files_modified: 3
---

# Phase 52 Plan 02: Sidecar + Encrypted-Name Journal Shape

One-liner: Replaced the in-JSON `ciphertext_b64` blob with a 0600 `<id>.bin` sidecar (`sidecar_path` + `sidecar_sha256`) and the plaintext `filename`/`name` fields with ECIES-encrypted hex (`filename_encrypted_hex`/`name_encrypted_hex`), added `put_with_sidecar` + sidecar-aware `remove` + the three GC/cap constants, and preserved one-time legacy-entry compat — the on-disk contract every downstream Phase-52 plan builds against.

## What Was Built

### Journal entry shape (queue.rs)

- `JournalOp::UploadFile`: removed `ciphertext_b64`; added `sidecar_path: PathBuf` and `sidecar_sha256: String` (both `#[serde(default)]`); renamed `filename` → `filename_encrypted_hex` with `#[serde(alias = "filename")]`.
- `JournalOp::MkdirPublish`: renamed `name` → `name_encrypted_hex` with `#[serde(alias = "name")]`.
- Three public constants: `MAX_JOURNAL_PAYLOAD_BYTES = 2 GiB`, `JOURNAL_GC_MAX_AGE_DAYS = 30`, `JOURNAL_GC_MAX_SIZE_BYTES = 500 MiB`, re-exported from the crate root (`cipherbox_sdk::MAX_JOURNAL_PAYLOAD_BYTES` resolves).

### Write/remove API (queue.rs)

- `WriteQueue::sidecar_path_for(id) -> PathBuf` resolves `<journal_dir>/<id>.bin`.
- `WriteQueue::put_with_sidecar(entry, ciphertext)`: pre-cleans any stale `.bin`, streams ciphertext to a 0600 sidecar in 1 MiB chunks (never a full `String`), `sync_all`s it, then writes the `.json` via the existing `put` fsync barrier. On `.json` failure it removes the orphaned `.bin` (Pitfall 2 atomic cleanup).
- `WriteQueue::remove(id)`: now deletes BOTH `<id>.json` and `<id>.bin`, idempotent on NotFound (a MkdirPublish entry has no sidecar), parent-dir fsync after.

### Dependencies (Cargo.toml)

- Added `sha2 = { workspace = true }` to `[dependencies]` (sidecar hashing is computed write-side in 52-03; the dep lives here).
- Added `ecies = { workspace = true }` to `[dev-dependencies]` for the round-trip test keypair.

## Legacy Compatibility (shape-break detail)

The plan's passthrough-once strategy covered the `filename`/`name` rename via `#[serde(alias)]`. But removing `ciphertext_b64` entirely is a larger break: a pre-Phase-52 in-flight entry has its ciphertext inline and no sidecar fields. To keep those entries deserializable (passthrough-once replay, never strand in-flight pre-upgrade writes), `sidecar_path` and `sidecar_sha256` carry `#[serde(default)]`. Serde ignores the now-unknown `ciphertext_b64` key (no `deny_unknown_fields`), so a legacy entry loads with an empty `sidecar_path` — the signal the replay side (52-04) uses to drive a one-time legacy replay. Verified by `legacy_plaintext_filename_compat` (raw legacy JSON for both ops) and the pre-existing `legacy_empty_string_ipns_loads_as_none` test (still green with old-shape raw JSON).

## Test Results

- cipherbox-sdk: 54/54 (was 49 after 52-01). New: `legacy_plaintext_filename_compat`, `journal_no_plaintext_filename`, `filename_encryption_round_trips`, `sidecar_ciphertext_not_in_json`, `put_with_sidecar_cleans_stale_bin`.
- `filename_encryption_round_trips` proves `wrap_key` → hex → decode → `unwrap_key` recovers the plaintext (the write-side shape 52-03 produces is decryptable by 52-04). Handles the Phase-51 `unwrap_key -> Zeroizing<Vec<u8>>` return via `.to_vec()`.
- All renamed existing fixtures (`make_upload_entry`, `make_mkdir_entry`, parent-ipns-key round-trips, no-plaintext, replay-ordering) updated to the new shape and green.

## Phase 51 Reconciliation

`cipherbox_crypto::ecies::unwrap_key` now returns `Zeroizing<Vec<u8>>` (Phase 51). The round-trip test consumes it via `.to_vec()` rather than assuming `Vec<u8>`. No Phase 51 hardening touched.

## Expected Cross-Crate State

`cipherbox-fuse` does NOT compile after this plan alone — `journal_helpers.rs`/`lib.rs` still reference `ciphertext_b64`/`filename`. This is the intended interface-first ordering: 52-03 (write side) and 52-04 (replay side) update those consumers to the new shape. The sdk crate compiles and tests clean in isolation.

## Known Stubs

None in the sdk crate. The `sidecar_sha256` is populated write-side by 52-03 and verified replay-side by 52-04.

## Self-Check: PASSED

- `crates/sdk/src/queue.rs` contains `put_with_sidecar`, `sidecar_path_for`, `sidecar_path`, `sidecar_sha256`, `filename_encrypted_hex`, `name_encrypted_hex`, and the three constants.
- `remove` deletes the `.bin` (contains `.bin`).
- Constants resolve as `cipherbox_sdk::*` (re-exported in lib.rs).
- 54/54 sdk tests pass; legacy entries deserialize.

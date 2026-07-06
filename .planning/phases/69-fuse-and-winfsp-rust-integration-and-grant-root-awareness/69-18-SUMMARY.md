---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 18
subsystem: sdk-write-journal
tags: [node-v3, journal, queue, d-07, d-04, replay, seals]
status: complete
requires:
  - "69-15 (seal_published_node, node/v3 seal path)"
  - "69-16 (emit.rs build_child_refs + encode_published_node)"
provides:
  - "node/v3-shaped JournalOp::{UploadFile,MkdirPublish} (crates/sdk::queue)"
  - "fail-closed stale-entry skip for pre-cutover journal entries (D-04)"
affects:
  - "69-09 (fuse journal_helpers constructors + replay reader migrate onto this shape)"
tech-stack:
  added: []
  patterns:
    - "node/v3 dual-plane journal splice (SealedChildRef read plane + WriteChildRef write plane, D-07)"
    - "clean flag-day serde (no compat on reshaped crypto fields; stale entries fail serde and skip)"
key-files:
  created: []
  modified:
    - crates/sdk/src/queue.rs
decisions:
  - "JournalOp carries base64(encode_published_node) + SealedChildRef + WriteChildRef; node-to-node keys live only inside the symmetric read_key_sealed/write_key_sealed seals (NODE-06)"
  - "MkdirPublish keeps child_ipns_name as a routing keeper (child node identity); reshape removed only the hex-ECIES key/name fields"
  - "Parent IPNS signing seed is NOT re-introduced as a user-ECIES field; replay recovers it via list_folder_owned (69-17). Doc-comment marks parent_folder_ipns_name as the field finalized against 69-09's constructor site"
metrics:
  tasks: 2
  files-modified: 1
  sdk-tests: 130
  queue-tests: 31
  completed: 2026-07-06
---

# Phase 69 Plan 18: Reshape JournalOp onto node/v3 Summary

Reshaped `crates/sdk::queue::JournalOp::{UploadFile,MkdirPublish}` off the legacy hex-ECIES-under-user-key key/metadata model onto the node/v3 symmetric-seal model, and added a fail-closed stale-entry skip — `cargo test -p cipherbox-sdk` green (130 tests), workspace RED-until-69-09 by design.

## What was built

### Task 1 — node/v3 reshape (commit `dc8f421a4`)

Both variants had their hex-ECIES-under-user-key node-to-node KEY/metadata fields removed and replaced with node/v3 fields:

- **Removed (UploadFile):** `wrapped_key_hex`, `iv_hex`, `file_ipns_key_hex`, `parent_ipns_key_hex`, `filename_encrypted_hex`.
- **Removed (MkdirPublish):** `child_folder_key_hex`, `child_ipns_key_hex`, `parent_ipns_key_hex`, `name_encrypted_hex`.
- **Added (both):**
  - `child_published_node: String` — base64 of `encode_published_node(..)` (69-16), the sealed child node envelope replay re-publishes.
  - `parent_child_ref: cipherbox_core::node::SealedChildRef` — read plane, keyed by ipnsName, carrying `read_key_sealed`.
  - `parent_write_child_ref: cipherbox_core::node::WriteChildRef` — write plane, keyed by childId UUID, carrying `write_key_sealed` (D-07).
- **Retained keepers (unchanged compat):** D-01/WR-06 sidecar fields (`sidecar_path`/`sidecar_sha256`/`legacy_ciphertext_b64`), routing/timestamp fields (`file_meta_ipns_name`, `parent_folder_ipns_name`, `size`, `created_at_ms`), plus `child_ipns_name` on MkdirPublish.

The node/v3 crypto fields carry **no** `#[serde(alias)]`/`#[serde(default)]` (D-04 clean flag-day). The queue.rs impl match arms (`created_at_ms`, `ordered_for_replay`, `put_with_sidecar`, `migrate_legacy_inline`) were unaffected — they only touch retained keeper/discriminant fields. All inline `#[cfg(test)]` constructors and round-trip/no-plaintext tests were migrated to the node/v3 shape, including D-07 `childId != ipnsName` dual-plane assertions and the retargeted no-plaintext invariant (asserts symmetric base64 seals + base64 PublishedNode, never a raw/plaintext node-to-node key).

### Task 2 — fail-closed stale skip (commit `0c2911ef6`)

Added `stale_legacy_shaped_entry_fails_closed`: a well-formed but legacy hex-ECIES-shaped `.json` (missing the node/v3 crypto fields) fails serde under the reshaped types and is `log::warn!`+skipped by the EXISTING `load_all_for_vault` Err-skip loop — returning empty with no panic, and no new bridge/migration code. A fresh node/v3 entry written alongside still loads, proving the skip is a selective per-entry serde Err.

## Deviations from Plan

### Auto-fixed / documented

**1. [Task 1 grep-AC intent vs Task 2 fixture] `grep -c 'parent_ipns_key_hex|child_folder_key_hex|wrapped_key_hex'` is 4, not 0.**
- **Found during:** AC verification.
- **Reason:** All 4 occurrences are JSON string-literal keys inside the Task 2 `stale_legacy_shaped_entry_fails_closed` fixture — deliberately authoring a pre-cutover on-disk entry to prove the old fields now fail serde (exactly what Task 2's action mandates). The **reshaped struct variants** carry zero such fields (verifiable: the 4 lines are all in the test JSON, lines 1185–1212, never in a struct definition). The Task 1 grep-AC's intent — "the reshaped variants carry no hex-ECIES node-to-node key field" — is satisfied.
- **Files modified:** crates/sdk/src/queue.rs (test fixture only).

**2. Removed obsolete legacy-compat tests.** `legacy_plaintext_filename_compat`, `filename_encryption_round_trips` (+ its `generate_test_keypair` helper), and `journal_no_plaintext_filename` tested the removed hex-ECIES filename mechanism / whole-entry legacy deserialization — both forbidden under D-04. `legacy_empty_string_ipns_loads_as_none` was retargeted to prove the retained `file_meta_ipns_name` keeper still honors its `deser_opt_string` compat within a node/v3-shaped entry.

## Verification

- `cargo test -p cipherbox-sdk` — **130 passed, 0 failed** (queue module: 31 passed).
- `grep -n 'parent_child_ref|parent_write_child_ref|child_published_node'` — present on both variants; `SealedChildRef`/`WriteChildRef` confirm the D-07 dual splice.
- `sidecar_path`/`sidecar_sha256` retained; `migrate_legacy_inline` behavior unchanged.
- `git diff --stat crates/fuse` — **empty**. No new `[dependencies]` in `crates/sdk/Cargo.toml`.
- `cargo check --workspace` — **RED, expected**: only `cipherbox-fuse` (lib) fails, with 13 errors, all JournalOp-shape mismatches (E0026/E0027/E0559 at the `journal_helpers.rs` constructor sites + the `replay.rs` reader). `cipherbox-sdk` and all other crates compile green. This is the sanctioned mid-flip RED that 69-09 (depends_on this plan) resolves atomically.

## Operational note — one-time journal clear (D-04)

On a dev machine that ran a pre-cutover build, `~/.cipherbox/journal` must be cleared **once** at the flag-day. Stale pre-cutover entries are skipped-with-warn (never replayed, never panic), so no data migration is needed — there are no production vaults (D-04). Clearing the directory removes the noise of the skip warnings on first post-cutover mount.

## Deferred / finalized-in-69-09

The parent IPNS **signing** seed replay needs to re-publish the parent record is deliberately NOT carried as a user-ECIES field (it is not a node-to-node key hop). Replay recovers the parent `ipns_private_key` via `list_folder_owned` (69-17) at replay time from `parent_folder_ipns_name`. A doc-comment on `UploadFile::parent_folder_ipns_name` marks that this ONE field is finalized against 69-09's fuse constructor site, should 69-09 prove it must thread the signing seed more directly.

## Self-Check: PASSED

- `crates/sdk/src/queue.rs` — FOUND (modified).
- Commit `dc8f421a4` — FOUND.
- Commit `0c2911ef6` — FOUND.

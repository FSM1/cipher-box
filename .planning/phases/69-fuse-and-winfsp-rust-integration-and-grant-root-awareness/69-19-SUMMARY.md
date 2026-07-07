---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 19
subsystem: recycle-bin
tags: [node-v3, bin, delete, d-07, ecies, legacy-retirement]
requires: ["69-09", "69-13"]
provides: ["BinEntry reshaped to node/v3 restore data", "FUSE delete bin-write on D-07 dual refs"]
affects: ["69-10 (legacy folder-model type deletion)", "69-14 (WinFsp Windows CI)"]
tech-stack:
  added: []
  patterns: ["cipherbox_sdk::build_child_refs at the delete site", "re-splice round-trip restore-sufficiency proof"]
key-files:
  created: []
  modified:
    - crates/core/src/bin.rs
    - crates/fuse/src/write_ops/implementation/delete.rs
    - crates/fuse/src/platform/windows/write_ops.rs
decisions:
  - "BinEntry reshaped as a hard cutover (D-04): no serde alias, no From<FilePointer/FolderEntry> bridge"
  - "child_published_node captured as empty String at delete time (no blocking I/O in the single-thread FUSE callback)"
  - "generation/version_floor pinned to 0 for the delete-time seal, matching the creation-time convention in journal_helpers (inodes carry no read-generation clock)"
  - "ECIES bin-metadata envelope kept verbatim — user-level keeper (NODE-06), not a node-to-node hop"
metrics:
  duration: ~35m
  completed: 2026-07-06
requirements: [SC-04]
status: complete
---

# Phase 69 Plan 19: Recycle-Bin node/v3 Migration (P4a) Summary

Reshaped `BinEntry` off the legacy `FilePointer`/`FolderEntry`/`original_folder_key_encrypted` fields onto node/v3 restore data (`child_published_node` + `child_ref: SealedChildRef` + `write_child_ref: WriteChildRef`), kept the ECIES bin-metadata envelope, and migrated the FUSE + WinFsp delete bin-write to capture the D-07 dual refs — retiring one of the two consumers blocking the 69-10 legacy-type deletion.

## What Changed

### Task 1 — Reshape BinEntry (crates/core/src/bin.rs) — commit `f0605a0d9`

- Replaced `use crate::folder::{FilePointer, FolderEntry};` with `use crate::node::{SealedChildRef, WriteChildRef};`.
- Dropped `file_pointer`, `folder_entry`, and `original_folder_key_encrypted`.
- Added three node/v3 restore fields (camelCase on the wire): `child_published_node: String` (b64 `encode_published_node` keeper), `child_ref: SealedChildRef` (read plane, keyed by ipnsName), `write_child_ref: WriteChildRef` (write plane, D-07, keyed by childId UUID).
- Kept `id`/`item_type`/`name`/`original_parent_ipns_name`/`original_path`/`deleted_at`/`size`/`mime_type`/`content_cid`/`content_size`/`version_cids` and the `VersionCidEntry`/`BinItemType`/`RecycleBinMetadata`/`empty_bin_metadata` surface.
- Kept `encrypt_bin_metadata`/`decrypt_bin_metadata` (ECIES-under-user-key) verbatim.
- Reshaped test samples; added a D-07 non-conflation assertion (`child_id != ipns_name`) and a camelCase serialization test for the new fields.

### Task 2 — FUSE + WinFsp delete bin-write on D-07 dual refs — commit `9b9215aa1`

- `handle_unlink` (File) and `handle_rmdir` (Folder) now capture the parent inode's read/write keys (copied by value), read the child inode's own read/write keys + ipns_name (borrow), and build the D-07 dual ref via `cipherbox_sdk::build_child_refs`: `SealedChildRef.ipns_name` = child ipns_name (read plane, a k51); `WriteChildRef.child_id` = `crate::fs::uuid_from_ino(child_ino)` (write plane, a UUID). Never conflated. `SECURITY-REVIEW: D-07` markers at both capture sites.
- `child_published_node` is captured best-effort as an empty String (the single-thread FUSE callback forbids blocking I/O to re-seal the envelope).
- Both BinEntry constructions reshaped to the node/v3 fields.
- Added `bin_dual_refs_are_restore_sufficient_and_d07_distinct`: re-splices the captured `child_ref` into a fresh parent `Node::Folder{children:[..]}` and `write_child_ref` into its `NodeWriteBody{write_children:[..]}`, seals+encodes the parent, then unseals and asserts (a) the child ipns_name reappears in the recovered parent read children, (b) the child_id reappears in the recovered write-body, (c) `write_child_ref.child_id != child_ref.ipns_name`.
- `metadata.rs::spawn_bin_entry_publish` verified unchanged — it only pushes the entry and ECIES-wraps the blob (no legacy-field references).
- `platform/windows/write_ops.rs` (`#[cfg(feature="winfsp")]`) cleanup-delete bin capture edited to mirror the FUSE change (node/v3 InodeKind fields + build_child_refs + reshaped BinEntry). Best-effort; verified by 69-14's Windows CI.

## Green-Boundary Verification (run in this worktree)

| Check | Result | Evidence |
|-------|--------|----------|
| `cargo check --workspace` (default fuse) | GREEN | `Finished dev profile ... in 34.47s` |
| `cargo test -p cipherbox-core` | GREEN | 87 + 3 + 7 + 1 passed, 0 failed |
| `cargo test -p cipherbox-fuse` | GREEN | 97 + 1 passed, 0 failed (incl. new re-splice + 4 existing delete tests) |
| `grep FilePointer\|FolderEntry crates/core/src/bin.rs` | GONE | empty (replaced by SealedChildRef/WriteChildRef) |
| `grep FilePointer\|FolderEntry\|original_folder_key_encrypted delete.rs` | GONE | empty |
| SECURITY-REVIEW D-07 markers in delete.rs | present | 2 markers |
| ECIES in bin.rs | only in envelope | `ecies::wrap_key`/`unwrap_key` only in encrypt/decrypt_bin_metadata |
| `--features winfsp` | EXPECTED-RED | fails compiling the `windows-future` platform crate (`windows_core::imp::IMarshal` missing on macOS) — never reaches our code; 69-14 Windows CI owns it |

### Final BinEntry shape

```
id, item_type, name, original_parent_ipns_name, original_path,
deleted_at, size, mime_type, content_cid?, content_size?, version_cids?,
child_published_node: String,          // b64 encode_published_node keeper
child_ref: SealedChildRef,             // read plane, keyed by ipnsName
write_child_ref: WriteChildRef,        // write plane, D-07, keyed by childId UUID
```

### How the delete path captures the restore refs

At delete time the FUSE callback copies the parent inode's read/write keys, borrows the child inode's own read/write keys + ipns_name, computes `child_id = uuid_from_ino(child_ino)`, and calls `build_child_refs(child_read, child_write, parent_read, parent_write, child_id, ipns_name, name, kind, 0, 0)` → `(SealedChildRef, WriteChildRef)`. The read plane is sealed under the parent read key (child readKey sealed, keyed by ipnsName); the write plane under the parent write key (child writeKey sealed, keyed by the UUID). The whole `RecycleBinMetadata` blob is then ECIES-wrapped to the user by `spawn_bin_entry_publish`.

### ECIES envelope

Kept verbatim. `encrypt_bin_metadata`/`decrypt_bin_metadata` still ECIES-wrap the whole `RecycleBinMetadata` under the user's secp256k1 key. No node-to-node ECIES hop introduced — the BinEntry contents are the only change. Round-trip test green.

## Deviations from Plan

None — plan executed as written. Rules 1-3 not triggered.

## Deferred / Residual E2E Risks (not overclaiming runtime correctness)

- **No live Rust restore command** exists on this branch (bin is write-only). Restore-sufficiency is proven by the pure re-splice round-trip unit test, NOT by a live FUSE/Tauri restore flow. A future plan wires the restore consumer.
- **`child_published_node` is an empty String** at delete time (no blocking I/O allowed in the FUSE callback). A live restore must re-derive/re-fetch the published node from the live record rather than relying on this keeper. Flagged for the future restore plan.
- **`generation`/`version_floor` pinned to 0** in the delete-time seal, matching the creation-time convention (`journal_helpers` uses 0/0; inodes carry no per-node read-generation clock). If a per-node read-generation clock lands later, the delete capture must read the live generation for restore-sufficiency across a rotated child.
- **Version history not captured** in the file bin entry (`version_cids: None`) — versions now live in the sealed NodeContent (Slice 1); file-versioning restore is a separate E2E flag.
- **WinFsp bin-write is unverified locally** — `--features winfsp` cannot build on macOS (platform crate). The edit mirrors the FUSE change and is best-effort forward-looking; 69-14's `Cargo Check & Test (Windows)` CI is authoritative (D-06). If 69-14 migrates the Windows `InodeKind` to a shape differing from the shared node/v3 one, this block needs reconciliation there.
- **Desktop-e2e deferred** (root-key recovery, phase-63 accepted). The reachable validation gate here is unit tests (bin round-trip + re-splice) + the cross-lang KAT already present in core.

## Threat Register Coverage

| Threat ID | Disposition | How addressed |
|-----------|-------------|---------------|
| T-69-19-01 (conflate childId/ipnsName) | mitigated | build_child_refs; child_id=uuid_from_ino, ipns_name=k51; re-splice test asserts child_id != ipns_name; SECURITY-REVIEW markers |
| T-69-19-02 (key leak / premature zero) | mitigated | parent keys copied by value; child keys borrowed; build_child_refs borrows; no inode-owned buffer zeroed; no key logged |
| T-69-19-03 (dual-format leak) | mitigated | no serde alias, no From bridge; grep gate empty |
| T-69-19-04 (ECIES weakened) | mitigated | envelope kept verbatim; grep shows ECIES only in encrypt/decrypt; round-trip test green |
| T-69-19-SC (cargo installs) | mitigated | zero new crates (fuse already deps cipherbox-sdk + cipherbox-core) |

## Commits

- `f0605a0d9` feat(69-19): reshape BinEntry to node/v3 restore data
- `9b9215aa1` feat(69-19): FUSE delete bin-write on node/v3 D-07 dual refs

## Self-Check: PASSED

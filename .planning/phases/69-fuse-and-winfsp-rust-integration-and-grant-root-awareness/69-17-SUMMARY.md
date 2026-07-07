---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 17
subsystem: sdk
tags: [sdk, listing, node-v3, owned-materialization, d-07, d-09, sc-06]
status: complete
requirements: [SC-01, SC-06]
dependency_graph:
  requires:
    - "69-06 (resolve_published_node gate-first resolver)"
    - "69-15 (seal_published_node dual-body seal, unseal_child_write_key)"
    - "69-16 (emit.rs build_child_refs / FolderEmission redacting Debug)"
  provides:
    - "crates/sdk::listing::list_folder_owned (pub) — gated write-owner tree materialization"
    - "crates/sdk::listing::resolve_owned_child (pub(crate)) — per-child owned recovery"
    - "crates/sdk::listing::ResolvedOwnedChild (pub) — {read_key, write_key, ipns_private_key} carrier"
  affects:
    - "69-09 P1b FUSE populate_folder (consumes list_folder_owned to build InodeKind)"
tech_stack:
  added: []
  patterns:
    - "Owned twin of the read-only resolve_child/list_folder gated chain — reuses the SAME resolve_published_node gate"
    - "D-07 dual-keying paired by published.id == WriteChildRef.child_id (never ipns_name)"
    - "D-09 terminal-owner zeroization: borrowed parent keys never zeroed; recovered keys returned raw in Zeroizing; redacting Debug"
key_files:
  created: []
  modified:
    - crates/sdk/src/listing.rs
    - crates/sdk/src/lib.rs
decisions:
  - "resolve_owned_child stays pub(crate); list_folder_owned is the only new pub read entrypoint (SC#6 — no new public raw-resolve surface)"
  - "list_folder_owned takes no on_updated callback — owned key material must never fan out to a log/event; it is the mount's internal materialization"
  - "Write-body plaintext scratch (carrying ipns_private_key) wrapped in Zeroizing before decode so it is wiped after the key is moved out"
metrics:
  duration_minutes: 35
  tasks_completed: 2
  files_modified: 2
  completed_date: 2026-07-06
---

# Phase 69 Plan 17: Gated Write-Owner Tree Materialization (P1a-2) Summary

Adds `list_folder_owned` (+ `resolve_owned_child` + `ResolvedOwnedChild`) to `crates/sdk::listing` — the gated write-plane tree-materialization API that recovers, per child of an existing tree, its `{read_key, write_key, ipns_private_key}` through the SAME `NodeFetcher` + `RotationHighWater::enforce_resolved` gate `list_folder` uses. This is the owned read path the P1b FUSE cutover (69-09) `populate_folder` consumes to build `InodeKind`. Additive: `crates/fuse` untouched, no new Cargo dependency.

## What Was Built

### Task 1 — `ResolvedOwnedChild` + `resolve_owned_child` (commit `54e7190f5`)

- `ResolvedOwnedChild { child: ResolvedChild, read_key: Zeroizing<[u8;32]>, write_key: Zeroizing<[u8;32]>, ipns_private_key: Zeroizing<Vec<u8>> }` with a hand-written `Debug` that redacts every key field to `[REDACTED]` (mirrors `emit::FolderEmission`).
- `pub(crate) async fn resolve_owned_child`: gate-first resolve of the child via the shared `resolve_published_node` (using the PARENT-mirror `child_ref.generation`/`.version_floor`, M1 downgrade defense), then:
  - D-07 pairing: selects the `WriteChildRef` whose `child_id == published.id` — fails closed (`Err`) if none matches. `ipns_name` is never the pairing key.
  - Recovers `read_key` (`unseal_child_read_key` under `parent_read_key`) and `write_key` (`unseal_child_write_key` under `parent_write_key` — the write-plane half `resolve_child` discards), both at the parent-mirror generation, each copied into a `Zeroizing` fixed buffer with the intermediate wiped.
  - Recovers the child's own `ipns_private_key` via `unseal_node(published.write_sealed, write_key, ..., published.generation)` → `decode_write_body`, moved into `Zeroizing<Vec<u8>>`.
  - Fail-closed on: missing D-07 pair, `write_sealed == None`, non-32-byte unsealed key, or any AEAD auth-tag failure (never panics/unwraps).

### Task 2 — `list_folder_owned` (commit `0bcb99160`)

- `pub async fn list_folder_owned`: parallels `list_folder` (own-generation floor gate → `resolve_published_node` → read-body unseal → children), but ADDITIONALLY unseals the parent WRITE-body (`folder_write_key`, requiring `write_sealed` Some) → `decode_write_body` → `write_children: Vec<WriteChildRef>` so the D-07 pairing is possible, then resolves each child through `resolve_owned_child`.
- Requires the write body — an owned folder with no `write_sealed` fails closed. Takes no `on_updated` callback (keys never fan out).
- Re-exported from `lib.rs`; `resolve_published_node` stays `pub(crate)` (SC#6).

## Tests (all green — 8 new, 132 total in `cipherbox-sdk`)

- `resolve_owned_child_recovers_minted_read_write_ipns_keys` — recovered keys byte-equal what `emit.rs` minted (via `build_file_emission` + `build_child_refs`).
- `resolve_owned_child_pairs_by_published_id_never_by_ipns_name` — an ipns_name-keyed `WriteChildRef` fails closed; the UUID-keyed one pairs.
- `resolve_owned_child_missing_write_pair_fails_closed` — empty write-children → `Err`.
- `resolve_owned_child_write_sealed_none_fails_closed` — absent write body → `Err`.
- `resolve_owned_child_leaves_parent_key_buffers_unchanged` — D-09 terminal-owner.
- `list_folder_owned_two_level_round_trip_recovers_minted_keys` — a file child + subfolder child emitted, re-sealed at the parent identity, fed through `list_folder_owned`, recovers each child's read/write/ipns keys == minted.
- `list_folder_owned_high_water_floor_gate_rejects_regressed_child` — a pre-seeded floor above a child's parent-mirror generation fails the whole owned listing closed with `Gated`.
- `list_folder_owned_leaves_parent_key_buffers_unchanged` — D-09 terminal-owner.

## Green Boundary (verified in worktree)

- `cargo test -p cipherbox-sdk` — 132 passed, 0 failed.
- `cargo check --workspace` — green (additive; `crates/fuse` untouched).
- `git diff --stat crates/fuse` — empty.
- `crates/sdk/Cargo.toml` — no new `[dependencies]`.
- `resolve_published_node` — still `pub(crate)`; `list_folder_owned` is the only new `pub` read entrypoint.
- clippy: zero new warnings from this plan (the sole `cipherbox-sdk` warning is the pre-existing `build_child_refs` too-many-arguments in `emit.rs`).

## Deviations from Plan

None — plan executed exactly as written. No auto-fixes were required.

### Tooling note (not a code deviation)

`rustfmt crates/sdk/src/lib.rs` follows the crate's `mod` declarations and reformatted the entire `crates/sdk` (pre-existing formatting drift vs rustfmt 1.8.0 in `client.rs`, `queue.rs`, `registry.rs`, `rotation/engine.rs`, `rotation/high_water.rs`, `state.rs`, `sync.rs`). Those out-of-scope reformats were reverted with `git checkout --`; only `listing.rs` and `lib.rs` were kept. No pre-existing code in `listing.rs` was reformatted (only the two import lines I changed).

## Known Stubs

None.

## Self-Check: PASSED

- `crates/sdk/src/listing.rs` — FOUND (modified, contains `ResolvedOwnedChild`, `resolve_owned_child`, `list_folder_owned`).
- `crates/sdk/src/lib.rs` — FOUND (re-exports `list_folder_owned` + `ResolvedOwnedChild`).
- Commit `54e7190f5` (Task 1) — FOUND.
- Commit `0bcb99160` (Task 2) — FOUND.

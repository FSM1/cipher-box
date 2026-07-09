---
created: 2026-07-09T09:59:49.407Z
title: Deep scope-exit rotation refreshes only the grant-root inode's in-memory key, not intermediate parents
area: desktop-fuse-rotation
severity: medium
source: Phase 70.1 D-16 debug note limitation (.planning/debug/scope-exit-part-a-fail.md "Known limitation"); related to [[2026-07-08-winfsp-d15d-gate-ordering-parity]]
files:
  - crates/fuse/src/write_ops/grant_scope.rs
  - crates/sdk/src/rotation/engine.rs
  - packages/sdk-core/src/rotation/engine.ts
  - crates/fuse/src/write_ops/implementation/delete.rs
---

## Problem

Phase 70.1's revocation-bypass fix ("Fix A", `grant_scope.rs`
`refresh_grant_root_read_key`) copies the rotation's new read key back into the
in-memory grant-root inode so the delete's local **relink** reseals under the
NEW key (otherwise a revoked reader could still derive child keys from a relink
sealed under the stale key).

But `cipherbox_sdk::RotateReadResult` surfaces only the **grant-root node's**
new key — the rotation engine (`crates/sdk/src/rotation/engine.rs`,
`packages/sdk-core/src/rotation/engine.ts`) walks and re-keys the whole subtree
but returns a single result for the root. So `refresh_grant_root_read_key` can
only refresh the grant-root inode.

Consequence, by scope-exit depth:

- **Shallow** (grant-root IS the deleted node's direct parent): the only inode
  that relinks is the grant-root, whose key was refreshed → correct. This is
  exactly what the Phase 70.1 D-16 acceptance leg tests (green on all 3
  platforms).
- **Deep** (deleted node is >1 level below the grant root): the rotation
  re-keys the subtree, but the **intermediate parent inodes** in the FUSE
  `InodeTable` still hold their PRE-rotation read keys in memory. If one of them
  performs its own post-rotation relink, it reseals under a stale in-memory key
  — a latent revocation-bypass on the deep path.

The shallow path is covered and tested; the deep path is uncovered and, until
now, was only documented in the D-16 debug note (not tracked as a forward item).

## Solution

1. Have the rotation engine surface **every rotated node's** new read key — e.g.
   `RotateReadResult` carries a per-`nodeId` key map, or the engine invokes a
   per-node callback as it commits each rotation. Mirror the change in both the
   Rust engine and the TS twin (parity).
2. Generalize `refresh_grant_root_read_key` to walk **all** rotated nodes and
   refresh each corresponding intermediate inode's in-memory read key, so any
   subsequent relink reseals under the new key.

## Acceptance

- A deep covered scope-exit delete (e.g. grant-root → folder → subfolder →
  deleted file) rotates the subtree AND refreshes every rotated inode's
  in-memory read key.
- A desktop-e2e leg asserts a revoked recipient cannot decrypt any rotated
  intermediate node after the deep scope-exit (not just the grant-root).
- Shallow-path behavior and the D-16 acceptance leg remain unchanged/green.

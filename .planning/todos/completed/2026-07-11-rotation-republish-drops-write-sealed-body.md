---
created: 2026-07-11T00:00:00.000Z
title: Read-key rotation republishes rotated nodes with write_sealed=None — breaks owned-walks + replay signing-seed recovery
area: desktop-fuse-rotation
severity: high
source: Found while root-causing the macOS Part-D overwrite-rename failure (2026-07-11). Separate, orthogonal bug — NOT the Part-D cause (that was the stale-refresh clobber, fixed inline). Prototyped a fix (607→0 "no write_sealed body") and reverted to keep the Part-D fix minimal.
files:
  - crates/fuse/src/write_ops/rotation_deps.rs
  - crates/sdk/src/rotation/engine.rs
  - crates/sdk/src/listing.rs
  - crates/fuse/src/replay.rs
resolves_phase: null
---

## Problem

A scope-exit read-key rotation republishes every rotated node with
`write_sealed: None` — the engine (`engine.rs::seal_and_publish`, ~2 sites)
never populates it (read-key rotation is a read-plane op), and the FUSE
adapter (`rotation_deps.rs`, documented as a Phase-72 deferral) doesn't
reconstruct it either. Consequences:

- Any `list_folder_owned` over a folder containing a rotated node fails closed
  ("owned child … has no write_sealed body"). On the OWNER's mount this makes
  the background root/folder metadata refresh permanently fail for any
  shared-folder subtree that has been scope-exit-rotated (observed 607×
  "no write_sealed body" per run on macOS; folder-refresh WARN, non-fatal but
  the folder listing never refreshes).
- On a fresh mount, `replay.rs` cannot recover the node's signing seed (the
  seed lives in the write body) — a DURABILITY hole: after a rotation +
  remount the owner may lose the ability to sign updates to the rotated
  subtree.

## Fix (prototyped, verified, reverted)

Preserve the write plane on the rotation republish: in
`ApiClientTransport::publish` (rotation_deps.rs), when `node.write_sealed` is
`None`, reconstruct it from the mount's in-memory InodeTable (the node's own
stable write key + `ipns_private_key` + child `WriteChildRef`s rebuilt from the
child inodes — child write keys are read-key-rotation-independent) and re-seal
`NodeWriteBody` under the node's write key at the node's NEW generation via
`seal_node` (which shares the ROLE_BODY AAD with `seal_published_node`'s
write-body path). Round-trips: unseal under the write key at the new generation
recovers the write body + child refs. Fails-open to `None` for a node not
locally materialized (matches the existing signing-seed fail-closed lookup).
Verified locally: the "no write_sealed body" flood drops 607→0.

Write-key *rotation* remains a separate Phase-72 concern; this only re-seals the
UNCHANGED write plane at the bumped generation. Add unit tests for the
reconstruction round-trip + the None fallback (were written in the prototype).

## Resolution

Resolved by Phase 80 (rotation-write-plane-and-re-mint-durability), shipped on branch `feat/rotation-write-plane-and-re-mint-durability`. D-01/D-02/D-03/D-04 implemented and verified (SDK-E2E 106/106, fuse 130).

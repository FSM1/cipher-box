---
created: 2026-07-11T00:00:00.000Z
title: Dirty-resume repaired descendants are not surfaced in the returned rotatedNodes map (Rust return-discard + TS missing-insert)
area: sdk-core-rotation
severity: medium
source: Phase 74 PR #607 review — greptile P1 (engine.rs:2003), coderabbit Major + greptile P1 (engine.ts:2051)
files:
  - crates/sdk/src/rotation/engine.rs
  - packages/sdk-core/src/rotation/engine.ts
resolves_phase: null
---

## Problem

Phase 74 (74-01/74-02) made `RotateReadResult`/`rotateReadFromNode` carry a
per-node `rotatedNodes`/`rotated_nodes` map so the FUSE/WinFsp caller can
refresh every rotated inode's cached read key (the deliverable for
`2026-07-09-deep-scope-exit-rotation-refreshes-only-grant-root-inode-key.md`).
On the dirty-RESUME path (a crash-recovery run where a descendant was already
rotated by a lost prior run and is repaired from the ECIES checkpoint) that map
is NOT fully surfaced to the caller. The two engines fail differently but with
the same net effect:

- Rust (`crates/sdk/src/rotation/engine.rs` ~:2003): `repair_dirty_node`
  correctly `rotated_nodes.insert(...)`s each recovered descendant key, BUT the
  terminal return is `Ok(fresh_root.map(|root| RotateReadResult { ..,
  rotated_nodes }))`. On a dirty resume where the root was already committed,
  `fresh_root` is `None`, so the whole `Option` is `None` and the populated
  `rotated_nodes` map is discarded. The FUSE caller only refreshes inode keys
  for `Some(result)`, so repaired descendants keep stale in-memory read keys.

- TS (`packages/sdk-core/src/rotation/engine.ts` ~:2051): the reverse — the
  dirty-resume return path DOES carry `rotatedNodes` (via `dirtyResumeResult`,
  74-02 SC1), but `repairDirtyNode` (~:1793) never inserts the recovered
  `readKeyPrime` into `rotatedNodes` at all. It reseals the parent mirror,
  decrements pending, seeds its own `ParentTrackingState`, and enqueues
  children — but the recovered node's own key is omitted. Dirty-resume callers
  therefore receive a map missing every repaired descendant.

## Impact

After a crash-resumed scope-exit rotation, repaired descendant inodes keep
their PRE-rotation cached read keys. Their content is now sealed under the
recovered (new) key, so reads mis-decrypt / appear unreadable until a fresh
resolve, and any post-rotation relink under the stale in-memory key is a latent
revocation-bypass (the exact hazard the deep-scope-refresh work targets). Only
reachable on the dirty-RESUME (crash-recovery) branch; the happy path is
correct.

## Fix

Achieve Rust/TS parity so BOTH engines surface every repaired descendant on the
dirty-resume path:

- TS: in `repairDirtyNode`, after resolving the node's current record, insert
  into the shared `rotatedNodes` map keyed by `item.childRef.ipnsName` —
  `{ ipnsName, readKey: new Uint8Array(readKeyPrime) (defensive copy — see
  2026-07-11-ts-rotatednodes-defensive-copy-parity), generation:
  childPub.generation, sequenceNumber: resolved.sequenceNumber }`. Mirror the
  Rust `repair_dirty_node` insert block.
- Rust: surface `rotated_nodes` on the dirty-resume-with-dirty-frontier return
  even when `fresh_root` is `None` (introduce a dirty-resume result analogous
  to the TS `dirtyResumeResult`, or return the map unconditionally when the BFS
  repaired at least one node). Preserve the "root has no fresh key to hand
  back" semantics for the root entry itself.

Do NOT guess-fix live rotation crypto — this needs a plan + a dirty-resume
regression test in each engine.

## Acceptance

- A dirty-RESUME scope-exit rotation returns a `rotatedNodes`/`rotated_nodes`
  map containing every repaired descendant (correct `ipnsName`, non-zero
  recovered key, generation, sequence number).
- TS and Rust engines agree (parity) on the dirty-resume return contents.
- New dirty-resume regression test in each engine asserting the FUSE caller
  can refresh every repaired inode's cached read key after crash recovery.

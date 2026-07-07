---
created: 2026-07-07T00:00:00.000Z
title: SDK anti-rollback floor store is non-atomic under concurrency and blocks the async executor
area: sdk-rotation-durability
severity: low
source: Phase 69 ship review (CodeRabbit crates/sdk); verified against live code 2026-07-07
files:
  - crates/sdk/src/rotation/high_water.rs
  - crates/sdk/src/floor_store.rs
---

## Problem

Two related concurrency observations in the durable anti-rollback floor path (net-new in Phase 69,
a faithful Rust port of the shipped TS `packages/sdk/src/state/rotation-high-water.ts`):

1. **`bump_floor` (high_water.rs) is a non-atomic read/compare/write.** Two concurrent
   `bump_floor(node, hi)` / `bump_floor(node, lo)` for the same `node_id` can interleave
   read→compare→`put` such that the lower value wins, regressing the monotonic-max floor.
   `RotationHighWater` derives `Clone` and is cloned for owned prefetch, so cloned instances
   share the same backing store.
2. **`JsonSidecarFloorStore` get/put (floor_store.rs) is a race-prone whole-map read-modify-write
   and does blocking filesystem I/O directly inside `async fn`.** Concurrent `put`s on *different*
   `node_id`s can lost-update each other (both load the same map, each inserts its key, the second
   write clobbers the first). The sync `read`/`write`/`rename`/`fsync` also block the tokio executor.

## Why it is deferred (not a Phase 69 blocker)

- The design is an explicit **single-daemon** model (module doc: "the FUSE single-daemon model
  means this file is small … read-modify-write on every access is cheap"). Under a single daemon
  processing resolves/rotation sequentially, concurrent same-`node_id` bumps do not occur.
- The monotonic-max invariant **self-heals**: even if a floor briefly regressed, the next resolve
  of the real (higher-seq) record bumps it back; the security property (reject a *stale* record) is
  re-established on the next observation. The exploit window requires a concurrent malicious low
  record to win a specific interleave — not reachable in the single-daemon model.
- This mirrors the **already-shipped TS twin** byte-for-byte; it is a property of the ported design,
  not a Rust-specific regression. A fix should be applied on BOTH sides (cross-language parity) or
  neither.

## Fix (when hardening concurrency / moving off single-daemon)

1. Add per-`node_id` synchronization (or a compare-and-swap `HighWaterStore` API) so
   read→compare→`put` cannot interleave; apply the same guard in `enforce_resolved`'s bump path.
2. In `JsonSidecarFloorStore`, take a shared async lock (e.g. `tokio::sync::Mutex`) around
   `load_map` + `write_map_atomic` so concurrent `put`s on different node_ids serialize, and move
   the blocking fs work to `spawn_blocking`.
3. Apply the equivalent change to the TS `HighWaterStore` implementation to keep the twins in sync.

## Acceptance

Concurrent `bump`/`put` on the same and different node_ids preserve the monotonic-max floor and the
full node→floor map with no lost updates, and the floor store performs no blocking I/O on the async
executor. The TS and Rust implementations remain behaviorally equivalent.

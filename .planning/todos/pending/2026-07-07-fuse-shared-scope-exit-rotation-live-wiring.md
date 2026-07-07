---
created: 2026-07-07T00:00:00.000Z
title: FUSE shared-scope-exit read-key rotation is fail-closed, not live-wired
area: desktop-fuse-rotation
severity: medium
source: Phase 69 SC#3 (69-VERIFICATION.md notes); matches known ROT-07 live-wiring gap (69-13-SUMMARY); verified against live code 2026-07-07
files:
  - crates/fuse/src/write_ops/grant_scope.rs
  - crates/fuse/src/write_ops/implementation/delete.rs
  - crates/fuse/src/write_ops/implementation/rename.rs
  - crates/sdk/src/rotation/engine.rs
---

## Problem

Phase 69 SC#3 (grant-root awareness) delivered the scope-exit **gate**: on a
shared-scope-exit delete/move, `grant_scope::gate_scope_exit` correctly decides
`NoRotation` (pure relink, zero publishes) for private deletes with no covering
grant, and `rotate` for a covered scope-exit. The gate is wired fail-CLOSED into
`delete.rs` / `rename.rs`.

However, the `rotate` path (`rotate_read_on_scope_exit` → SDK
`rotate_read_from_node`) currently returns `Err → EIO` because **no production
`cipherbox_sdk::rotation::engine::RotationDeps` implementor exists** — only the
engine's in-test `FakeDeps`. So a covered scope-exit delete/move *refuses to
complete* rather than silently completing without rotating.

This is security-safe (fail-closed prevents the revocation-bypass the gate exists
to close, and private deletes never reach this seam and work fully), but the
*live rotation execution* half of SC#3 is deferred. This is the same live-wiring
shape as the known ROT-07 gap flagged in `69-13-SUMMARY`.

## Fix

1. Implement a production `RotationDeps` for the FUSE/desktop client (real IPNS
   publish + node fetch/seal via the SDK adapter, not `FakeDeps`).
2. Wire it into `rotate_read_on_scope_exit` so a covered scope-exit delete/move
   performs `rotate_read_from_node` and completes instead of returning `EIO`.
3. Add a FUSE-level test (or desktop-e2e leg) exercising a covered scope-exit that
   asserts exactly one read-key rotation publish and a successful delete/move.

## Acceptance

A shared-scope-exit delete/move on a node with an active covering grant completes
successfully (no `EIO`), publishes exactly one `rotate_read_from_node` rotation,
and a revoked recipient can no longer read the rotated subtree. Private deletes
remain pure relinks with zero rotation publishes.

---
created: 2026-07-07T00:00:00.000Z
title: FUSE shared-scope-exit read-key rotation is fail-closed, not live-wired
area: desktop-fuse-rotation
severity: medium
resolves_phase: "70.1"
source: Phase 69 SC#3 (69-VERIFICATION.md notes); matches known ROT-07 live-wiring gap (69-13-SUMMARY); verified against live code 2026-07-07
folded: 2026-07-08 into Phase 70.1 SC#8 / D-14..D-17 (depends on the Rust engine.rs soundness fixes D-11..D-13 landing first)
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

## Gate-correctness findings to resolve WITH the live-wiring (CodeRabbit, Phase 69 ship review)

The scope-exit **gate** (`run_scope_exit_gate` → `gate_scope_exit`) is already LIVE on every
delete (`delete.rs:200,399`) and rename (`rename.rs:102`), but the rotation it can trigger EIOs
(above). These gate-correctness issues are latent today (a wrong "NoRotation" just skips a
rotation that would EIO anyway) but become live revocation-bypass vectors the moment rotation is
wired — so they MUST be fixed as part of this live-wiring, with desktop-e2e coverage:

- **[CRITICAL] `grant_scope.rs` `SentSharesCache::empty()` fail-open** — an empty cache is treated
  as "no shares → private → NoRotation", but empty may just mean "not yet refreshed / refresh
  failed". A shared-scope exit then proceeds without rotating. Fix requires tracking cache
  authoritativeness (freshness flag) and returning `Err` (→ EIO) until authoritative. NOTE: naive
  "empty → Err" would break ALL private deletes when the cache is legitimately empty — needs the
  authoritative-vs-stale distinction, hence deferred to a deliberate change with E2E.
- **[MAJOR] `grant_scope.rs` ancestor walk fails open** — the ancestry chain can stop early on a
  missing inode or a cycle and be treated as "no grant found". Require a complete path to
  `ROOT_INO`; on missing inode / cycle, treat the scope as unsafe (fail closed), not `NoRotation`.
- **[MAJOR] `grant_scope.rs` poisoned-lock panic** — `fs.sent_shares.read().expect("… poisoned")`
  panics the fuser callback thread; return `Err(())` (→ EIO) instead, consistent with the
  surrounding `Result<(), ()>` flow.
- **[MAJOR] `delete.rs`/`rename.rs` scope-exit gate ordering** — build D-07 bin child refs only
  AFTER `run_scope_exit_gate` (unlink/rmdir can rotate the matched grant-root read key before bin
  sealing); and gate the OVERWRITTEN destination in rename (`dest_ino`), not just the source, and
  run the `ENOTDIR`/`EISDIR`/`ENOTEMPTY` replacement checks before gating so a failed rename can't
  rotate keys.

## Acceptance

A shared-scope-exit delete/move on a node with an active covering grant completes
successfully (no `EIO`), publishes exactly one `rotate_read_from_node` rotation,
and a revoked recipient can no longer read the rotated subtree. Private deletes
remain pure relinks with zero rotation publishes. The gate fails CLOSED (EIO, never
a silent no-rotation) on a non-authoritative sent-shares cache, an incomplete
ancestry walk, or a poisoned lock; rename gates both source and overwritten
destination; bin child refs are built with post-gate key material.

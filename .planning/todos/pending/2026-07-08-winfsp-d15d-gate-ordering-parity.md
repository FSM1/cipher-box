---
created: 2026-07-08T00:00:00.000Z
title: WinFsp path lacks the D-15d scope-exit gate-ordering fix (parity gap)
area: desktop-fuse-rotation
severity: medium
source: Phase 70.1 plan 12 SUMMARY + plan 13 static review; flagged during execution 2026-07-08
files:
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/write_ops/implementation/delete.rs
  - crates/fuse/src/write_ops/implementation/rename.rs
---

## Problem

Phase 70.1 plan 12 (D-15d) fixed scope-exit gate ordering in the FUSE
(`fuser`, macOS/Linux) delete/rename path: build the D-07 bin child refs only
AFTER `run_scope_exit_gate`, gate the OVERWRITTEN `dest_ino` in rename, and run
the `ENOTDIR`/`EISDIR`/`ENOTEMPTY` replacement checks before gating so a failed
rename cannot rotate keys.

`crates/fuse/src/platform/windows/write_ops.rs` contains an independent
DUPLICATE of the same gate-ordering pattern and did NOT receive the D-15d fix.
So on Windows/WinFsp the old ordering persists — the same latent
revocation-bypass / bin-ref-uses-stale-key vectors D-15d closes on the FUSE
path remain open on the WinFsp path. `winfsp-sys` cannot build on macOS
(requires Windows COM APIs), so this is verifiable only in the Windows CI leg.

## Fix

1. Port the D-15d reordering into `platform/windows/write_ops.rs`: bin refs
   built post-gate; rename gates the overwritten destination; replacement
   validity checks (ENOTDIR/EISDIR/ENOTEMPTY equivalents) run before gating.
2. Factor the shared gate-ordering logic if practical so FUSE and WinFsp cannot
   drift again.
3. Verify via the `Cargo Check & Test (Windows)` CI job (budget a CI round-trip).

## Acceptance

On WinFsp: a covered shared-scope-exit delete/move rotates exactly once with
bin refs sealed under post-rotation key material; a failed rename
(ENOTDIR/EISDIR/ENOTEMPTY) publishes zero rotations; the overwritten
destination of a rename is gated. Behavior matches the FUSE path (D-15d).

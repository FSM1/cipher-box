---
created: 2026-07-08T00:00:00.000Z
title: WinFsp RENAME path lacks D-15d dest-gating + coalescing parity
area: desktop-fuse-rotation
severity: medium
source: Phase 70.1 plan 12 SUMMARY + plan 13 static review; NARROWED 2026-07-09 after the delete-path coalescing port (70.1-13a)
files:
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/write_ops/implementation/rename.rs
---

## Status (2026-07-09) — delete path CLOSED, rename path REMAINS

The DELETE half of this parity gap is now closed (commit porting 70.1-13a
coalescing to WinFsp):

- **Coalescing parity (delete):** WinFsp `handle_set_delete` now uses the SHARED
  `crate::write_ops::grant_scope::run_scope_exit_gate_coalesced` (the exact
  function the fuser `delete.rs` handlers use), and `handle_cleanup` consumes
  the `coalesced_scope_exit_relink_suppressed` hand-off to SKIP its plain relink.
  A shallow covered scope-exit delete now publishes the grant-root exactly ONCE
  (Windows CI `+1` count, matching Linux). Verified by Windows CI run (pending
  dispatch of the re-run).
- **D-15d delete bin-ref ordering:** already satisfied on WinFsp by construction —
  the rotation runs in `set_delete`, the D-07 bin refs are built later in
  `handle_cleanup`, so bin refs are inherently sealed under post-rotation key
  material (Fix A refreshes the grant-root inode key in `set_delete`). Windows CI
  confirmed "key rotated PASS, Bob cut off PASS".

Shared logic was FACTORED into `run_scope_exit_gate_coalesced` so the fuser and
WinFsp delete paths cannot drift again.

## Remaining gap — WinFsp RENAME (not addressed here; out of scope for the delete-leg fix)

`crates/fuse/src/platform/windows/write_ops.rs` `handle_rename`:

1. **Overwritten dest not gated (D-15d):** the source scope-exit is gated
   (`run_scope_exit_gate(&mut fs, source_ino)`, ~line 1116), but the OVERWRITTEN
   destination `dest_ino` is removed (~line 1147-1148) WITHOUT a scope-exit gate.
   The fuser `rename.rs` gates the dest (rename.rs dest gate). So deleting a
   shared node via overwrite-rename on WinFsp does not rotate — a revocation
   bypass. Port `run_scope_exit_gate`/coalesced gate for `dest_ino`.
2. **Replacement-validity vs gating order (D-15d):** on WinFsp the source gate
   runs BEFORE the dest replacement validation (ENOTEMPTY-equivalent etc.), so a
   doomed overwrite-rename can rotate the source before failing. The fuser path
   runs POSIX validation before gating. Reorder to match.
3. **Coalescing parity (rename):** optional — rename is a two-parent relink, not
   a single-authoritative-publish scenario like delete; evaluate whether the
   override coalescing applies before porting.

## Acceptance (remaining)

On WinFsp `handle_rename`: the overwritten destination of a rename is gated
(rotates when it roots a covering grant); a rename that fails replacement
validation publishes zero rotations. Verify via the `Cargo Check & Test
(Windows)` CI job. The DELETE-path coalescing + D-15d ordering is already done.

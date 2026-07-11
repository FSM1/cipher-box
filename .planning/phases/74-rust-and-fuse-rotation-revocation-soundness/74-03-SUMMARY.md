---
phase: 74-rust-and-fuse-rotation-revocation-soundness
plan: 03
subsystem: fuse
tags: [rust, fuse, rotation-engine, read-key-refresh, revocation, tdd]

# Dependency graph
requires:
  - phase: 74-rust-and-fuse-rotation-revocation-soundness
    provides: "RotatedNodeKey struct + RotateReadResult.rotated_nodes: HashMap<String, RotatedNodeKey> keyed by ipns_name (74-01)"
provides:
  - "refresh_rotated_inode_read_keys(inodes, result) — generalized multi-node FUSE inode read_key refresh"
  - "cipherbox_sdk::rotation::RotatedNodeKey re-exported (was engine.rs-internal)"
affects: [74-desktop-e2e-deep-scope-exit-verification]

# Tech tracking
tech-stack:
  added: []
  patterns: ["Loop over RotateReadResult.rotated_nodes with no early return, matching Root|Folder|File inode kinds by ipns_name"]

key-files:
  created: []
  modified:
    - crates/fuse/src/write_ops/grant_scope.rs
    - crates/sdk/src/rotation/mod.rs

key-decisions:
  - "RotatedNodeKey exported from cipherbox_sdk::rotation (mod.rs re-export) — was previously only pub within engine.rs, not reachable from crates/fuse without this addition (Rule 3, blocking-issue auto-fix)"
  - "File inode arm added to the match (Root | Folder | File) per the plan's explicit low-cost-fix bundling — files ARE rotated via mint_file_key_on_rotate/CRIT-1 and were silently skipped before"

requirements-completed: [SC1]

coverage:
  - id: D1
    description: "After a scope-exit rotation, every rotated node's matching FUSE inode (Root/Folder/File) has its in-memory read_key refreshed by ipns_name, not only the grant root"
    requirement: SC1
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/grant_scope.rs#write_ops::grant_scope::refresh_rotated_inode_read_keys_refreshes_intermediate_and_file_inodes"
        status: pass
    human_judgment: false
  - id: D2
    description: "No regression to the existing grant_scope.rs test suite (ancestor walk, gate_scope_exit spy tests, D-07/D-15a/b/c fail-closed tests) after the generalization"
    verification:
      - kind: unit
        ref: "cargo test -p cipherbox-fuse write_ops::grant_scope:: (17/17 passing)"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-11
status: complete
---

# Phase 74 Plan 03: Deep Scope-Exit Inode Refresh (FUSE) Summary

**Generalized `refresh_grant_root_read_key` into `refresh_rotated_inode_read_keys`, looping over `RotateReadResult.rotated_nodes` (74-01) to refresh every rotated node's in-memory FUSE inode read_key — Root, Folder, AND File — not only the grant root, closing the deep-path revocation-bypass class.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-11
- **Tasks:** 2 (TDD: RED + GREEN)
- **Files modified:** 2 (`crates/fuse/src/write_ops/grant_scope.rs`, `crates/sdk/src/rotation/mod.rs`)

## Accomplishments

- Renamed `refresh_grant_root_read_key(inodes, grant_root_ipns_name, result)` to `refresh_rotated_inode_read_keys(inodes, result)` and generalized its body to loop over `result.rotated_nodes` (the map 74-01 added to the Rust engine), matching each entry's `ipns_name` against every inode in the table — with NO early `return`, so every rotated node gets refreshed, not just the first match.
- Extended the match arms from `InodeKind::Root | InodeKind::Folder` to `InodeKind::Root | InodeKind::Folder | InodeKind::File`, closing a related staleness gap: files are rotated too via `mint_file_key_on_rotate` (CRIT-1) but were previously silently skipped by the refresh.
- Updated the call site inside `rotate_read_on_scope_exit` (line ~530) from `refresh_grant_root_read_key(&mut fs.inodes, grant_root_ipns_name, &result)` to `refresh_rotated_inode_read_keys(&mut fs.inodes, &result)`.
- Added `refresh_rotated_inode_read_keys_refreshes_intermediate_and_file_inodes`, a unit test seeding a depth-2 tree (grant-root Folder → intermediate Folder → File, each with a distinct `ipns_name` and a zeroed pre-rotation key) and asserting all three inodes' `read_key`s are refreshed to their new post-rotation values from a synthetic `RotateReadResult.rotated_nodes` map — proving the intermediate-Folder and File cases the prior single-node implementation missed.
- Exported `RotatedNodeKey` from `cipherbox_sdk::rotation` (added to the `pub use engine::{...}` re-export list in `crates/sdk/src/rotation/mod.rs`) — 74-01 defined the struct as `pub` inside `engine.rs` but never re-exported it up through the module tree, so `crates/fuse` could not name the type. This was required to write the test and the (already-`crate`-private) function signature reads `&RotateReadResult` directly, so the export is consumed only by the test module — a minimal, additive fix (Rule 3: blocking-issue auto-fix, not an architectural change).

## Task Commits

Each task was committed atomically (TDD RED → GREEN):

1. **Task 1 (RED): Failing intermediate+file inode refresh test** — `9bd391713` (test)
2. **Task 2 (GREEN): Generalize refresh to all rotated inodes + File arm; update call site** — `f9aa023ef` (feat)

_TDD gate sequence verified in git log: `test(74-03)` commit precedes `feat(74-03)` commit; RED was a genuine compile error (`cannot find function refresh_rotated_inode_read_keys in this scope`), confirmed via `cargo test` before Task 2 landed._

## Files Created/Modified

- `crates/fuse/src/write_ops/grant_scope.rs` — `refresh_rotated_inode_read_keys` (renamed/generalized from `refresh_grant_root_read_key`), updated call site, and the new multi-inode refresh unit test.
- `crates/sdk/src/rotation/mod.rs` — re-exports `RotatedNodeKey` alongside the existing `RotateReadResult` re-export.

## Decisions Made

- **`RotatedNodeKey` import scoped to the test module, not the file top level.** The generalized function only needs `&RotateReadResult` (already imported); `RotatedNodeKey` is a concrete type only the test constructs directly (via `make_rotated_node_key`). Importing it at file scope produced an unused-import warning in the non-test build, so the `use cipherbox_sdk::rotation::RotatedNodeKey;` was placed inside `mod tests` instead, matching the existing pattern for test-only imports (`use zeroize::Zeroizing;` in the same module).
- **`delete.rs` confirmed unchanged.** `git diff --name-only` across both commits lists only `grant_scope.rs` (and `rotation/mod.rs` for the export) — `rotate_read_on_scope_exit`'s caller contract (`Result<(), RotationError>`) is unaffected by the internal refresh generalization, exactly as the plan's acceptance criteria required.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Exported `RotatedNodeKey` from `cipherbox_sdk::rotation`**
- **Found during:** Task 1 (RED test authoring)
- **Issue:** 74-01 added `pub struct RotatedNodeKey` inside `crates/sdk/src/rotation/engine.rs` but did not add it to the `pub use engine::{...}` re-export list in `crates/sdk/src/rotation/mod.rs` (or the top-level `crates/sdk/src/lib.rs` re-export) — `crates/fuse` had no way to name the type to construct a `RotateReadResult.rotated_nodes` map in the test.
- **Fix:** Added `RotatedNodeKey` to the existing `pub use engine::{...}` list in `crates/sdk/src/rotation/mod.rs` (module-path export, `cipherbox_sdk::rotation::RotatedNodeKey`) — a one-line additive change, no other call sites affected.
- **Files modified:** `crates/sdk/src/rotation/mod.rs`
- **Verification:** `cargo test -p cipherbox-fuse write_ops::grant_scope::` compiles and passes; `cargo test -p cipherbox-sdk` unaffected (additive export only).
- **Committed in:** `9bd391713` (Task 1 RED commit, alongside the failing test)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary to make the plan's own test authoring possible; no scope creep — purely an additive re-export, no behavior change to any existing call site.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `refresh_rotated_inode_read_keys` is live-wired at the one call site (`rotate_read_on_scope_exit`), so any future scope-exit rotation on the desktop FUSE mount now refreshes every rotated node's in-memory key (Root/Folder/File), not just the grant root — closing the FUSE half of source todo `2026-07-09-deep-scope-exit-rotation-refreshes-only-grant-root-inode-key`.
- The desktop-e2e deep-scope-exit verification leg (mentioned in 74-PATTERNS.md's test-analog section, `tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts`) can now exercise a depth≥2 tree end-to-end against this fix.
- No blockers. `cargo test -p cipherbox-fuse write_ops::grant_scope::` is green (17/17); `cargo fmt -p cipherbox-fuse -p cipherbox-sdk -- --check` shows no drift in either file this plan touched (pre-existing drift in unrelated `crates/fuse/src/file_handle.rs` left untouched, out of scope).

---
*Phase: 74-rust-and-fuse-rotation-revocation-soundness*
*Plan: 03*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: crates/fuse/src/write_ops/grant_scope.rs
- FOUND: crates/sdk/src/rotation/mod.rs
- FOUND: .planning/phases/74-rust-and-fuse-rotation-revocation-soundness/74-03-SUMMARY.md
- FOUND commit: 9bd391713 (test RED)
- FOUND commit: f9aa023ef (feat GREEN)

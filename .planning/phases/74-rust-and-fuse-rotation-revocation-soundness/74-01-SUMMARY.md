---
phase: 74-rust-and-fuse-rotation-revocation-soundness
plan: 01
subsystem: crypto
tags: [rust, rotation-engine, read-key-chaining, revocation, tdd]

# Dependency graph
requires:
  - phase: 69-rotation-soundness-revocation-guarantees
    provides: rotate_read_from_node BFS rotation engine, CommittedRotation, RotateReadResult (root-only)
provides:
  - "RotatedNodeKey struct (crates/sdk/src/rotation/engine.rs)"
  - "RotateReadResult.rotated_nodes: HashMap<String, RotatedNodeKey> keyed by ipns_name"
  - "Per-node key population at root commit hook, BFS child commit hook, and repair_dirty_node crash-resume hook"
affects: [74-02-rust-and-fuse-rotation-revocation-soundness, 74-03-rust-and-fuse-rotation-revocation-soundness]

# Tech tracking
tech-stack:
  added: []
  patterns: ["Per-node result map threaded at call sites rather than widening host-agnostic CommittedRotation"]

key-files:
  created: []
  modified:
    - crates/sdk/src/rotation/engine.rs

key-decisions:
  - "repair_dirty_node's recovered_key folded into rotated_nodes (RESEARCH Open Question 1 resolved: readily available, not deferred)"
  - "CommittedRotation kept host-agnostic — no ipns_name field added; ipns_name threaded in at each of the three call sites"

patterns-established:
  - "RotatedNodeKey { ipns_name, read_key: Zeroizing<[u8;32]>, generation, sequence_number } — the frozen Rust-side shape TS plan 74-02 must mirror field-for-field"

requirements-completed: [SC1]

coverage:
  - id: D1
    description: "RotateReadResult.rotated_nodes surfaces every rotated node's post-rotation read key (root, intermediate folder, leaf file), keyed by ipns_name, for a depth>=2 tree"
    requirement: SC1
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#rotate_read_from_node::rotate_read_surfaces_every_rotated_node_key_for_a_deep_tree"
        status: pass
    human_judgment: false
  - id: D2
    description: "No regression to the ~27 existing RotateReadResult/rotate_read_from_node call sites after the additive widening"
    verification:
      - kind: unit
        ref: "cargo test -p cipherbox-sdk rotation::engine:: (27/27 passing)"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-11
status: complete
---

# Phase 74 Plan 01: Deep Scope-Exit Key Surfacing (Rust Engine) Summary

**Widened `RotateReadResult` with a `rotated_nodes: HashMap<String, RotatedNodeKey>` map so the Rust rotation engine surfaces every rotated node's post-rotation read key (root + every BFS descendant + crash-resume repairs), not just the grant root's.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-11
- **Tasks:** 2 (TDD: RED + GREEN)
- **Files modified:** 1 (`crates/sdk/src/rotation/engine.rs`)

## Accomplishments

- Added `RotatedNodeKey` struct (`ipns_name`, `read_key: Zeroizing<[u8;32]>`, `generation`, `sequence_number`) — the LOCKED cross-language contract shape the TS twin (plan 74-02) must mirror field-for-field.
- Added `RotateReadResult.rotated_nodes: HashMap<String, RotatedNodeKey>` additively — the existing top-level `read_key`/`generation`/`sequence_number` root-convenience fields are unchanged, avoiding churn to the ~27 existing call sites.
- Populated the map at all three points that produce a genuinely-valid post-rotation key for a node:
  1. The root commit branch inside `rotate_read_from_node_inner` (`RotateOneOutcome::Committed(root_committed)`), keyed by `root_ipns_name`.
  2. The BFS child commit branch (same function's walk loop, `RotateOneOutcome::Committed(child)`), keyed by `item.child_ref.ipns_name`.
  3. `repair_dirty_node`'s crash-resume repair path — its `recovered_key` (from the ECIES checkpoint of an already-committed prior-run rotation) is the node's current valid key, so it was folded into the same map rather than deferred (resolves RESEARCH's Open Question 1 in favor of "fold in, it's cheap").
- `CommittedRotation` was left untouched (no new `ipns_name` field) — it stays host-agnostic by design; `ipns_name` is threaded into `RotatedNodeKey` at each call site where it is already in scope (`root_ipns_name`, `item.child_ref.ipns_name`), per RESEARCH Pitfall 1.
- Added a new deep-tree unit test, `rotate_read_surfaces_every_rotated_node_key_for_a_deep_tree`, seeding a 3-node tree (grant-root → folderB → fileC, each a distinct `ipns_name`) and asserting all three levels appear in `rotated_nodes` with distinct, non-zero, 32-byte post-rotation keys, and that the existing top-level `read_key`/`generation`/`sequence_number` still equal the grant-root's own map entry.

## Task Commits

Each task was committed atomically (TDD RED → GREEN):

1. **Task 1 (RED): Failing deep-tree unit test for per-node key surfacing** — `a8449ee98` (test)
2. **Task 2 (GREEN): Widen RotateReadResult + populate at both commit hooks** — `043e7ae7b` (feat)

_TDD gate sequence verified in git log: `test(74-01)` commit precedes `feat(74-01)` commit; no `refactor` commit was needed (the initial implementation was already clean and fmt-checked)._

## Files Created/Modified

- `crates/sdk/src/rotation/engine.rs` — `RotatedNodeKey` struct, `RotateReadResult.rotated_nodes` field, population at the root/BFS-child/repair-dirty-node hooks, and the new deep-tree unit test.

## Decisions Made

- **`repair_dirty_node` folded in, not deferred.** RESEARCH flagged this as an open question (its return shape wasn't traced in that pass). On inspection, `repair_dirty_node` has `recovered_key` (the node's current post-rotation key, unwrapped from its ECIES checkpoint), `published.generation`, `resolved.sequence_number`, and `item.child_ref.ipns_name` all in scope at the same point the existing code already re-seals the parent's `SealedChildRef` mirror — inserting into `rotated_nodes` there was a ~10-line addition with no new plumbing, so it was folded in rather than left as a D-16-style documented follow-up. This closes a corner the plan's own acceptance criteria left as "either/or": a crash-resumed deep rotation now also surfaces every repaired node's key, not just the ones committed in the current run.
- **Map keyed by `ipns_name`, not `node_id`.** Matches the LOCKED contract and RESEARCH Pitfall 1 — `refresh_grant_root_read_key`/its future generalized successor (plan 74-03) matches FUSE inodes by `ipns_name`, not `node_id`.

## Deviations from Plan

None — plan executed exactly as written, including the one item RESEARCH left open (Open Question 1 / `repair_dirty_node`), which was resolved in favor of the "fold in" branch the plan explicitly sanctioned as an option.

## Issues Encountered

None. `cargo fmt -p cipherbox-sdk -- --check` flagged one line-length issue in the newly added test (pre-existing formatting drift in several unrelated files in the same crate was left untouched, out of scope) — fixed inline before the GREEN commit.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `RotatedNodeKey`/`RotateReadResult.rotated_nodes` (Rust) is the frozen contract plan 74-02 (TS `packages/sdk-core/src/rotation/engine.ts` parity twin) must mirror field-for-field: `ipnsName: string`, `readKey: Uint8Array`, `generation: number`, `sequenceNumber: number`, keyed by `ipnsName`.
- Plan 74-03 (FUSE intermediate-inode refresh) can now generalize `refresh_grant_root_read_key` in `crates/fuse/src/write_ops/grant_scope.rs` to loop over `result.rotated_nodes` instead of matching only the grant-root's single `ipns_name` — the map is populated and tested for depth>=2 trees including the crash-resume repair path.
- No blockers. `cargo test -p cipherbox-sdk rotation::engine::` is green (27/27); the scoped verify command declared in the plan passed as-is.

---
*Phase: 74-rust-and-fuse-rotation-revocation-soundness*
*Plan: 01*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: crates/sdk/src/rotation/engine.rs
- FOUND: .planning/phases/74-rust-and-fuse-rotation-revocation-soundness/74-01-SUMMARY.md
- FOUND commit: a8449ee98 (test RED)
- FOUND commit: 043e7ae7b (feat GREEN)

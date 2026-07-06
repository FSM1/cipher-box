---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 11
subsystem: crypto
tags: [rust, rotation, ipns, crash-recovery, tdd]

# Dependency graph
requires:
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
    provides: "69-08's engine.rs (rotate_one / rotate_read_from_node BFS walk, RotationJobRecord)"
provides:
  - "verify_subtree_clean: rebuilds the dirty rotation frontier from published IPNS records"
  - "Crash-safe resume wiring in rotate_read_from_node (ROT-06 no-double-bump convergence)"
  - "Documented M1 completed_node_ids seeding contract for callers"
affects: [69-12, 69-14]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Generation-comparison dirty-frontier detection: compare a child's own published PublishedNode.generation (plaintext wire field) against the parent's SealedChildRef mirror — no child unsealing required"
    - "Fast-path idempotency skip (existing since 69-08) is the actual no-double-bump mechanism for already-committed nodes; the caller's job is to seed completed_node_ids correctly on resume"

key-files:
  created: []
  modified:
    - crates/sdk/src/rotation/engine.rs
    - crates/sdk/src/rotation/mod.rs

key-decisions:
  - "verify_subtree_clean only detects children that individually committed but whose parent's batched republish never landed (generation strictly greater than mirror) — a genuinely never-started child (generation unchanged) is invisible to this check, an acknowledged limitation inherited unchanged from the TS reference (packages/sdk-core/src/rotation/engine.ts's own documented gap)"
  - "rotate_read_from_node always returns Ok(None) when the root itself was a resume-skip, even when the dirty-frontier reconciliation performed further publishing underneath it (ROT-07 Gap 2 parity with the TS reference)"
  - "completed_node_ids seeding is a caller responsibility (no load_job counterpart to persist_job exists); tests demonstrate both the seeded (no double-bump) and unseeded (double-bump hazard) paths explicitly"

requirements-completed: [SC-03]

coverage:
  - id: D1
    description: "verify_subtree_clean rebuilds the dirty frontier from published IPNS records, distinguishing a fully-converged subtree (empty frontier) from one with an unreconciled child"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#rotate_read_from_node::verify_subtree_clean_reports_no_dirty_entries_when_fully_converged"
        status: pass
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#rotate_read_from_node::verify_subtree_clean_reports_a_dirty_entry_when_a_child_outpaces_the_mirror"
        status: pass
    human_judgment: false
  - id: D2
    description: "A crash mid-walk (root + children fully committed, but the crash-time job record only remembered the root) converges on resume without double-bumping any node's generation"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#rotate_read_from_node::resume_after_crash_converges_without_double_bump_when_seeded"
        status: pass
    human_judgment: false
  - id: D3
    description: "M1: an empty completed_node_ids seed double-bumps the root; seeding from the crash-time record prevents it"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#rotate_read_from_node::empty_completed_node_ids_seed_double_bumps_the_root_seeded_path_does_not"
        status: pass
    human_judgment: false

# Metrics
duration: 25min
completed: 2026-07-06
status: complete
---

# Phase 69 Plan 11: Crash-Safety Resume for Read-Key Rotation Summary

**Added `verify_subtree_clean` (Rust twin of `engine.ts`'s same-named seam) plus resume wiring in `rotate_read_from_node` so a mid-walk crash converges from published IPNS records without double-bumping any node's generation (ROT-06 / M1).**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-06T04:05:00Z
- **Completed:** 2026-07-06T04:30:23Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments
- `verify_subtree_clean(deps, root_ipns_name, root_read_key)`: resolves + fetches + unseals the root's current published envelope, then compares each child's own published `generation` (a plaintext wire field, no unsealing needed) against the root's `SealedChildRef` mirror to build a dirty frontier
- `rotate_read_from_node`'s `Skipped`-root (resume) branch now calls `verify_subtree_clean` instead of unconditionally returning `None`: an empty frontier converges immediately with zero further publishes; a non-empty frontier seeds `ParentTrackingState` for the root from its current published state and folds the dirty entries into the same BFS loop the fresh-run path already uses
- Documented (module doc, `RotationJobRecord` doc, and two new tests) the M1 contract: the caller must seed `completed_node_ids` from the durably-persisted crash-time job record before resuming, or `rotate_one`'s fast idempotency path never fires and already-committed nodes get re-minted and re-published (a real double-bump)

## Task Commits

Each task was committed atomically:

1. **Task 1: verify_subtree_clean + crash-safe resume (no double-bump)** - `bfc5bfefc` (feat)

**Plan metadata:** (this commit — plan doc updates only, per worktree convention orchestrator handles STATE.md/ROADMAP.md)

## Files Created/Modified
- `crates/sdk/src/rotation/engine.rs` - Added `DirtyFrontierEntry` + `verify_subtree_clean`; restructured `rotate_read_from_node` to branch on `rotate_one(root)`'s outcome (fresh commit vs. resume-skip) while sharing the same BFS loop; added 4 new tests (2 for `verify_subtree_clean` in isolation, 2 for the full resume scenarios)
- `crates/sdk/src/rotation/mod.rs` - Exported `verify_subtree_clean` and `DirtyFrontierEntry`

## Decisions Made
- Scoped `verify_subtree_clean`'s dirty detection to exactly what's safely reconcilable: a child whose OWN rotation individually committed (its published generation is ahead of the parent's mirror) but whose parent's batched republish never landed. A genuinely never-started child (generation unchanged) is invisible to this check by design — this mirrors the TS reference's own acknowledged incompleteness (see `packages/sdk-core/src/rotation/engine.ts`'s `verifySubtreeClean` doc comment: "a true fresh-record resume ... is not yet wired here"). Attempting to reconcile a child whose own key was minted-then-lost mid-crash would require re-deriving a plaintext key from a stale wrap that was never sealed under the correct key — a cryptographic dead end, not a bug to fix in this plan.
- `rotate_read_from_node` always returns `Ok(None)` on a resume-skip root, even if the dirty-frontier reconciliation underneath did further publishing — matches the TS reference's `if (rootResult.skipped) return undefined;` exactly (ROT-07 Gap 2 parity: no fresh root key exists to hand back when the root itself didn't rotate this call).
- `completed_node_ids` seeding remains entirely the caller's responsibility (no `load_job` counterpart to `persist_job` exists in this engine). Rather than inventing a mechanism the plan didn't ask for, the two new tests demonstrate the contract directly: seeded resume converges with zero re-publishes; unseeded resume re-mints and re-publishes the root a second time (the exact M1 hazard).

## Deviations from Plan

None - plan executed exactly as written. `cargo fmt` reformatting was applied to the two lines this plan touched that rustfmt flagged (a pre-existing repo-wide fmt drift on unrelated files like `client.rs`/`queue.rs`/`state.rs`/`high_water.rs` was left untouched, out of scope for this plan).

## Issues Encountered

While designing the dirty-resume reconciliation branch, I confirmed a real cryptographic limitation shared with the TS reference: a child that individually rotated but whose parent's batched republish didn't land before a crash cannot have its NEW read key recovered from the stale parent mirror (the mirror only ever holds the child's OLD, pre-rotation wrap). This is documented in code comments as an inherited, acknowledged scope boundary rather than silently "fixed" with an unverifiable guess — the plan's required tests (converge-without-double-bump, and the M1 seeding contrast) are both satisfied via crash scenarios that don't depend on recovering an unrecoverable key (a fully-converged-but-unacknowledged crash, and an explicit empty-vs-seeded `completed_node_ids` contrast).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

`rotate_read_from_node` is now resumable after a mid-walk crash for the cases this plan scopes (fully converged-but-unacknowledged, and the M1 seeding contract). 69-12's revocation-guarantee closures (inner-grant re-mint, CAS-409 concurrent-child merge, write-plane rotation) can build on this without re-deriving the resume contract. The genuinely-never-started-child gap remains open (matches the TS reference) and is not a blocker for 69-12's stated scope.

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-06*

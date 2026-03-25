# GSD UI Phase Branching — Stay on the Phase Branch

**Date:** 2026-03-24

## Original Prompt

> /gsd:discuss-phase 21, then /gsd:plan-phase 21 (which triggered /gsd:ui-phase 21)

## What I Learned

- **All GSD workflow steps for a phase should stay on one branch.** When discuss-phase creates a branch (e.g., `docs/phase-21-context`), subsequent steps (plan-phase, ui-phase, execute-phase) should continue on that same branch — not create new ones.
- The ui-phase workflow was invoked as a sub-step of plan-phase (the UI design contract gate). The researcher and checker agents committed to a new branch (`docs/phase-21-ui-spec-revision`) instead of staying on the existing phase branch. This created unnecessary branch fragmentation that had to be cleaned up with a merge.
- The root cause: the GSD tooling's `commit` command creates commits on whatever branch is checked out. If an agent spawns in a worktree or switches branches, commits end up scattered.
- **Fix pattern:** Before any GSD workflow step, verify you're on the correct phase branch. Never `git checkout -b` mid-workflow unless the branch doesn't exist yet.

## What Would Have Helped

- Checking `git branch --show-current` at the start of ui-phase to confirm we were still on the phase branch
- A single branch naming convention for all phase work (e.g., `docs/phase-21` or `feat/phase-21`) established at discuss-phase and reused throughout
- Awareness that ui-phase is a sub-step of plan-phase, not an independent workflow — it shouldn't create its own branch

## Key Files

- `.claude/get-shit-done/workflows/discuss-phase.md` — Creates the initial phase branch
- `.claude/get-shit-done/workflows/plan-phase.md` — Orchestrates research, UI-SPEC, and planning on the same branch
- `.claude/get-shit-done/workflows/ui-phase.md` — Should inherit the branch from plan-phase, not create a new one

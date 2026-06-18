---
created: 2026-06-18
title: gsd-tools `phase complete` regresses STATE.md body on a milestone's final phase
area: tooling
files:
  - .claude/gsd-core/bin/lib/state.cjs
  - .planning/STATE.md
---

## Problem

Running `gsd-tools phase complete <N>` on the LAST phase of a milestone updates
the frontmatter correctly (`status: Milestone complete`, `completed_phases`,
`percent`) but silently corrupts two `## Current Position` body lines and the
velocity headline.

Observed 2026-06-18 on PR #512 (commit `21cfd78dc`):

- `Plan: 5 of 5 — COMPLETE` was rewritten to `Plan: Not started`.
- The phase line lost its `— COMPLETE` marker (`Phase: 49 (...) — COMPLETE`
  became bare `Phase: 49`).
- `- Total plans completed: 182 (72 M1 + 83 M2 + 6 M3)` was bumped to `199` —
  a value matching neither its own breakdown (`72 + 83 + 6 = 161`) nor the real
  audited count (`151`).

CodeRabbit flagged both the `Not started` inconsistency and the `199` mismatch;
both were artifacts of this regression, fixed by hand in `a3986cc9c` (velocity →
audited `151`) and `a7e8bd80e` (Current Position restored).

## Root cause

In `.claude/gsd-core/bin/lib/state.cjs`, the `## Current Position` sync
(`updateCurrentPositionFields`) and the velocity-total writer only run as a
side-effect of `begin-phase` / `advance-plan` on an ACTIVE phase. There is no
milestone-complete path that resets the body to a terminal state, so completing
the final phase leaves these lines stale or regressed. `query validate.health`
reports `healthy` and does not catch it (existing-STATE content drift is
non-repairable by design).

## Solution

TBD. Options to evaluate:

- Teach `phase complete` (when it is the milestone's last phase) to write a
  terminal Current Position (`Phase: N (...) — COMPLETE`, `Plan: M of M —
  COMPLETE`) and recompute the velocity total from the current milestone's
  `*-SUMMARY.md` count, instead of the cumulative `begin-phase` increment.
- Add a `validate.health` check that compares the velocity "Total plans
  completed" headline against the disk audit (`*-PLAN.md` / `*-SUMMARY.md` per
  milestone phase) and flags drift.
- At minimum, document that the STATE.md body is not authoritative after a
  milestone completes — the frontmatter `progress` block is.

## Notes

- Authoritative count is the frontmatter `total_plans`/`completed_plans` plus a
  disk audit; for v1.1 all four sources agreed at `151` (34 phases, every PLAN
  has a SUMMARY).

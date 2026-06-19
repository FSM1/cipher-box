# Phase 55: Large Source-File Refactor - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-19
**Phase:** 55-large-source-file-refactor
**Areas discussed:** Tier scope, client.ts approach, Tier 3 test-first, PR/plan granularity

---

## Tier scope

| Option           | Description                                                                          | Selected |
| ---------------- | ----------------------------------------------------------------------------------- | -------- |
| Tier 1 + Tier 2  | Test-guarded mechanical splits + high-value cross-platform dedup; defer Tier 3.      | ✓        |
| Tier 1 only      | Quick low-risk wins only.                                                            |          |
| All three tiers  | Everything incl. the bigger/riskier untested Tier-3 web/desktop crypto refactors.    |          |

**User's choice:** Tier 1 + Tier 2 (D-01)

---

## client.ts approach (forward-looking — client.ts is Tier 3, deferred)

| Option                    | Description                                                            | Selected |
| ------------------------- | --------------------------------------------------------------------- | -------- |
| Conservative              | Extract pinning.ts + shared-folder.ts (~600 LoC), test-guarded.         |          |
| Full facade decomposition | ClientCore + 7-phase split to a ~350-LoC delegating facade.             | ✓        |

**User's choice:** Full facade decomposition (D-02)
**Notes:** Applies when Tier 3 / client.ts is eventually tackled (not this phase). Locked now so the deferred work is unambiguous; honor public-API freeze + ClientCore.folderTree single-source-of-truth.

---

## Tier 3 test-first

| Option                    | Description                                                                | Selected |
| ------------------------- | ------------------------------------------------------------------------- | -------- |
| In-phase gating           | Each untested Tier-3 refactor lands its tests first within the same effort. |          |
| Separate test-backfill first | A dedicated test-backfill phase adds the missing tests BEFORE any Tier-3 refactor. | ✓        |

**User's choice:** Separate test-backfill first (D-03)
**Notes:** Implies a future test-backfill phase + a Tier-3 refactor phase; capture as follow-up todos at execute time.

---

## PR / plan granularity

| Option         | Description                                                                  | Selected |
| -------------- | --------------------------------------------------------------------------- | -------- |
| Per-item PRs   | One refactor/ branch + PR per survey item (the survey's model).               |          |
| Batched groups | Group coherent work into fewer PRs (lib.rs decomposition, Windows dedup, etc.). | ✓        |

**User's choice:** Batched groups (D-04)
**Notes:** Overrides the survey's per-item recommendation. Planner decides the exact grouping (e.g. lib.rs as one PR, all Windows/cross-platform dedup as one, remaining Rust Tier-1 as one, TS/web Tier-1 grouped).

---

## Claude's Discretion

- Exact PR grouping within the "batched groups" decision (D-04).
- The lib.rs internal module phasing follows the survey's deep-dive; planner may sub-sequence.

## Deferred Ideas

- All Tier 3 refactors — deferred, gated on the separate test-backfill phase (D-03); client.ts approach locked (D-02).
- windows/host.rs dispatcher split — deferred (can't exercise off Windows).

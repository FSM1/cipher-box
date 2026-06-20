# Phase 53: Release & Supply-Chain Engineering - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-19
**Phase:** 53-release-supply-chain-engineering
**Areas discussed:** #16 target architecture, #13 Cargo.lock sync, #6 zizmor + perms, #6 rollout

---

## #16 — release-please pin automation architecture

| Option                   | Description                                                                                          | Selected |
| ------------------------ | --------------------------------------------------------------------------------------------------- | -------- |
| Patch the bot            | Clear satisfied pins + enforce rebase + re-run preview on final state + reconcile attribution + clean traps. |          |
| Patch now + spike re-arch | Full patch now + research task to evaluate native release-please ownership later.                    |          |
| Re-architect now         | Remove the committed release-as config; release-please owns versioning natively.                      |          |

**User's choice:** Free-text — disagreed with the framing. The stale-satisfied-pins are NOT an independent problem ("as soon as the release-please commit is merged, the pins work normally"); the much simpler solution is agent correctness — not force-pushing over the bot's release-target commit.
**Resolution (confirmed):** User's diagnosis is correct. Per the todo's own root-cause chain, the sdk loop was caused by a force-push orphaning the bot's release-target commit + `cancel-in-progress` killing the recompute. A satisfied pin only collides with a new commit when that recompute is skipped — so pin-clearing is a band-aid for a symptom, not a cause. **Primary fix = fetch+rebase instead of force-pushing over the bot commit** (codified in tooling + agent instructions). **Optional safety-net** (planner evaluates, don't over-build) = re-run preview on final pre-merge state / revisit cancel-in-progress, to avoid relying purely on discipline. **Dropped:** the ongoing clear-satisfied-pins machinery. Path-attribution reconcile + one-time cleanup of the ~8 existing stale pins kept as optional hygiene (D-07).

---

## #13 — Cargo.lock sync

| Option                    | Description                                                                              | Selected |
| ------------------------- | --------------------------------------------------------------------------------------- | -------- |
| Auto-update PR + guard    | cargo update --precise on the release PR + CI guard.                                      |          |
| Guard only                | CI fails the release PR on stale lock; human regenerates.                                 |          |
| Native release-please updater | Enable release-please's cargo-aware Cargo.lock updater (if it rewrites first-party versions). | ✓ (preferred) |

**User's choice:** Native release-please updater if possible; failing that, auto-update + guard on the release PR.
**Notes:** Conditional (D-05) — planner verifies the native updater works; falls back to auto-update+guard. Either way the lock update lands on the release PR so main is never stale.

---

## #6 — CI hardening depth (zizmor + permissions)

| Option            | Description                                                                            | Selected |
| ----------------- | ------------------------------------------------------------------------------------- | -------- |
| zizmor gate + perms | zizmor CI gate (fail unpinned refs) + least-privilege job-level permissions: blocks.   | ✓        |
| zizmor gate only  | Gate only; defer the permissions pass.                                                  |          |
| Minimal           | Pin + Dependabot only; skip gate + permissions.                                         |          |

**User's choice:** zizmor gate + perms (D-04)

---

## #6 — Pinning rollout

| Option                | Description                                                              | Selected |
| --------------------- | ----------------------------------------------------------------------- | -------- |
| All-at-once           | One PR converting every third-party ref. Keeps the convention consistent. | ✓        |
| Staged high-risk first | High-risk non-GitHub publishers first, then the rest.                     |          |

**User's choice:** All-at-once (D-02)

---

## Claude's Discretion

- pinact vs ratchet for the bulk SHA conversion (D-01) — planner picks.
- Whether to include the optional #16 cancel-in-progress safety-net and the D-07 hygiene items — planner evaluates, kept minimal per the user.
- Concrete Dependabot schedule/grouping for the github-actions ecosystem.

## Deferred Ideas

- Full re-architecture of release-target computation (remove committed release-as config / release-please native ownership) — deferred; per-PR recompute resilience is sufficient now.

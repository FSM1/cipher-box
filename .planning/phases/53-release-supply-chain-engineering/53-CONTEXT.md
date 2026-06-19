# Phase 53: Release & Supply-Chain Engineering - Context

**Gathered:** 2026-06-19
**Status:** Ready for planning
**Source:** Discuss-phase. Scope is three re-verified captured todos (#6, #13, #16) under requirement
HARD-04 — pure CI/release-process hardening, no app-runtime code. Four forks discussed; the user
corrected the #16 root-cause framing (see D-05).

<domain>

## Phase Boundary

Harden the CI / release supply chain under requirement **HARD-04**:

- **#6** — Pin every third-party GitHub Action to an immutable commit SHA (111 `uses:` refs across 14
  workflows, currently all mutable tags) and keep them current via Dependabot.
- **#13** — Keep the workspace `Cargo.lock` in sync with release-please's crate version bumps so
  `main` is never stale-on-first-cargo post-release.
- **#16** — Stop the release-please self-compare / stuck-loop class by making the per-PR release-target
  recompute resilient to force-push / rebase clobber.

Out of scope: HARD-02 / HARD-03 / HARD-05 / HARD-06 (Phases 51, 52, 54, 55); any app or runtime code;
a full re-architecture of release versioning (noted as a possible follow-up, not this phase).

**Repo convention (MUST follow):** implementation commits and the eventual PR for this phase use
`chore(ci):`, NOT `feat`/`fix` — per the project's CI/release-work rule. (GSD's planning-doc commits
remain `docs(53):` on the `feat/release-supply-chain-engineering` branch; only the implementation
work is `chore(ci)`.)

</domain>

<decisions>

## Implementation Decisions

### #6 — Pin GitHub Actions to immutable SHAs

- **D-01 (pinning):** SHA-pin **all ~111 third-party `uses:` refs** across the 14 workflow files to a
  full 40-char commit SHA with a trailing version comment (e.g. `uses: actions/checkout@<sha> # v6.0.0`).
  Internal reusable-workflow refs (`./.github/workflows/*.yml`) are excluded. Bulk-convert with
  `pinact` or `ratchet` (planner picks) — do not hand-edit 111 refs.
- **D-02 (rollout, fork):** **All-at-once in one PR.** Keeps the convention consistent (the work was
  deferred on PR #487 precisely to avoid a lone SHA-pinned action). Not staged.
- **D-03 (Dependabot, locked companion):** Add/extend `.github/dependabot.yml` with
  `package-ecosystem: "github-actions"` so the pinned SHAs (and version comments) are bumped on new
  releases. Without this, pinning freezes CI on stale SHAs — this step is mandatory, not optional.
- **D-04 (zizmor + permissions, fork):** Add a **zizmor CI gate** that fails any newly-introduced
  unpinned `uses:` ref (`unpinned-uses`), AND fix the **excessive-permissions** finding by adding
  least-privilege job-level `permissions:` blocks (e.g. the `cargo-linux` job in `ci.yml`, and any
  others lacking one).

### #13 — Cargo.lock sync on release

- **D-05 (lock sync, fork):** **Prefer the native release-please cargo-aware `Cargo.lock` updater** —
  the researcher/planner first verifies whether enabling a workspace/lock updater in
  `release-please-config.json` makes release-please rewrite the first-party crates' `[[package]]
  version` lines automatically. **Fallback** (if unsupported or insufficient): auto-update the lock
  **on the release PR** via `cargo update -p <crate> --precise <new-version>` for each bumped
  first-party crate (committed onto the release PR), PLUS a CI guard (`git diff --exit-code
  Cargo.lock` after `cargo generate-lockfile`, or `cargo update --locked --dry-run`) that fails the
  release PR when the lock is stale. Either path keeps the lock update on the release PR so `main` is
  never stale post-merge. First-party crates only — the diff is just version strings, no dependency
  re-resolution.

### #16 — release-please pin automation (root-cause corrected by user)

- **D-06 (architecture, fork — user-corrected):** **Root cause is the force-push / rebase clobbering
  the bot's `chore(release): set release targets` commit, compounded by
  `concurrency: cancel-in-progress: true` aborting the recompute so it never self-corrects.** The
  "stale satisfied pins are never cleared" framing from the todo is a **band-aid for a symptom, not an
  independent cause** — a satisfied pin only collides with a new releasable commit *when that same
  recompute is skipped*; if the bot reliably recomputes the release target on the final pre-merge
  state, the pin always advances to the next unreleased version and never sits stale (confirmed by
  walking the todo's own root-cause chain for the sdk #509 case).
  - **Primary fix (the simpler solution):** ensure pushes to a PR branch `git fetch` + rebase the
    bot's release-target commit instead of force-pushing over it — codified in tooling + agent
    instructions (mirrors the known "PR-create triggers a bot release commit" gotcha).
  - **Optional lightweight safety-net (planner evaluates — do NOT over-build):** make
    `pr-release-preview.yml` self-correcting so a clobbered/cancelled run can't ship a stale config —
    e.g. re-run the preview on the final state before merge and/or revisit
    `concurrency: cancel-in-progress: true`. This closes the fragility of relying purely on
    discipline ("enforce, don't rely on discipline") without adopting the pin-clearing machinery.
  - **Explicitly NOT doing:** the ongoing "clear any `release-as` ≤ manifest version" auto-clearing
    logic as the fix. Satisfied pins work normally once the release commit merges.
- **D-07 (secondary hygiene — planner's call):**
  - Reconcile path attribution between `pr-release-preview.js` (`packageBumps`, ~line 298) and
    release-please so a source change under `packages/<x>/**` can't leave `<x>`'s target behind
    (supports recompute correctness).
  - One-time cleanup of the ~8 existing `release-as` entries currently equal to their manifest version
    (latent hazard only until their next recompute advances them) — optional belt-and-suspenders.

### Folded Todos

- **[#6]** `2026-06-14-pin-github-actions-to-immutable-shas.md` — SHA pinning + Dependabot + zizmor.
  Maps to D-01..D-04.
- **[#13]** `2026-06-18-releaseplease-does-not-bump-cargo-lock.md` — Cargo.lock sync. Maps to D-05.
- **[#16]** `2026-06-19-harden-release-please-pin-automation.md` — pin automation resilience. Maps to
  D-06/D-07.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & source findings

- `.planning/todos/pending/2026-06-14-pin-github-actions-to-immutable-shas.md` — #6: full action
  inventory, pinact/ratchet, Dependabot, zizmor. The primary ref for #6.
- `.planning/todos/pending/2026-06-18-releaseplease-does-not-bump-cargo-lock.md` — #13: the stale-lock
  drift + the three solution options.
- `.planning/todos/pending/2026-06-19-harden-release-please-pin-automation.md` — #16: the confirmed
  root-cause chain (read alongside D-06's correction).
- `.planning/REQUIREMENTS.md` — HARD-04.
- `.planning/ROADMAP.md` §"Phase 53" — scope checkboxes.

### #6 — Workflows & supply-chain config

- `.github/workflows/*.yml` (14 files: ci, ci-e2e, codecov-base, deploy-landing, deploy-staging,
  desktop-e2e, desktop-staging-release, load-test, pr-release-preview, pr-title, release-gate,
  release-please, tag-staging, web-e2e) — the `uses:` refs to pin.
- `.github/dependabot.yml` — add `github-actions` ecosystem (create if absent).

### #13 — Release/lock config

- `release-please-config.json`, `.release-please-manifest.json`, `Cargo.lock`,
  `.github/workflows/release-please.yml` — lock-sync target.

### #16 — Pin automation

- `.github/scripts/pr-release-preview.js` (clear logic ~lines 644-652; `packageBumps` ~line 298) and
  `.github/workflows/pr-release-preview.yml` (the `concurrency` block) — recompute resilience target.
- `release-please-config.json`, `.release-please-manifest.json` — the `release-as` pins.

### Repo conventions

- CLAUDE.md §"Releases & Versioning" — release-please mechanics, tag patterns, `include-component-in-tag`.

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `pinact` / `ratchet` — idempotent tag→SHA converters with version comments; use one rather than
  hand-editing (D-01).
- The known "PR-create triggers a bot release commit" workflow gotcha (fetch+rebase, never
  force-push over the bot's `chore(release)` commit) is exactly the discipline D-06 codifies.

### Established Patterns

- release-please bumps per-package independently; `apps/desktop` propagates its version via
  `extra-files`. The Cargo.lock drift (#13) is because the lock isn't in that update set.
- `concurrency: cancel-in-progress: true` on `pr-release-preview.yml` is load-bearing in the #16
  failure — a cancelled run never recomputes the release target.

### Integration Points

- Pure CI/release config — no app or runtime code. Verify #6 by re-running the full workflow suite on
  a PR (SHAs must resolve to the same versions, so behavior is unchanged).
- #13 and #16 both touch the release-please pipeline; sequence so the Cargo.lock change and the pin
  automation change don't fight each other on the same release PR.

</code_context>

<specifics>

## Specific Ideas

- D-05 is conditional: planning must first establish whether release-please's native Cargo.lock
  updater actually rewrites first-party `[[package]] version` lines. Record which path (native vs
  auto-update+guard) was taken in the plan.
- D-06 is deliberately minimal per the user: the simpler force-push-discipline fix is primary; the
  cancel-in-progress / re-run safety-net is optional and the planner should not over-build it.

</specifics>

<deferred>

## Deferred Ideas

- Full re-architecture of release-target computation (remove the committed `release-as` config / let
  release-please own versioning natively) — considered for #16 and deferred; the per-PR-recompute
  resilience fix is sufficient for now.

None other — discussion stayed within phase scope.

</deferred>

---

_Phase: 53-release-supply-chain-engineering_
_Context gathered: 2026-06-19_

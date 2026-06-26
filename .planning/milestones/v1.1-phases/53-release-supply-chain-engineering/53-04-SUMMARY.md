---
phase: 53-release-supply-chain-engineering
plan: 04
subsystem: infra
tags: [ci, release-please, release-as, force-push, tdd, node-test]

requires:
  - phase: 53-03
    provides: the #13 Cargo.lock change landed first so the two release-please-pipeline changes do not collide on one release PR
provides:
  - check-stale-release-as.js guard (pure findStaleReleaseAs + CLI) with node:test coverage
  - removal of the stale release-as pins (release-as == manifest)
  - cancel-in-progress false self-healing safety-net in pr-release-preview.yml
  - force-push discipline codified in CLAUDE.md + MEMORY draft
affects: [release-please pipeline, future PR force-push hygiene]

tech-stack:
  added: []
  patterns: [node:test for stdlib-only CI guard scripts, pure-function + import.meta.url CLI guard]

key-files:
  created:
    - .github/scripts/check-stale-release-as.js
    - .github/scripts/check-stale-release-as.test.js
    - .planning/phases/53-release-supply-chain-engineering/MEMORY-ENTRY.md
  modified:
    - release-please-config.json
    - .github/workflows/pr-release-preview.yml
    - CLAUDE.md

key-decisions:
  - 'RECONCILED with main merge: the plan named 3 stale release-as entries (packages/core 0.31.0, packages/crypto 0.33.0, crates/core 0.5.1) but main commit #529 bumped crates/core 0.5.1 -> 0.5.2 BEFORE this phase merged. So crates/core is no longer stale; only 2 entries (packages/core, packages/crypto) were removed. The guard script itself confirmed exactly 2 stale at deletion time.'
  - 'release-as count dropped from 14 to 12 (by exactly 2, not 3) — the correct post-merge number'
  - 'D-06 PRIMARY fix is docs (fetch+rebase discipline in CLAUDE.md + MEMORY draft); cancel-in-progress: false is the minimal safety-net (Option A)'
  - 'EXPLICITLY did NOT touch the pr-release-preview.js clear-satisfied-pins machinery (rejected per D-06 as a symptom band-aid)'
  - 'Guard uses Node stdlib only (node:fs, node:test, node:assert, node:url) — no package added (T-53-SC accepted)'
  - 'MEMORY-ENTRY.md is a DRAFT under .planning/ — the shared MEMORY.md is NOT written from the worktree'

patterns-established:
  - 'CI guard script: pure exported comparison function + CLI entry gated on process.argv[1] === fileURLToPath(import.meta.url) so tests import without process.exit'
  - 'TDD with node --test (RED via missing import, GREEN via implementation), no test-runner dependency'
---

# 53-04 Summary: stale release-as guard + release automation hardening

## What was delivered

1. `.github/scripts/check-stale-release-as.js` — exports pure
   `findStaleReleaseAs(config, manifest)` returning every `release-as` pin equal
   to its manifest version; CLI reads `release-please-config.json` +
   `.release-please-manifest.json`, prints `STALE: ...` lines and exits 1 on any
   finding, else exits 0. CLI gated on `import.meta.url` so the test imports the
   pure function without triggering `process.exit`.
2. `.github/scripts/check-stale-release-as.test.js` — `node:test` unit test:
   stale detected, all-ahead passes, no false positives (no `release-as` /
   missing-from-manifest). Stdlib only, no added dependency.
3. Removed the stale `release-as` keys (see reconciliation below).
4. `pr-release-preview.yml` concurrency `cancel-in-progress: true -> false`.
5. CLAUDE.md "Release Automation Rules" subsection + `MEMORY-ENTRY.md` draft.

## TDD sequence

- RED: wrote the test first → `node --test` failed (missing module import).
- GREEN: implemented `check-stale-release-as.js` → all 3 tests pass.
- Committed test + impl together as one atomic TDD unit (a0d222d81); the RED→GREEN
  order is recorded here.

## Reconciliation with the main merge (important)

The plan named 3 confirmed-stale entries: `packages/core 0.31.0`,
`packages/crypto 0.33.0`, `crates/core 0.5.1`. But STEP 0's `git merge origin/main`
brought in commit #529 which bumped `crates/core` `release-as` `0.5.1 -> 0.5.2`,
so `crates/core` is now strictly ahead of its manifest (0.5.1) and is NOT stale.
The guard script run against the live post-merge config reported exactly 2 stale
entries — `packages/core` and `packages/crypto` — so only those two `release-as`
keys were deleted. `release-as` count dropped 14 -> 12 (by 2). This is precisely
the class of drift the guard exists to catch; deleting the plan's hardcoded 3rd
entry would have dropped a real pending release target for crates/core.

## Rejected machinery (D-06)

`.github/scripts/pr-release-preview.js` clear-satisfied-pins logic (~lines 644-652)
was deliberately NOT adopted — confirmed `git status` shows it unmodified.

## Verification

- `node --test .github/scripts/check-stale-release-as.test.js` — 3 pass, 0 fail.
- `node .github/scripts/check-stale-release-as.js` exits 0 ("No stale release-as
  entries found.") after the 2 deletions.
- `release-please-config.json` is valid JSON; surrounding keys in the two edited
  blocks intact; `release-as` count 12.
- `pr-release-preview.yml` has `cancel-in-progress: false`, no `true`.
- `pr-release-preview.js` untouched.
- CLAUDE.md mentions force-push, the bot `chore(release)` commit, and rebase;
  `MEMORY-ENTRY.md` draft exists; shared MEMORY.md not written from the worktree.
- `zizmor --offline .github/workflows/` still exits 0 (the concurrency edit is clean).

## Commits

- `chore(ci): add stale release-as guard script with node:test coverage` — a0d222d81
- `chore(ci): remove stale release-as pins and harden release automation` — 7542a684d

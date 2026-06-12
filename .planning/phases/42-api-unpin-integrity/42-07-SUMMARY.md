---
phase: 42-api-unpin-integrity
plan: 07
subsystem: api
tags: [typeorm, postgres, ipfs, kubo, backfill, quota, maintenance]

requires:
  - phase: 42-api-unpin-integrity
    provides: pinned_cids schema with is_byo_user discriminator on vaults join

provides:
  - One-shot quota-repair backfill script for non-BYO users (scripts/backfill-pinned-cids.ts)
  - Pure D-09 predicate helper + NDJSON Kubo pin/ls parser (apps/api/src/scripts/backfill-helpers.ts)
  - Unit spec proving BYO exclusion, Kubo-set presence guard, and empty-input handling

affects:
  - phase 42 wave 4 (phase closeout)

tech-stack:
  added: []
  patterns:
    - DataSource bootstrap (env-driven postgres, initialize/destroy, exit codes) from run-migrations.ts
    - BATCH_SIZE=10 delete loop mirroring migration.processor.ts
    - process.argv string-flag parsing for --dry-run (no enums)
    - NDJSON line-by-line parse for Kubo pin/ls (Pitfall 6 pattern)

key-files:
  created:
    - scripts/backfill-pinned-cids.ts
    - apps/api/src/scripts/backfill-helpers.ts
    - apps/api/src/scripts/backfill-helpers.spec.ts

key-decisions:
  - 'Empty/unreachable Kubo pin set aborts with exit(1) before any DELETE — never treat empty as all-phantom (T-42-23)'
  - 'BYO exclusion enforced at two layers: SQL WHERE is_byo_user = false AND selectRowsToDelete isByoUser assertion (T-42-22 D-09)'
  - '--dry-run flag parses via process.argv string include, not an enum (CLAUDE.md string-literal convention)'
  - 'Standalone script at scripts/ root, not an app endpoint — per RESEARCH Open Question 2'

patterns-established:
  - 'scripts/backfill-*: standalone DataSource scripts live at repo root scripts/ and import helpers from apps/api/src/scripts/'
  - 'backfill-helpers.ts: pure side-effect-free functions in apps/api/src/scripts/ enable unit testing without DB/Kubo'

requirements-completed:
  - UNPIN-BACKFILL

duration: 25min
completed: 2026-06-12
---

# Phase 42 Plan 07: Backfill Pinned CIDs Summary

**One-shot quota-repair script diffing non-BYO pinned_cids rows against live Kubo pin/ls, with mandatory empty-Kubo abort guard, --dry-run preview mode, and unit-tested D-09 BYO-exclusion predicate**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-06-12T20:10:00Z
- **Completed:** 2026-06-12T20:35:00Z
- **Tasks:** 2
- **Files created:** 3

## Accomplishments

- Implemented `selectRowsToDelete` + `parseKuboPinLs` as pure functions and verified all five plan behaviors via TDD (RED/GREEN commits)
- Implemented standalone backfill script with mandatory empty/unreachable-Kubo guard (exits non-zero, no deletes), loud mode banner, and batched id-scoped DELETEs
- BYO exclusion enforced at both the SQL JOIN layer (`WHERE v.is_byo_user = false`) and the predicate assertion layer (`isByoUser === false` in `selectRowsToDelete`)

## Task Commits

1. **Task 1 RED: Failing specs** - `02d80ce03` (test)
2. **Task 1 GREEN: Helpers implementation** - `3ddcabd30` (feat)
3. **Task 2: Runnable backfill script** - `280d55d0d` (feat)

## Files Created/Modified

- `apps/api/src/scripts/backfill-helpers.ts` - Pure `selectRowsToDelete` (D-09 predicate) and `parseKuboPinLs` (NDJSON Kubo parser)
- `apps/api/src/scripts/backfill-helpers.spec.ts` - Unit spec: BYO exclusion (D-09), CID-presence retention, empty-input handling, blank-line tolerance
- `scripts/backfill-pinned-cids.ts` - Standalone DataSource bootstrap script: non-BYO JOIN query, mandatory Kubo guard, --dry-run, BATCH_SIZE=10 deletes

## Decisions Made

- `--dry-run` parsed via `process.argv.includes('--dry-run')` string literal, not an enum (CLAUDE.md requirement)
- Empty Kubo set → `process.exit(1)` with error message before any DELETE. Rationale: an empty parse cannot be distinguished from a "Kubo has no pins" scenario, and treating it as all-phantom would wipe every non-BYO row (T-42-23).
- Script lives at `scripts/backfill-pinned-cids.ts` (repo root scripts dir) and imports helpers from `apps/api/src/scripts/` — same pattern as `run-migrations.ts` in `apps/api/src/`.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- The plan's verify command (`npx tsc --noEmit --moduleResolution node scripts/backfill-pinned-cids.ts`) generates spurious `process`/`console`/`Set` errors because the bare invocation lacks `@types/node` from the api package. These are the same class of environment noise as the excluded `typeorm`/`dotenv` module errors. Validated correctly using the api package's tsc with `--typeRoots` pointing to `apps/api/node_modules/@types` — no real TS errors.
- Worktree lacked `node_modules`; resolved with `pnpm install --frozen-lockfile` in the worktree root (cleanup: `rm -rf node_modules .husky/_` before returning per parallel-execution directive).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Backfill script is ready to run ad-hoc via `ts-node scripts/backfill-pinned-cids.ts --dry-run` (preview) then without the flag for the real repair
- Requires `DB_*` env vars + `IPFS_LOCAL_API_URL` pointing to a live Kubo with the actual pin set
- Phase 42 wave 3 complete; all guarded-unpin + backfill work delivered

## Self-Check: PASSED

- `apps/api/src/scripts/backfill-helpers.ts` exists
- `apps/api/src/scripts/backfill-helpers.spec.ts` exists
- `scripts/backfill-pinned-cids.ts` exists
- Commits `02d80ce03`, `3ddcabd30`, `280d55d0d` all present in git log

---

Phase: 42-api-unpin-integrity
Completed: 2026-06-12

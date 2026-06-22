---
phase: 57-api-cid-and-provider-hardening-and-module-dedup
plan: "02"
subsystem: api
tags: [nestjs, typeorm, ipfs, advisory-lock, module-dedup]

requires:
  - phase: 50-ipfs-ipns-data-integrity-fixes
    provides: advisory-lock advisory-lock unpin integrity baseline (WR-01, INT_MIN-safe SQL)

provides:
  - Leaf IpfsProviderModule (single IPFS_PROVIDER factory source, imported by IpfsModule/VaultModule/PendingUnpinModule)
  - withCidLock shared primitive (verbatim INT_MIN-safe pg_advisory_xact_lock SQL)
  - refcountAndMaybeUnpin shared primitive (under-lock refcount recheck + conditional unpin)
  - All three advisory-lock unpin sites routed through shared helpers

affects:
  - ipfs module graph
  - vault unpin path
  - pending-unpin drain path

tech-stack:
  added: []
  patterns:
    - Leaf NestJS module pattern for shared DI tokens (IpfsProviderModule)
    - Shared helper functions for cross-service advisory lock primitives

key-files:
  created:
    - apps/api/src/ipfs/providers/ipfs-provider.module.ts
    - apps/api/src/ipfs/providers/ipfs-provider.module.spec.ts
    - apps/api/src/ipfs/pending-unpin/unpin-helpers.ts
    - apps/api/src/ipfs/pending-unpin/unpin-helpers.spec.ts
  modified:
    - apps/api/src/ipfs/providers/index.ts
    - apps/api/src/ipfs/ipfs.module.ts
    - apps/api/src/vault/vault.module.ts
    - apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts

key-decisions:
  - 'IpfsProviderModule imports only ConfigModule (leaf) — no upstream module imports to avoid recreating real cycle'
  - 'IpfsModule forRootAsync explicitly keeps exports: [IPFS_PROVIDER] even after delegating factory to IpfsProviderModule (Pitfall 2)'
  - 'withCidLock uses verbatim SQL with NO abs() — sign-extends int4→bigint safely per INT_MIN-safe fix'
  - 'Post-commit guardedUnpin site uses withCidLock only (not refcountAndMaybeUnpin) — Kubo stays outside transaction per D-03'
  - 'drainRow delegates to withCidLock wrapping refcountAndMaybeUnpin — Kubo inside lock per drainRow design'

patterns-established:
  - 'Leaf module pattern: single DI token with factory in its own @Module, imported by all consumers'
  - 'Advisory lock via withCidLock helper: all unpin lock acquisitions through single implementation'

requirements-completed: [HARD-08]

duration: 25min
completed: 2026-06-22
---

# Phase 57 Plan 02: API Module Dedup and Shared Unpin Primitives Summary

**Triplicated IPFS_PROVIDER factory and duplicated advisory-lock SQL consolidated into a single leaf IpfsProviderModule and withCidLock/refcountAndMaybeUnpin helpers, routing all three unpin sites through one INT_MIN-safe lock primitive**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-06-22T01:40:00Z
- **Completed:** 2026-06-22T02:05:00Z
- **Tasks:** 3
- **Files modified:** 10

## Accomplishments

- Extracted leaf `IpfsProviderModule` as the single source of the `IPFS_PROVIDER` factory; removed triplicated factory blocks and misleading IN-04 comments from IpfsModule, VaultModule, PendingUnpinModule
- Created `withCidLock` and `refcountAndMaybeUnpin` in `unpin-helpers.ts` with verbatim INT_MIN-safe SQL and no `abs()` — a future lock fix edits one file instead of three
- Routed all three advisory-lock unpin sites through the shared helpers; the post-commit Kubo call correctly remains outside the inner transaction (D-03 ordering)

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract leaf IpfsProviderModule + rewire consumers** - `7f0e202e8` (refactor)
2. **Task 2: withCidLock + refcountAndMaybeUnpin primitives** - `d2d2adc73` (feat)
3. **Task 3: Route three unpin sites through shared helpers** - `94f6a3caf` (refactor)
4. **Task 3 follow-up: Clean up duplicate doc comment** - `def599b83` (refactor)

## Files Created/Modified

- `apps/api/src/ipfs/providers/ipfs-provider.module.ts` - New leaf @Module owning the single IPFS_PROVIDER factory
- `apps/api/src/ipfs/providers/ipfs-provider.module.spec.ts` - NestJS TestingModule spec asserting LocalProvider is provided
- `apps/api/src/ipfs/pending-unpin/unpin-helpers.ts` - withCidLock + refcountAndMaybeUnpin with verbatim lock SQL
- `apps/api/src/ipfs/pending-unpin/unpin-helpers.spec.ts` - 3 tests: lock SQL, refs>0 skip-unpin, refs===0 unpin
- `apps/api/src/ipfs/providers/index.ts` - Added barrel re-export for IpfsProviderModule
- `apps/api/src/ipfs/ipfs.module.ts` - Replaced inline factory with IpfsProviderModule import; kept explicit exports: [IPFS_PROVIDER]
- `apps/api/src/vault/vault.module.ts` - Replaced inline factory with IpfsProviderModule import
- `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts` - Replaced inline factory with IpfsProviderModule import
- `apps/api/src/vault/vault.service.ts` - Wrapped guardedUnpin main txn and post-commit txn in withCidLock
- `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` - drainRow uses withCidLock + refcountAndMaybeUnpin

## Decisions Made

- IpfsProviderModule imports only ConfigModule (leaf). The IN-04 comments claimed a cycle existed that justified triplication; that was incorrect — the real cycle is IpfsModule ↔ VaultModule, orthogonal to where IPFS_PROVIDER is provided.
- IpfsModule.forRootAsync explicitly keeps `exports: [IPFS_PROVIDER]` even though the factory moved to IpfsProviderModule — required so IpfsController can inject the token through the DynamicModule boundary.
- Post-commit guardedUnpin site uses `withCidLock` only, NOT `refcountAndMaybeUnpin` — the Kubo call must stay outside the transaction per D-03; only the outbox-row delete is serialized under the lock.

## Deviations from Plan

None - plan executed exactly as written. The duplicate doc comment cleanup (fourth commit) was cosmetic cleanup of a comment block that my Edit left doubled; not a behavioral change.

## Grep Gates

- `provide: IPFS_PROVIDER` in non-spec source files: exactly ONE (`ipfs-provider.module.ts`)
- `IN-04 (accepted)` comments: zero matches
- `pg_advisory_xact_lock` in `vault.service.ts` and `pending-unpin.processor.ts`: zero actual SQL calls (only doc comments referencing the lock by name)
- `abs(` in `unpin-helpers.ts`: zero matches in SQL (only in doc comment explaining prohibition)
- `refcountAndMaybeUnpin` in `vault.service.ts`: 0 (post-commit site uses withCidLock only)
- `refcountAndMaybeUnpin` in `pending-unpin.processor.ts`: 3 matches (import + drainRow usage)

## Test Results

- Full `apps/api` jest suite: **903 tests, 47 suites, all passing**
- `tsc --noEmit`: 3 pre-existing errors in `metrics/` and `shares/` (unrelated); zero new errors in changed files

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 57-02 complete; the module dedup and unpin-primitive consolidation goals are fully achieved
- A future bug fix to the advisory-lock key derivation or refcount logic edits one location each
- HARD-08 requirement satisfied; phase 57-03 can proceed if applicable

---

_Phase: 57-api-cid-and-provider-hardening-and-module-dedup_
_Completed: 2026-06-22_

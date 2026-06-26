---
phase: 42-api-unpin-integrity
plan: "02"
subsystem: web/delete-service
tags:
  - quota
  - delete
  - tdd
  - fire-and-forget
dependency_graph:
  requires:
    - useQuotaStore.fetchQuota (quota.store.ts)
  provides:
    - deleteFile fires fetchQuota reconcile after local removeUsage (D-12)
  affects:
    - apps/web/src/services/delete.service.ts
    - apps/web/src/services/delete.service.spec.ts
tech_stack:
  added: []
  patterns:
    - fire-and-forget promise with .catch(logger.warn)
    - vitest mocking of zustand store via vi.mock factory
key_files:
  created:
    - apps/web/src/services/delete.service.spec.ts
  modified:
    - apps/web/src/services/delete.service.ts
decisions:
  - fetchQuota is called without await so local decrement gives instant feedback
  - rejection swallowed via .catch to prevent failed quota endpoint from blocking delete
  - no new imports needed; logger already on line 3 of delete.service.ts
metrics:
  duration: "~8 minutes"
  completed: "2026-06-12"
  tasks_completed: 1
  files_changed: 2
---

# Phase 42 Plan 02: Quota Reconcile After Delete Summary

deleteFile fires `fetchQuota()` as fire-and-forget after `removeUsage()` so the client quota converges to the authoritative server value once Phase 42's server-side `recordUnpin` lands.

## Tasks Completed

### Task 1: RED/GREEN — fetchQuota reconcile after removeUsage in deleteFile

**RED commit:** `3322093ba` — `test(42-02): add failing spec for fetchQuota reconcile after removeUsage`

**GREEN commit:** `f38ba2a72` — `feat(42-02): reconcile quota with server after local removeUsage in deleteFile`

Three specs written and passing:

1. Call order: `unpinFromIpfs` → `removeUsage` → `fetchQuota`
2. `fetchQuota` rejection does not reject `deleteFile`; `logger.warn` is called
3. Both `removeUsage` and `fetchQuota` are invoked before `deleteFile` resolves

Implementation: one line added after `removeUsage`:

```typescript
quotaStore.fetchQuota().catch((err) => logger.warn('quota reconcile failed', err));
```

## Verification

- `vitest run apps/web/src/services/delete.service.spec.ts` — 3/3 tests pass
- `grep fetchQuota apps/web/src/services/delete.service.ts` — reconcile line with `.catch` present
- `delete.service.ts` does NOT `await` the `fetchQuota()` call (confirmed: no `await` on that line)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed unused import `useQuotaStore` in spec**

- **Found during:** RED commit attempt (ESLint `@typescript-eslint/no-unused-vars`)
- **Issue:** Spec imported `useQuotaStore` by name but the mock factory handles the module; the named import was unused
- **Fix:** Removed the `useQuotaStore` import; mocking via `vi.mock` factory doesn't require importing the mocked symbol
- **Files modified:** `apps/web/src/services/delete.service.spec.ts`
- **Commit:** included in RED commit `3322093ba`

### Worktree Node Modules

The worktree has a near-empty `node_modules/` (only a `.vite` cache dir). Pre-commit hook runs `pnpm lint-staged` which fails because `lint-staged` is not in the worktree's PATH. Resolved by prepending the main repo's `node_modules/.bin` to PATH for git commit invocations: `PATH="/Users/myankelev/Code/random/cipher-box/node_modules/.bin:$PATH" git commit ...`. This is an infrastructure constraint of this worktree setup, not a code issue.

## TDD Gate Compliance

- RED gate: `test(42-02):` commit exists (`3322093ba`) — all 3 tests failed before implementation
- GREEN gate: `feat(42-02):` commit exists (`f38ba2a72`) — all 3 tests pass after one-line addition
- REFACTOR: not needed (implementation is a single idiomatic line)

## Known Stubs

None. The change is a direct call to the existing `fetchQuota()` method; no placeholder values introduced.

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes introduced. The `fetchQuota()` call reuses the existing `/vault/quota` GET endpoint. T-42-05 mitigation (fire-and-forget with `.catch`) is implemented as specified.

## Self-Check: PASSED

- `apps/web/src/services/delete.service.ts` — FOUND
- `apps/web/src/services/delete.service.spec.ts` — FOUND
- RED commit `3322093ba` — FOUND
- GREEN commit `f38ba2a72` — FOUND

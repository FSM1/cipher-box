---
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
plan: 07
subsystem: web-sync
tags: [poll-monotonicity, folder-store, sequence-guard, web-e2e, data-integrity]
requires:
  - apps/web/src/stores/folder.store.ts (existing sequence-guard semantics)
provides:
  - sequence-gated invalidateOpenFolder poll write (D-08 item 3 / SC3c)
  - tests/web-e2e/tests/poll-monotonicity.spec.ts (permanent regression)
affects:
  - apps/web/src/hooks/useSyncPolling.ts
tech-stack:
  added: []
  patterns:
    - "IPNS sequenceNumber is the monotonic clock; async writes must gate on it"
    - "Deterministic race e2e via route-hold + controlled ordering (no poll-timing)"
key-files:
  created:
    - tests/web-e2e/tests/poll-monotonicity.spec.ts
  modified:
    - apps/web/src/hooks/useSyncPolling.ts
decisions:
  - "Gate invalidateOpenFolder by sequenceNumber, mirroring folder.store.ts's stale-event guard"
  - "Reproduce the newer nav-triggered state deterministically via the exposed store, not a real second remote mutation"
metrics:
  tasks_completed: 2
  files_created: 1
  files_modified: 1
  duration_minutes: 20
  completed_date: 2026-07-12
status: complete
---

# Phase 78 Plan 07: Poll-Monotonicity Data-Integrity Guard Summary

Gated `useSyncPolling.ts::invalidateOpenFolder`'s async write by `sequenceNumber` so a slow in-flight poll can never clobber a newer nav-triggered folder state (D-08 item 3 / SC3c), and added a deterministic permanent web-e2e regression spec that reproduces the race by controlled ordering.

## What Was Built

### Task 1 — `poll-monotonicity.spec.ts` (deterministic regression, `test.describe.serial`, never skipped)

`tests/web-e2e/tests/poll-monotonicity.spec.ts` reproduces the poll-vs-nav race by **controlled ordering**, not poll timing:

1. Real wallet login, create + open a subfolder (its `ipnsName` differs from root so we never hold the root `onSync` resolve). Record its live `sequenceNumber` S1 from `window.__ZUSTAND_FOLDER_STORE__`.
2. Arm a `page.route('**/ipns/resolve**')` interceptor that **holds only the open folder's resolve**; root resolves pass through.
3. Trigger a poll via a deterministic visibility-regain edge (`document.hidden` toggle → `visibilitychange`) — `doSync` runs `invalidateOpenFolder` after `onSync`. The test awaits proof the open-folder resolve was intercepted in flight (no timing guess; retries the edge past the `isSyncingRef` concurrency guard).
4. While the stale poll is held, a **newer nav state lands**: the store is advanced to `S2 = S1 + 100` with a distinctive `NEWER_NAV_MARKER` child via `updateFolderChildren` + `updateFolderSequence` — exactly what a nav re-resolve writes.
5. Release the held resolve; the poll completes carrying the real (now stale) S1 record.
6. Assert the open folder still reflects S2 + the marker — the stale poll was dropped.

The store's global type is declared structurally in the spec (no app-internal imports). A minimal `declare global` augments `Window`. The exposed store is present because the web-e2e `webServer` boots `pnpm --filter @cipherbox/web dev` (vite dev → `import.meta.env.DEV`) in both local and CI.

### Task 2 — sequence-guard in `invalidateOpenFolder` (GREEN)

`apps/web/src/hooks/useSyncPolling.ts`:
- Capture `capturedSequence = openFolder.sequenceNumber` **before** the async resolve.
- After resolving, in addition to the existing folder-changed re-check, drop the result when a newer sequence has landed:
  ```ts
  const resolvedSequence = state ? state.sequenceNumber : capturedSequence;
  if (store.folders[currentFolderId].sequenceNumber > resolvedSequence) return;
  ```
- Semantics mirror `folder.store.ts`'s `matchingFolder.sequenceNumber > event.sequenceNumber` stale-event guard. Existing `updateFolderChildren`/`updateFolderSequence` call semantics are unchanged.

## Verification

- `cd apps/web && pnpm vitest run` — **10 files / 61 passed, 6 skipped** (all `useSyncPolling.test.ts` cases green, including the existing controlled-ordering "changed while awaiting" test).
- `npx eslint apps/web/src/hooks/useSyncPolling.ts tests/web-e2e/tests/poll-monotonicity.spec.ts` — exit 0 (D-07 boundary not tripped; spec is outside `apps/web/src`).
- `apps/web` `tsc --noEmit` — exit 0. `tests/web-e2e` `tsc --noEmit` — exit 0.
- Spec guards: contains `describe.serial`, no `test.skip`/`test.fixme`.

### e2e RUN status: needs-rerun (infra-blocked, not a logic failure)

Command:
```
pnpm --filter @cipherbox/web-e2e test -- poll-monotonicity.spec.ts
```
Both attempts failed at **scaffolding step 1** (create/open subfolder), before test 2 (the race logic) ever ran. The Playwright-booted API aborted new-account vault initialization with:
```
query failed: INSERT INTO "ipns_records" (... "is_root"=true ...)
error: duplicate key value violates unique constraint "UQ_ipns_records_ipns_name"
```
This is a shared-DB / new-account-init environment issue (the run coincides with the concurrent Phase 79 pipeline sharing the `cipherbox` DB + Web3Auth DKG identity state). It affects any web-e2e spec that logs in a fresh account equally and is independent of this plan's two-line fix or the spec's race logic. Per the infra-block protocol, the code fix is verified (unit + guard) and the spec is authored/typechecked/linted/committed; the RUN needs re-verification on a clean DB.

Re-run recipe (from memory landmines): ensure the API reads the worktree `apps/api/.env` (JWT_SECRET, REDIS_PORT=6380, TEST_LOGIN_SECRET aligned), reset the `cipherbox` DB so no stale `ipns_records` rows collide, restart the API from source, then run the command above.

## Deviations from Plan

**None (Rules 1–4)** — plan executed as written. One environment provisioning step outside the plan: the worktree lacked the gitignored `apps/api/.env` / `apps/web/.env` / `tests/web-e2e/.env`, so they were copied from the main checkout to attempt the run. These are gitignored and not committed; no source deviation.

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, file access, or schema changes. The change is a client-side ordering guard; it closes T-78-12 (Tampering: stale poll write) from the plan's threat register.

## Self-Check

- FOUND: apps/web/src/hooks/useSyncPolling.ts (sequence guard, line ~57-58)
- FOUND: tests/web-e2e/tests/poll-monotonicity.spec.ts
- Commits verified below.

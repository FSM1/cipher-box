---
created: 2026-07-06T00:00:00Z
title: D-03 poll-invalidation freshness leg lacks dedicated automated coverage (Phase 68.2 Plan 09)
area: web
files:
  - apps/web/src/hooks/useSyncPolling.ts
  - apps/web/src/stores/folder.store.ts
  - .planning/phases/68.2-sdk-owned-read-chain-and-resolved-folder-listings/68.2-09-PLAN.md
  - .planning/phases/68.2-sdk-owned-read-chain-and-resolved-folder-listings/68.2-05-PLAN.md
source: Phase 68.2 plan-checker WARNING (non-blocking; checker recommended proceed + log follow-up)
type: research
resolves_phase: null
---

## Problem

D-03 (locked) requires **belt-and-suspenders** freshness: (1) re-resolve on every
folder open/navigation AND (2) poll-driven invalidation for the currently-open
folder. Leg (1) — the deterministic nav-resolve — is the primary SC#5 fix and is
covered behaviorally by the Plan 05 desync web-e2e (exercised as the Plan 12 phase
gate). Leg (2) — the **poll-driven invalidation** — has no dedicated automated
proof in the 12-plan set:

- Plan 05's e2e explicitly drives "the deterministic nav-triggered re-resolve …
  not the 30s poll timing."
- Plan 09 Task 2's acceptance for the poll leg is **grep-only**
  (`grep -rn "listFolder" …useSyncPolling.ts`) — it asserts the call site exists,
  not that invalidation actually fires on a poll tick when the open folder's IPNS
  `sequenceNumber` bumps.

This matches the known project landmine "grep-based ACs can force runtime-broken
impls" — a poll leg that greps clean can still fail to invalidate at runtime.

## Why it's non-blocking

The poll leg is a redundancy mechanism layered on top of the deterministic
nav-resolve fix, which IS tested. So the desync bug class (SC#5) is closed even if
the poll leg is subtly wrong; the risk is a bounded, up-to-~30s staleness window
for an already-open folder, not a correctness/security hole.

## Suggested fix (before or during Plan 09 execution)

Add a behavioral test for the poll-invalidation path independent of nav-resolve:
either a Plan 09 unit/integration test that simulates a poll tick observing a
higher `sequenceNumber` for the open folder and asserts the SDK cache is
invalidated + a `folder:updated` event fires, or a dedicated web-e2e case that
leaves a folder open and asserts a grantee's later write appears via the poll
(not via navigation). Upgrade Plan 09 Task 2's poll AC from grep to that test.

## Disposition

Re-check at Phase 68.2 gap-closure (or when Plan 09 executes). If Plan 09's
executor upgrades the poll AC to a behavioral test, retire this todo.

## Resolution (2026-07-06, Plan 09)

Added `apps/web/src/hooks/__tests__/useSyncPolling.test.ts` (6 tests) directly
exercising the poll-invalidation leg's exported `invalidateOpenFolder`
function against the real `useFolderStore` (no React render harness, only
the SDK client boundary mocked). Covers: a poll tick observing a higher
`sequenceNumber` re-projects children/rawChildren/sequenceNumber; no-ops when
no folder is open, the open folder isn't loaded yet, or the SDK client isn't
initialized; a resolve failure is swallowed (best-effort, never fails the
poll tick); and a stale in-flight resolve is discarded if the open folder
changes mid-flight. Retiring per the disposition above.

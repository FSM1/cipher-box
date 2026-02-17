---
phase: 07-multi-device-sync
plan: 02
subsystem: ui
tags: [react, hooks, polling, visibility, network, zustand]

# Dependency graph
requires:
  - phase: 07-01
    provides: sync state store (useSyncStore)
provides:
  - useInterval hook with proper cleanup
  - useVisibility hook for Page Visibility API
  - useOnlineStatus hook for network detection
  - useSyncPolling orchestrator hook
affects: [07-03, ui-components, sync-indicator]

# Tech tracking
tech-stack:
  added: []
  patterns: [useRef for stale callback prevention, Page Visibility API, navigator.onLine]

key-files:
  created:
    - apps/web/src/hooks/useInterval.ts
    - apps/web/src/hooks/useVisibility.ts
    - apps/web/src/hooks/useOnlineStatus.ts
    - apps/web/src/hooks/useSyncPolling.ts
  modified:
    - apps/web/src/hooks/index.ts

key-decisions:
  - 'Pause polling when tab backgrounded (battery optimization per RESEARCH.md)'
  - 'Immediate sync on visibility regain (per RESEARCH.md recommendation)'
  - 'Immediate sync on reconnect (per CONTEXT.md)'
  - 'useRef for callback tracking to avoid stale closure issue'

patterns-established:
  - 'useInterval: pass null delay to pause, cleanup on unmount'
  - 'Edge detection via useRef tracking previous state values'
  - "SSR guards: typeof document/navigator !== 'undefined'"

# Metrics
duration: 3min
completed: 2026-02-02
---

# Phase 7 Plan 02: Polling Infrastructure Hooks Summary

Custom React hooks for interval polling, tab visibility, network status, and sync orchestration with proper cleanup and SSR safety.

## Performance

- **Duration:** 3 min
- **Started:** 2026-02-02T02:36:34Z
- **Completed:** 2026-02-02T02:39:43Z
- **Tasks:** 2
- **Files created:** 4
- **Files modified:** 1

## Accomplishments

- Created useInterval hook with ref-based callback and null-delay pause mechanism
- Created useVisibility hook wrapping Page Visibility API with SSR guard
- Created useOnlineStatus hook with online/offline event listeners and SSR guard
- Created useSyncPolling orchestrator that polls every 30s when visible+online, pauses otherwise
- Implemented immediate sync on visibility regain and network reconnect

## Task Commits

Each task was committed atomically:

1. **Task 1: Create utility hooks** - `f890d9f` (feat)
2. **Task 2: Create useSyncPolling orchestrator hook** - `e6b175f` (feat)

## Files Created/Modified

- `apps/web/src/hooks/useInterval.ts` - Reusable interval hook with cleanup, null pauses
- `apps/web/src/hooks/useVisibility.ts` - Page Visibility API wrapper
- `apps/web/src/hooks/useOnlineStatus.ts` - Network status detection via navigator.onLine
- `apps/web/src/hooks/useSyncPolling.ts` - Main sync polling orchestrator combining all hooks
- `apps/web/src/hooks/index.ts` - Added exports for all new hooks

## Decisions Made

1. **Pause polling when backgrounded** - Per RESEARCH.md recommendation, saves battery by setting delay to null when tab is hidden
2. **Immediate sync on focus regain** - Per RESEARCH.md, poll immediately when user returns to tab for fresh data
3. **Immediate sync on reconnect** - Per CONTEXT.md, auto-sync when connection returns
4. **useRef for callback tracking** - Prevents stale callback closure issue documented in RESEARCH.md pitfalls
5. **SSR guards on all hooks** - typeof checks prevent errors during server-side rendering

## Deviations from Plan

None - plan executed exactly as written.

Note: The sync store (useSyncStore) was already created by plan 07-01 which was executed prior to this plan. No additional deviations were needed.

## Issues Encountered

None - all hooks compiled and linted successfully on first attempt.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Polling infrastructure complete and ready for sync service integration
- useSyncPolling hook takes an onSync callback that will be implemented in Plan 03 (sync service)
- All four hooks are exported from the hooks barrel file
- Ready for SyncIndicator component to consume sync state

---

_Phase: 07-multi-device-sync_
_Completed: 2026-02-02_

---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 04
subsystem: ui
tags: [react, zustand, notifications, accessibility, terminal-aesthetic]

# Dependency graph
requires:
  - phase: 68-web-integration-rotation-ux-and-durable-client-state
    provides: 68-UI-SPEC.md design contract (narrow five-state notification/status surface)
provides:
  - "Notification.action?: { label; onClick } field on the existing notification store"
  - "NotificationToast renders an action button before [x] dismiss, and terminal error+action toasts skip auto-dismiss"
  - "rotation.store.ts presentation-only status state machine (idle/root-cut/tail-walk/resuming)"
  - "RotationStatusBadge.tsx non-interactive header status pill mounted in AppHeader"
affects: [68-08-badge-lifecycle-driver, 68-09-mutation-failure-toasts, 68-10-web-e2e-rotation-ux]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Notification action affordance: optional action?: { label; onClick } rendered as a muted/green-on-hover text button before the existing [x] dismiss"
    - "Rotation status store: string-literal union status, plain Zustand set(), no persistence/IndexedDB reads (driver plans own that)"
    - "Rotation badge color semantics: green border + spinner for root-cut (active/healthy); warning-accent border, no spinner, for tail-walk/resuming (background, non-blocking) per the UI-SPEC Color table's explicit 'rotation-tail badge accent' assignment"

key-files:
  created:
    - apps/web/src/stores/rotation.store.ts
    - apps/web/src/components/layout/RotationStatusBadge.tsx
  modified:
    - apps/web/src/stores/notification.store.ts
    - apps/web/src/components/NotificationToast.tsx
    - apps/web/src/components/layout/AppHeader.tsx
    - apps/web/src/styles/layout.css
    - apps/web/src/index.css

key-decisions:
  - "Resolved a UI-SPEC internal inconsistency (Copywriting Contract table says tail-walk uses a 'green border'; the Color table explicitly assigns --color-warning to 'rotation-tail badge accent', and the task's read_first note said the same) by following the Color table + task hint: green+spinner only for root-cut, warning-accent static pill for tail-walk/resuming."
  - "Action button hover/default color implemented via a new .notification-action-btn CSS class in index.css (global) rather than inline styles, since inline styles cannot express :hover; the existing [x] dismiss button was left untouched (extend, don't replace)."
  - "Reused the existing layout.css @keyframes pulse (already used by .status-indicator-dot--loading) for the badge's root-cut spinner instead of introducing a new keyframe, keeping with the terminal aesthetic's ASCII/no-icon-library convention."

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "Notification action field + toast action button rendering (D-01 Refresh access / D-06 Retry), error+action toasts skip auto-dismiss"
    requirement: "ROT-07"
    verification:
      - kind: e2e
        ref: "68-10 web-e2e rotation-ux spec (action-toast rendering) — not yet written, deferred to 68-10"
        status: unknown
    human_judgment: true
    rationale: "Per docs/TESTING.md, apps/web UI has no unit tests; behavior is proven by the not-yet-executed 68-10 web-e2e spec. Static verification (grep + tsc) passed in this plan; runtime behavior is unverified until 68-10 runs."
  - id: D2
    description: "rotation.store.ts status state machine (idle/root-cut/tail-walk/resuming) with beginRootCut/beginTailWalk/markResuming/reset setters"
    requirement: "ROT-07"
    verification:
      - kind: e2e
        ref: "68-10 web-e2e rotation-ux spec (badge lifecycle) — not yet written, deferred to 68-10"
        status: unknown
    human_judgment: true
    rationale: "Presentation-only store with no driver wired yet (68-08 wires the driver); lifecycle behavior proven only once 68-10 runs against a real driver."
  - id: D3
    description: "RotationStatusBadge non-interactive status pill mounted in AppHeader .header-right, hidden when idle, role=status aria-live=polite"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "grep assertions: RotationStatusBadge mounted in AppHeader.tsx; aria-live=polite present once; assertive absent; onClick absent in RotationStatusBadge.tsx"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/web exec tsc --noEmit (via pnpm typecheck, workspace deps built first)"
        status: pass
    human_judgment: false

# Metrics
duration: 35min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 04: Rotation/Notification UI Surface Summary

**Notification action-button affordance plus a non-interactive rotation status badge (Zustand store + AppHeader mount), reusing the existing terminal-aesthetic toast/header primitives with zero new UI dependencies.**

## Performance

- **Duration:** 35 min
- **Started:** 2026-07-01T16:00Z (approx)
- **Completed:** 2026-07-01T16:33:10Z
- **Tasks:** 3
- **Files modified:** 7 (2 new, 5 modified)

## Accomplishments
- `Notification` type extended with an optional `action?: { label; onClick }` field; `NotificationToast` renders it as a muted/green-on-hover text button before the `[x]` dismiss, and terminal error+action toasts (D-06 exhaustion) skip auto-dismiss
- New `rotation.store.ts` (Zustand) exposing a string-literal `status: 'idle' | 'root-cut' | 'tail-walk' | 'resuming'` state machine with `beginRootCut`/`beginTailWalk`/`markResuming`/`reset` setters — presentation-only, no IndexedDB/crypto coupling
- New `RotationStatusBadge.tsx` — a non-interactive `role="status"` `aria-live="polite"` pill mounted in `AppHeader`'s `.header-right` before `UserMenu`, hidden when idle, reusing `.header-search-btn`'s spacing/typography tokens

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend Notification with action field + render action button in toast** - `ab2388308` (feat)
2. **Task 2: rotation.store.ts status state machine** - `af0e9a96a` (feat)
3. **Task 3: RotationStatusBadge + mount in AppHeader** - `be733ba55` (feat)

**Plan metadata:** (this commit, docs)

## Files Created/Modified
- `apps/web/src/stores/notification.store.ts` - Added `action?: { label; onClick }` field to `Notification`, threaded through `addNotification`
- `apps/web/src/components/NotificationToast.tsx` - Renders the action button before `[x]`; gates the auto-dismiss timer so error+action toasts never auto-dismiss
- `apps/web/src/index.css` - Added `.notification-action-btn` (muted default, green on hover) since inline styles can't express `:hover`
- `apps/web/src/stores/rotation.store.ts` - New Zustand store, `useRotationStore`, string-literal `status` union, plain setters
- `apps/web/src/components/layout/RotationStatusBadge.tsx` - New non-interactive status pill component
- `apps/web/src/components/layout/AppHeader.tsx` - Mounts `<RotationStatusBadge />` in `.header-right` before `<UserMenu />`
- `apps/web/src/styles/layout.css` - Added `.rotation-status-badge`, `.rotation-status-badge--background`, `.rotation-status-badge__spinner` (reuses existing `@keyframes pulse`)

## Decisions Made
- **UI-SPEC color conflict resolved via Color table + task hint:** the Copywriting Contract table's tail-walk row says "green border," but the Color table explicitly assigns `--color-warning` to "rotation-tail badge accent," and the task's `<read_first>` note said the same ("green border healthy, warning accent on tail"). Implemented root-cut = green border + spinner (healthy/active), tail-walk/resuming = warning-accent border, static, no spinner (background/non-blocking). Flagging this for the post-wave UI safety gate since the source document is internally inconsistent.
- Added a new global `.notification-action-btn` CSS class (index.css) for the action button's muted-default/green-hover treatment, since `NotificationToast` is otherwise fully inline-styled and inline styles cannot express `:hover`. Left the existing `[x]` dismiss button's styling untouched.
- Reused the existing `@keyframes pulse` (already driving `.status-indicator-dot--loading`) for the badge's root-cut spinner instead of adding a new keyframe.

## Deviations from Plan

None (Rule 1/2/3 sense) — no bugs found, no missing critical functionality, no blocking issues. The one interpretive call (badge tail-walk/resuming color) is documented above under Decisions Made since it resolves an ambiguity/inconsistency within the approved UI-SPEC document itself, not a deviation from the plan's explicit instructions (the plan's `<action>` text for Task 3 did not specify a border color for tail-walk/resuming, only "static pill, no spinner").

## Issues Encountered
- `pnpm --filter @cipherbox/web exec tsc --noEmit` alone fails in a fresh worktree because `@cipherbox/core`/`@cipherbox/sdk-core`/`@cipherbox/sdk`/`@cipherbox/crypto`/`@cipherbox/api-client` have no built `dist/` yet (cross-package dist staleness, a known project gotcha). Resolved by running the root `pnpm typecheck` script instead, which builds workspace deps in dependency order before running `tsc -b` on `apps/web` — this is also what `<project_setup_gotchas>` in the executor prompt specified as the correct verification command. All three tasks' individual `tsc --noEmit` grep-gated verify commands passed once the dependency dists existed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- The action-button primitive and rotation status store/badge exist and typecheck cleanly; 68-08 (badge lifecycle driver) and 68-09 (mutation-failure toasts) can now wire behavior into these primitives without touching chrome.
- Runtime/behavioral proof (badge state transitions, action-toast rendering, auto-dismiss suppression) is deferred to the 68-10 web-e2e rotation-ux spec, as intended by this plan's scope — coverage entries D1/D2 above are marked `human_judgment: true` pending that spec.
- Flag for the post-wave UI safety gate: verify the tail-walk/resuming warning-accent color choice against the UI-SPEC's internally conflicting Copywriting Contract vs. Color table language (see Decisions Made).

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*

## Self-Check: PASSED

All created files and task commit hashes verified present on disk / in git log.

---
phase: quick
plan: 011
subsystem: ui
tags: [react, css, health-check, login, footer, status-indicator]

requires:
  - phase: quick-010
    provides: 'Matrix effect visibility improvements on login page'
provides:
  - 'Login page footer with copyright, links, and StatusIndicator'
  - 'API-aware connect button that disables when API is unreachable'
affects: []

tech-stack:
  added: []
  patterns:
    - 'Health check hook lifted to parent for cross-component API awareness'

key-files:
  created: []
  modified:
    - apps/web/src/routes/Login.tsx
    - apps/web/src/components/auth/AuthButton.tsx
    - apps/web/src/App.css

key-decisions:
  - "Kept StatusIndicator in footer (uses React Query deduplication with Login's health hook)"
  - 'Used absolute positioning for login-footer to stay at bottom of login-container'

patterns-established:
  - 'apiDown prop pattern: parent lifts health state, child button disables itself'

duration: 3min
completed: 2026-02-11
---

# Quick Task 011: Login Footer Status Indicator Summary

**Login page footer restored with StatusIndicator moved from panel to footer, and connect button disabled with [API OFFLINE] when API is unreachable**

## Performance

- **Duration:** 3 min
- **Started:** 2026-02-11T17:25:45Z
- **Completed:** 2026-02-11T17:28:45Z
- **Tasks:** 1
- **Files modified:** 3

## Accomplishments

- Restored login page footer matching AppShell footer content pattern (copyright, links, status indicator)
- Moved StatusIndicator from inside login-panel to the footer-right section
- Added useHealthControllerCheck hook to Login component for API status awareness
- AuthButton now accepts `apiDown` prop, shows [API OFFLINE] with red border styling when API is down
- Footer appears in both loading and ready states for consistent UX
- Added focus-visible styles on footer links for keyboard accessibility

## Task Commits

Each task was committed atomically:

1. **Task 1: Add footer to Login page and lift health state** - `9745251` (fix)

## Files Created/Modified

- `apps/web/src/routes/Login.tsx` - Added health hook, moved StatusIndicator to footer, passed apiDown to AuthButton
- `apps/web/src/components/auth/AuthButton.tsx` - Added apiDown prop, disabled state, [API OFFLINE] text, api-down CSS class
- `apps/web/src/App.css` - Added login-footer positioning, login-button--api-down styles, focus-visible for footer links

## Decisions Made

- Kept StatusIndicator component in the footer rather than replacing it with inline health status display. React Query deduplicates the identical health queries from both Login and StatusIndicator, so there is no double-fetching.
- Used absolute positioning for the login-footer (bottom: 0) since login-container is already position: relative with min-height: 100vh, ensuring the footer stays at the page bottom.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Login page now has proper footer with status indicator
- Connect button provides clear feedback when API is unavailable
- No blockers for future work

---

_Quick Task: 011-login-footer-status-indicator_
_Completed: 2026-02-11_

---
phase: 15-link-sharing
plan: 03
subsystem: ui
tags: [react, tabs, invite-link, landing-page, auth, hashrouter, css, aria]

# Dependency graph
requires:
  - phase: 14
    provides: ShareDialog component, share.store, ECIES key-wrapping
  - phase: 15-01
    provides: InvitesController, ShareInvitesController, API endpoints
  - phase: 15-02
    provides: invite.service.ts (createInviteLink, claimInvite, checkInviteStatus), collectChildKeys utility
provides:
  - Tabbed ShareDialog with Direct Share and Invite Link tabs
  - InviteLinkTab component for invite link creation, listing, and revocation
  - InvitePage standalone landing page with auth integration and auto-claim
  - Route /invite/:token configured outside AppShell
affects:
  - 15-04 (E2E tests exercise ShareDialog invite tab and InvitePage claim flow)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Tabbed modal with ARIA tablist/tab/tabpanel roles'
    - 'Standalone auth page with inline Google/Email/Wallet matching Login.tsx'
    - 'Auto-claim on isAuthenticated transition via useEffect with claimingRef guard'
    - 'Ephemeral key in useRef (not state) to prevent re-render loss'

key-files:
  created:
    - apps/web/src/components/file-browser/InviteLinkTab.tsx
    - apps/web/src/routes/InvitePage.tsx
    - apps/web/src/styles/invite-page.css
  modified:
    - apps/web/src/components/file-browser/ShareDialog.tsx
    - apps/web/src/routes/index.tsx
    - apps/web/src/styles/share-dialog.css
    - apps/api/src/shares/shares.service.spec.ts

key-decisions:
  - 'Auto-claim via useEffect watching isAuthenticated -- navigate(/shared, replace:true) overrides useAuth navigate(/files)'
  - 'Ephemeral key stored in useRef not useState -- prevents re-render loss and accidental logging'
  - 'MFA/REQUIRED_SHARE handled with same DeviceWaitingScreen and RecoveryInput as Login.tsx'

patterns-established:
  - 'Standalone auth page pattern: MatrixBackground + StagingBanner + inline auth components (reusable for future public pages)'
  - 'Tab bar with focus-visible and ARIA roles for accessible modal navigation'

# Metrics
duration: 12min
completed: 2026-02-23
---

# Phase 15 Plan 03: ShareDialog Tabbed UI + InvitePage Landing Page Summary

**Tabbed ShareDialog with Direct Share and Invite Link tabs, InvitePage landing page with inline auth (Google/Email/Wallet) and auto-claim flow via ephemeral key bridge**

## Performance

- **Duration:** 12 min
- **Started:** 2026-02-23T01:09:11Z
- **Completed:** 2026-02-23T01:21:12Z
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments

- ShareDialog now has tab bar (DIRECT SHARE | INVITE LINK) with ARIA tablist/tab/tabpanel roles, widened to 600px
- InviteLinkTab creates invite links with clipboard auto-copy, shows active invites with status badges, and revoke with inline confirm
- InvitePage at /#/invite/:token?key=<hex> shows branded landing page with state machine (loading/valid/claiming/claimed/error)
- InvitePage renders inline Google, Email, Wallet auth matching Login.tsx patterns with MFA/device-approval support
- Auto-claim triggers when isAuthenticated transitions to true, navigates to /shared after success
- Ephemeral key zeroed in both success and finally paths; never logged

## Task Commits

Each task was committed atomically:

1. **Task 1: ShareDialog tabbed interface + InviteLinkTab** - `f6e01b785` (feat)
2. **Task 2: InvitePage landing page + route config** - `59dc3c94b` (feat)
3. **Task 3: InvitePage auth integration, claim flow, build verification** - `d8e360ff4` (feat)

## Files Created/Modified

- `apps/web/src/components/file-browser/InviteLinkTab.tsx` - Invite link creation, listing, and management UI component
- `apps/web/src/components/file-browser/ShareDialog.tsx` - Updated with tab bar, activeTab state, InviteLinkTab integration
- `apps/web/src/routes/InvitePage.tsx` - Standalone invite landing page with auth + auto-claim
- `apps/web/src/routes/index.tsx` - Added /invite/:token route outside AppShell
- `apps/web/src/styles/share-dialog.css` - Tab bar styles, invite link item styles, 600px modal width
- `apps/web/src/styles/invite-page.css` - Full-viewport centered card, green/red variants, terminal aesthetic
- `apps/api/src/shares/shares.service.spec.ts` - Fixed missing ShareInvite mock repository

## Decisions Made

- **Auto-claim via useEffect watching isAuthenticated**: When auth completes, useAuth navigates to /files. The InvitePage useEffect detects isAuthenticated=true, sets pageState='claiming', runs claimInvite, then navigates to /shared with replace:true to override the pending /files navigation.
- **Ephemeral key in useRef**: Stored as ref (not state) to prevent loss on re-renders and to avoid accidental serialization/logging. Zeroed to null after claim (success or failure).
- **MFA/REQUIRED_SHARE support**: InvitePage renders DeviceWaitingScreen and RecoveryInput matching Login.tsx patterns. After MFA resolves, the auto-claim useEffect fires normally.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed pre-existing shares.service.spec.ts missing ShareInvite mock**

- **Found during:** Task 3 (build verification)
- **Issue:** Plan 15-01 added @InjectRepository(ShareInvite) to SharesService but didn't update shares.service.spec.ts mock providers, causing all 37 tests to fail with dependency injection error
- **Fix:** Added ShareInvite import and mockShareInviteRepo to test module providers
- **Files modified:** apps/api/src/shares/shares.service.spec.ts
- **Verification:** All 37 tests pass, full suite 529/529 pass
- **Committed in:** d8e360ff4 (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary fix for test suite correctness. No scope creep.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All frontend UI for invite link sharing is complete
- Ready for Plan 15-04 (E2E test suite for invite link workflow)
- No blockers

---

_Phase: 15-link-sharing_
_Completed: 2026-02-23_

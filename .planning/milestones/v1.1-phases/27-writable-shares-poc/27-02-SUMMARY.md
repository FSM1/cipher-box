---
phase: 27-writable-shares-poc
plan: 02
subsystem: ui
tags: [react, zustand, ecies, ipns, css, a11y, radio-group]

# Dependency graph
requires:
  - phase: 27-writable-shares-poc
    provides: Share entity with permission/encryptedIpnsKey columns, UpdatePermissionDto, API client with permission types
  - phase: 14-sharing
    provides: ShareDialog, share.store.ts, share.service.ts, key-wrapping utilities
provides:
  - ReceivedShare and SentShare types with permission fields
  - updateSharePermission service function
  - ShareDialog permission toggle (read-only / read-write radio group)
  - IPNS private key wrapping for write shares in creation and upgrade flows
  - Recipient list with [read]/[write] labels and --upgrade/--downgrade controls
  - Permission-aware CSS with terminal aesthetic
affects: [27-03, shared-file-browser, recipient-write-actions]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Permission toggle using role=radiogroup with ArrowLeft/ArrowRight keyboard navigation
    - IPNS key unwrap-rewrap pattern for write share creation and upgrade
    - Inline confirm pattern reused for downgrade (matching existing revoke UX)
    - updateSentSharePermission optimistic local state update

key-files:
  created: []
  modified:
    - apps/web/src/stores/share.store.ts
    - apps/web/src/services/share.service.ts
    - apps/web/src/components/file-browser/ShareDialog.tsx
    - apps/web/src/styles/share-dialog.css

key-decisions:
  - 'Permission toggle only shown for folder shares (file shares have no IPNS keys to wrap)'
  - 'Upgrade requires no confirmation (non-destructive); downgrade uses confirm? [y] [n] inline pattern matching revoke UX'
  - 'IPNS private key zeroed immediately after wrapping (ipnsPrivKey.fill(0) in finally block)'

patterns-established:
  - 'IPNS key wrapping for write shares: unwrap owner ECIES -> wrap for recipient ECIES -> hex encode for API'
  - 'Permission upgrade/downgrade uses updateSharePermission service with optimistic local state update via updateSentSharePermission store action'

requirements-completed: [SHARE-05, SHARE-06, SHARE-07]

# Metrics
duration: 5min
completed: 2026-03-26
---

# Phase 27 Plan 02: Owner Share Dialog UI Summary

**ShareDialog with permission toggle (read-only/read-write radio group), IPNS key wrapping for write shares, and inline recipient permission upgrade/downgrade controls**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-26T04:28:07Z
- **Completed:** 2026-03-26T04:33:28Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Share store types extended with permission and encryptedIpnsKey fields for both ReceivedShare and SentShare
- Share service has updateSharePermission function wrapping the new PATCH endpoint
- ShareDialog renders terminal-style permission toggle between pubkey input and share button
- Write shares wrap IPNS private key for recipient using ECIES (unwrap owner key, re-wrap for recipient)
- Recipients list shows [read]/[write] labels with --upgrade and --downgrade inline controls
- Downgrade uses confirm? [y] [n] pattern identical to existing revoke UX

## Task Commits

Each task was committed atomically:

1. **Task 1: Share store types and share service updates** - `72e5b27` (feat)
2. **Task 2: ShareDialog permission toggle, IPNS key wrapping, and recipient management** - `736ece3` (feat)

## Files Created/Modified

- `apps/web/src/stores/share.store.ts` - Added permission/encryptedIpnsKey to ReceivedShare, permission to SentShare, updateSentSharePermission action
- `apps/web/src/services/share.service.ts` - Added updateSharePermission function, updated fetch mappings to include permission fields
- `apps/web/src/components/file-browser/ShareDialog.tsx` - Permission toggle UI, IPNS key wrapping in handleShare and handleUpgrade, recipient list with permission labels and upgrade/downgrade controls
- `apps/web/src/styles/share-dialog.css` - Styles for permission toggle, recipient permission labels, upgrade/downgrade buttons with modern rgb() color syntax

## Decisions Made

- **Permission toggle only for folders:** File shares have no IPNS keys, so the permission toggle is conditionally rendered only when `item.type === 'folder'`. File shares always default to read-only.
- **No confirmation for upgrade:** Upgrade is non-destructive (grants more access), so it executes immediately. Downgrade requires confirmation since it removes write capability.
- **Sensitive key zeroing:** IPNS private key is zeroed in a `finally` block immediately after wrapping, following the project's security rules for clearing sensitive data from memory.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Owner-facing UI for writable shares is complete: create write shares, upgrade/downgrade existing recipients
- Plan 27-03 (recipient-facing write actions) can proceed using the permission and encryptedIpnsKey fields now present in share types
- SharedFileBrowser needs to conditionally render write toolbar and [RW] badge based on permission (Plan 03 scope)

---

## Self-Check: PASSED

All 4 modified files verified present. Both commit hashes (72e5b27, 736ece3) confirmed in git log.

---

_Phase: 27-writable-shares-poc_
_Completed: 2026-03-26_

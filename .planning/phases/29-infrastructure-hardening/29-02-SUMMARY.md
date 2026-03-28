---
phase: 29-infrastructure-hardening
plan: 02
subsystem: sdk
tags: [sdk, ipns, tee, unenroll, bin, delete]

requires:
  - phase: 29-infrastructure-hardening
    provides: POST /ipns/unenroll endpoint and ipnsControllerUnenrollBatch client function (plan 01)
provides:
  - fireAndForgetUnenroll() method in CipherBoxClient
  - collectSubtreeIpnsNames() recursive IPNS name collector
  - Automatic IPNS unenrollment on deleteItem, deleteToBin, permanentDelete, emptyBin
  - Legacy TODO cleanup in folder.service.ts and delete.service.ts
affects: [web-app, desktop, sdk-consumers]

tech-stack:
  added: []
  patterns: [fire-and-forget-unenroll, recursive-subtree-ipns-collection]

key-files:
  created: []
  modified:
    - packages/sdk/src/client.ts
    - apps/web/src/services/folder.service.ts
    - apps/web/src/services/delete.service.ts

key-decisions:
  - 'Added emptyBin unenrollment beyond plan scope -- same pattern, logical consistency'
  - 'Fire-and-forget with console.warn on failure -- never blocks delete UX'
  - 'collectSubtreeIpnsNames only walks loaded folders -- unloaded subtrees are skipped gracefully'

patterns-established:
  - 'Fire-and-forget unenrollment: collect IPNS names, call API, catch errors with warn'
  - 'Recursive subtree collection via folderTree in-memory walk'

requirements-completed: []

duration: 8min
completed: 2026-03-28
---

# Plan 29-02: SDK IPNS Unenrollment on Delete + Legacy TODO Cleanup Summary

**Fire-and-forget IPNS unenrollment in CipherBoxClient's 4 delete paths + recursive subtree collection for folder deletes**

## Performance

- **Duration:** 8 min
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- Added fireAndForgetUnenroll() helper using ipnsControllerUnenrollBatch from generated API client
- Added collectSubtreeIpnsNames() for recursive IPNS name collection from folder subtrees
- Wired unenrollment into deleteItem, deleteToBin, permanentDelete, and emptyBin (4 call sites)
- Removed 3 legacy TODO comments referencing Phase 14 deferred unenrollment
- Fixed pre-existing implicit-any type on catch callback (strict TS compliance)

## Task Commits

1. **Task 1+2: SDK unenroll wiring** - `a5e90b98f` (feat)
2. **Task 3: Legacy TODO cleanup** - `22b840746` (chore)
3. **Auto-fix: Strict TS catch param** - `a954103f1` (fix)

## Files Created/Modified

- `packages/sdk/src/client.ts` - fireAndForgetUnenroll, collectSubtreeIpnsNames, 4 delete method updates
- `apps/web/src/services/folder.service.ts` - Replaced 2 TODO blocks with SDK reference comments
- `apps/web/src/services/delete.service.ts` - Replaced 1 TODO block with SDK reference comment

## Decisions Made

- Extended plan to include emptyBin() unenrollment for completeness (same fire-and-forget pattern)
- Used `{ _axiosInstance: this.ctx.axiosInstance }` pattern matching existing SDK API call convention

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed implicit-any on pre-existing catch callback**

- **Found during:** Build verification
- **Issue:** `catch((err) =>` lacked type annotation under strict mode
- **Fix:** Changed to `catch((err: unknown) =>`
- **Files modified:** packages/sdk/src/client.ts
- **Verification:** Full SDK build passes (DTS included)
- **Committed in:** a954103f1

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Essential for build correctness. No scope creep.

## Issues Encountered

None

## Next Phase Readiness

- All 3 plans complete
- SDK builds successfully with new unenrollment code
- Ready for phase verification

---

_Phase: 29-infrastructure-hardening_
_Completed: 2026-03-28_

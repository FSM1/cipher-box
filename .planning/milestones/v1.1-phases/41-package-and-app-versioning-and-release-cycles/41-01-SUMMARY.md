---
phase: 41-package-and-app-versioning-and-release-cycles
plan: 01
subsystem: infra
tags: [release-please, versioning, github-labels, monorepo, ci]

# Dependency graph
requires: []
provides:
  - Per-package Release Please config with all 15 monorepo components
  - Version manifest with initial versions for 4 new app entries
  - 61 pre-created GitHub release labels for PR-time release preview
affects: [41-02, 41-03, 41-04, 41-05]

# Tech tracking
tech-stack:
  added: []
  patterns: [per-package-versioning, release-label-naming-convention]

key-files:
  created:
    - .github/scripts/create-release-labels.sh
  modified:
    - .release-please-manifest.json
    - release-please-config.json

key-decisions:
  - 'Root extra-files cascade removed and 4 app packages added to release-please-config.json'
  - 'Label script uses bash 3.2-compatible case statements instead of associative arrays for macOS compatibility'

patterns-established:
  - 'Release label naming: release:{component-short-name}:{type} with color coding by bump type'
  - 'API lock group represented by single api prefix in labels (apps/api + packages/api-client + crates/api-client)'

requirements-completed: [D-04, D-05, D-06, D-07, D-08, D-09, D-10, D-11, D-12, D-13, D-14, D-20]

# Metrics
duration: 4min
completed: 2026-03-31
---

# Phase 41 Plan 01: Release Please Config Summary

**Per-package RP config for all 15 monorepo components with 61 color-coded GitHub release labels**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-31T20:43:55Z
- **Completed:** 2026-03-31T20:47:55Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Restructured release-please-config.json: removed root extra-files cascade, added 4 app packages, now has 15 entries
- Updated .release-please-manifest.json with 4 new app entries (api, web, desktop, tee-worker) bringing total to 15 matching config
- Created bash 3.2-compatible label creation script that generates 61 release labels (12 components x 5 types + release:none)
- All 61 labels created in GitHub repo with color coding: feat=green, fix=red-orange, perf=yellow, refactor=blue, breaking=dark-red

## Task Commits

Each task was committed atomically:

1. **Task 1: Restructure release-please-config.json and manifest** - `93f6bc9f4` + `274abf361` (feat)
2. **Task 2: Create and run GitHub release label creation script** - `7d7fe337f` (feat)

## Files Created/Modified

- `.release-please-manifest.json` - Added 4 app entries (apps/api, apps/web, apps/desktop, apps/tee-worker) with current versions
- `.github/scripts/create-release-labels.sh` - Script to pre-create 61 release labels with --dry-run support
- `release-please-config.json` - Removed root extra-files cascade, added 4 app packages with correct components

## Decisions Made

- Removed root extra-files cascade from release-please-config.json and added 4 app packages per plan spec
- Rewrote label script to use case/function pattern instead of bash associative arrays for macOS bash 3.2 compatibility

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed bash 3.2 compatibility in label script**

- **Found during:** Task 2 (Create label script)
- **Issue:** Plan specified `declare -A` associative arrays which require bash 4+; macOS ships bash 3.2
- **Fix:** Replaced associative arrays with `get_color()` and `get_description()` case-statement functions
- **Files modified:** .github/scripts/create-release-labels.sh
- **Verification:** Dry-run executes correctly on macOS bash 3.2, outputs 61 labels
- **Committed in:** 7d7fe337f (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Essential fix for script portability. No scope creep.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Known Stubs

None

## Next Phase Readiness

- Release Please config and manifest ready for per-package versioning
- 61 release labels available for PR-time release preview action (Plan 02)
- API lock group entries present for synchronization action (Plan 02)

## Self-Check: PASSED

- All created files exist on disk
- All task commits verified in git history (93f6bc9f4, 274abf361, 7d7fe337f)

---

_Phase: 41-package-and-app-versioning-and-release-cycles_
_Completed: 2026-03-31_

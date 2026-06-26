---
phase: 41-package-and-app-versioning-and-release-cycles
plan: 03
subsystem: ci
tags: [github-actions, release-please, semver, versioning, release-as]

# Dependency graph
requires:
  - phase: 41-01
    provides: tee-worker RP config entry and updated manifest
  - phase: 41-02
    provides: PR release preview labels (release:{component}:{type} format) and component mapping
provides:
  - Post-merge GitHub Action that reads merged PR labels and injects release-as into RP config
  - Concurrency-safe release target injection with serialized runs
  - Semver bump computation with monotonic versioning for web/desktop
  - API lock group version synchronization across 3 packages
affects: [41-04, 41-05, release-please, staging-deploy]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      post-merge release-as injection,
      concurrency group serialization,
      GitHub App token for main write access,
    ]

key-files:
  created:
    - .github/scripts/post-merge-release.js
    - .github/workflows/post-merge-release.yml
  modified: []

key-decisions:
  - 'Inline semver bump without external dependencies (no semver library needed)'
  - 'Concurrency group with cancel-in-progress:false ensures serialized runs for concurrent merges'
  - 'Skip conditions prevent infinite loops: both RP release commits and own release target commits are excluded'
  - 'Higher bump wins when multiple PRs merge before RP runs (D-29 conflict resolution via versionDelta comparison)'

patterns-established:
  - 'Release-as injection: post-merge action writes release-as to RP config, RP consumes and clears them'
  - 'Dual skip pattern: job-level if condition excludes both upstream (RP) and own commits'

requirements-completed: [D-02, D-03, D-25, D-26, D-27, D-28, D-29, D-30]

# Metrics
duration: 3min
completed: 2026-03-31
---

# Phase 41 Plan 03: Post-Merge Release Target Injection Summary

**Post-merge GitHub Action reads merged PR labels, computes semver target versions with lock group sync and monotonic handling, and injects release-as overrides into release-please-config.json**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-31T21:25:42Z
- **Completed:** 2026-03-31T21:28:51Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Created post-merge-release.js that finds originating merged PR, parses release labels, computes target versions, and writes release-as to RP config
- Created post-merge-release.yml workflow with concurrency serialization, GitHub App token authentication, and loop-preventing skip conditions
- Implemented API lock group handling (one api label bumps apps/api + packages/api-client + crates/api-client)
- Implemented monotonic versioning for web/desktop (patch bumps promoted to minor per D-08/D-13)
- Implemented D-29 conflict resolution: when existing release-as entries exist, takes the higher bump

## Task Commits

Each task was committed atomically:

1. **Task 1: Create post-merge release-as injection script** - `9a7c51670` (feat)
2. **Task 2: Create post-merge workflow with concurrency and App token** - `e285527f1` (ci)

## Files Created/Modified

- `.github/scripts/post-merge-release.js` - Post-merge script: PR lookup, label parsing, semver bump, release-as injection with conflict resolution
- `.github/workflows/post-merge-release.yml` - GitHub Action workflow: triggers on main push, serialized concurrency, App token auth, skip conditions

## Decisions Made

- Used inline semver bump logic (bumpVersion function) without external semver library since only increment operations are needed
- Concurrency group `post-merge-release` with `cancel-in-progress: false` ensures all runs complete in order (no skipping)
- versionDelta comparison uses weighted scoring (major=10000, minor=100, patch=1) for reliable bump magnitude comparison
- Script sets GitHub Actions step summary with a table of bumped packages for visibility
- Checkout step uses `ref: main` to always read latest state, not the triggering commit

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required. The workflow reuses existing RELEASE_BOT_APP_ID and RELEASE_BOT_PRIVATE_KEY secrets already configured for release-please.yml.

## Next Phase Readiness

- Post-merge release-as injection is complete and ready for integration testing
- D-30 validation (RP clears release-as entries in its release PR) will be confirmed during first real release cycle
- Plan 04 (staging deploy updates) and Plan 05 (integration testing) can proceed

## Self-Check: PASSED

- All created files exist on disk
- All task commits verified in git log (9a7c51670, e285527f1)

---

_Phase: 41-package-and-app-versioning-and-release-cycles_
_Completed: 2026-03-31_

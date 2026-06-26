---
phase: 41-package-and-app-versioning-and-release-cycles
plan: 04
subsystem: infra
tags: [github-actions, docker, staging, ci-cd, deployment]

# Dependency graph
requires:
  - phase: 41-01
    provides: Version validation strategy and phase context for staging infrastructure changes
provides:
  - Date-based staging tag format (staging-YYYYMMDD-release-N) decoupled from component versions
  - Docker images triple-tagged with component version, latest-staging, and deploy tag
  - Component version recording in .env.staging for traceability
affects: [deploy-staging, tag-staging, staging-deploys]

# Tech tracking
tech-stack:
  added: []
  patterns: [date-based-staging-tags, docker-component-version-tagging]

key-files:
  created: []
  modified:
    - .github/workflows/deploy-staging.yml
    - .github/workflows/tag-staging.yml

key-decisions:
  - 'Triple-tag Docker images (component version + latest-staging + deploy tag) for maximum traceability'
  - 'Date-based staging tags (staging-YYYYMMDD-release-N) fully decouple staging from release versioning'
  - 'Record API_VERSION and TEE_VERSION in .env.staging as informational metadata'

patterns-established:
  - 'Date-based staging tag: staging-YYYYMMDD-release-N with sequential counter per date'
  - 'Docker version extraction: read component version from package.json at build time'

requirements-completed: [D-34, D-35, D-36]

# Metrics
duration: 2min
completed: 2026-03-31
---

# Phase 41 Plan 04: Staging Infrastructure Summary

**Date-based staging tags (staging-YYYYMMDD-release-N) and Docker triple-tagging with component versions for version-agnostic staging deploys**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-31T21:11:59Z
- **Completed:** 2026-03-31T21:14:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Broadened deploy-staging.yml tag trigger from `staging-v*` to `staging-*` to match both old and new date-based format
- Docker images now triple-tagged: component version (e.g., `cipherbox-api:0.35.0`), rolling `latest-staging`, and deploy tag for traceability
- Rewrote tag-staging.yml to use date-based format `staging-YYYYMMDD-release-N`, removing coupling to release tags
- Added component version recording (API_VERSION, TEE_VERSION) in .env.staging for operational visibility

## Task Commits

Each task was committed atomically:

1. **Task 1: Update deploy-staging.yml tag pattern and Docker tagging** - `a5ec962a3` (ci)
2. **Task 2: Update tag-staging.yml to date-based tag format** - `0d1e42853` (ci)

## Files Created/Modified

- `.github/workflows/deploy-staging.yml` - Updated tag trigger, added version extraction steps, Docker triple-tagging, and .env.staging version recording
- `.github/workflows/tag-staging.yml` - Rewritten to create date-based staging tags from main HEAD with sequential counters

## Decisions Made

- Triple-tag Docker images (component version + latest-staging + deploy tag) to satisfy D-36 while maintaining backward compatibility with compose files using DEPLOY_TAG
- Date-based staging tags fully decouple staging from release versioning per D-35
- Component versions recorded in .env.staging as informational metadata (D-34 Phase 1 logging)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Staging infrastructure ready for date-based tag deployments
- Existing `staging-v*` tags still trigger deploy-staging.yml (backward compatible during transition)
- Docker images now carry proper component version tags for artifact registry traceability

---

_Phase: 41-package-and-app-versioning-and-release-cycles_
_Completed: 2026-03-31_

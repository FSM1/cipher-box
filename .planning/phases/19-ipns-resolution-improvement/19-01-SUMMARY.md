---
phase: 19-ipns-resolution-improvement
plan: 01
subsystem: infra
tags: [ipns, someguy, docker, delegated-routing, ipfs]

# Dependency graph
requires:
  - phase: 09.1-staging-deployment
    provides: Docker Compose staging infrastructure and deploy workflow
provides:
  - Self-hosted Someguy delegated routing sidecar in Docker Compose staging
  - DELEGATED_ROUTING_URL pointing to local Someguy instead of external delegated-ipfs.dev
affects: [19-02, staging-deployment, ipns-resolution]

# Tech tracking
tech-stack:
  added: [someguy v0.11.1]
  patterns: [self-hosted delegated routing sidecar]

key-files:
  created: []
  modified:
    - docker/docker-compose.staging.yml
    - .github/workflows/deploy-staging.yml
    - apps/api/.env.example

key-decisions:
  - 'Standard DHT mode chosen over accelerated to stay within VPS memory constraints (768M vs 2GB+)'
  - 'No depends_on from api to someguy -- API handles routing failures gracefully with DB fallback'
  - 'No host port exposure for someguy -- only reachable within Docker network'

patterns-established:
  - 'Sidecar pattern: self-hosted IPFS tooling as Docker Compose services rather than external dependencies'

requirements-completed: [IPNS-01, IPNS-02, IPNS-03]

# Metrics
duration: 2min
completed: 2026-03-07
---

# Phase 19 Plan 01: Someguy Sidecar Summary

**Self-hosted Someguy v0.11.1 as Docker Compose sidecar replacing unreliable delegated-ipfs.dev for IPNS delegated routing**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-07T06:46:11Z
- **Completed:** 2026-03-07T06:48:17Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Added Someguy service to docker-compose.staging.yml with correct image, listen address, DHT mode, health check, and resource limits
- Swapped DELEGATED_ROUTING_URL from external delegated-ipfs.dev to self-hosted http://someguy:8190 in deploy workflow
- Updated .env.example to document Someguy as recommended routing provider with legacy service noted

## Task Commits

Each task was committed atomically:

1. **Task 1: Add Someguy service to Docker Compose staging** - `fa8aa3dd5` (feat)
2. **Task 2: Update deploy workflow and .env.example** - `9336171e9` (feat)

## Files Created/Modified

- `docker/docker-compose.staging.yml` - Added someguy service definition with v0.11.1 image, standard DHT, 768M memory limit
- `.github/workflows/deploy-staging.yml` - Changed DELEGATED_ROUTING_URL from delegated-ipfs.dev to someguy:8190
- `apps/api/.env.example` - Updated IPNS routing documentation block

## Decisions Made

- Used standard DHT mode (not accelerated) to keep memory under 768M on staging VPS
- No `depends_on` from api to someguy since API already handles routing failures gracefully via DB fallback
- No host port exposure for someguy since it only needs Docker-internal connectivity
- TEE worker config intentionally unchanged per plan constraints

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required. The Someguy sidecar is fully self-contained within the Docker Compose stack.

## Next Phase Readiness

- Infrastructure is ready for Plan 02 (API-level IPNS resolution improvements)
- Someguy will be available at http://someguy:8190 when next staging deploy runs
- No blockers

---

_Phase: 19-ipns-resolution-improvement_
_Completed: 2026-03-07_

## Self-Check: PASSED

- All 3 modified files exist on disk
- Both task commits (fa8aa3dd5, 9336171e9) verified in git log
- SUMMARY.md created successfully

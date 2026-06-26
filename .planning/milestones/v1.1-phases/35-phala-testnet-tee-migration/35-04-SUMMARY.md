---
phase: 35-phala-testnet-tee-migration
plan: 04
subsystem: infra
tags: [phala, tee, docker-compose, github-actions, cvm, staging, ci-cd]

# Dependency graph
requires:
  - phase: 35-03
    provides: Phala CVM docker-compose file, dstack SDK integration, structured logging
provides:
  - Staging docker-compose without local tee-worker service
  - Deploy workflow with Phala Cloud CVM deployment step
  - TEE_WORKER_URL pointing to external Phala endpoint
affects: [35-05, 35-06, staging-deployment]

# Tech tracking
tech-stack:
  added: [phala-cli]
  patterns: [external-cvm-deployment, envsubst-compose-templating]

key-files:
  created: []
  modified:
    - docker/docker-compose.staging.yml
    - .github/workflows/deploy-staging.yml

key-decisions:
  - 'TEE_WORKER_URL stored as GitHub environment variable (PHALA_TEE_WORKER_URL) set after first CVM deploy'
  - 'deploy-vps waits for deploy-tee-phala to complete before deploying VPS services'
  - 'envsubst used for compose variable substitution in CI (avoids sed fragility)'

patterns-established:
  - 'Phala CVM deploy pattern: build image -> push GHCR -> phala deploy with --wait'
  - 'External TEE endpoint: API connects to Phala Cloud HTTPS URL instead of Docker internal network'

requirements-completed: []

# Metrics
duration: 2min
completed: 2026-03-29
---

# Phase 35 Plan 04: Staging Infrastructure Migration Summary

**Staging TEE worker migrated from local Docker container to external Phala Cloud CVM with CI/CD deployment pipeline**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-29T11:29:22Z
- **Completed:** 2026-03-29T11:31:28Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Removed local tee-worker service from staging docker-compose (TEE now runs on Phala Cloud CVM)
- Added deploy-tee-phala CI/CD job that deploys TEE Docker image to Phala Cloud via phala CLI
- Updated staging API to connect to external Phala endpoint via configurable PHALA_TEE_WORKER_URL env var
- Documented required GitHub secrets (PHALA_CLOUD_API_KEY) and vars (PHALA_TEE_WORKER_URL) for staging environment

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove local tee-worker from staging docker-compose** - `8e85e0017` (feat)
2. **Task 2: Add Phala CVM deployment step to deploy-staging workflow** - `53a264ff6` (feat)

## Files Created/Modified

- `docker/docker-compose.staging.yml` - Removed tee-worker service block, added comment documenting external CVM
- `.github/workflows/deploy-staging.yml` - Added deploy-tee-phala job, updated deploy-vps needs, changed TEE_WORKER_URL to use PHALA_TEE_WORKER_URL var

## Decisions Made

- **TEE_WORKER_URL as GitHub env var:** Since the Phala Cloud endpoint URL is dynamic (contains app-id hash), it must be set as a GitHub environment variable (PHALA_TEE_WORKER_URL) after the first CVM deployment rather than being hardcoded
- **deploy-vps depends on deploy-tee-phala:** VPS deploy waits for CVM to be ready, ensuring the API starts with a reachable TEE endpoint
- **envsubst for compose templating:** Using envsubst to substitute ${TAG} and ${GITHUB_REPOSITORY_OWNER} in the Phala compose file avoids fragile sed-based replacements

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

**External services require manual configuration after first deploy:**

- **Secret:** `PHALA_CLOUD_API_KEY` must be added to GitHub staging environment secrets (from Phala Cloud dashboard API keys)
- **Variable:** `PHALA_TEE_WORKER_URL` must be set in GitHub staging environment vars after first CVM deploy (format: `https://{app-id}-3001.dstack-prod{N}.phala.network`)
- **Existing:** `STAGING_TEE_WORKER_SECRET` already exists and is reused

## Next Phase Readiness

- Infrastructure ready for first Phala Cloud deployment
- Plan 35-05 (End-to-End Verification) can validate the full TEE republish cycle through the external CVM
- Plan 35-06 (Documentation and Rollback) can document the operational procedures

## Self-Check: PASSED

- docker/docker-compose.staging.yml: FOUND
- .github/workflows/deploy-staging.yml: FOUND
- 35-04-SUMMARY.md: FOUND
- Commit 8e85e0017: FOUND
- Commit 53a264ff6: FOUND

---

_Phase: 35-phala-testnet-tee-migration_
_Completed: 2026-03-29_

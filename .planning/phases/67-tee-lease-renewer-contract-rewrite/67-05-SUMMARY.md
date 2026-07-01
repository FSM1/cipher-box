---
phase: 67-tee-lease-renewer-contract-rewrite
plan: "05"
subsystem: infra/docker
tags: [docker, tee-worker, sdk-e2e, devdeps]
status: complete

dependency_graph:
  requires: []
  provides:
    - tee-worker service in docker-compose (host 3002, simulator mode)
    - bullmq/pg devDependencies in sdk-e2e
  affects:
    - tests/sdk-e2e (67-08 TEE round-trip)
    - docker/docker-compose.yml (local dev stack)

tech_stack:
  added:
    - bullmq@5.67.3 (sdk-e2e devDep — existing lockfile version)
    - pg@8.14.1 (sdk-e2e devDep — existing lockfile version)
    - "@types/pg@8.20.0 (sdk-e2e devDep)"
  patterns:
    - "tee-worker container with simulator TEE_MODE for local dev (no Phala dependency)"
    - "distinct host port (3002) to avoid mock-ipns-routing conflict on 3001"

key_files:
  modified:
    - docker/docker-compose.yml
    - apps/api/.env.example
    - tests/sdk-e2e/package.json
    - pnpm-lock.yaml

decisions:
  - "Build context is repo root (..) not apps/tee-worker — tee-worker Dockerfile COPYs pnpm-lock.yaml and packages/* from monorepo root; plan spec of context:../apps/tee-worker would fail"
  - "TEE_WORKER_URL documented as uncommented active value in .env.example (not a comment) so it applies by default in dev"

metrics:
  duration_seconds: 171
  completed_date: "2026-07-01"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 4
---

# Phase 67 Plan 05: Add tee-worker to dev docker-compose and sdk-e2e devDeps Summary

Local dev stack gains a simulator tee-worker service on host 3002 (build from monorepo root), and sdk-e2e gains bullmq/pg devDependencies pinned to the existing apps/api lockfile versions.

## Tasks Completed

| # | Name | Commit | Files |
|---|------|--------|-------|
| 1 | Add tee-worker service to docker-compose + document API env | 6e8758e14 | docker/docker-compose.yml, apps/api/.env.example |
| 2 | Add bullmq + pg devDependencies to tests/sdk-e2e | 7e017047d | tests/sdk-e2e/package.json, pnpm-lock.yaml |

## What Was Built

### Task 1 — docker-compose tee-worker service

Added `tee-worker` service to `docker/docker-compose.yml`:

- Build context `..` (repo root) + `dockerfile: apps/tee-worker/Dockerfile`
- `container_name: cipherbox-tee-worker`
- `TEE_MODE: simulator`, `CIPHERBOX_ENVIRONMENT: development`
- `TEE_WORKER_SECRET: ${TEE_WORKER_SECRET:-dev-secret}`
- Port mapping `127.0.0.1:3002:3001` (host 3002, container 3001)
- Healthcheck hitting `http://localhost:3001/health`
- Resource limits: 256M / 0.5 cpu (mirroring staging block)

Updated `apps/api/.env.example` TEE section from commented-out `localhost:3001` to active:

```
TEE_WORKER_URL=http://localhost:3002
TEE_WORKER_SECRET=dev-secret
```

### Task 2 — sdk-e2e devDependencies

Added to `tests/sdk-e2e/package.json` devDependencies:

- `bullmq@^5.67.3` — same as apps/api; no new lockfile version
- `pg@^8.14.1` — same as apps/api; no new lockfile version
- `@types/pg@^8.11.14` — resolves to 8.20.0

Ran `pnpm install` at repo root; lockfile updated to include sdk-e2e importer entries.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Docker build context corrected to repo root**

- **Found during:** Task 1
- **Issue:** Plan specified `context: ../apps/tee-worker` but the `apps/tee-worker/Dockerfile` COPYs files from the monorepo root (`pnpm-lock.yaml`, `pnpm-workspace.yaml`, `packages/*`). Using the tee-worker directory as context would cause `COPY pnpm-lock.yaml` to fail at build time. The Dockerfile itself documents this: `# Build from repo root: docker build -f apps/tee-worker/Dockerfile -t cipherbox-tee-worker .`
- **Fix:** Used `context: ..` (repo root relative to `docker/`) and `dockerfile: apps/tee-worker/Dockerfile`
- **Files modified:** docker/docker-compose.yml
- **Commit:** 6e8758e14

## Verification

```
$ docker compose -f docker/docker-compose.yml config 2>&1 | grep -E "tee-worker|3002:3001|TEE_MODE"
  tee-worker:
      dockerfile: apps/tee-worker/Dockerfile
    container_name: cipherbox-tee-worker
      TEE_MODE: simulator

$ grep -nE "127.0.0.1:3002:3001" docker/docker-compose.yml
136:      - '127.0.0.1:3002:3001'

$ grep -n "cvm" docker/docker-compose.yml
(no output — cvm not present)
```

Lockfile: `pg@8.17.1` and `bullmq@5.67.3` — single entries each, no new version introduced.

## Self-Check: PASSED

- docker/docker-compose.yml modified: FOUND (commit 6e8758e14)
- apps/api/.env.example modified: FOUND (commit 6e8758e14)
- tests/sdk-e2e/package.json modified: FOUND (commit 7e017047d)
- pnpm-lock.yaml updated: FOUND (commit 7e017047d)
- No `cvm` in docker-compose: CONFIRMED
- TEE_WORKER_URL=http://localhost:3002 in .env.example: CONFIRMED
- bullmq@^5.67.3, pg@^8.14.1, @types/pg in sdk-e2e devDeps: CONFIRMED

---
phase: 26-observability-ux-tuning
plan: 01
subsystem: infra
tags: [grafana, alerting, promql, prometheus, observability]

# Dependency graph
requires:
  - phase: 18-performance-baselines
    provides: Server-side Prometheus histogram baselines (p50/p95/p99) for threshold derivation
  - phase: 22-performance-baselines-completion
    provides: Client-side journey timing baselines and load test thresholds
provides:
  - Five Grafana alert rule JSON definitions covering IPNS resolve, IPFS pin, API endpoints, IPNS publish, and DB fallback rate
  - Provisioning script for deploying alert rules to Grafana Cloud via HTTP API
affects: [26-02, staging-deployment, grafana-cloud]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Grafana alert rules as version-controlled JSON with placeholder UIDs'
    - 'Two-tier severity: warning at p95, critical at p99/2x-p95'
    - 'Threshold + expression node pattern (refId A = query, refId B = threshold)'
    - 'Shell provisioning script with dry-run mode for Grafana Cloud API'

key-files:
  created:
    - docker/grafana/alerts/ipns-resolve-latency.json
    - docker/grafana/alerts/ipfs-pin-latency.json
    - docker/grafana/alerts/api-endpoint-latency.json
    - docker/grafana/alerts/ipns-publish-latency.json
    - docker/grafana/alerts/db-fallback-rate.json
    - docker/grafana/scripts/provision-alerts.sh
  modified: []

key-decisions:
  - 'Used simplified two-node alert structure (A=query, B=threshold) instead of three-node (A=query, B=reduce, C=threshold) for cleaner provisioning'
  - 'noDataState set to OK for all rules to prevent false alerts during low-traffic periods'
  - 'DB fallback rate uses 10m rate window for stable ratio calculation vs 5m for latency alerts'
  - 'All 17 alert rules organized in 5 files by operation category for maintainability'

patterns-established:
  - 'Grafana alert JSON in docker/grafana/alerts/ with placeholder UIDs replaced at deploy time'
  - 'Provisioning script discovers/creates folder, iterates JSON files, handles array rules'

requirements-completed: [OBS-01]

# Metrics
duration: 5min
completed: 2026-03-26
---

# Phase 26 Plan 01: Grafana Alert Rules Summary

**17 Grafana-managed alert rules covering IPNS resolve/publish latency, IPFS pin latency, 5 API endpoint routes, and DB fallback rate with thresholds derived from Phase 18/22 baselines**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-26T00:45:42Z
- **Completed:** 2026-03-26T00:51:01Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Created 5 alert rule JSON files with 17 total rules covering all critical operation categories
- Thresholds derived from Phase 18 server-side histograms and Phase 22 journey baselines: IPNS resolve 300ms/600ms, IPFS pin 50ms/100ms, IPNS publish 600ms/1200ms, DB fallback 20%
- API endpoint latency alerts cover 5 critical routes (upload, download, resolve, publish, vault) with route-specific thresholds
- Provisioning script handles folder discovery/creation, placeholder replacement, array-of-rules iteration, and dry-run validation

## Task Commits

Each task was committed atomically:

1. **Task 1: Create Grafana alert rule JSON files** - `14d4d077` (feat)
2. **Task 2: Create provisioning script** - `339cf317` (feat, pre-existing from prior session)

## Files Created/Modified

- `docker/grafana/alerts/ipns-resolve-latency.json` - Warning (p95 >300ms) and critical (p99 >600ms) for IPNS network resolve
- `docker/grafana/alerts/ipfs-pin-latency.json` - Warning (p95 >50ms) and critical (p99 >100ms) for Kubo pin operations
- `docker/grafana/alerts/api-endpoint-latency.json` - 10 rules: warning + critical for upload, download, resolve, publish, vault endpoints
- `docker/grafana/alerts/ipns-publish-latency.json` - Warning (p95 >600ms) and critical (p99 >1200ms) for IPNS publish
- `docker/grafana/alerts/db-fallback-rate.json` - Warning when >20% of resolves fall back to DB cache over 10m
- `docker/grafana/scripts/provision-alerts.sh` - Bash script to deploy rules to Grafana Cloud via HTTP API

## Decisions Made

- Used two-node alert structure (A=PromQL query, B=threshold expression) instead of three-node pattern from research doc. Simpler and fully functional for threshold-based alerts.
- Set `noDataState: "OK"` on all rules to prevent false alerts during low-traffic periods when `histogram_quantile` returns NaN.
- DB fallback rate uses 10m rate window (vs 5m for latency) for more stable ratio calculation with fewer data points.
- All files use placeholder strings (`GRAFANA_CLOUD_DATASOURCE_UID`, `GRAFANA_ALERTS_FOLDER_UID`) replaced by the provisioning script at deploy time.

## Deviations from Plan

None - plan executed exactly as written.

Note: The provisioning script (Task 2) was found to already exist from a prior interrupted session. The content was verified to meet all acceptance criteria.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required. Alert rules are deployed via `provision-alerts.sh` when ready to connect to Grafana Cloud.

## Next Phase Readiness

- Alert rule definitions ready for provisioning to Grafana Cloud
- Provisioning script tested with dry-run mode (17 rules processed)
- Plan 02 (client-side timeout tuning) can proceed independently

---

## Self-Check: PASSED

All 7 files verified present. Both commit hashes verified in git log.

---

_Phase: 26-observability-ux-tuning_
_Completed: 2026-03-26_

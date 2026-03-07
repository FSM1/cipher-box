---
phase: 18-performance-instrumentation
plan: 02
subsystem: infra
tags: [grafana, alloy, prometheus, kubo, ipfs, ipns, monitoring, dashboards, benchmarking]

# Dependency graph
requires:
  - phase: 18-performance-instrumentation
    provides: cipherbox_ipfs_ipns_duration_seconds and cipherbox_republish_batch_duration_seconds histograms (Plan 01)
  - phase: 10-monitoring-infrastructure
    provides: Alloy config, Grafana dashboard JSON, docker-compose staging stack
provides:
  - Kubo Prometheus scrape target in Alloy (ipfs:5001/debug/metrics/prometheus)
  - IPFS/IPNS duration dashboard panels (p50/p95/p99 with operation/source breakdowns)
  - TEE republish batch duration dashboard panel
  - Kubo Health dashboard row (peer connections, bandwidth, datastore)
  - Synthetic baseline benchmark script (scripts/baseline-benchmark.sh)
  - Performance baselines template (.planning/baselines/18-performance-baselines.md)
affects: [22-client-load-testing, staging-deployment]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      Alloy multi-target scrape pattern,
      PromQL histogram_quantile for p50/p95/p99,
      percentile computation in bash,
    ]

key-files:
  created:
    - scripts/baseline-benchmark.sh
    - .planning/baselines/18-performance-baselines.md
  modified:
    - docker/alloy-config.river
    - docker/grafana/dashboards/cipherbox-staging.json

key-decisions:
  - 'Alloy scrapes Kubo directly via Docker internal network (ipfs:5001), not proxied through CipherBox API'
  - 'Kubo Health row uses fallback metrics (go_memstats_alloc_bytes, go_goroutines) alongside libp2p metrics since Kubo v0.34 metric names need post-deploy verification'
  - 'Benchmark script skips IPNS publish (requires signed record) -- publish timing captured from organic Prometheus data'
  - 'Duration panels placed as sub-rows within existing dashboard sections to preserve logical grouping'

patterns-established:
  - 'PromQL histogram percentile pattern: histogram_quantile(0.XX, sum(rate(metric_bucket{filters}[$__rate_interval])) by (le, label_dims))'
  - 'Bash percentile computation: sort file, compute index=ceil(p/100*count), extract Nth line'

requirements-completed: [PERF-02, PERF-03]

# Metrics
duration: 5min
completed: 2026-03-07
---

# Phase 18 Plan 02: Monitoring Dashboard & Baselines Summary

**Kubo scrape target in Alloy, IPFS/IPNS/TEE duration dashboard panels with p50/p95/p99 PromQL queries, Kubo Health row, and synthetic baseline benchmark script**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-07T05:22:44Z
- **Completed:** 2026-03-07T05:28:00Z
- **Tasks:** 2 of 3 (Task 3 is human-verify checkpoint)
- **Files modified:** 4

## Accomplishments

- Added Kubo Prometheus scrape target to Alloy config targeting ipfs:5001/debug/metrics/prometheus
- Extended Grafana dashboard from 27 to 41 panels/rows with IPFS Pin/Cat Duration, IPNS Resolve/Publish Duration, IPNS Source breakdown, TEE Batch Duration, and Kubo Health (peer connections, bandwidth, datastore) panels
- Created reproducible baseline benchmark script that exercises IPNS resolve, IPFS upload, and IPFS download with 20 iterations and computes p50/p95/p99 percentiles
- Created baselines template document with sections for client-side, server-side, HTTP API, and Kubo health metrics (TBD until staging deploy)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add Kubo scrape target to Alloy and update Grafana dashboard** - `7aeb8a361` (feat)
2. **Task 2: Create synthetic baseline benchmark script and baselines document** - `08cd9c6ec` (feat)
3. **Task 3: Verify monitoring infrastructure and benchmark script** - checkpoint:human-verify (pending)

## Files Created/Modified

- `docker/alloy-config.river` - Added prometheus.scrape "kubo" block targeting ipfs:5001/debug/metrics/prometheus
- `docker/grafana/dashboards/cipherbox-staging.json` - Added 14 new panels: IPFS duration, IPFS error rate, IPNS duration, IPNS source breakdown, TEE batch duration, Kubo Health row with 3 panels
- `scripts/baseline-benchmark.sh` - NEW: Synthetic benchmark script with 20 iterations, warmup, and percentile computation
- `.planning/baselines/18-performance-baselines.md` - NEW: Performance baselines template with TBD values

## Decisions Made

- Alloy scrapes Kubo directly via Docker internal network (ipfs:5001) -- no API proxy needed since both containers share the default Docker Compose network
- Kubo Health panels use both primary libp2p metrics and fallback Go runtime metrics since exact Kubo v0.34 metric names need post-deploy verification
- Benchmark script skips IPNS publish because it requires cryptographically signed records -- publish timing will come from organic Prometheus histogram data
- Duration panels are placed as sub-rows within existing dashboard sections (File Operations, IPNS Operations, TEE Republishing) to preserve logical grouping
- Dashboard grid positions were calculated programmatically with overlap validation

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required. Dashboard and Alloy config changes take effect on next staging deployment.

## Next Phase Readiness

- Monitoring stack is ready to visualize IPFS/IPNS and TEE duration metrics from Plan 01 histograms
- Baseline benchmark script is ready to run against staging after deploy
- Baselines document template is ready to be populated with actual values
- All Phase 18 code changes are complete; staging deploy and baseline capture are the remaining manual steps

## Self-Check: PASSED

All 4 files verified present. Both commit hashes verified in git log.

---

_Phase: 18-performance-instrumentation_
_Completed: 2026-03-07_

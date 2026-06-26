---
phase: 18
slug: performance-instrumentation
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-07
validated: 2026-06-11
---

# Phase 18 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                      |
| ---------------------- | -------------------------- |
| **Framework**          | Jest 29.x + ts-jest        |
| **Config file**        | `apps/api/jest.config.js`  |
| **Quick run command**  | `cd apps/api && pnpm test` |
| **Full suite command** | `cd apps/api && pnpm test` |
| **Estimated runtime**  | ~30 seconds                |

---

## Sampling Rate

- **After every task commit:** Run `cd apps/api && pnpm test`
- **After every plan wave:** Run `cd apps/api && pnpm test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type | Automated Command                                                         | File Exists    | Status |
| -------- | ---- | ---- | ----------- | --------- | ------------------------------------------------------------------------- | -------------- | ------ |
| 18-01-01 | 01   | 1    | PERF-01     | unit      | `cd apps/api && npx jest src/metrics/metrics.service.spec.ts -x`          | Yes (9 tests)  | green  |
| 18-01-02 | 01   | 1    | PERF-01     | unit      | `cd apps/api && npx jest src/ipns/ipns.service.spec.ts -x`                | Yes (71 tests) | green  |
| 18-01-03 | 01   | 1    | PERF-01     | unit      | `cd apps/api && npx jest src/ipfs/ipfs.controller.spec.ts -x`             | Yes (20 tests) | green  |
| 18-01-04 | 01   | 1    | PERF-02     | unit      | `cd apps/api && npx jest src/metrics/http-metrics.interceptor.spec.ts -x` | Yes (25 tests) | green  |
| 18-02-01 | 02   | 1    | PERF-03     | manual    | Verify `alloy-config.river` has prometheus.scrape "kubo" block            | N/A (config)   | green  |
| 18-02-02 | 02   | 1    | PERF-03     | manual    | Verify `cipherbox-staging.json` has Kubo Health panels                    | N/A (JSON)     | green  |
| 18-03-01 | 03   | 1    | PERF-04     | unit      | `cd apps/api && npx jest src/republish/republish.processor.spec.ts -x`    | Yes (11 tests) | green  |

_Status: pending · green · red · flaky_

---

## Wave 0 Requirements

- [x] `apps/api/src/metrics/metrics.service.spec.ts` — stubs for PERF-01, PERF-04: verify new histograms are registered and observable (created during execution, 9 tests)
- [x] `apps/api/src/metrics/http-metrics.interceptor.spec.ts` — stubs for PERF-02: verify interceptor records duration (created by validation audit 2026-06-11, 25 tests)

_Existing spec files for ipns.service, ipfs.controller, and republish.processor need updates to mock and verify new histogram calls._

---

## Manual-Only Verifications

| Behavior           | Requirement | Why Manual             | Test Instructions                                                                                              |
| ------------------ | ----------- | ---------------------- | -------------------------------------------------------------------------------------------------------------- |
| Alloy scrapes Kubo | PERF-03     | Infra config, not code | Inspect alloy-config.river for `prometheus.scrape "kubo"` block targeting `ipfs:5001`                          |
| Kubo Health panels | PERF-03     | Grafana dashboard JSON | Verify `cipherbox-staging.json` contains Kubo Health row with peer/bandwidth/datastore panels                  |
| Baseline document  | PERF-02     | Requires staging env   | Run synthetic script on staging, verify .planning/baselines/18-performance-baselines.md has p50/p95/p99 values |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated 2026-06-11 via /gsd-validate-phase

## Validation Audit 2026-06-11

| Metric     | Count |
| ---------- | ----- |
| Gaps found | 1     |
| Resolved   | 1     |
| Escalated  | 0     |

Audit notes: All four unit suites confirmed green (111 pre-existing tests + 25 new). The single gap — missing `http-metrics.interceptor.spec.ts` (PERF-02 Wave 0 item) — was filled with 25 tests covering success/error paths, duration calculation, method and status-code label dimensions, and `/metrics` self-exclusion. Manual PERF-03 items verified directly: `prometheus.scrape "kubo"` block present at `docker/alloy-config.river:83`; Kubo Health panels present in `cipherbox-staging.json`. PERF-02 baseline document `.planning/baselines/18-performance-baselines.md` is populated with staging p50/p95/p99 values.

---
phase: 18-performance-instrumentation
verified: 2026-06-19T16:00:00Z
status: passed
score: 4/4 must-haves verified (PERF-03 via accepted override — upstream Kubo limitation)
overrides_applied: 1
overrides:
  - must_have: 'PERF-03: Kubo node health metrics (peer count, bandwidth, datastore size) visible in Prometheus via scraped Kubo endpoint'
    reason: 'The deliverable — scraping the Kubo /debug/metrics/prometheus endpoint and providing Kubo Health dashboard panels — is implemented and correctly wired (alloy-config.river:83-91, cipherbox-staging.json Kubo Health row). The peer/bandwidth metrics do not populate because Kubo v0.34.0 does not emit libp2p metrics upstream (documented in .planning/baselines/18-performance-baselines.md lines 87-92); datastore size is observed via the app gauge. No human verification or code change can surface metrics the Kubo build does not emit — this is an upstream constraint, not a code defect. The scrape will populate automatically on a Kubo version that exposes these metrics.'
    accepted_by: 'myankelev'
    accepted_at: '2026-06-19'
---

# Phase 18: Performance Instrumentation Verification Report

**Phase Goal:** Operators can observe IPFS/IPNS latency and API performance in Prometheus/Grafana before any architectural changes are made
**Verified:** 2026-06-19T16:00:00Z
**Status:** passed (1 accepted override — PERF-03 upstream Kubo limitation)
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #   | Truth                                                                                                          | Status     | Evidence                                                                                                                                                                                                                                                                                |
| --- | ------------------------------------------------------------------------------------------------------------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Prometheus exposes duration histograms for IPNS resolve, IPNS publish, IPFS pin, and IPFS cat (PERF-01)      | ✓ VERIFIED | `metrics.service.ts:206-212` registers `cipherbox_ipfs_ipns_duration_seconds` with labels `operation`/`result`/`source`. Wired with start+end timers: resolve `ipns.service.ts:391,485`, publish `ipns.service.ts:48,140`, pin `ipfs.controller.ts:106,113,115`, cat `ipfs.controller.ts:212,219,221` |
| 2   | API endpoint response times captured at p50/p95/p99 for all critical routes via interceptor (PERF-02)        | ✓ VERIFIED | `http-metrics.interceptor.ts:48-50` records `httpRequestDuration` (method/route/status_code); globally registered `app.module.ts:131-132` (APP_INTERCEPTOR). Dashboard p50/p95/p99 `histogram_quantile` queries `cipherbox-staging.json:1763-1775`; per-route baselines doc lines 68-82 |
| 3   | Kubo node health metrics (peer count, bandwidth, datastore size) visible in Prometheus via scraped endpoint (PERF-03) | ✓ PASSED (override) | Deliverable wired: scrape block `alloy-config.river:83-91` targets `ipfs:5001` `/debug/metrics/prometheus`; Grafana Kubo Health row `cipherbox-staging.json:1914`. Panels don't populate peer/bandwidth because Kubo v0.34.0 emits no libp2p metrics upstream (baseline doc lines 87-92) — accepted override (upstream constraint, not a code defect); populates automatically on a Kubo build that exposes them |
| 4   | TEE republish batch duration histogram captures per-batch timing with success/failure labels (PERF-04)       | ✓ VERIFIED | `metrics.service.ts:214-220` registers `cipherbox_republish_batch_duration_seconds` with labels `tee_provider`/`result`. Wired `republish.processor.ts:22` (startTimer) and `:49` (`endBatchTimer({ result: batchResult })`); `batchResult` toggled to `'error'` on failure `:40,44`              |

**Score:** 4/4 truths verified — PERF-01/02/04 outright; PERF-03 PASSED via accepted override (Kubo v0.34 upstream metrics limitation)

### Required Artifacts

| Artifact                                              | Expected                                                       | Status     | Details                                                                                                                                                              |
| ---------------------------------------------------- | ------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `apps/api/src/metrics/metrics.service.ts`            | `ipfsIpnsDuration` + `republishBatchDuration` histograms      | ✓ VERIFIED | Lines 206-220 register both histograms on the registry with correct labels and buckets                                                                             |
| `apps/api/src/metrics/http-metrics.interceptor.ts`   | Interceptor records request duration per route                | ✓ VERIFIED | 53-line interceptor; records on `next` and `error`, excludes `/metrics`, caps cardinality on unmatched routes (lines 36-51)                                          |
| `apps/api/src/ipns/ipns.service.ts`                  | Timing wrappers around resolve and publish                    | ✓ VERIFIED | `startTimer` at lines 48 (publish) and 391 (resolve); finalized at 140 and 485                                                                                       |
| `apps/api/src/ipfs/ipfs.controller.ts`              | Timing wrappers around pin (upload) and cat (download)        | ✓ VERIFIED | `startTimer` at lines 106 (pin) and 212 (cat); success/error finalization at 113/115 and 219/221                                                                     |
| `apps/api/src/republish/republish.processor.ts`     | Timing wrapper around processRepublishBatch                   | ✓ VERIFIED | `republishBatchDuration.startTimer` at line 22; `endBatchTimer` in `finally` at line 49                                                                              |
| `docker/alloy-config.river`                          | Second `prometheus.scrape "kubo"` block targeting Kubo        | ✓ VERIFIED | Block at lines 83-91 targets `ipfs:5001` path `/debug/metrics/prometheus`, 30s interval, forwards via `keep_infra_metrics` relabel                                   |
| `docker/grafana/dashboards/cipherbox-staging.json`  | IPFS/IPNS duration panels + Kubo Health row                   | ⚠️ PARTIAL | Duration panels reference `cipherbox_ipfs_ipns_duration_seconds` / `cipherbox_republish_batch_duration_seconds` / `cipherbox_http_request_duration_seconds`; Kubo Health row at 1914 has peer/bandwidth/heap but NO datastore-size panel from the Kubo scrape |
| `scripts/baseline-benchmark.sh`                      | Synthetic test script for reproducible baseline capture       | ✓ VERIFIED | Executable 10 KB script present                                                                                                                                     |
| `.planning/baselines/18-performance-baselines.md`   | Documented p50/p95/p99 baseline values from staging           | ✓ VERIFIED | Per-operation (lines 30-45) and per-route (lines 68-82) p50/p95/p99 tables populated; also documents Kubo metric gaps (lines 87-92)                                  |

### Key Link Verification

| From                                                 | To                                        | Via                                                       | Status | Details                                                                                                       |
| ---------------------------------------------------- | ----------------------------------------- | -------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------- |
| `apps/api/src/ipns/ipns.service.ts`                  | `apps/api/src/metrics/metrics.service.ts` | DI `MetricsService` → `metricsService.ipfsIpnsDuration`   | WIRED  | Injection `ipns.service.ts:36`; usage lines 48, 391                                                          |
| `apps/api/src/ipfs/ipfs.controller.ts`              | `apps/api/src/metrics/metrics.service.ts` | DI `MetricsService` → `metricsService.ipfsIpnsDuration`   | WIRED  | Injection `ipfs.controller.ts:53`; usage lines 106, 212                                                      |
| `apps/api/src/republish/republish.processor.ts`     | `apps/api/src/metrics/metrics.service.ts` | DI `MetricsService` → `metricsService.republishBatchDuration` | WIRED  | Injection `republish.processor.ts:13`; usage line 22                                                         |
| `apps/api/src/metrics/http-metrics.interceptor.ts`   | NestJS request pipeline                   | `APP_INTERCEPTOR` global provider                         | WIRED  | `app.module.ts:131-132` `{ provide: APP_INTERCEPTOR, useClass: HttpMetricsInterceptor }`                     |
| `docker/alloy-config.river`                          | `ipfs:5001`                               | `prometheus.scrape` Kubo target + relabel keep filter    | WIRED  | Lines 83-91; relabel keeps libp2p/go metrics (line 77) — but Kubo node does not emit them (live gap)         |
| `docker/grafana/dashboards/cipherbox-staging.json`  | `apps/api/src/metrics/metrics.service.ts` | PromQL queries reference metric names                     | WIRED  | Duration metric names match the registered histograms (lines 593-1906)                                       |

### Data-Flow Trace (Level 4)

| Artifact                          | Data Variable                                | Source                                      | Produces Real Data | Status        |
| --------------------------------- | -------------------------------------------- | ------------------------------------------- | ------------------ | ------------- |
| Duration histograms (API)         | `cipherbox_ipfs_ipns_duration_seconds` etc.  | `startTimer`/`endTimer` in service/controller | Yes (server-side)  | ✓ FLOWING     |
| HTTP duration histogram           | `cipherbox_http_request_duration_seconds`    | global interceptor on every non-/metrics req | Yes                | ✓ FLOWING     |
| Republish batch histogram         | `cipherbox_republish_batch_duration_seconds` | republish processor `finally` block          | Yes                | ✓ FLOWING     |
| Kubo Health panels (peer/bw)      | `libp2p_swarm_connections_*` / `libp2p_network_*` | Kubo `/debug/metrics/prometheus` scrape  | No (Kubo v0.34.0)  | ✗ DISCONNECTED (live) |

### Behavioral Spot-Checks

Skipped — static analysis only per task constraints (no test suite / probe execution).

### Probe Execution

Not applicable — no `scripts/*/tests/probe-*.sh` declared for this phase; static analysis only.

### Requirements Coverage

| Requirement | Source Plan | Description                                                              | Status            | Evidence                                                                                                                                                                                                                                       |
| ----------- | ----------- | ----------------------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PERF-01     | 18-01-PLAN  | IPFS/IPNS duration histograms (publish, resolve, pin, cat)              | SATISFIED         | `metrics.service.ts:206-212`; resolve `ipns.service.ts:391,485`; publish `ipns.service.ts:48,140`; pin `ipfs.controller.ts:106,113`; cat `ipfs.controller.ts:212,219`                                                                            |
| PERF-02     | 18-01/02    | API endpoint p50/p95/p99 baselines per critical route                   | SATISFIED         | `http-metrics.interceptor.ts:48-50` + `app.module.ts:131-132`; dashboard `histogram_quantile` p50/p95/p99 `cipherbox-staging.json:1763-1775`; baselines doc lines 68-82                                                                          |
| PERF-03     | 18-02-PLAN  | Kubo Prometheus endpoint scraped for node health (peers, bandwidth, datastore) | SATISFIED (override) | Scrape block `alloy-config.river:83-91` + Kubo Health panels `cipherbox-staging.json:1914-2116` wired. Peer/bandwidth panels empty because Kubo v0.34.0 emits no libp2p metrics upstream (baselines doc lines 87-92) — accepted as upstream limitation, not a code defect |
| PERF-04     | 18-01-PLAN  | TEE republish batch duration histogram                                  | SATISFIED         | `metrics.service.ts:214-220`; `republish.processor.ts:22,49` with success/failure `result` label (`:25,40,44`)                                                                                                                                  |

No orphaned requirements: all of PERF-01..04 are declared in plan frontmatter (18-01 → PERF-01/02/04; 18-02 → PERF-02/03) and mapped above. This report closes the PERF-01..04 "orphaned" finding in `.planning/v1.1-MILESTONE-AUDIT.md` with concrete file:line evidence.

### Anti-Patterns Found

| File                              | Line | Pattern                          | Severity | Impact                                                                              |
| --------------------------------- | ---- | -------------------------------- | -------- | ---------------------------------------------------------------------------------- |
| `ipns.service.ts` / `ipfs.controller.ts` | 50, 108 | `source: ''` empty label value | ℹ️ Info  | Intentional empty default label dimension for the histogram; not a stub — timers are observed via `endTimer` |

No debt markers (TBD/FIXME/XXX) or stub returns introduced by Phase 18 code. The `source: ''` defaults are deliberate label placeholders, not unimplemented logic.

### Known Limitations (Accepted — upstream Kubo, not human-actionable)

PERF-03's deliverable (scrape Kubo + Kubo Health panels) is implemented and wired. The peer/bandwidth/datastore visibility gap is an **upstream Kubo limitation**, accepted by the maintainer on 2026-06-19 (see `overrides`) — it is not routed to human verification because no human action or code change can surface metrics the Kubo build does not emit.

#### 1. Kubo peer count and bandwidth metrics — upstream gap

The Alloy scrape block and Grafana Kubo Health panels are correctly wired, but `.planning/baselines/18-performance-baselines.md` (lines 87-91) records that **Kubo v0.34.0 does not expose libp2p metrics** to Prometheus (`libp2p_swarm_connections_*`, `libp2p_network_*_bytes_total`), so the panels show "No data". The scrape will populate automatically on a Kubo build that exposes these metrics.

#### 2. Kubo-sourced datastore size metric — app gauge used instead

No datastore-size panel is sourced from the Kubo scrape; the dashboard's storage figure uses the CipherBox `cipherbox_storage_bytes_total` app gauge (baseline doc line 92). Datastore observability is therefore satisfied via the app gauge rather than the Kubo endpoint.

### Gaps Summary

The API-side instrumentation contract (PERF-01, PERF-02, PERF-04) is fully achieved and wired in current code: two new histograms are registered on the Prometheus registry with correct labels/buckets, all four IPFS/IPNS operations (resolve, publish, pin, cat) and the TEE republish batch are instrumented with start/end timers carrying success/failure result labels, the HTTP interceptor is globally registered, and the Grafana dashboard renders p50/p95/p99 via `histogram_quantile`. The baselines document and benchmark script exist with real per-operation and per-route p50/p95/p99 values from staging.

PERF-03's deliverable is also in place — the Kubo Alloy scrape block and Grafana Kubo Health panels are present and wired. The peer/bandwidth panels show "No data" only because Kubo v0.34.0 does not emit libp2p metrics upstream, and datastore size is observed via the app gauge rather than the Kubo endpoint. This is an upstream-infrastructure constraint that no human action or code change can resolve, so it is recorded as an accepted override (maintainer, 2026-06-19) rather than an open human item — the scrape wiring is correct and will surface data on a Kubo build that exposes those metrics. No code blockers were found; status is `passed`.

---

_Verified: 2026-06-19T16:00:00Z_
_Verifier: Claude (gsd-verifier); PERF-03 upstream-Kubo limitation accepted by maintainer 2026-06-19_

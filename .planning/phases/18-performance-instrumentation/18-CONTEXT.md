# Phase 18: Performance Instrumentation - Context

**Gathered:** 2026-03-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Add IPFS/IPNS duration histograms, Kubo node health metrics scraping, and TEE batch timing to the existing Prometheus instrumentation. Capture "before" baselines via a synthetic test script on staging. This phase instruments only — no architectural changes, no client-side timing (Phase 22), no alerting.

</domain>

<decisions>
## Implementation Decisions

### Histogram bucket design

- Two-tier bucket strategy: "fast" tier for DB-path operations, "slow" tier for network operations
- Fast tier: exponential spacing, ~1ms to 500ms (DB resolve, local lookups)
- Slow tier: exponential spacing, ~50ms to 30s upper bound (DHT resolve, IPFS pin, IPFS cat)
- Extended tier for TEE republish batches: 1s to 120s (batches process multiple entries)
- Exponential bucket spacing for all tiers (not linear) — better resolution where observations cluster

### Kubo metrics scope

- Scrape full Kubo Prometheus endpoint but only build dashboard panels for: peer count, bandwidth in/out, datastore size
- Other Kubo metrics exist in Prometheus for ad-hoc queries but don't need dedicated panels
- Alloy scrapes Kubo directly as a second prometheus.scrape target (ipfs:5001/debug/metrics/prometheus) — not proxied through CipherBox API
- Metrics infrastructure is staging-only; local dev does not run Alloy/Prometheus

### Dashboard and baseline format

- Extend existing cipherbox-staging.json dashboard with new rows (not a separate dashboard)
- Add IPFS/IPNS duration panels alongside existing counter panels in their respective rows
- Add a new "Kubo Health" row for peer count, bandwidth, datastore panels
- No Grafana alerting rules in this phase — observation only, alerts premature before baselines established
- "Before" baselines documented as a markdown file in .planning/ with observed p50/p95/p99 values
- Baselines captured from staging using a synthetic test script (uploads, downloads, resolves, publishes) — reproducible and comparable with Phase 22

### Metric label granularity

- IPFS/IPNS duration histograms carry labels: `operation` (resolve/publish/pin/cat) + `result` (success/error/timeout) + `source` (db/network, for resolve only)
- TEE republish batch histogram carries `tee_provider` label (currently `mock`, later `phala`, then `nitro` in M4) — zero cardinality cost now, future-proofs comparison
- Whether to add `record_type` (folder/file) to IPNS histograms: Claude's discretion based on whether code paths actually differ

### Claude's Discretion

- Whether IPFS pin/cat histograms carry a `size_bucket` label — depends on whether file size is easily accessible at the instrumentation point
- Whether IPNS histograms carry `record_type` (folder/file) label — depends on code path divergence
- Exact exponential bucket values for each tier
- Synthetic test script implementation details (language, number of iterations, warm-up)
- Grafana panel layout within existing rows

</decisions>

<code_context>

## Existing Code Insights

### Reusable Assets

- `MetricsService` (`apps/api/src/metrics/metrics.service.ts`): Central prom-client registry with 5 gauges, 8 counters, 1 HTTP histogram. New histograms should be added here following the same pattern.
- `HttpMetricsInterceptor` (`apps/api/src/metrics/http-metrics.interceptor.ts`): Already captures per-route HTTP latency with method/route/status_code labels. Covers PERF-02 requirement partially.
- `MetricsModule` (`apps/api/src/metrics/metrics.module.ts`): Global module — any service can inject MetricsService.
- `MetricsController` (`apps/api/src/metrics/metrics.controller.ts`): Exposes `/metrics` endpoint, excluded from Swagger.

### Established Patterns

- Counters incremented in controllers: `ipns.controller.ts` increments ipnsPublishes/ipnsResolves, `ipfs.controller.ts` increments fileUploads/fileDownloads
- Duration timing should wrap the same call sites — add `process.hrtime.bigint()` around the IPNS service calls and IPFS provider calls
- Alloy config (`docker/alloy-config.river`): scrapes API /metrics every 30s, ships to Grafana Cloud Mimir
- Grafana dashboard JSON (`docker/grafana/dashboards/cipherbox-staging.json`): manually maintained, imported to Grafana Cloud

### Integration Points

- `apps/api/src/ipns/ipns.service.ts`: IPNS resolve and publish logic — instrument here for resolve/publish duration
- `apps/api/src/ipfs/providers/local.provider.ts`: IPFS pin and cat operations — instrument here for pin/cat duration
- `apps/api/src/republish/republish.processor.ts`: TEE batch processing — already has counter increments, add duration histogram
- `docker/alloy-config.river`: Add second scrape target for Kubo metrics
- `docker/docker-compose.staging.yml`: May need Kubo API port exposed to Alloy network

</code_context>

<specifics>
## Specific Ideas

- TEE provider is currently the local mock (not Phala yet) — `tee_provider` label will be `mock` for now
- Synthetic baseline script should be reusable in Phase 22 for "after" comparison
- 30s upper bound on slow tier matches the IPNS polling interval — anything beyond is a full cycle miss

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

_Phase: 18-performance-instrumentation_
_Context gathered: 2026-03-07_

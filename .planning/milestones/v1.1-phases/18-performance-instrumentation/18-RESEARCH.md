# Phase 18: Performance Instrumentation - Research

**Researched:** 2026-03-07
**Domain:** Prometheus metrics instrumentation, Grafana dashboards, Kubo metrics scraping
**Confidence:** HIGH

## Summary

Phase 18 adds duration histograms for IPFS/IPNS operations, scrapes Kubo Prometheus metrics, adds TEE batch duration tracking, and captures "before" baselines. The existing `MetricsService` in `apps/api/src/metrics/metrics.service.ts` is a well-structured central registry using `prom-client` v15.1.3 with 5 gauges, 8 counters, and 1 HTTP histogram. New histograms follow the same pattern -- register against `this.registry`, expose via `/metrics`. The existing `HttpMetricsInterceptor` already captures per-route HTTP latency with `method/route/status_code` labels, partially satisfying PERF-02.

The main instrumentation points are `IpnsService.publishRecord()` / `resolveRecord()` for IPNS operations, `LocalProvider.pinFile()` / `getFile()` for IPFS operations, and `RepublishProcessor.process()` for TEE batch duration. Kubo exposes Prometheus metrics at `http://ipfs:5001/debug/metrics/prometheus` -- Alloy scrapes this as a second `prometheus.scrape` target.

**Primary recommendation:** Add 3 new Histogram instances to MetricsService (IPFS/IPNS duration, TEE batch duration), wrap existing service calls with `process.hrtime.bigint()` timing, add a second Alloy scrape target for Kubo, extend the existing Grafana dashboard JSON with new panels, and write a shell/TypeScript synthetic test script for baseline capture.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- Two-tier bucket strategy: "fast" tier for DB-path operations, "slow" tier for network operations
- Fast tier: exponential spacing, ~1ms to 500ms (DB resolve, local lookups)
- Slow tier: exponential spacing, ~50ms to 30s upper bound (DHT resolve, IPFS pin, IPFS cat)
- Extended tier for TEE republish batches: 1s to 120s (batches process multiple entries)
- Exponential bucket spacing for all tiers (not linear)
- Scrape full Kubo Prometheus endpoint but only build dashboard panels for: peer count, bandwidth in/out, datastore size
- Other Kubo metrics exist in Prometheus for ad-hoc queries but don't need dedicated panels
- Alloy scrapes Kubo directly as a second prometheus.scrape target (ipfs:5001/debug/metrics/prometheus) -- not proxied through CipherBox API
- Metrics infrastructure is staging-only; local dev does not run Alloy/Prometheus
- Extend existing cipherbox-staging.json dashboard with new rows (not a separate dashboard)
- Add IPFS/IPNS duration panels alongside existing counter panels in their respective rows
- Add a new "Kubo Health" row for peer count, bandwidth, datastore panels
- No Grafana alerting rules in this phase -- observation only
- "Before" baselines documented as a markdown file in .planning/ with observed p50/p95/p99 values
- Baselines captured from staging using a synthetic test script (uploads, downloads, resolves, publishes) -- reproducible and comparable with Phase 22
- IPFS/IPNS duration histograms carry labels: `operation` (resolve/publish/pin/cat) + `result` (success/error/timeout) + `source` (db/network, for resolve only)
- TEE republish batch histogram carries `tee_provider` label (currently `mock`, later `phala`, then `nitro` in M4)
- Whether to add `record_type` (folder/file) to IPNS histograms: Claude's discretion based on whether code paths actually differ

### Claude's Discretion

- Whether IPFS pin/cat histograms carry a `size_bucket` label -- depends on whether file size is easily accessible at the instrumentation point
- Whether IPNS histograms carry `record_type` (folder/file) label -- depends on code path divergence
- Exact exponential bucket values for each tier
- Synthetic test script implementation details (language, number of iterations, warm-up)
- Grafana panel layout within existing rows

### Deferred Ideas (OUT OF SCOPE)

None -- discussion stayed within phase scope

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                            | Research Support                                                                                                                          |
| ------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| PERF-01 | IPFS/IPNS duration histograms added to Prometheus (publish, resolve, pin, cat)         | Add histograms to MetricsService; wrap IpnsService and LocalProvider calls with hrtime timing; labels per CONTEXT.md                      |
| PERF-02 | API endpoint p50/p95/p99 baselines defined per critical route                          | HttpMetricsInterceptor already captures per-route latency; dashboard already has p50/p95/p99 panel; baselines captured via synthetic test |
| PERF-03 | Kubo Prometheus endpoint scraped for node health metrics (peers, bandwidth, datastore) | Add second Alloy scrape target for ipfs:5001; Kubo exposes libp2p*swarm*\* and Go runtime metrics; build 3 Grafana panels                 |
| PERF-04 | TEE republish batch duration histogram added                                           | Add histogram to MetricsService; wrap processRepublishBatch in RepublishProcessor with timing; extended bucket tier                       |

</phase_requirements>

## Standard Stack

### Core

| Library     | Version | Purpose                          | Why Standard                                                       |
| ----------- | ------- | -------------------------------- | ------------------------------------------------------------------ |
| prom-client | ^15.1.3 | Prometheus metrics for Node.js   | Already in use; project standard. Supports histograms with labels. |
| Alloy       | v1.6.1  | Prometheus scraping and shipping | Already deployed in staging docker-compose.                        |

### Supporting

| Library | Version | Purpose                          | When to Use                       |
| ------- | ------- | -------------------------------- | --------------------------------- |
| Grafana | Cloud   | Dashboard visualization          | Dashboard JSON maintained in repo |
| Kubo    | v0.34.0 | IPFS node with Prometheus /debug | Existing staging deployment       |

### Alternatives Considered

| Instead of    | Could Use              | Tradeoff                                                                                      |
| ------------- | ---------------------- | --------------------------------------------------------------------------------------------- |
| prom-client   | @opentelemetry/api     | OTel is future direction but project already uses prom-client; migration is Phase 22+ concern |
| Manual hrtime | prom-client startTimer | startTimer() returns a function; slightly cleaner but same underlying mechanism               |

**Installation:**
No new dependencies needed. `prom-client` v15.1.3 is already installed.

## Architecture Patterns

### Recommended Project Structure

No new files beyond the ones modified:

```
apps/api/src/
  metrics/
    metrics.service.ts          # ADD: 3 new Histogram instances
  ipns/
    ipns.service.ts             # ADD: timing wrappers in publishRecord/resolveRecord
  ipfs/
    providers/
      local.provider.ts         # ADD: timing wrappers in pinFile/getFile
  republish/
    republish.processor.ts      # ADD: timing wrapper around processRepublishBatch

docker/
  alloy-config.river            # ADD: second prometheus.scrape for Kubo
  docker-compose.staging.yml    # VERIFY: Kubo API port accessible to Alloy
  grafana/dashboards/
    cipherbox-staging.json      # ADD: new panels in existing rows + new Kubo Health row

scripts/
  baseline-benchmark.ts         # NEW: synthetic test script for baseline capture

.planning/
  baselines/
    18-performance-baselines.md  # NEW: documented p50/p95/p99 values
```

### Pattern 1: Histogram Registration in MetricsService

**What:** Add new `client.Histogram` instances following the existing pattern.
**When to use:** All new duration metrics.
**Example:**

```typescript
// In MetricsService constructor, after existing httpRequestDuration
this.ipfsIpnsDuration = new client.Histogram({
  name: 'cipherbox_ipfs_ipns_duration_seconds',
  help: 'Duration of IPFS/IPNS operations in seconds',
  labelNames: ['operation', 'result', 'source'] as const,
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30],
  registers: [this.registry],
});
```

### Pattern 2: Timing Wrapper Using process.hrtime.bigint()

**What:** Wrap async calls with timing, matching existing HttpMetricsInterceptor pattern.
**When to use:** Around each IPFS/IPNS service call.
**Example:**

```typescript
// In IpnsService.resolveRecord()
async resolveRecord(ipnsName: string) {
  const startTime = process.hrtime.bigint();
  let result: 'success' | 'error' | 'timeout' = 'success';
  let source = 'network';
  try {
    // ... existing logic ...
  } catch (error) {
    result = 'error';
    throw error;
  } finally {
    const durationNs = Number(process.hrtime.bigint() - startTime);
    const durationSec = durationNs / 1e9;
    this.metricsService.ipfsIpnsDuration
      .labels('resolve', result, source)
      .observe(durationSec);
  }
}
```

### Pattern 3: prom-client startTimer() Alternative

**What:** Use the built-in `startTimer()` method on Histogram for cleaner code.
**When to use:** When the label values are known before timing starts.
**Example:**

```typescript
const end = this.metricsService.ipfsIpnsDuration.startTimer({ operation: 'pin' });
try {
  const result = await this.pinFile(data);
  end({ result: 'success', source: '' });
  return result;
} catch (err) {
  end({ result: 'error', source: '' });
  throw err;
}
```

Note: `startTimer()` returns a function that, when called, observes the elapsed time. Label values can be provided at start and/or completion. This is the recommended pattern from prom-client.

### Anti-Patterns to Avoid

- **Timing at the controller layer instead of service layer:** Controllers already have HttpMetricsInterceptor for HTTP-level timing. IPFS/IPNS operation timing must be at the service/provider layer to capture the actual network call duration, not the full request lifecycle.
- **Using `Date.now()` for timing:** Insufficient resolution for fast operations. Use `process.hrtime.bigint()` (nanosecond precision) or `startTimer()`.
- **Creating separate histograms per operation:** One histogram with an `operation` label is more queryable (can aggregate or filter). Don't create `cipherbox_ipns_resolve_duration_seconds` and `cipherbox_ipns_publish_duration_seconds` separately.
- **Timing inside retry loops:** The delegated routing client has retry logic. Timing should wrap the entire call to `DelegatedRoutingClient.publish()` or `resolve()`, including retries, since that's what the caller actually waits for.

## Don't Hand-Roll

| Problem                   | Don't Build                                | Use Instead                               | Why                                                                |
| ------------------------- | ------------------------------------------ | ----------------------------------------- | ------------------------------------------------------------------ |
| Histogram percentile math | Custom p50/p95/p99 calculation             | Prometheus `histogram_quantile()`         | Prometheus handles this natively from histogram buckets            |
| Metrics registry          | Custom metric collection and serialization | prom-client Registry                      | Already in use; handles text format, content type                  |
| Kubo health metrics       | Custom polling via `ipfs stats bw` API     | Kubo's native `/debug/metrics/prometheus` | Built-in Prometheus endpoint; Alloy scrapes directly               |
| Synthetic load generation | Custom HTTP client with timing             | `curl` + `jq` in a shell script           | Simple, reproducible, no dependencies; or `tsx` for typed approach |

**Key insight:** The entire metrics pipeline (collection -> scraping -> storage -> visualization) is already built. This phase only adds new metric definitions and dashboard panels.

## Common Pitfalls

### Pitfall 1: High Cardinality Labels

**What goes wrong:** Adding labels like `userId`, `ipnsName`, or `cid` to histograms creates unbounded label cardinality, causing Prometheus to OOM.
**Why it happens:** Temptation to add debugging detail to metrics.
**How to avoid:** Only use bounded labels: `operation` (4 values), `result` (3 values), `source` (2 values), `tee_provider` (1-3 values). Total cardinality stays under 30.
**Warning signs:** Prometheus scrape duration increasing, "too many time series" errors.

### Pitfall 2: Bucket Boundaries Not Covering Expected Range

**What goes wrong:** If all observations fall into the +Inf bucket, the histogram becomes useless for percentile calculation.
**Why it happens:** Choosing bucket boundaries without knowing the actual latency distribution.
**How to avoid:** Use the two-tier strategy from CONTEXT.md. The slow tier's 30s upper bound matches the IPNS polling interval -- anything beyond is already a full cycle miss. Fast tier covers 1ms-500ms for DB lookups.
**Warning signs:** All histogram observations in the +Inf or first bucket.

### Pitfall 3: Alloy Network Isolation

**What goes wrong:** Alloy container can't reach `ipfs:5001` because they're in different Docker networks.
**Why it happens:** docker-compose.staging.yml doesn't explicitly define networks; default network should work, but Kubo's API port (5001) is bound to `127.0.0.1`.
**How to avoid:** Alloy accesses Kubo via Docker's internal network (service name `ipfs`), not via host-bound ports. The `127.0.0.1:5001:5001` binding is for host access. Container-to-container uses port 5001 directly. Verify by checking that Alloy can resolve `ipfs:5001`.
**Warning signs:** Alloy logs showing connection refused or timeout for Kubo scrape target.

### Pitfall 4: Kubo /debug/metrics/prometheus Requires API Port

**What goes wrong:** Scraping the gateway port (8080) for metrics instead of the API port (5001).
**Why it happens:** Confusion between Kubo's gateway (read-only, port 8080) and API (full access, port 5001).
**How to avoid:** Always use `ipfs:5001/debug/metrics/prometheus` for metrics scraping. The path `/debug/metrics/prometheus` is only available on the API port.
**Warning signs:** 404 responses from metrics endpoint.

### Pitfall 5: Timing the Wrong Layer for IPNS Resolve

**What goes wrong:** Timing only the delegated routing call, missing the DB fallback path.
**Why it happens:** `resolveRecord()` in IpnsService has two sources -- network (delegatedRouting.resolve) and DB (folderIpnsRepository.findOne). The `source` label must accurately reflect which path was taken.
**How to avoid:** Instrument inside `resolveRecord()` with logic to determine the source. The existing code already has this logic (checking `signatureV2` presence for network vs DB).
**Warning signs:** Metrics show only network resolves but logs show DB fallbacks happening.

### Pitfall 6: Dashboard Panel Y-Axis Collisions

**What goes wrong:** Existing panels shift position when new panels/rows are added, breaking the dashboard layout.
**Why it happens:** Grafana uses a grid layout with `gridPos` (`x`, `y`, `w`, `h`). Inserting rows requires updating all subsequent panels' `y` coordinates.
**How to avoid:** Add new duration panels within existing rows (after their respective counter panels) and append the new "Kubo Health" row at the end of existing content rows (before Logs rows). Calculate y-offsets carefully.
**Warning signs:** Dashboard JSON validation errors, panels overlapping.

## Code Examples

### New Histogram Definitions (MetricsService)

```typescript
// IPFS/IPNS operation duration -- two bucket tiers combined
// Fast operations (DB resolve): 1ms to 500ms
// Slow operations (network): 50ms to 30s
readonly ipfsIpnsDuration: client.Histogram;

// TEE republish batch duration -- extended tier: 1s to 120s
readonly republishBatchDuration: client.Histogram;

// In constructor:
this.ipfsIpnsDuration = new client.Histogram({
  name: 'cipherbox_ipfs_ipns_duration_seconds',
  help: 'Duration of IPFS/IPNS operations in seconds',
  labelNames: ['operation', 'result', 'source'] as const,
  // Combined: fast tier (0.001-0.5) + slow tier (0.05-30)
  // Exponential spacing: each ~2-2.5x the previous
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30],
  registers: [this.registry],
});

this.republishBatchDuration = new client.Histogram({
  name: 'cipherbox_republish_batch_duration_seconds',
  help: 'Duration of TEE republish batch processing in seconds',
  labelNames: ['tee_provider', 'result'] as const,
  // Extended tier: 1s to 120s for batch processing
  buckets: [1, 2.5, 5, 10, 15, 30, 45, 60, 90, 120],
  registers: [this.registry],
});
```

### Instrumented IpnsService.resolveRecord()

```typescript
async resolveRecord(ipnsName: string): Promise<{...} | null> {
  const end = this.metricsService.ipfsIpnsDuration.startTimer({
    operation: 'resolve',
  });
  let resolveResult: 'success' | 'error' | 'timeout' = 'error';
  let source = 'db'; // default; overwritten if network succeeds
  try {
    // ... existing delegated routing + DB logic ...
    // After determining source:
    if (result?.signatureV2) source = 'network';
    if (result || cached) resolveResult = 'success';
    return /* result */;
  } catch (error) {
    resolveResult = 'error';
    throw error;
  } finally {
    end({ result: resolveResult, source });
  }
}
```

### Instrumented LocalProvider.pinFile()

```typescript
async pinFile(data: Buffer, _metadata?: Record<string, string>): Promise<{ cid: string; size: number }> {
  const end = this.metricsService.ipfsIpnsDuration.startTimer({
    operation: 'pin',
    source: '',  // source label not applicable for IPFS ops
  });
  try {
    const result = /* existing pin logic */;
    end({ result: 'success' });
    return result;
  } catch (error) {
    end({ result: 'error' });
    throw error;
  }
}
```

Note: LocalProvider currently does not inject MetricsService. It will need MetricsService injected, which means either:
(a) Injecting it via the IpfsModule provider factory, or
(b) Moving timing to IpfsController (less ideal but simpler).

Since LocalProvider is constructed manually in the IpfsModule factory (not via NestJS DI), the cleanest approach is to pass MetricsService to the constructor or to instrument at the IpfsController level where MetricsService is already injected.

### Alloy Config for Kubo Scrape

```river
// Scrape Kubo /debug/metrics/prometheus endpoint
prometheus.scrape "kubo" {
  targets = [{
    __address__ = "ipfs:5001",
  }]
  metrics_path = "/debug/metrics/prometheus"
  scrape_interval = "30s"

  forward_to = [prometheus.remote_write.grafana_cloud.receiver]
}
```

### Grafana Dashboard -- Kubo Health Panel (PromQL)

```promql
// Peer count (connected peers derived from swarm connections)
// Kubo exposes libp2p_swarm_connections_opened_total and _closed_total
// Net open connections = opened - closed (as an approximation)
libp2p_swarm_connections_opened_total - libp2p_swarm_connections_closed_total

// Alternative: use Go process metrics if libp2p metrics aren't exposed in v0.34
// go_goroutines, process_open_fds can serve as proxies
```

### Synthetic Baseline Script Structure

```bash
#!/usr/bin/env bash
# scripts/baseline-benchmark.sh
# Runs against staging API to generate metrics observations
# Usage: ./scripts/baseline-benchmark.sh https://api-staging.cipherbox.cc <JWT_TOKEN>

API_URL="${1:?Usage: $0 <api-url> <jwt-token>}"
TOKEN="${2:?Usage: $0 <api-url> <jwt-token>}"

ITERATIONS=20
WARMUP=3

echo "=== CipherBox Performance Baseline ==="
echo "API: $API_URL"
echo "Iterations: $ITERATIONS (warmup: $WARMUP)"
echo ""

# 1. IPNS Resolve (tests DB and network paths)
echo "--- IPNS Resolve ---"
for i in $(seq 1 $((WARMUP + ITERATIONS))); do
  curl -s -o /dev/null -w "%{time_total}" \
    -H "Authorization: Bearer $TOKEN" \
    "$API_URL/ipns/resolve?ipnsName=<test-name>"
  echo ""
done | tail -n $ITERATIONS | sort -n

# 2. File Upload (small file, tests IPFS pin)
# 3. File Download (tests IPFS cat)
# 4. IPNS Publish (tests delegated routing)
```

## Discretion Decisions

### `size_bucket` label on IPFS pin/cat: DO NOT ADD

**Reasoning:** `LocalProvider.pinFile()` receives a `Buffer` so `data.length` is available. However, adding a `size_bucket` label (e.g., `<1KB`, `1-100KB`, `100KB-1MB`, `>1MB`) increases cardinality by 4x for only modest diagnostic value. File size correlation can be done via log analysis if needed. The overhead is not justified for a baseline phase.

### `record_type` label on IPNS histograms: DO NOT ADD

**Reasoning:** Examining `IpnsService.publishRecord()` and `resolveRecord()`, the code paths are identical for folder and file records. The `recordType` parameter only affects the DB field value, not the network call behavior. Adding this label would double cardinality without providing actionable information. If future phases show different performance characteristics, it can be added then.

## State of the Art

| Old Approach                   | Current Approach                        | When Changed     | Impact                                                      |
| ------------------------------ | --------------------------------------- | ---------------- | ----------------------------------------------------------- |
| prom-client default buckets    | Custom bucket tiers per operation type  | Project decision | Better resolution for both fast (DB) and slow (network) ops |
| Separate histogram per metric  | Single histogram with `operation` label | Best practice    | Simpler queries, lower total metric count                   |
| Proxy Kubo metrics through API | Alloy scrapes Kubo directly             | Project decision | No code changes in API; clean separation of concerns        |
| Manual baseline measurement    | Synthetic test script                   | Project decision | Reproducible, comparable across phases                      |

**Deprecated/outdated:**

- Kubo `total_provide_count_total` metric renamed to `provider_provides_total` in v0.39+. Not relevant for v0.34 but noted for future upgrade.
- Kubo v0.35+ disabled datastore metrics by default (need `--profile=flatfs-measure`). v0.34 still has them enabled by default.

## Open Questions

1. **Exact Kubo v0.34 Prometheus metric names for peer count and bandwidth**
   - What we know: Kubo exposes metrics at `/debug/metrics/prometheus`. libp2p swarm metrics (`libp2p_swarm_connections_opened_total`, `_closed_total`) are available in go-libp2p since v0.26. Go runtime metrics (`go_goroutines`, `process_*`) are always present. Bandwidth and peer count are NOT natively exported as Prometheus metrics in Kubo -- they are available via RPC API (`/api/v0/swarm/peers`, `/api/v0/stats/bw`).
   - What's unclear: Whether Kubo v0.34 includes the go-libp2p swarm Prometheus metrics (they were added in go-libp2p v0.26, which Kubo v0.34 may or may not bundle).
   - Recommendation: Deploy the Alloy scrape target first, then inspect the actual metric output from Kubo on staging. Build dashboard panels based on observed metrics. If swarm connection metrics aren't available, use `ipfs swarm peers | wc -l` via a custom exporter or accept that peer count requires the RPC API. This can be resolved during implementation.

2. **LocalProvider MetricsService injection**
   - What we know: `LocalProvider` is constructed manually (not via NestJS DI). `MetricsService` is injected in `IpfsController` but not available in `LocalProvider`.
   - What's unclear: Best approach to inject MetricsService into LocalProvider without refactoring the provider factory.
   - Recommendation: Instrument at the controller level (IpfsController already has MetricsService) rather than modifying the provider factory. The timing difference between controller-level and provider-level is negligible (the provider is called synchronously from the controller).

## Validation Architecture

### Test Framework

| Property           | Value                                 |
| ------------------ | ------------------------------------- |
| Framework          | Jest + ts-jest                        |
| Config file        | `apps/api/jest.config.js`             |
| Quick run command  | `cd apps/api && pnpm test -- --watch` |
| Full suite command | `cd apps/api && pnpm test`            |

### Phase Requirements -> Test Map

| Req ID  | Behavior                                            | Test Type | Automated Command                                                         | File Exists?      |
| ------- | --------------------------------------------------- | --------- | ------------------------------------------------------------------------- | ----------------- |
| PERF-01 | IPFS/IPNS duration histograms registered + observed | unit      | `cd apps/api && npx jest src/metrics/metrics.service.spec.ts -x`          | Wave 0            |
| PERF-01 | IpnsService timing wraps resolve/publish            | unit      | `cd apps/api && npx jest src/ipns/ipns.service.spec.ts -x`                | Existing (update) |
| PERF-01 | IpfsController timing wraps upload/download         | unit      | `cd apps/api && npx jest src/ipfs/ipfs.controller.spec.ts -x`             | Existing (update) |
| PERF-02 | HTTP histogram already captures per-route latency   | existing  | `cd apps/api && npx jest src/metrics/http-metrics.interceptor.spec.ts -x` | Wave 0            |
| PERF-03 | Alloy config has Kubo scrape target                 | manual    | Verify `alloy-config.river` has prometheus.scrape "kubo" block            | N/A (config)      |
| PERF-03 | Dashboard JSON has Kubo Health row                  | manual    | Verify `cipherbox-staging.json` has Kubo Health panels                    | N/A (JSON)        |
| PERF-04 | TEE batch duration histogram observed               | unit      | `cd apps/api && npx jest src/republish/republish.processor.spec.ts -x`    | Existing (update) |

### Sampling Rate

- **Per task commit:** `cd apps/api && pnpm test` (full unit suite, ~30s)
- **Per wave merge:** `cd apps/api && pnpm test` (same -- no integration test infra for metrics)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `apps/api/src/metrics/metrics.service.spec.ts` -- covers PERF-01, PERF-04: verify new histograms are registered and observable
- [ ] `apps/api/src/metrics/http-metrics.interceptor.spec.ts` -- covers PERF-02: verify interceptor records duration (may exist but not found in file listing)

_(Existing spec files for ipns.service, ipfs.controller, and republish.processor need updates to mock and verify new histogram calls)_

## Sources

### Primary (HIGH confidence)

- **Codebase inspection:** `apps/api/src/metrics/metrics.service.ts` -- existing MetricsService with registry, gauges, counters, 1 histogram
- **Codebase inspection:** `apps/api/src/metrics/http-metrics.interceptor.ts` -- existing HTTP latency interceptor with process.hrtime.bigint()
- **Codebase inspection:** `apps/api/src/ipns/ipns.service.ts` -- IPNS resolve/publish with delegated routing + DB fallback
- **Codebase inspection:** `apps/api/src/ipfs/providers/local.provider.ts` -- IPFS pin/cat via Kubo API
- **Codebase inspection:** `apps/api/src/republish/republish.processor.ts` -- TEE batch processing with existing counter metrics
- **Codebase inspection:** `docker/alloy-config.river` -- Alloy scrape config for CipherBox API
- **Codebase inspection:** `docker/docker-compose.staging.yml` -- staging services including Kubo v0.34.0 on ports 5001/8080
- **Codebase inspection:** `docker/grafana/dashboards/cipherbox-staging.json` -- 984-line dashboard JSON with 6 rows, 20 panels
- **Codebase inspection:** `apps/api/package.json` -- prom-client ^15.1.3, NestJS v11

### Secondary (MEDIUM confidence)

- [prom-client npm](https://www.npmjs.com/package/prom-client) -- Histogram API with startTimer(), labels, buckets
- [Grafana Alloy prometheus.scrape docs](https://grafana.com/docs/alloy/latest/reference/components/prometheus/prometheus.scrape/) -- multiple scrape targets syntax
- [go-libp2p swarm dashboard](https://github.com/libp2p/go-libp2p/tree/master/dashboards/swarm) -- `libp2p_swarm_connections_opened_total`, `_closed_total`, `_handshake_latency_seconds` metric names

### Tertiary (LOW confidence)

- Kubo v0.34 specific Prometheus metric names for peer count and bandwidth -- documentation is sparse; actual available metrics must be verified by scraping a running instance
- [Kubo /debug/metrics/prometheus issue #9210](https://github.com/ipfs/kubo/issues/9210) -- confirmed docs were added to `docs/metrics.md` but file covers DHT/gateway/HTTP metrics, not swarm/bandwidth/peer count

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- prom-client and Alloy already in use, no new dependencies
- Architecture: HIGH -- patterns directly extend existing MetricsService code; well-understood
- Pitfalls: HIGH -- based on direct codebase inspection of integration points
- Kubo metrics: LOW -- exact metric names for v0.34 peer/bandwidth not verified; must inspect running instance

**Research date:** 2026-03-07
**Valid until:** 2026-04-07 (stable domain; metrics APIs rarely change)

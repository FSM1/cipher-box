# Phase 26: Observability & UX Tuning - Research

**Researched:** 2026-03-26
**Domain:** Grafana Cloud alerting, PromQL alert rules, client-side timeout tuning
**Confidence:** HIGH

## Summary

Phase 26 bridges the gap between collected performance baselines (Phase 18/22) and actionable operational monitoring. The work divides into two tracks: (1) creating Grafana-managed alert rules that fire when IPNS resolve, IPFS pin, API latency, and IPNS publish exceed p95 thresholds derived from documented baselines, and (2) tuning client-side timeout/retry constants in SDK providers and API services based on observed p99 values to deliver sub-2s perceived latency on upload-to-visible, vault load, and download-to-open.

The project uses Grafana Cloud (hosted SaaS) with Alloy shipping metrics to Grafana Cloud Mimir. There is no self-hosted Grafana instance, which means file-based provisioning (`provisioning/alerting/`) does not apply. Alert rules must be provisioned via the Grafana Alerting Provisioning HTTP API (`POST /api/v1/provisioning/alert-rules`) or created through the Grafana Cloud UI. Since CONTEXT.md specifies "alert rules provisioned as code in `docker/grafana/` directory, version-controlled alongside dashboard JSON," the implementation should store rule definitions as JSON files in the repo and use a script to apply them via the HTTP API.

**Primary recommendation:** Store alert rule definitions as JSON in `docker/grafana/alerts/`, apply via `curl` script against Grafana Cloud API. Reduce timeout constants to 2-3x observed p99 values from baselines. Validate with Phase 22 journey tests before and after.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- Two-tier severity: Warning at p95 threshold, Critical at p99 or 2x p95
- DB fallback rate alert at >20% (IPNS resolves falling back to database indicates Someguy/DHT degradation)
- Thresholds hardcoded in Grafana alert rule provisioning files (not env-driven)
- Four operations get dedicated alert rules: IPNS resolve latency, IPFS pin latency, API endpoint latency (critical routes: upload, download, vault load), IPNS publish latency
- Threshold values derived from Phase 18/22 documented baselines (p95/p99 columns)
- Grafana Cloud built-in alerting (alert rules + contact points)
- Notification channel: Grafana UI only (no email/Slack/Discord push for now)
- Alert rules provisioned as code in `docker/grafana/` directory, version-controlled alongside dashboard JSON
- No self-hosted Alertmanager or Alloy-side alerting
- Sub-2s targets for: Upload-to-visible (1,355ms baseline), Vault/folder load (86ms + 224ms p95 IPNS resolve), Download-to-open (133ms IPFS cat p50)
- Share-to-accessible (3,039ms): tune where possible but accept >2s target
- Timeout reduction strategy: conservative 2-3x observed p99 from baselines
- Login-to-vault (23s) dominated by Web3Auth, not a tuning target
- Dual-environment validation: local for fast iteration, staging for final comparison
- Rerun Phase 22 Playwright journey tests before and after changes
- Rerun vitest load harness from Phase 22 with updated timeouts
- Manual comparison of before/after timings (no automated CI timing gates)

### Claude's Discretion

- Exact threshold values per operation (derived from baseline documents)
- Grafana alert rule YAML/JSON structure and provisioning format
- Which specific API routes to include in HTTP latency alerting
- Retry backoff tuning details (exponential backoff base delay, max retries per operation)

### Deferred Ideas (OUT OF SCOPE)

- Dedicated timeout regression test suite
- Push notification channels (email, Slack, Discord webhooks)
- Automated CI timing gates

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID     | Description                                                                                | Research Support                                                                                                                                                    |
| ------ | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OBS-01 | Grafana alerts fire when IPNS/IPFS/API response times exceed p95 thresholds from baselines | Baseline data extracted (see Threshold Derivation); Grafana Cloud API provisioning format documented; PromQL query patterns for histogram_quantile verified         |
| OBS-02 | Client-side timeouts and retry config tuned for sub-2s perceived latency                   | All timeout constants inventoried (7 files, 8 constants); current vs proposed values derived from baselines; validation approach via existing Phase 22 journey tests |

</phase_requirements>

## Standard Stack

### Core

| Library        | Version | Purpose                           | Why Standard                                                         |
| -------------- | ------- | --------------------------------- | -------------------------------------------------------------------- |
| prom-client    | (exist) | Prometheus histograms/counters    | Already in use in metrics.service.ts; alert rules query these        |
| Grafana Cloud  | SaaS    | Alert rule management             | Already the metrics backend; Grafana-managed alert rules are native  |
| Alloy          | v1.6.1  | Scrape metrics, ship to Mimir     | Already deployed in docker-compose.staging.yml                       |
| Playwright     | (exist) | Journey timing validation         | Phase 22 journey-timing.spec.ts already exists                       |
| Vitest         | (exist) | Load test harness                 | Phase 22 load test scenarios already exist in tests/load/            |

### Supporting

| Library | Version | Purpose                   | When to Use                               |
| ------- | ------- | ------------------------- | ----------------------------------------- |
| curl    | system  | Grafana API provisioning  | Script to POST alert rules to Grafana API |

### Alternatives Considered

| Instead of                     | Could Use          | Tradeoff                                                          |
| ------------------------------ | ------------------ | ----------------------------------------------------------------- |
| Grafana HTTP API provisioning  | Terraform provider | More infrastructure, but no Terraform setup exists in this project |
| Grafana-managed alert rules    | Mimir ruler rules  | Mimir rules are more ops-heavy, Grafana-managed has richer UI     |
| File-based provisioning (YAML) | HTTP API (JSON)    | File-based requires self-hosted Grafana; project uses Grafana Cloud |
| mimirtool                      | HTTP API           | mimirtool is for Mimir ruler, not Grafana-managed rules           |

**No installation needed:** All required libraries and infrastructure are already in place. This phase only adds configuration files and tunes existing constants.

## Architecture Patterns

### Recommended Project Structure

```
docker/grafana/
  dashboards/
    cipherbox-staging.json          # Existing dashboard
  alerts/
    ipns-resolve-latency.json       # Alert rule definition
    ipfs-pin-latency.json           # Alert rule definition
    api-endpoint-latency.json       # Alert rule definition
    ipns-publish-latency.json       # Alert rule definition
    db-fallback-rate.json           # Alert rule definition
  scripts/
    provision-alerts.sh             # curl-based provisioning script
```

### Pattern 1: Grafana-Managed Alert Rule JSON

**What:** JSON files defining alert rules that can be POSTed to the Grafana Alerting Provisioning API
**When to use:** For each alert rule that needs to be version-controlled

**Example:**
```json
{
  "title": "IPNS Resolve p95 Warning",
  "ruleGroup": "CipherBox Performance",
  "folderUID": "<grafana-alerts-folder-uid>",
  "noDataState": "OK",
  "execErrState": "OK",
  "for": "5m",
  "condition": "C",
  "annotations": {
    "summary": "IPNS resolve p95 latency exceeds {{ $value }}s (threshold: 0.3s)",
    "description": "IPNS resolution latency (network source, p95 over 5m window) has exceeded the baseline threshold. Check Someguy health, DHT connectivity, and Kubo status."
  },
  "labels": {
    "severity": "warning",
    "service": "cipherbox",
    "operation": "ipns-resolve"
  },
  "data": [
    {
      "refId": "A",
      "queryType": "",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "<grafana-cloud-metrics-uid>",
      "model": {
        "expr": "histogram_quantile(0.95, sum(rate(cipherbox_ipns_resolve_duration_seconds_bucket{source=\"network\", outcome=\"success\"}[5m])) by (le))",
        "intervalMs": 15000,
        "maxDataPoints": 43200,
        "refId": "A"
      }
    },
    {
      "refId": "B",
      "queryType": "",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "<grafana-cloud-metrics-uid>",
      "model": {
        "expr": "histogram_quantile(0.95, sum(rate(cipherbox_ipns_resolve_duration_seconds_bucket{source=\"network\", outcome=\"success\"}[5m])) by (le)) > 0",
        "intervalMs": 15000,
        "refId": "B"
      }
    },
    {
      "refId": "C",
      "datasourceUid": "__expr__",
      "model": {
        "type": "threshold",
        "expression": "A",
        "conditions": [{
          "evaluator": { "type": "gt", "params": [0.3] },
          "operator": { "type": "and" },
          "query": { "params": ["A"] },
          "reducer": { "type": "last" }
        }],
        "refId": "C"
      }
    }
  ]
}
```

**Source:** [Grafana Alerting Provisioning HTTP API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/alerting_provisioning/)

### Pattern 2: DB Fallback Rate Alert (Counter-Based)

**What:** Alert on the ratio of DB fallback resolves to total resolves exceeding a threshold
**When to use:** For the 20% DB fallback rate alert

**PromQL expression:**
```promql
(
  sum(rate(cipherbox_delegated_routing_fallbacks_total{operation="resolve"}[10m]))
  /
  sum(rate(cipherbox_delegated_routing_requests_total{operation="resolve"}[10m]))
) > 0.2
```

This uses the existing `cipherbox_delegated_routing_fallbacks_total` counter (already instrumented in `delegated-routing.client.ts`) divided by total resolve requests.

### Pattern 3: Timeout Constant Tuning

**What:** Replace generous hardcoded timeout constants with values derived from baseline p99 data
**When to use:** For each SDK provider and API service timeout

**Example (kubo-provider.ts):**
```typescript
// Before: generous 30s timeout
const REQUEST_TIMEOUT_MS = 30_000;

// After: 2-3x observed p99 from baselines
// Pin p99 = 31ms server-side, Cat p99 = 9ms server-side
// Client-side round-trip adds ~130ms network overhead
// Conservative: 3x client-side p99 (227ms) = ~700ms, round up to 1000ms for pin/cat
// Keep 10s for overall operation timeout (includes retries)
const REQUEST_TIMEOUT_MS = 10_000;
```

### Anti-Patterns to Avoid

- **Creating alerts in Grafana UI without version control:** Always define as JSON in repo, deploy via API script
- **Alerting on raw counters instead of rates:** Always use `rate()` or `increase()` over a window
- **Setting timeouts at exactly p99:** Leaves no headroom; use 2-3x p99 as the formula states
- **Reducing timeouts without checking retry behavior:** Some operations retry on timeout; reducing timeout without adjusting retry config can cause cascading failures

## Don't Hand-Roll

| Problem                | Don't Build               | Use Instead                        | Why                                                  |
| ---------------------- | ------------------------- | ---------------------------------- | ---------------------------------------------------- |
| Histogram percentiles  | Custom percentile math    | `histogram_quantile()` PromQL      | Prometheus native, handles bucket interpolation       |
| Alert evaluation       | Custom polling/check code | Grafana alerting engine            | Handles state transitions, repeat intervals, silences |
| Metric scraping        | Custom metric exporter    | Alloy (already configured)         | Already scrapes API, Kubo, Someguy every 30s          |
| Load testing framework | Custom concurrent test    | Vitest load harness (Phase 22)     | Already implemented with threshold checking           |

**Key insight:** This phase is entirely about configuration and constant tuning. No new code patterns or libraries are needed. Every piece of infrastructure already exists.

## Common Pitfalls

### Pitfall 1: Grafana Cloud datasource UID mismatch

**What goes wrong:** Alert rules reference a datasource UID that doesn't match the Grafana Cloud Mimir instance
**Why it happens:** Dashboard JSON uses template variable `${DS_GRAFANA_CLOUD_METRICS}` but alert rules need the actual resolved UID
**How to avoid:** Query the Grafana Cloud API for the actual Mimir datasource UID before provisioning, or use the Grafana UI to find it: Settings > Data Sources > Prometheus/Mimir > copy UID from the URL
**Warning signs:** Alert rules show "No data" even though dashboard panels work

### Pitfall 2: histogram_quantile returns NaN when no data

**What goes wrong:** Alert fires on "no data" state because `histogram_quantile()` returns NaN when there are no observations in the window
**Why it happens:** Low-traffic operations may have no samples in a 5m window
**How to avoid:** Set `noDataState: "OK"` in alert rule definition. Only alert when the quantile exceeds a threshold AND data exists
**Warning signs:** Constant alert notifications during low-traffic periods

### Pitfall 3: Rate window too short for scrape interval

**What goes wrong:** `rate()` over 1m with 30s scrape interval produces unreliable results
**Why it happens:** Prometheus needs at least 2 data points in a range to calculate rate; with 30s scrape, a 1m window only guarantees 2-3 points
**How to avoid:** Use `rate(...[5m])` minimum for a 30s scrape interval (gives ~10 data points per window)
**Warning signs:** Noisy/spiky alert evaluations

### Pitfall 4: Timeout reduction causes cascade failures

**What goes wrong:** Reducing a timeout (e.g., Kubo 30s -> 10s) causes operations to fail that would have succeeded with the longer timeout, triggering retries that compound the problem
**Why it happens:** The 2-3x p99 formula works for typical load, but under high concurrency (50+ clients), p99 is much higher than under normal load
**How to avoid:** Use the single-client or low-concurrency (5 client) p99 baselines for timeout derivation, NOT the 50-client stress test values. Validate with the load test harness at representative concurrency (5-10 clients)
**Warning signs:** Load test threshold violations after timeout changes

### Pitfall 5: Alerting on the wrong histogram

**What goes wrong:** Alerts fire on `cipherbox_ipfs_ipns_duration_seconds` when they should fire on `cipherbox_ipns_resolve_duration_seconds`
**Why it happens:** The project has TWO resolve histograms: the general IPFS/IPNS one (Phase 18) and the dedicated IPNS resolve one (Phase 19). They have different labels.
**How to avoid:** Use the Phase 19 histograms for IPNS-specific alerts: `cipherbox_ipns_resolve_duration_seconds` (source/outcome labels) and `cipherbox_ipns_publish_duration_seconds` (outcome label). Use the general `cipherbox_ipfs_ipns_duration_seconds` for IPFS pin/cat alerts.
**Warning signs:** Alert expressions don't match any time series

## Code Examples

### Threshold Derivation from Baselines

The following threshold values are derived from the baseline documents:

**IPNS Resolve (network source, success):**
| Source | p50 | p95 | p99 | Proposed Warning | Proposed Critical |
| --- | --- | --- | --- | --- | --- |
| Phase 18 client-side | 147ms | 224ms | 278ms | 300ms (p95 + headroom) | 560ms (2x p95) |
| Phase 18 server-side (network) | 135ms | 284ms | 488ms | 300ms | 600ms |
| Phase 19 staging (createFolder p95) | -- | 848ms | 1.0s | (E2E, includes publish) | -- |

**Recommended thresholds:** Warning at 300ms, Critical at 600ms (based on Phase 18 server-side network resolve p95/p99)

**IPFS Pin:**
| Source | p50 | p95 | p99 | Proposed Warning | Proposed Critical |
| --- | --- | --- | --- | --- | --- |
| Phase 18 server-side | 8ms | 18ms | 31ms | 50ms | 100ms |
| Phase 19.2 Prometheus (pebbleds, mean 1.37s at load) | -- | -- | -- | (high concurrency) | -- |
| Phase 19.2 staging 50-client p50 | 3,242ms | 4,615ms | 6,400ms | (load, not typical) | -- |

**Recommended thresholds:** Warning at 50ms, Critical at 100ms (server-side pin latency under normal single-user load). Note: Under high concurrency these will always fire. Use `for: 5m` to filter transient spikes during load tests.

**API Endpoint Latency (critical routes):**
| Route | p50 | p95 | p99 | Proposed Warning | Proposed Critical |
| --- | --- | --- | --- | --- | --- |
| POST /ipfs/upload [201] | 8ms | 45ms | 50ms | 100ms | 250ms |
| GET /ipfs/:cid [200] | 5ms | 10ms | 10ms | 25ms | 50ms |
| GET /ipns/resolve [200] | 50ms | 245ms | 467ms | 300ms | 600ms |
| POST /ipns/publish [201] | 165ms | 477ms | 871ms | 600ms | 1200ms |
| GET /vault [200] | 5ms | 9ms | 10ms | 25ms | 50ms |

**IPNS Publish (delegated routing):**
| Source | p50 | p95 | p99 | Proposed Warning | Proposed Critical |
| --- | --- | --- | --- | --- | --- |
| Phase 18 server-side | 180ms | 519ms | 904ms | 600ms | 1200ms |

**DB Fallback Rate:**
| Metric | Threshold | Notes |
| --- | --- | --- |
| Fallback resolve / Total resolve | >20% over 10m | Indicates Someguy/DHT health degradation |

### Timeout Tuning Values

Current and proposed timeout constants:

| File | Constant | Current | Observed p99 (single-client) | Proposed | Rationale |
| --- | --- | --- | --- | --- | --- |
| `kubo-provider.ts` | `REQUEST_TIMEOUT_MS` | 30,000ms | Pin: 227ms client-side (p99) | 10,000ms | ~44x p99, conservative for large files |
| `pinata-provider.ts` | `REQUEST_TIMEOUT_MS` | 60,000ms | 2.0s p50 upload (BYO baselines) | 30,000ms | External network, large variance |
| `psa-provider.ts` | `REQUEST_TIMEOUT_MS` | 30,000ms | N/A (similar to Kubo profile) | 15,000ms | External service, less control |
| `connection-test.ts` | `PROBE_TIMEOUT_MS` | 10,000ms | N/A (one-time probes) | 10,000ms | No change needed, already reasonable |
| `delegated-routing.client.ts` | `requestTimeoutMs` | 10,000ms | Resolve: 488ms p99 server-side | 5,000ms | 10x p99, generous for DHT lookup |
| `delegated-routing.client.ts` | `baseDelayMs` | 1,000ms | -- | 500ms | Faster retry start for transient failures |
| `tee.service.ts` | TEE timeout | 30,000ms | N/A (TEE batch, long-running) | 30,000ms | No change, batch operation |
| `upload.service.ts` | `MAX_RETRIES` | 3 | -- | 3 | No change |
| `upload.service.ts` | `RETRY_BASE_DELAY` | 1,000ms | -- | 500ms | Faster recovery for upload retries |

**Key considerations:**
- Kubo timeout stays relatively generous (10s) because large file uploads can legitimately take several seconds
- Pinata timeout reduced 50% but stays generous due to external network variability
- Delegated routing timeout cut in half (10s -> 5s) because p99 is 488ms; 5s is still 10x headroom
- Connection test probe timeout unchanged; it's a one-time diagnostic operation
- TEE service timeout unchanged; batch republishing is inherently long-running
- Retry base delays reduced from 1s to 500ms for faster recovery on transient failures

### Provisioning Script Pattern

```bash
#!/usr/bin/env bash
# provision-alerts.sh - Apply alert rules to Grafana Cloud
# Usage: ./provision-alerts.sh <grafana-url> <api-key>

GRAFANA_URL="${1:?Usage: $0 <grafana-url> <api-key>}"
API_KEY="${2:?Usage: $0 <grafana-url> <api-key>}"

ALERT_DIR="$(dirname "$0")/../alerts"

for rule_file in "$ALERT_DIR"/*.json; do
  rule_name=$(basename "$rule_file" .json)
  echo "Provisioning alert rule: $rule_name"

  curl -s -X POST "$GRAFANA_URL/api/v1/provisioning/alert-rules" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -H "X-Disable-Provenance: true" \
    -d @"$rule_file"

  echo ""
done
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
| --- | --- | --- | --- |
| delegated-ipfs.dev as primary IPNS routing | Self-hosted Someguy sidecar | Phase 19 (2026-03) | Thresholds based on Someguy baselines, not delegated-ipfs.dev |
| flatfs Kubo datastore | pebbleds LSM-tree datastore | Phase 19.2 (2026-03) | Pin latency reduced ~41% p50; affects pin threshold derivation |
| Sequential SDK pins | Concurrent pins (Promise.allSettled) | Phase 19.2 (2026-03) | Upload E2E time reduced; tail latency improved |
| Server-side metrics only | Client-side perf.ts instrumentation | Phase 22 (2026-03) | Journey timing baselines now available for validation |

**Deprecated/outdated:**
- Phase 18 baselines for IPNS resolve/publish may differ from current values post-Someguy deployment; Phase 19 baselines are more current
- The `cipherbox_ipfs_ipns_duration_seconds` histogram from Phase 18 is supplemented (not replaced) by dedicated `cipherbox_ipns_resolve_duration_seconds` and `cipherbox_ipns_publish_duration_seconds` from Phase 19

## Open Questions

1. **Grafana Cloud datasource UID**
   - What we know: Dashboard JSON uses template variable `${DS_GRAFANA_CLOUD_METRICS}`; alert rules need the actual UID
   - What's unclear: The exact UID of the Mimir datasource in the project's Grafana Cloud instance
   - Recommendation: Query the Grafana Cloud API (`GET /api/datasources`) or look it up in the UI before creating alert rule JSON files. Document it in the provisioning script as a configurable parameter.

2. **Grafana Cloud alerts folder UID**
   - What we know: Alert rules need a `folderUID` to be placed in
   - What's unclear: Whether a "CipherBox Alerts" folder already exists in Grafana Cloud
   - Recommendation: Create the folder via API if it doesn't exist, or use the existing dashboard folder UID

3. **Pin latency thresholds under load**
   - What we know: Single-user pin p99 is 31ms, but at 50 clients it's 6.4s
   - What's unclear: What "normal" production concurrency will look like
   - Recommendation: Set thresholds for typical (low-concurrency) operation with `for: 5m` evaluation window. Accept that alerts will fire during load tests or traffic spikes, but those are transient.

## Validation Architecture

### Test Framework

| Property           | Value                                                                   |
| ------------------ | ----------------------------------------------------------------------- |
| Framework          | Playwright (journey tests) + Vitest (load tests)                        |
| Config file        | `tests/web-e2e/playwright.config.ts` + `tests/load/vitest.config.ts`    |
| Quick run command  | `cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts` |
| Full suite command | `cd tests/load && pnpm exec vitest run`                                 |

### Phase Requirements to Test Map

| Req ID | Behavior                                        | Test Type | Automated Command                                                           | File Exists? |
| ------ | ----------------------------------------------- | --------- | --------------------------------------------------------------------------- | ------------ |
| OBS-01 | Alert rules fire on threshold breach            | manual    | Grafana UI verification (alert rules exist, query returns data)             | N/A          |
| OBS-01 | Alert rule JSON is valid and provisioned        | smoke     | `./docker/grafana/scripts/provision-alerts.sh` returns HTTP 2xx             | Wave 0       |
| OBS-02 | Upload-to-visible under 2s after timeout tuning | e2e       | `cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts` | Exists       |
| OBS-02 | Load tests pass with updated timeouts           | load      | `cd tests/load && pnpm exec vitest run`                                     | Exists       |

### Sampling Rate

- **Per task commit:** Run journey-timing.spec.ts locally (requires API + frontend)
- **Per wave merge:** Full load test suite
- **Phase gate:** Journey timing tests + load test thresholds green on staging

### Wave 0 Gaps

- [ ] `docker/grafana/alerts/` directory -- alert rule JSON files
- [ ] `docker/grafana/scripts/provision-alerts.sh` -- provisioning script
- [ ] Grafana Cloud datasource UID discovery (runtime config, not test file)

_(Existing test infrastructure covers all validation needs. No new test files required.)_

## Sources

### Primary (HIGH confidence)

- Project baseline documents: `.planning/baselines/18-performance-baselines.md`, `.planning/baselines/19-someguy-ipns-baselines.md`, `.planning/baselines/19.2-post-optimization-baselines.md`, `.planning/baselines/22-journey-baselines.md` -- all threshold derivation data
- Project source code: `apps/api/src/metrics/metrics.service.ts` -- all 5 histogram definitions with exact metric names, labels, and buckets
- Project source code: `docker/alloy-config.river` -- scrape configuration (30s interval)
- Project source code: timeout constants in `kubo-provider.ts`, `pinata-provider.ts`, `psa-provider.ts`, `connection-test.ts`, `delegated-routing.client.ts`, `upload.service.ts`

### Secondary (MEDIUM confidence)

- [Grafana Alerting Provisioning HTTP API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/alerting_provisioning/) -- JSON format for alert rule creation via API
- [Grafana file provisioning docs](https://grafana.com/docs/grafana/latest/alerting/set-up/provision-alerting-resources/file-provisioning/) -- YAML structure reference (adapted to JSON for HTTP API)
- [Grafana Cloud provisioning overview](https://grafana.com/docs/grafana-cloud/alerting-and-irm/alerting/set-up/provision-alerting-resources/) -- confirms HTTP API is the correct approach for Grafana Cloud
- [PromQL alerting with histogram_quantile](https://oneuptime.com/blog/post/2026-02-09-grafana-alerting-promql/view) -- verified PromQL expression patterns

### Tertiary (LOW confidence)

- Exact Grafana Cloud datasource UID and folder UID -- must be discovered at implementation time from the project's Grafana Cloud instance

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- all infrastructure already exists; no new libraries needed
- Architecture: HIGH -- Grafana provisioning API well-documented; timeout tuning is straightforward constant changes
- Pitfalls: HIGH -- derived from project-specific baseline data and known infrastructure characteristics
- Threshold values: MEDIUM -- derived from baselines under specific conditions; may need adjustment after real-world observation

**Research date:** 2026-03-26
**Valid until:** 2026-04-26 (stable domain; baselines won't change unless infrastructure changes)

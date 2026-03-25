# Phase 26: Observability & UX Tuning - Context

**Gathered:** 2026-03-26
**Status:** Ready for planning

<domain>
## Phase Boundary

Make Phase 18/22 performance baselines actionable via Grafana alerting rules and tune client-side timeouts/retries for sub-2s perceived latency on common operations. This phase does NOT add new metrics or instrumentation -- it builds on existing histograms and baselines.

</domain>

<decisions>
## Implementation Decisions

### Alert Thresholds & Severity

- Two-tier severity: Warning at p95 threshold, Critical at p99 or 2x p95
- DB fallback rate alert at >20% (IPNS resolves falling back to database indicates Someguy/DHT degradation)
- Thresholds hardcoded in Grafana alert rule provisioning files (not env-driven)
- Four operations get dedicated alert rules:
  1. IPNS resolve latency
  2. IPFS pin latency
  3. API endpoint latency (critical routes: upload, download, vault load)
  4. IPNS publish latency
- Threshold values derived from Phase 18/22 documented baselines (p95/p99 columns)

### Alert Delivery

- Grafana Cloud built-in alerting (alert rules + contact points)
- Notification channel: Grafana UI only (no email/Slack/Discord push for now)
- Alert rules provisioned as code in `docker/grafana/` directory, version-controlled alongside dashboard JSON
- No self-hosted Alertmanager or Alloy-side alerting

### Timeout Tuning Targets

- Sub-2s targets for three operations:
  1. **Upload-to-visible** (currently 1,355ms baseline -- already under 2s, tuning ensures it stays there)
  2. **Vault/folder load** (vault 86ms + IPNS resolve ~224ms p95 -- tune resolve timeouts for snappy navigation)
  3. **Download-to-open** (IPFS cat p50=133ms -- tune for graceful degradation under load)
- **Share-to-accessible** (currently 3,039ms): tune where possible but accept >2s target -- more round-trips inherent
- Timeout reduction strategy: conservative 2-3x observed p99 from baselines (e.g., if pin p99=4s, timeout=10s)
- Current generous timeouts (Kubo 30s, delegated routing 10s) to be reduced based on this formula

### Validation Approach

- Dual-environment validation: local for fast iteration, staging for final comparison against baselines
- Rerun Phase 22 Playwright journey tests (login-to-vault, upload-to-visible, share-to-accessible) before and after changes
- Rerun vitest load harness from Phase 22 with updated timeouts to verify no regressions under concurrent load
- Manual comparison of before/after timings (no automated CI timing gates)

### Claude's Discretion

- Exact threshold values per operation (derived from baseline documents)
- Grafana alert rule YAML/JSON structure and provisioning format
- Which specific API routes to include in HTTP latency alerting
- Retry backoff tuning details (exponential backoff base delay, max retries per operation)

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Performance Baselines (threshold source of truth)

- `.planning/baselines/18-performance-baselines.md` -- Server-side p50/p95/p99 for IPNS resolve, IPFS pin/cat, publish
- `.planning/baselines/19-someguy-ipns-baselines.md` -- Post-Someguy IPNS resolution baselines
- `.planning/baselines/19.2-post-optimization-baselines.md` -- Upload optimization results (concurrent pin baselines)
- `.planning/baselines/22-journey-baselines.md` -- E2E journey timing: login-to-vault, upload-to-visible, share-to-accessible
- `.planning/perf/staging-baseline-2026-03-24.md` -- Vault login path baseline

### Existing Observability Infrastructure

- `apps/api/src/metrics/metrics.service.ts` -- All Prometheus histogram/counter/gauge definitions
- `apps/api/src/metrics/http-metrics.interceptor.ts` -- HTTP request duration recording
- `docker/grafana/dashboards/cipherbox-staging.json` -- Existing Grafana dashboard to extend
- `docker/alloy-config.river` -- Alloy scrape config (API + Kubo + Someguy)

### Client-Side Timeout/Retry Code

- `packages/sdk-core/src/pinning/kubo-provider.ts` -- Kubo timeout (30s)
- `packages/sdk-core/src/pinning/pinata-provider.ts` -- Pinata timeout (60s)
- `packages/sdk-core/src/pinning/psa-provider.ts` -- PSA timeout (30s)
- `packages/sdk-core/src/pinning/connection-test.ts` -- Connection probe timeout (5s)
- `apps/api/src/ipns/delegated-routing.client.ts` -- Delegated routing timeout (10s) + retry logic
- `apps/api/src/tee/tee.service.ts` -- TEE timeout (30s)
- `apps/web/src/services/upload.service.ts` -- Upload retry (3x exponential backoff)
- `packages/api-client/src/instance.ts` -- 401 refresh retry with shared promise

### Prior Phase Context

- `.planning/phases/18-performance-instrumentation/18-CONTEXT.md` -- Histogram design, bucket strategy, "no alerting yet"
- `.planning/phases/22-performance-baselines-completion/22-CONTEXT.md` -- Client-side perf, journey tests, load test design

### Validation Infrastructure

- `tests/web-e2e/` -- Playwright E2E tests including journey timing tests from Phase 22
- `tests/load/` -- Vitest-based SDK load harness from Phase 22

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- **5 Prometheus histograms** already defined in `metrics.service.ts` -- alert rules query these directly
- **Grafana dashboard JSON** (`cipherbox-staging.json`) -- extend with alert panels or create separate alert provisioning
- **Alloy config** (`alloy-config.river`) -- already scrapes all relevant metric endpoints
- **Phase 22 journey tests** -- reusable for before/after timing comparison
- **Vitest load harness** -- reusable for concurrent load validation

### Established Patterns

- **Histogram bucket design**: two-tier (fast 1-500ms, slow 50ms-30s) with exponential spacing
- **Timeout pattern**: `AbortSignal.timeout(MS)` in SDK providers, `fetchWithTimeout()` in delegated routing
- **Retry pattern**: exponential backoff with configurable max retries and base delay
- **Metrics labels**: operation/result/source for IPFS/IPNS histograms

### Integration Points

- Grafana Cloud Mimir (where Alloy ships metrics) -- alert rules query Mimir
- `docker/grafana/` directory -- provisioning files deployed with docker-compose
- SDK provider timeout constants -- each file has a `REQUEST_TIMEOUT_MS` constant to tune
- Upload service retry config -- `MAX_RETRIES` and `RETRY_BASE_DELAY` constants

</code_context>

<specifics>
## Specific Ideas

- Alert rules should be provisioned as files in the repo, not created ad-hoc in Grafana UI
- DB fallback rate threshold (20%) aligns with the network-first IPNS strategy -- DB is safety net, not primary path
- Login-to-vault (23s) is dominated by Web3Auth (23.4s) which is outside our control -- not a tuning target

</specifics>

<deferred>
## Deferred Ideas

- Dedicated timeout regression test suite -- noted for future hardening phase
- Push notification channels (email, Slack, Discord webhooks) -- add when team grows or on-call rotation exists
- Automated CI timing gates -- flaky due to runner variance, revisit when stable CI environment available

</deferred>

---

_Phase: 26-observability-ux-tuning_
_Context gathered: 2026-03-26_

# Phase 22: Performance Baselines Completion - Context

**Gathered:** 2026-03-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Complete the performance picture: add client-side timing instrumentation to the SDK, capture end-to-end user journey timings via Playwright, enhance the existing load test harness with pass/fail thresholds, and produce a full capacity model document. Server-side Prometheus instrumentation (Phase 18) and upload optimization baselines (Phase 19.2) are already complete — this phase adds the client and documentation layers.

</domain>

<decisions>
## Implementation Decisions

### Client-side timing instrumentation (PERF-05)

- Timing lives in **SDK packages** (@cipherbox/sdk-core and @cipherbox/sdk), not web app hooks — desktop and future CLI get instrumentation for free
- Use browser **Performance API** (performance.mark/measure) to surface timing data — shows up in DevTools Performance tab natively, can be scraped programmatically
- **Dev/debug only** — gate behind environment check or feature flag, zero overhead in production
- Operations to instrument: encrypt/decrypt throughput, upload/download duration, IPNS resolve/publish timing

### End-to-end journey timing (PERF-06)

- **Playwright E2E tests** measuring real browser wall-clock time (not SDK programmatic flows)
- Three journeys per ROADMAP: login-to-vault, upload-to-visible, share-to-accessible
- Results captured in **`.planning/baselines/22-journey-baselines.md`** — consistent with existing Phase 18/19/19.2 baseline docs
- Builds on existing 8 Playwright E2E test suites

### Load testing approach (PERF-07)

- **Enhance existing vitest/SDK harness** — not k6. The harness already works with 5 scenarios, MetricsCollector, CI workflow, and extensive baselines from Phase 19.2. Avoids introducing a new tool for a tech demo.
- Add **automated pass/fail thresholds** in CI — define p95 latency and error rate thresholds per scenario. CI fails if thresholds breached. Catches regressions automatically.
- Add concurrency ramp profiles and any missing scenarios needed for comprehensive coverage

### Capacity documentation (PERF-08)

- **Full capacity model** in `docs/CAPACITY.md` — detailed projections with formulas, growth curves, cost estimates
- Content: observed limits from load tests (max concurrent users, IPNS throughput limits, storage growth rate), scaling recommendations (when to scale Kubo, add API replicas), projections and formulas
- Audience: operators deploying CipherBox

### Claude's Discretion

- Specific Performance API mark/measure naming conventions
- Which SDK methods get instrumented (beyond the core encrypt/decrypt/upload/download/IPNS set)
- Environment check mechanism for gating dev-only instrumentation
- Exact pass/fail threshold values (based on existing baseline data from 19.2)
- Playwright journey test implementation details (selectors, wait strategies)
- Capacity model formula methodology and presentation format

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Performance requirements

- `.planning/REQUIREMENTS.md` — PERF-05, PERF-06, PERF-07, PERF-08 requirement definitions
- `.planning/ROADMAP.md` — Phase 22 success criteria (4 items)

### Existing instrumentation (Phase 18)

- `apps/api/src/metrics/metrics.service.ts` — Server-side Prometheus registry with 5 histograms, gauges, counters
- `apps/api/src/metrics/http-metrics.interceptor.ts` — HTTP request duration interceptor
- `.planning/phases/18-performance-instrumentation/18-CONTEXT.md` — Phase 18 decisions (bucket design, label granularity, dashboard approach)

### Existing baselines (Phases 18, 19, 19.2)

- `.planning/baselines/18-performance-baselines.md` — Initial server-side baselines
- `.planning/baselines/19-someguy-ipns-baselines.md` — IPNS resolution baselines post-Someguy
- `.planning/baselines/19.2-pre-optimization-baselines.md` — Upload baselines before concurrent pins + pebbleds
- `.planning/baselines/19.2-post-optimization-baselines.md` — Comprehensive post-optimization baselines with three-point comparison, staging CI results, Prometheus histograms

### Existing load test harness

- `tests/load/src/harness/metrics.ts` — MetricsCollector with percentile calculation
- `tests/load/src/harness/client-pool.ts` — Multi-client pool management using SDK test harness
- `tests/load/src/scenarios/` — 5 scenarios: upload-throughput, mixed-workload, sustained-load, spike-test, ipns-publish-storm
- `.github/workflows/load-test.yml` — CI workflow for staging load tests (workflow_dispatch)

### SDK packages (instrumentation targets)

- `packages/sdk-core/` — Stateless folder/file/IPFS/IPNS operations
- `packages/sdk/` — Stateful CipherBoxClient with events

### Playwright E2E (journey timing base)

- `tests/web-e2e/` — 8 existing Playwright E2E test suites

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `MetricsCollector` (`tests/load/src/harness/metrics.ts`): Full percentile calculation engine (p50/p95/p99), throughput tracking, JSON export. Already used by all 5 load test scenarios.
- `client-pool.ts`: Creates N authenticated CipherBoxClient instances with per-client metrics. Supports batch account creation with rate limiting.
- `reporter.ts`: Pretty-prints and JSON-exports load test results. Pattern to follow for journey timing output.
- `MetricsService` (API): 5 Prometheus histograms already instrumented server-side. Client-side instrumentation complements this.
- `load-test.yml` workflow: Parameterized CI workflow (environment, client_count, scenario). Add threshold checking here.

### Established Patterns

- Load test scenarios use vitest `describe/it` blocks with `performance.now()` timing
- Metrics JSON exported to `tests/load/metrics-*.json` files
- Baselines documented as markdown in `.planning/baselines/` with tables of p50/p95/p99 values
- SDK operations use `SdkContext` (apiUrl + getAccessToken) — instrumentation wraps these calls

### Integration Points

- SDK packages (`@cipherbox/sdk-core`, `@cipherbox/sdk`): Add Performance API marks around encrypt/decrypt/upload/download/IPNS operations
- Playwright E2E (`tests/web-e2e/`): Add journey-timing spec files alongside existing test suites
- CI workflow (`.github/workflows/load-test.yml`): Add threshold validation step after scenario execution
- `docs/CAPACITY.md`: New file, lives alongside `docs/METADATA_SCHEMAS.md`

</code_context>

<specifics>
## Specific Ideas

- Phase 18 context explicitly noted "synthetic baseline script should be reusable in Phase 22 for 'after' comparison" — leverage the same patterns
- Existing baselines from 19.2 provide the "before all features stable" reference; Phase 22 captures "after all features stable" (post BYO-IPFS Phase 21)
- The three-point comparison methodology from Phase 19.2 (isolating variables, matched environment) is a good template for any new comparisons
- Load test harness already handles rate limit bypass (LOAD_TEST_SECRET + THROTTLE_BYPASS_SECRET) — reuse for threshold testing

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

_Phase: 22-performance-baselines-completion_
_Context gathered: 2026-03-25_

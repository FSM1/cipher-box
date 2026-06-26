# Phase 19: IPNS Resolution Improvement - Research

**Researched:** 2026-03-07
**Domain:** IPFS Delegated Routing, Docker Compose, Prometheus Metrics
**Confidence:** HIGH

## Summary

Phase 19 replaces the external `delegated-ipfs.dev` delegated routing service with a self-hosted Someguy instance running as a Docker Compose sidecar. The change is architecturally simple: Someguy implements the identical Delegated Routing V1 HTTP API that `delegated-ipfs.dev` uses (same spec, same wire format), and the existing `DelegatedRoutingClient` already abstracts the routing URL behind the `DELEGATED_ROUTING_URL` environment variable. The core code change is a URL swap.

Someguy v0.11.1 (released February 2026) runs its own embedded libp2p node with a built-in DHT client -- it does NOT require Kubo for DHT connectivity. It listens on `127.0.0.1:8190` by default and exposes the standard `/routing/v1/ipns/{name}` endpoints (GET for resolve, PUT for publish). The Docker image is `ghcr.io/ipfs/someguy:v0.11.1` and runs with entrypoint `someguy start`. It has no `/health` endpoint -- health checks must use `/version` or TCP port checks.

The key risk is resource consumption: Someguy's default `accelerated` DHT mode crawls the entire Amino DHT on startup (12+ hours to warm up, 30k+ peers). For the staging environment, use `SOMEGUY_DHT=standard` to avoid overwhelming a small VPS. The `standard` mode participates in DHT passively (queries on demand, no full crawl).

**Primary recommendation:** Deploy Someguy v0.11.1 as a Docker Compose sidecar with `SOMEGUY_DHT=standard` for staging. Change `DELEGATED_ROUTING_URL` from `https://delegated-ipfs.dev` to `http://someguy:8190`. Add Prometheus histograms for Someguy-specific latency tracking. Keep timeout/retry config identical to Phase 18 baselines.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- Keep **network-first resolution** (current logic) -- Someguy replaces delegated-ipfs.dev as the routing provider, DB remains the fallback
- **No resolution logic change needed** -- just swap `DELEGATED_ROUTING_URL` from `https://delegated-ipfs.dev` to `http://someguy:<port>`
- Keep **identical timeout/retry config** (10s timeout, 3 retries, exponential backoff) for apples-to-apples comparison with Phase 18 delegated-ipfs.dev baselines
- **Someguy handles both publish and resolve** for the CipherBox API -- single routing provider, single config
- **Docker Compose sidecar** -- new `someguy` service in `docker-compose.staging.yml`, depends on `ipfs` (Kubo)
- **Configurable Someguy backend** via environment: Staging: Kubo-only (local DHT, no external HTTP dependencies); Production: Kubo + public Amino DHT (broader resolution coverage)
- **TEE worker stays on delegated-ipfs.dev** -- async batch republishes are latency-tolerant
- **Recovery defaults to public routing** (delegated-ipfs.dev or public IPFS gateways) for self-sovereignty. Self-hosted Someguy is an optional configurable endpoint, not the default
- **Sequential with timeout** (current pattern) -- try Someguy, fall back to DB on failure/timeout. No parallel race
- **Dedicated Prometheus metrics** for Someguy resolution: latency histogram, success/db-fallback/timeout counters
- **Transparent to client** -- no `source` field in resolve API response. Source tracking is server-side metrics only
- **Metrics only, no alerting thresholds** -- establish baselines first, configure alerts after data exists

### Claude's Discretion

- Exact Someguy Docker image version and configuration flags
- Someguy port selection and health check configuration
- How to structure the Prometheus histogram labels for Someguy metrics
- E2E test updates (mock-ipns-routing may need adjustment)
- Whether to update OpenAPI descriptions that reference "delegated-ipfs.dev"

### Deferred Ideas (OUT OF SCOPE)

- **Standalone CLI recovery tool** -- build a Node.js CLI that reads vault export JSON, resolves IPNS, and decrypts/downloads all files. Separate phase.
- **TEE worker routing through Someguy** -- revisit when capacity metrics show delegated-ipfs.dev is a bottleneck for batch republishes, or when TEE moves to Phala infra.
- **Timeout tuning for UX** -- after baseline data from Phase 18 + early Phase 19, tune timeout/retry for sub-2s user experience.
- **Alerting thresholds** -- configure Grafana alerts for DB fallback rate after baseline data exists.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                                       | Research Support                                                                                                                                                       |
| ------- | ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IPNS-01 | Self-hosted Someguy deployed alongside Kubo, replacing delegated-ipfs.dev as primary IPNS routing provider        | Someguy v0.11.1 Docker image available at `ghcr.io/ipfs/someguy:v0.11.1`. Implements same Routing V1 HTTP API. Runs own libp2p+DHT. Config via env vars documented.   |
| IPNS-02 | IPNS resolution uses DB-first strategy with async Kubo DHT verification via self-hosted Someguy                   | Per CONTEXT.md, resolution stays **network-first** (not DB-first as REQUIREMENTS.md states). Swap URL only. `IpnsService.resolveRecord()` logic unchanged.             |
| IPNS-03 | Recovery tool resolves IPNS via self-hosted Someguy instead of delegated-ipfs.dev                                 | Per CONTEXT.md, recovery defaults to **public routing** for self-sovereignty. Someguy is optional/configurable. No standalone CLI tool this phase.                      |
| IPNS-04 | System degrades gracefully when DHT resolution is slow (timeout + DB fallback within 2s)                          | Current sequential timeout+DB fallback pattern preserved. 10s timeout kept for baseline comparison. `DelegatedRoutingClient` already handles timeout and BAD_GATEWAY.  |

**Note:** IPNS-02 and IPNS-03 requirement text as written in REQUIREMENTS.md does not match the locked decisions from CONTEXT.md. The CONTEXT.md decisions take precedence. The planner should note these discrepancies but implement per CONTEXT.md.

</phase_requirements>

## Standard Stack

### Core

| Library/Tool         | Version  | Purpose                           | Why Standard                                                       |
| -------------------- | -------- | --------------------------------- | ------------------------------------------------------------------ |
| Someguy              | v0.11.1  | Self-hosted delegated routing     | Same software that powers delegated-ipfs.dev. Stable, maintained.  |
| `ghcr.io/ipfs/someguy` | v0.11.1 | Docker image for Someguy         | Official GHCR image. Tags: `latest`, `vX.Y.Z`, `main-latest`.     |
| `prom-client`        | ^15.1.3  | Prometheus metrics (already used) | Already installed, existing `MetricsService` pattern established.  |

### Supporting

| Library/Tool       | Version   | Purpose                        | When to Use                                               |
| ------------------ | --------- | ------------------------------ | --------------------------------------------------------- |
| Kubo               | v0.34.0   | IPFS node (already deployed)   | Someguy uses its own DHT, not Kubo's. Kubo stays as-is.  |
| Grafana Alloy      | v1.6.1    | Metrics scraping (already deployed) | May optionally scrape Someguy's `/debug/metrics/prometheus` |

### Alternatives Considered

| Instead of         | Could Use                    | Tradeoff                                                                                           |
| ------------------ | ---------------------------- | -------------------------------------------------------------------------------------------------- |
| Someguy sidecar    | Kubo `Gateway.ExposeRoutingAPI` | Simpler (no new container), but Kubo Routing API on v0.34.0 is opt-in and less feature-rich. User decided Someguy. |
| Someguy sidecar    | Direct Kubo RPC (`/api/v0/name/resolve`) | Different API contract, would require rewriting `DelegatedRoutingClient`. Not compatible with current abstraction. |

**Installation:** No npm dependencies needed. Docker image pull only:
```bash
docker pull ghcr.io/ipfs/someguy:v0.11.1
```

## Architecture Patterns

### Recommended Project Structure

No new source directories needed. Changes are distributed across existing files:

```
apps/api/src/
  ipns/
    delegated-routing.client.ts  # No code changes (URL comes from env)
    ipns.service.ts              # No code changes (resolution logic unchanged)
  metrics/
    metrics.service.ts           # Add Someguy-specific histograms
docker/
  docker-compose.staging.yml     # Add someguy service
  alloy-config.river             # Optionally scrape Someguy metrics
.github/workflows/
  deploy-staging.yml             # Update DELEGATED_ROUTING_URL env var
  e2e.yml                        # E2E still uses mock-ipns-routing (no change)
apps/api/
  .env.example                   # Update docs for DELEGATED_ROUTING_URL
```

### Pattern 1: Docker Compose Sidecar

**What:** Add `someguy` as a service in `docker-compose.staging.yml` that runs alongside the existing `ipfs` (Kubo) service.

**When to use:** When a service needs to be co-located and networked with existing services but runs as a separate process.

**Example:**
```yaml
# Source: Someguy docs + existing docker-compose.staging.yml patterns
someguy:
  image: ghcr.io/ipfs/someguy:v0.11.1
  restart: unless-stopped
  environment:
    SOMEGUY_LISTEN_ADDRESS: 0.0.0.0:8190
    SOMEGUY_DHT: standard
    SOMEGUY_LIBP2P_CONNMGR_LOW: 50
    SOMEGUY_LIBP2P_CONNMGR_HIGH: 300
    SOMEGUY_LIBP2P_MAX_MEMORY: 512MB
    GOLOG_LOG_LEVEL: info
  logging: *default-logging
  healthcheck:
    test: ['CMD-SHELL', 'wget -qO- http://localhost:8190/version || exit 1']
    interval: 10s
    timeout: 5s
    retries: 10
    start_period: 30s
  deploy:
    resources:
      limits:
        memory: 768M
        cpus: '0.5'
```

**Key details:**
- `SOMEGUY_LISTEN_ADDRESS` must be `0.0.0.0:8190` (not default `127.0.0.1:8190`) for Docker inter-container networking
- `SOMEGUY_DHT=standard` for staging (avoids 2GB+ memory of accelerated mode)
- No exposed host ports needed -- only accessed by `api` service within Docker network
- Health check uses `/version` endpoint (Someguy has no `/health` endpoint)
- The `api` service accesses Someguy at `http://someguy:8190` via Docker DNS

### Pattern 2: Environment Variable URL Swap

**What:** Change `DELEGATED_ROUTING_URL` from the external service to the internal Docker service name.

**When to use:** When swapping an external dependency with an internal one that implements the same API contract.

**Example in deploy-staging.yml:**
```yaml
# Before:
DELEGATED_ROUTING_URL=https://delegated-ipfs.dev
# After:
DELEGATED_ROUTING_URL=http://someguy:8190
```

**Key details:**
- The `DelegatedRoutingClient` reads this URL at constructor time via `ConfigService`
- The URL path `/routing/v1/ipns/{name}` is appended by the client, not included in the env var
- E2E tests continue using `http://localhost:3001` (the mock service) -- no E2E change needed
- Local development can continue using `https://delegated-ipfs.dev` or the mock service

### Pattern 3: Prometheus Histogram for Operation Latency

**What:** Add dedicated histograms to track Someguy resolution/publish latency and outcome.

**When to use:** When you need p50/p95/p99 latency data for a specific operation, not just success/failure counts.

**Example:**
```typescript
// Source: existing MetricsService patterns in metrics.service.ts
// New histograms to add alongside existing counters
readonly ipnsPublishDuration: client.Histogram;
readonly ipnsResolveDuration: client.Histogram;

// In constructor:
this.ipnsPublishDuration = new client.Histogram({
  name: 'cipherbox_ipns_publish_duration_seconds',
  help: 'IPNS publish duration in seconds',
  labelNames: ['outcome'],  // 'success', 'error', 'timeout'
  buckets: [0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60],
  registers: [this.registry],
});

this.ipnsResolveDuration = new client.Histogram({
  name: 'cipherbox_ipns_resolve_duration_seconds',
  help: 'IPNS resolve duration in seconds',
  labelNames: ['source'],  // 'network', 'db_cache', 'network_stale'
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30],
  registers: [this.registry],
});
```

**Label design:**
- `ipnsPublishDuration` labels: `outcome` = `success` | `error` | `timeout`
- `ipnsResolveDuration` labels: `source` = `network` (Someguy returned result) | `db_cache` (fell back to DB) | `network_stale` (network returned but DB was newer)
- Keep cardinality low -- no per-ipnsName labels

### Anti-Patterns to Avoid

- **Setting `SOMEGUY_DHT=accelerated` in staging:** The accelerated DHT client crawls the entire Amino DHT (30k+ peers, 12+ hours warm-up, 2GB+ memory). Use `standard` for staging, reserve `accelerated` for production if needed.
- **Exposing Someguy ports to the host:** Someguy only needs to be reachable from the `api` container. Exposing `8190` to the host is unnecessary and increases attack surface.
- **Adding `depends_on: someguy` to the `api` service:** While the API depends on Someguy, it already handles routing failures gracefully (DB fallback). A hard dependency would prevent the API from starting if Someguy is slow to initialize. Use a soft dependency or no dependency.
- **Changing resolution logic simultaneously with the URL swap:** Per CONTEXT.md, keep identical timeout/retry config for apples-to-apples comparison with Phase 18 baselines.

## Don't Hand-Roll

| Problem                          | Don't Build                              | Use Instead                        | Why                                                                                               |
| -------------------------------- | ---------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| Delegated routing server         | Custom HTTP proxy to Kubo's DHT          | Someguy v0.11.1                    | Someguy IS the reference implementation. Maintained by IPFS Foundation. Same spec as delegated-ipfs.dev. |
| DHT client                       | Custom libp2p DHT node in Node.js        | Someguy's embedded Go DHT client   | Go implementation is battle-tested (same code as Kubo). JS DHT client has known reliability issues. |
| Health check endpoint for Someguy| Custom sidecar that polls Someguy        | Docker healthcheck on `/version`   | Simpler, built-in to Docker Compose, no extra container needed.                                    |
| Metrics for routing latency      | Custom timing wrapper around fetch       | prom-client Histogram + `observe()`| Existing pattern in MetricsService. Consistent with httpRequestDuration histogram.                 |

**Key insight:** The entire Phase 19 infrastructure change is adding one Docker container and changing one environment variable. The `DelegatedRoutingClient` abstraction already exists -- don't bypass it.

## Common Pitfalls

### Pitfall 1: Someguy Default Listen Address is 127.0.0.1

**What goes wrong:** Someguy defaults to `SOMEGUY_LISTEN_ADDRESS=127.0.0.1:8190`. Inside a Docker container, `127.0.0.1` means "only this container." The `api` container cannot reach it.
**Why it happens:** Someguy follows Go convention of binding to localhost by default for security.
**How to avoid:** Set `SOMEGUY_LISTEN_ADDRESS=0.0.0.0:8190` in the Docker Compose environment.
**Warning signs:** `ECONNREFUSED` when `api` tries to connect to `http://someguy:8190`.

### Pitfall 2: Accelerated DHT Mode Resource Consumption

**What goes wrong:** Someguy with `SOMEGUY_DHT=accelerated` (the default) performs a full DHT crawl on startup, consuming 2GB+ memory and significant CPU/bandwidth for 12+ hours.
**Why it happens:** Accelerated mode builds a complete routing table for sub-second lookups -- great for public infrastructure, overkill for a single-app sidecar.
**How to avoid:** Set `SOMEGUY_DHT=standard` for staging. Consider `accelerated` only for production if standard mode latency is unacceptable.
**Warning signs:** Someguy container OOM-killed shortly after startup. High bandwidth usage from the VPS.

### Pitfall 3: Someguy Has No /health Endpoint

**What goes wrong:** Docker Compose health checks using `wget -qO- http://localhost:8190/health` fail with 404, causing container restarts.
**Why it happens:** Someguy only exposes `/routing/v1/*`, `/debug/metrics/prometheus`, and `/version`. No health endpoint.
**How to avoid:** Use `/version` for health checks: `wget -qO- http://localhost:8190/version || exit 1`.
**Warning signs:** Container stuck in "starting" state, repeated restarts in Docker logs.

### Pitfall 4: Someguy Needs Outbound Internet Access for DHT

**What goes wrong:** Someguy cannot resolve any IPNS names because it cannot connect to DHT bootstrap peers.
**Why it happens:** Docker network configuration or firewall blocks outbound connections from the `someguy` container.
**How to avoid:** Ensure the Docker network allows outbound connections (default bridge network does). Someguy uses libp2p ports 4001/udp + TCP for DHT. It does NOT need inbound ports -- DHT client mode works with outbound-only connections.
**Warning signs:** Someguy logs show "failed to bootstrap" or "no peers found". IPNS resolution returns 404 for known names.

### Pitfall 5: Deploy-Staging Workflow Hardcodes DELEGATED_ROUTING_URL

**What goes wrong:** After updating `docker-compose.staging.yml`, the deploy workflow still writes `DELEGATED_ROUTING_URL=https://delegated-ipfs.dev` to `.env.staging`, overriding the intended Someguy URL.
**Why it happens:** The URL is hardcoded at line 377 of `deploy-staging.yml` in the `Generate .env.staging` step.
**How to avoid:** Change the hardcoded value to `http://someguy:8190` in the deploy workflow.
**Warning signs:** After deployment, API logs still show connections to `delegated-ipfs.dev` instead of `someguy:8190`.

### Pitfall 6: Timing Metrics Not Instrumenting the Right Layer

**What goes wrong:** Latency histograms placed at the controller level include HTTP overhead and serialization, making Someguy resolution look slower than it is. Or, placed only inside `DelegatedRoutingClient`, they miss DB fallback timing.
**Why it happens:** Unclear about which layer represents the "IPNS resolution duration" from the user's perspective.
**How to avoid:** Instrument at the `IpnsService.resolveRecord()` level for end-to-end resolution timing (includes network attempt + possible DB fallback). Add a second histogram at `DelegatedRoutingClient.resolve()` for pure Someguy latency. Both histograms together tell the full story.
**Warning signs:** Metrics show Someguy latency of 50ms but API p95 for `/ipns/resolve` is 2s -- the gap is the DB query + serialization overhead.

## Code Examples

Verified patterns from the existing codebase and official docs.

### Docker Compose Someguy Service Definition

```yaml
# Source: Someguy env vars docs + existing docker-compose.staging.yml patterns
someguy:
  image: ghcr.io/ipfs/someguy:v0.11.1
  restart: unless-stopped
  environment:
    # CRITICAL: Must be 0.0.0.0 for Docker inter-container access
    SOMEGUY_LISTEN_ADDRESS: 0.0.0.0:8190
    # Standard DHT for staging (accelerated uses 2GB+ memory)
    SOMEGUY_DHT: standard
    # Reduced connection limits for staging VPS
    SOMEGUY_LIBP2P_CONNMGR_LOW: 50
    SOMEGUY_LIBP2P_CONNMGR_HIGH: 300
    SOMEGUY_LIBP2P_MAX_MEMORY: 512MB
    # Logging
    GOLOG_LOG_LEVEL: info
    GOLOG_LOG_FMT: json
  logging: *default-logging
  healthcheck:
    # Someguy has NO /health endpoint -- use /version instead
    test: ['CMD-SHELL', 'wget -qO- http://localhost:8190/version || exit 1']
    interval: 10s
    timeout: 5s
    retries: 10
    start_period: 30s
  deploy:
    resources:
      limits:
        memory: 768M
        cpus: '0.5'
```

### Deploy Staging Workflow .env.staging Update

```yaml
# Source: .github/workflows/deploy-staging.yml line 377
# Change from:
DELEGATED_ROUTING_URL=https://delegated-ipfs.dev
# To:
DELEGATED_ROUTING_URL=http://someguy:8190
```

### Adding Latency Histograms to MetricsService

```typescript
// Source: existing MetricsService pattern (apps/api/src/metrics/metrics.service.ts)

// Add to class fields:
readonly ipnsResolveDuration: client.Histogram;
readonly ipnsPublishDuration: client.Histogram;

// Add to constructor:
this.ipnsResolveDuration = new client.Histogram({
  name: 'cipherbox_ipns_resolve_duration_seconds',
  help: 'IPNS resolve duration in seconds (end-to-end including fallback)',
  labelNames: ['source'],
  // Buckets cover sub-100ms (local cache) to 30s (DHT timeout)
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30],
  registers: [this.registry],
});

this.ipnsPublishDuration = new client.Histogram({
  name: 'cipherbox_ipns_publish_duration_seconds',
  help: 'IPNS publish duration to routing provider in seconds',
  labelNames: ['outcome'],
  buckets: [0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60],
  registers: [this.registry],
});
```

### Instrumenting IpnsService.resolveRecord() with Timing

```typescript
// Source: pattern from existing http-metrics.interceptor.ts
async resolveRecord(ipnsName: string): Promise<...> {
  const startTime = process.hrtime.bigint();
  let source = 'network';

  try {
    const recordBytes = await this.delegatedRouting.resolve(ipnsName);
    // ... existing logic ...
  } catch (error) {
    // ... existing fallback logic ...
    source = 'db_cache';
  }

  // After determining final result and source:
  const elapsed = Number(process.hrtime.bigint() - startTime) / 1e9;
  this.metricsService.ipnsResolveDuration.observe({ source }, elapsed);

  return result;
}
```

### .env.example Update

```bash
# IPNS Delegated Routing URL
# For production/staging: http://someguy:8190 (self-hosted)
# For local/E2E testing: http://localhost:3001 (mock service)
# Legacy: https://delegated-ipfs.dev (public, unreliable)
# DELEGATED_ROUTING_URL=http://localhost:3001
```

## State of the Art

| Old Approach                     | Current Approach                   | When Changed   | Impact                                                        |
| -------------------------------- | ---------------------------------- | -------------- | ------------------------------------------------------------- |
| `delegated-ipfs.dev` (public)    | Self-hosted Someguy v0.11.1        | Phase 19       | Eliminates external dependency, faster resolution              |
| Counter-only IPNS metrics        | Histograms + counters              | Phase 18-19    | Enables p50/p95/p99 latency tracking                          |
| `accelerated-dht` flag in Someguy | `dht` flag (standard/accelerated/disabled) | Someguy v0.9.0 | More granular control over DHT mode                       |
| No autoconf in Someguy           | `SOMEGUY_AUTOCONF=true` (default)  | Someguy v0.11.0 | Auto-configures bootstrap peers and routing endpoints        |

**Deprecated/outdated:**
- Someguy's `--accelerated-dht` flag was replaced by `--dht` in v0.9.0
- `delegated-ipfs.dev` continues to exist as a public service but is unreliable for CipherBox's use case

## Open Questions

1. **Someguy libp2p port requirements in Docker**
   - What we know: Someguy runs its own libp2p node. DHT client mode works with outbound-only connections.
   - What's unclear: Whether Docker's default bridge network allows sufficient outbound UDP connections for DHT bootstrap. No documentation specifically addresses Docker deployment.
   - Recommendation: Deploy with default Docker networking. If DHT fails to bootstrap, try adding `network_mode: host` or exposing UDP port 4001 (same as Kubo's swarm port -- use a different port to avoid conflict).

2. **Someguy warm-up time for standard DHT mode**
   - What we know: Accelerated mode takes 12+ hours to warm up. Standard mode is faster but no published benchmarks.
   - What's unclear: How long until Someguy in standard mode can resolve an existing IPNS name after cold start.
   - Recommendation: Plan for a 1-2 minute warm-up period after deployment. The start_period in health check (30s) should cover initial bootstrap. If early resolution fails, DB fallback handles it.

3. **Whether to scrape Someguy's Prometheus metrics**
   - What we know: Someguy exposes `/debug/metrics/prometheus` with its own metrics (routing client latency, response sizes as of v0.9.1).
   - What's unclear: Whether these metrics are useful alongside the application-level histograms.
   - Recommendation: Optionally add a second `prometheus.scrape` target in `alloy-config.river` for Someguy. Low effort, potentially useful for debugging DHT issues. Not blocking.

## Validation Architecture

### Test Framework

| Property           | Value                                    |
| ------------------ | ---------------------------------------- |
| Framework          | Jest 29.x (API unit tests)               |
| Config file        | `apps/api/jest.config.ts`                |
| Quick run command  | `pnpm --filter @cipherbox/api test -- --testPathPattern=ipns` |
| Full suite command | `pnpm --filter @cipherbox/api test`      |

### Phase Requirements to Test Map

| Req ID  | Behavior                                       | Test Type   | Automated Command                                                                        | File Exists? |
| ------- | ---------------------------------------------- | ----------- | ---------------------------------------------------------------------------------------- | ------------ |
| IPNS-01 | Someguy deployed, delegated-ipfs.dev removed   | infra/smoke | Manual: verify `docker compose ps` shows someguy healthy on staging                      | N/A          |
| IPNS-01 | API uses Someguy URL for routing                | unit        | `pnpm --filter @cipherbox/api test -- delegated-routing.client.spec.ts`                  | Existing     |
| IPNS-02 | Resolution via network-first with DB fallback   | unit        | `pnpm --filter @cipherbox/api test -- ipns.service.spec.ts`                              | Existing     |
| IPNS-03 | Recovery tool docs updated                     | manual-only | Review `.env.example` and OpenAPI descriptions                                           | N/A          |
| IPNS-04 | Graceful degradation on Someguy failure         | unit        | `pnpm --filter @cipherbox/api test -- ipns.service.spec.ts`                              | Existing     |
| IPNS-04 | Metrics recorded for resolve source/latency     | unit        | `pnpm --filter @cipherbox/api test -- metrics`                                           | Wave 0       |

### Sampling Rate

- **Per task commit:** `pnpm --filter @cipherbox/api test -- --testPathPattern=ipns`
- **Per wave merge:** `pnpm --filter @cipherbox/api test`
- **Phase gate:** Full API test suite green + staging deployment smoke test

### Wave 0 Gaps

- [ ] `apps/api/src/metrics/metrics.service.spec.ts` -- No existing test file for MetricsService. New histograms need at least registration verification.
- [ ] Integration test verifying `DELEGATED_ROUTING_URL` env var reaches the DelegatedRoutingClient constructor -- already covered by existing `delegated-routing.client.spec.ts:45`.
- [ ] Smoke test script for staging deployment (`scripts/smoke-test-staging.sh` or manual checklist) -- verify Someguy container health + IPNS resolve via API.

_(Existing `delegated-routing.client.spec.ts` and `ipns.service.spec.ts` comprehensively cover the resolution logic and fallback behavior. No new test files needed for the core URL swap -- existing tests already mock the routing URL.)_

## Sources

### Primary (HIGH confidence)

- [Someguy GitHub Repository](https://github.com/ipfs/someguy) - Docker image, version info, architecture
- [Someguy Environment Variables](https://github.com/ipfs/someguy/blob/main/docs/environment-variables.md) - Full configuration reference (SOMEGUY_LISTEN_ADDRESS, SOMEGUY_DHT, libp2p settings)
- [Someguy Releases](https://github.com/ipfs/someguy/releases) - v0.11.1 (Feb 2026) latest stable
- [Delegated Routing V1 HTTP API Spec](https://specs.ipfs.tech/routing/http-routing-v1/) - API contract (GET/PUT `/routing/v1/ipns/{name}`)
- [IPIP-0379: Delegated IPNS HTTP API](https://specs.ipfs.tech/ipips/ipip-0379/) - IPNS delegation specification
- Codebase: `apps/api/src/ipns/delegated-routing.client.ts` - Existing routing client with configurable URL
- Codebase: `apps/api/src/ipns/ipns.service.ts:290-350` - Network-first resolution with DB fallback
- Codebase: `apps/api/src/metrics/metrics.service.ts` - Existing Prometheus metrics patterns
- Codebase: `docker/docker-compose.staging.yml` - Existing Docker Compose staging config
- Codebase: `.github/workflows/deploy-staging.yml:377` - Hardcoded `DELEGATED_ROUTING_URL`

### Secondary (MEDIUM confidence)

- [Someguy Dockerfile](https://github.com/ipfs/someguy/blob/main/Dockerfile) - Container structure, entrypoint (`someguy start`), no EXPOSE/HEALTHCHECK
- [Someguy server.go](https://github.com/ipfs/someguy/blob/main/server.go) - No `/health` endpoint, only `/version`, `/debug/metrics/prometheus`, `/routing/v1/*`
- [IP Shipyard 2025 Review](https://ipshipyard.com/blog/2025-shipyard-ipfs-year-in-review/) - Someguy ecosystem context
- [Delegated Routing Caching Blog Post](https://blog.ipfs.tech/2025-delegated-routing-caching/) - Accelerated DHT warm-up details (12h, 30k peers)

### Tertiary (LOW confidence)

- [Kubo Accelerated DHT OOM Issue](https://github.com/ipfs/kubo/issues/9990) - Resource consumption concerns (from Kubo, likely similar in Someguy)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Someguy v0.11.1 is verified, Docker image exists, API contract matches
- Architecture: HIGH - URL swap pattern is trivial, existing abstraction covers it completely
- Pitfalls: HIGH - Verified through Someguy docs (listen address, DHT modes, no health endpoint)
- Docker deployment: MEDIUM - No published Docker Compose examples for Someguy, resource limits are estimates

**Research date:** 2026-03-07
**Valid until:** 2026-04-07 (Someguy releases monthly, but API contract is stable)

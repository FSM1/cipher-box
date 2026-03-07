# Phase 19: IPNS Resolution Improvement - Context

**Gathered:** 2026-03-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace delegated-ipfs.dev with a self-hosted Someguy instance for IPNS routing (publish + resolve) on the CipherBox API. Achieve reliable, fast IPNS resolution with DB as fallback. TEE worker and recovery flows are explicitly out of scope for routing changes.

</domain>

<decisions>
## Implementation Decisions

### Resolution strategy

- Keep **network-first resolution** (current logic) — Someguy replaces delegated-ipfs.dev as the routing provider, DB remains the fallback
- **No resolution logic change needed** — just swap `DELEGATED_ROUTING_URL` from `https://delegated-ipfs.dev` to `http://someguy:<port>`
- Keep **identical timeout/retry config** (10s timeout, 3 retries, exponential backoff) for apples-to-apples comparison with Phase 18 delegated-ipfs.dev baselines
- Timeout tuning for better UX deferred until baseline data exists
- **Someguy handles both publish and resolve** for the CipherBox API — single routing provider, single config

### Someguy deployment

- **Docker Compose sidecar** — new `someguy` service in `docker-compose.staging.yml`, depends on `ipfs` (Kubo)
- `DELEGATED_ROUTING_URL` changes from `https://delegated-ipfs.dev` to `http://someguy:<port>` in API env
- **Configurable Someguy backend** via environment:
  - Staging: Kubo-only (local DHT, no external HTTP dependencies)
  - Production: Kubo + public Amino DHT (broader resolution coverage)
- **TEE worker stays on delegated-ipfs.dev** — async batch republishes are latency-tolerant, and TEE will eventually move to Phala infra (remote), so routing through CipherBox Someguy would require exposing it publicly. Revisit if Phase 18 capacity metrics show a bottleneck.

### Recovery tool (IPNS-03 rewritten)

- **Recovery defaults to public routing** (delegated-ipfs.dev or public IPFS gateways) for self-sovereignty — recovery must not depend on CipherBox infrastructure
- Self-hosted Someguy is available as an **optional configurable endpoint** for recovery, not the default
- No standalone CLI recovery tool exists yet — building one is deferred to a future phase
- IPNS-03 requirement text should be updated: "Recovery tool CAN optionally use self-hosted Someguy as a configurable endpoint, but defaults to public routing"

### Degradation & fallback

- **Sequential with timeout** (current pattern) — try Someguy, fall back to DB on failure/timeout. No parallel race.
- Long-term vision: IPNS resolution should not be a responsibility of the core CipherBox solution — keeping sequential maintains clean separation
- **Dedicated Prometheus metrics** for Someguy resolution: latency histogram, success/db-fallback/timeout counters
- **Transparent to client** — no `source` field in resolve API response. Source tracking is server-side metrics only.
- **Metrics only, no alerting thresholds** — establish baselines first, configure alerts after data exists

### Claude's Discretion

- Exact Someguy Docker image version and configuration flags
- Someguy port selection and health check configuration
- How to structure the Prometheus histogram labels for Someguy metrics
- E2E test updates (mock-ipns-routing may need adjustment)
- Whether to update OpenAPI descriptions that reference "delegated-ipfs.dev"

</decisions>

<specifics>
## Specific Ideas

- Phase 18 baselines must exist before Phase 19 deploys, so metrics are comparable
- User wants to eventually reduce DB dependence for IPNS — this phase moves in that direction by making the network path reliable
- "IPNS resolution should not be a responsibility of the core CipherBox solution" — long-term architectural direction
- Staging currently hardcodes `DELEGATED_ROUTING_URL=https://delegated-ipfs.dev` in deploy workflow — needs update

</specifics>

<code_context>

## Existing Code Insights

### Reusable Assets

- `DelegatedRoutingClient` (`apps/api/src/ipns/delegated-routing.client.ts`): Already abstracts routing behind a configurable URL. Swapping Someguy URL is a config change, not a code change.
- `IpnsService.resolveRecord()` (`apps/api/src/ipns/ipns.service.ts:290-350`): Network-first with DB fallback and sequence number comparison. Logic stays as-is.
- `MetricsService` (`apps/api/src/metrics/metrics.service.ts`): Existing `ipnsResolves` counter with source label. New histograms extend this.
- `docker-compose.staging.yml`: Well-structured with health checks, resource limits, logging. Someguy fits the existing pattern.

### Established Patterns

- All IPNS routing goes through `DelegatedRoutingClient` — single abstraction point
- `DELEGATED_ROUTING_URL` env var controls the routing endpoint (default: `https://delegated-ipfs.dev`)
- E2E tests use `http://localhost:3001` mock for delegated routing — may need update or parallel mock
- TEE worker has its own routing path, independent of the API's `DelegatedRoutingClient`

### Integration Points

- `docker-compose.staging.yml` — add Someguy service
- `.github/workflows/deploy-staging.yml:377` — change `DELEGATED_ROUTING_URL` env var
- `.github/workflows/e2e.yml` / `e2e-desktop.yml` — E2E mock routing may need adjustment
- `apps/api/.env.example` — update default/docs for DELEGATED_ROUTING_URL
- `packages/api-client/openapi.json` — API descriptions reference delegated-ipfs.dev

</code_context>

<deferred>
## Deferred Ideas

- **Standalone CLI recovery tool** — build a Node.js CLI that reads vault export JSON, resolves IPNS, and decrypts/downloads all files. Separate phase.
- **TEE worker routing through Someguy** — revisit when capacity metrics show delegated-ipfs.dev is a bottleneck for batch republishes, or when TEE moves to Phala infra.
- **Timeout tuning for UX** — after baseline data from Phase 18 + early Phase 19, tune timeout/retry for sub-2s user experience.
- **Alerting thresholds** — configure Grafana alerts for DB fallback rate after baseline data exists.

</deferred>

---

_Phase: 19-ipns-resolution-improvement_
_Context gathered: 2026-03-07_

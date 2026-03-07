# Project Research Summary

**Project:** CipherBox v1.1 -- IPFS Infrastructure
**Domain:** IPFS/IPNS reliability, database minimization, BYO-IPFS node support, performance baselines
**Researched:** 2026-03-07
**Confidence:** HIGH

## Executive Summary

CipherBox v1.1 is an infrastructure-hardening milestone, not a feature milestone. The four workstreams -- IPNS reliability, database minimization, BYO-IPFS, and performance baselines -- aim to transform CipherBox from "IPFS as a storage backend with database fallbacks" to "IPFS-native with the database serving only coordination and auth." The dominant finding across all four research files is that the existing stack already has the capabilities needed. The Kubo v0.34.0 node can resolve IPNS records locally via its DHT; the `IpfsProvider` interface already abstracts pin/unpin/get for provider extension; `prom-client` is installed with an established `MetricsService` pattern; and TypeORM handles all necessary migrations. **Zero new npm dependencies are required for this entire milestone.**

The recommended approach is a four-phase execution with strict ordering. Phase 1 (performance instrumentation) is zero-risk and establishes baselines before any architectural changes. Phase 2 (IPNS reliability) inverts the resolution model to DB-first with async Kubo DHT verification, eliminating the `delegated-ipfs.dev` dependency. Phase 3 (database minimization) moves `encryptedRootFolderKey` into an IPFS blob via a versioned vault blob v2 format, with dual-write migration and DB fallback retained for disaster recovery. Phase 4 (BYO-IPFS) adds a `RemotePinningProvider` speaking the standard IPFS Pinning Service API, with dual-pin strategy (always pin to CipherBox node, best-effort mirror to user's node).

The primary risk is in Phase 3: moving rootFolderKey to IPFS creates a hard dependency on IPNS resolution for login. All four research files flag this independently. The mitigation is clear -- keep the DB copy as a permanent fallback, never make IPNS the sole access path for the root folder key. Secondary risks include sequence number divergence during routing provider migration (Phase 2) and quota tracking becoming unenforceable for BYO-IPFS users (Phase 4). Both have well-defined prevention strategies documented in PITFALLS.md.

## Key Findings

### Recommended Stack

The milestone requires zero new npm dependencies. Every capability is built using existing libraries, configuration changes, and new provider implementations. The only external tooling addition is Grafana k6 v1.0 (a standalone Go binary, not an npm package) for load testing scripts.

**Core technologies (all existing):**

- **Kubo v0.34.0 (recommend upgrade to v0.40.1):** Self-hosted IPFS node already participating in the Amino DHT. Supports `Gateway.ExposeRoutingAPI` and `Ipns.UsePubsub` for local IPNS resolution. v0.40.1 makes routing API default and improves IPNS-over-PubSub.
- **`prom-client` ^15.1.3:** Already installed with `MetricsService` pattern established. Extend with 4 new histograms for IPFS/IPNS latency tracking.
- **TypeORM ^0.3.28 + PostgreSQL 16.x:** Handles all migration needs. 2-3 new migrations (ADD COLUMN, ALTER COLUMN, CREATE TABLE for user IPFS config).
- **IPFS Pinning Service API (HTTP standard):** Vendor-agnostic OpenAPI spec with 4 endpoints. Implemented by Pinata, Filebase, web3.storage, IPFS Cluster. No SDK needed -- native `fetch` is sufficient.
- **k6 v1.0+ (dev tooling only):** Standalone load test runner with native TypeScript support. Install via `brew install k6`. Not committed to repo.

### Expected Features

**Must have (table stakes):**

- Reliable IPNS resolution (<2s, >99.5% availability) -- current `delegated-ipfs.dev` has documented 502s and stale records
- DB-cached CID fallback with sequence number comparison -- already implemented, needs to become the primary resolution path
- IPNS publish/resolve latency monitoring -- counters exist, need duration histograms
- API endpoint response time baselines with p50/p95/p99 targets
- Graceful degradation when IPFS/IPNS is slow -- timeout + fallback pattern, partially implemented

**Should have (differentiators):**

- Move rootFolderKey to IPFS vault record -- server stores zero crypto material, true zero-knowledge relay
- BYO-IPFS node support via Pinning Service API -- unique among encrypted storage apps, enables self-sovereignty over data persistence
- End-to-end user journey performance baselines -- login-to-vault, upload-to-visible timing
- IPFS/IPNS latency histograms with per-operation breakdown in Prometheus

**Defer (v1.2+):**

- CRDT-based share discovery via IPNS inbox -- research-only in v1.1, architecturally desirable but premature
- Migrate device registry off DB -- requires solving approval handshake without server coordination
- Eliminate `pinned_cids` table -- requires alternative quota tracking
- Client-direct IPFS upload mode -- CORS issues, breaks quota tracking and conflict detection

### Architecture Approach

The architecture follows a "DB-first, IPFS-verify" pattern for IPNS resolution, a versioned blob format for metadata evolution, a provider factory pattern for BYO-IPFS extensibility, and additive histogram instrumentation for performance baselines. The key insight is that the DB already serves as the reliable source for IPNS CIDs -- making this explicit (instead of treating it as a fallback) simplifies the architecture and eliminates the external `delegated-ipfs.dev` dependency without adding new infrastructure.

**Major components:**

1. **KuboIpnsClient** -- New NestJS injectable wrapping Kubo's RPC API (`/api/v0/name/resolve`, `/api/v0/name/publish`, `/api/v0/key/import`). Handles native DHT resolution and Kubo-native publishing for the TEE republish path.
2. **Vault Blob v2 Format** -- Extends the root IPNS blob with a version byte and ECIES-wrapped `encryptedRootFolderKey` header, enabling client-side key extraction without a DB round-trip. Version-aware reading allows graceful fallback to blob v1.
3. **Provider Factory + DualPinProvider** -- Per-user `IpfsProviderFactory` that returns either the default `LocalProvider` or a `DualPinProvider` wrapping both `LocalProvider` (always) and `UserCustomProvider` (best-effort mirror to user's node).
4. **MetricsService Extensions** -- 4 new Prometheus histograms: IPNS resolve duration, IPNS publish duration, IPFS operation duration, TEE republish batch duration. All use the existing `prom-client` infrastructure.

### Critical Pitfalls

1. **Sequence number divergence during routing provider migration** -- The new Kubo DHT endpoint may have no records initially. Run the new provider in read-parallel mode for 48+ hours before cutting writes. Dual-write to old and new providers during transition. Monitor for 409 Conflict error spikes.

2. **rootFolderKey on IPNS creates login-critical IPNS dependency** -- Moving rootFolderKey exclusively to IPFS means login fails when IPNS is down. The mitigation is absolute: keep the DB copy as the primary source for login, use the IPFS copy for recovery tool independence. This is a "both, not either" situation. Never drop the DB column.

3. **DHT record expiry during routing provider migration** -- IPNS records expire from the DHT after 48 hours regardless of the validity field. If both providers are misconfigured during a weekend deployment, ALL records expire simultaneously. Build an emergency republish endpoint that bypasses the 6-hour schedule.

4. **BYO-IPFS bypasses server-side optimistic concurrency** -- If users publish IPNS records directly to their node (bypassing the API), the server cannot check sequence numbers. The fix: BYO-IPFS affects ONLY where data is pinned, never how metadata is published. All IPNS publishes must still go through the CipherBox API.

5. **Quota tracking becomes unenforceable with BYO-IPFS** -- Server cannot meter uploads it does not relay. For BYO users, skip server-side quota enforcement and require client-reported CID sizes. Mark `pinned_cids` entries with a `provider` column to distinguish server-pinned from BYO-pinned.

## Implications for Roadmap

Based on research, suggested phase structure:

### Phase 1: Performance Instrumentation

**Rationale:** Zero risk to existing functionality. Purely additive. Establishes "before" measurements that Phase 2-4 can be compared against. Without baselines, we cannot prove that subsequent phases improve performance or detect regressions.
**Delivers:** 4 new Prometheus histograms (IPNS resolve/publish duration, IPFS operation duration, TEE republish batch duration), client-side timing utility, baseline measurements document, k6 load test scripts.
**Addresses:** Table stakes features -- IPNS publish latency monitoring, API endpoint baselines.
**Avoids:** Pitfall P7 (instrumentation overhead) -- verify overhead < 5% on P95 latency with and without instrumentation.
**Estimated scope:** Small. ~10 modified files, no new entities or migrations.

### Phase 2: IPNS Resolution Improvement

**Rationale:** Fixes the most critical reliability issue and is the gating dependency for Phase 3. The current `delegated-ipfs.dev` dependency causes 502 errors and stale records. Must be resolved before making IPNS a login-critical path.
**Delivers:** `KuboIpnsClient` for native Kubo DHT resolution, DB-first resolution strategy, `delegated-ipfs.dev` demoted to disabled-by-default fallback, Kubo config with `Ipns.UsePubsub: true`, updated recovery tool resolution chain.
**Addresses:** Table stakes -- reliable IPNS resolution, graceful degradation.
**Avoids:** Pitfall P1 (sequence number divergence) -- run dual-provider for 48+ hours, compare sequence numbers across providers. Pitfall P5 (DHT record expiry) -- never take old provider offline until new one has processed a full republish cycle.
**Estimated scope:** Medium. 1 new file, ~5 modified files, Kubo config change, recovery tool update.

### Phase 3: Database Minimization (rootFolderKey to IPFS)

**Rationale:** Requires reliable IPNS resolution from Phase 2. This is the highest-value zero-knowledge improvement: the server stores zero crypto material after migration. The vault blob v2 format is a breaking metadata change requiring careful migration across web, desktop, and recovery tool.
**Delivers:** Vault blob v2 format with embedded `encryptedRootFolderKey`, version-aware blob reading, dual-write migration strategy, `encryptedRootIpnsPrivateKey` deprecation, updated recovery tool, metadata schema version bump per METADATA_EVOLUTION_PROTOCOL.
**Addresses:** Differentiator -- server stores zero crypto material, true zero-knowledge relay.
**Avoids:** Pitfall P2 (rootFolderKey on IPNS) -- keep DB copy as permanent fallback for login, use IPFS copy for recovery tool independence. Pitfall P3 (share discovery on IPFS) -- explicitly do NOT migrate shares, keep sharing graph in DB.
**Estimated scope:** Large. New type definitions, serialization code, changes across 3 clients (web, desktop, recovery).

### Phase 4: BYO-IPFS Node Support

**Rationale:** Largest surface area but most independent feature. Benefits from stable IPNS resolution (Phase 2) and reduced DB dependency (Phase 3) but does not strictly require them. The `RemotePinningProvider` is additive -- it mirrors pins without replacing the local provider.
**Delivers:** `UserCustomProvider` (Kubo RPC + Pinning Service API), `DualPinProvider` wrapper, `ProviderFactory` for per-user resolution, `user_ipfs_config` entity and migration, IPFS config CRUD API endpoints, connection test endpoint, Settings page UI for IPFS node configuration, BYO-specific Prometheus metrics.
**Addresses:** Differentiator -- BYO-IPFS node support, unique among encrypted storage apps.
**Avoids:** Pitfall P4 (BYO bypasses concurrency) -- all IPNS publishes still go through API, BYO affects only pinning. Pitfall P6 (quota tracking) -- skip server-side quota for BYO users, require client-reported CID sizes, add `provider` column to `pinned_cids`.
**Estimated scope:** Large. New entity, migration, 4+ new provider files, UI component, multiple API endpoints.

### Phase Ordering Rationale

- **Phase 1 before everything:** Baselines must exist before changes, or you cannot measure impact. Zero dependencies, zero risk.
- **Phase 2 before Phase 3 (hard dependency):** Moving rootFolderKey to IPFS makes IPNS resolution login-critical. IPNS must be reliable first. All four research files independently flag this as the most important ordering constraint.
- **Phase 3 before Phase 4 (soft dependency):** Not strictly required, but Phase 3 reduces DB dependency which aligns with BYO-IPFS goals. Phase 4's design work can proceed in parallel with Phase 3's implementation.
- **Phase 4 last:** Largest surface area, most new code, benefits from all prior infrastructure improvements.

### Research Flags

Phases likely needing deeper research during planning:

- **Phase 3 (Database Minimization):** Migration protocol edge cases -- blob v2 format across 3 clients, dual-write/dual-read window management, recovery tool independence, desktop (Rust) blob parsing. This is the riskiest phase.
- **Phase 4 (BYO-IPFS):** Per-user provider routing in NestJS DI, IPFS Pinning Service API real-world testing, auth token storage model (ECIES-wrapped vs server-encrypted), Settings UI design.

Phases with standard patterns (skip research-phase):

- **Phase 1 (Performance Instrumentation):** Established `prom-client` + `MetricsService` pattern. k6 is well-documented. Purely additive.
- **Phase 2 (IPNS Resolution):** Kubo RPC API is documented, DB-first resolution is architecturally straightforward. The main risk (sequence number divergence during transition) is an operational concern, not a research gap.

## Confidence Assessment

| Area         | Confidence                                               | Notes                                                                                                                                                                                                                        |
| ------------ | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stack        | HIGH                                                     | Zero new npm dependencies. All capabilities use existing libraries. Kubo API contracts verified against official docs.                                                                                                       |
| Features     | HIGH for IPNS/perf, MEDIUM for DB migration and BYO-IPFS | IPNS reliability and performance monitoring are well-documented domains. DB-to-IPFS migration has app-specific edge cases. BYO-IPFS Pinning Service API is well-specified but per-user provider routing patterns are sparse. |
| Architecture | HIGH                                                     | Existing codebase analyzed in detail. DB-first resolution, provider factory, blob versioning are all established patterns. Build order validated against dependency graph.                                                   |
| Pitfalls     | HIGH                                                     | 6 critical pitfalls identified with specific prevention strategies, warning signs, and recovery plans. Phase-to-pitfall mapping is complete.                                                                                 |

**Overall confidence:** HIGH

### Gaps to Address

- **rootFolderKey migration dual-write window:** How long should the dual-write period last? What happens to users who never log in during the window? Need a forced migration strategy (background job that reads DB key, writes blob v2, publishes to IPNS) for dormant accounts.
- **BYO-IPFS auth token storage model:** STACK.md recommends server-side encryption (server needs to decrypt to call user's node). ARCHITECTURE.md implements this. PITFALLS.md warns about server compromise exposing tokens. The tradeoff (server sees token but not plaintext content) needs explicit acceptance and documentation.
- **Kubo version decision:** v0.34.0 works but v0.40.1 is recommended. The upgrade should happen before Phase 2 starts but is not blocking. Need to validate that Kubo v0.40.1 does not introduce breaking changes for the existing `LocalProvider` calls.
- **CRDT inbox for shares:** Research-only this milestone. Need to document the CRDT approach as a design RFC during Phase 3 work so it feeds into v1.2 planning.
- **Recovery tool independence:** The recovery tool currently resolves IPNS via `delegated-ipfs.dev` directly from the browser. Phases 2 and 3 both modify its behavior. Need to verify it works WITHOUT the CipherBox API running after all changes.
- **IPNS routing approach reconciliation:** STACK.md recommends Kubo's `Gateway.ExposeRoutingAPI`, FEATURES.md recommends self-hosted Someguy, ARCHITECTURE.md recommends DB-first with Kubo RPC `/api/v0/name/resolve`. Adopt the ARCHITECTURE.md approach (DB-first with async Kubo DHT verification) as the definitive strategy -- it is the most robust because it makes the already-reliable DB the primary path and uses Kubo DHT only for background verification.

## Sources

### Primary (HIGH confidence)

- [Delegated Routing V1 HTTP API Spec](https://specs.ipfs.tech/routing/http-routing-v1/) -- IPNS endpoint contract
- [IPFS Pinning Service API Spec](https://ipfs.github.io/pinning-services-api-spec/) -- BYO-IPFS integration standard
- [Kubo RPC API v0 Reference](https://docs.ipfs.tech/reference/kubo/rpc/) -- `/api/v0/name/resolve`, `/api/v0/name/publish`, `/api/v0/key/import`
- [Kubo Configuration Reference](https://github.com/ipfs/kubo/blob/master/docs/config.md) -- `Ipns.UsePubsub`, `Routing.Type`, `Gateway.ExposeRoutingAPI`
- [Kubo v0.34.0](https://github.com/ipfs/kubo/releases/tag/v0.34.0) and [v0.40.0](https://github.com/ipfs/kubo/releases/tag/v0.40.0) Release Notes
- [Someguy GitHub](https://github.com/ipfs/someguy) -- Self-hosted delegated routing reference
- [Grafana k6 1.0 Release](https://grafana.com/blog/grafana-k6-1-0-release/) -- Load testing
- [prom-client GitHub](https://github.com/siimon/prom-client) -- Prometheus client for Node.js
- [IPNS Record and Protocol spec](https://specs.ipfs.tech/ipns/ipns-record/) -- Sequence number semantics

### Secondary (MEDIUM confidence)

- [ProbeLab IPFS KPIs](https://www.probelab.io/ipfs/kpi/) and [Week 07, 2026 Results](https://discuss.ipfs.tech/t/probelabs-notable-ipfs-performance-results-week-07-2026/20048) -- DHT performance baselines
- [IPIP-0379: Delegated IPNS HTTP API](https://specs.ipfs.tech/ipips/ipip-0379/) -- IPNS delegation spec
- [IP Shipyard 2025 Year in Review](https://ipshipyard.com/blog/2025-shipyard-ipfs-year-in-review/) -- IPFS ecosystem context
- [Measuring IPNS Performance on the Public Amino DHT](https://www.probelab.network/blog/ipns-performance-amino-dht) -- Median 11s retrieval latency reference
- [Empirical study on performance overhead of code instrumentation (2025)](https://www.sciencedirect.com/science/article/pii/S0164121225002420) -- Instrumentation overhead benchmarks

### Codebase (HIGH confidence)

- `apps/api/src/ipns/ipns.service.ts` -- Current IPNS resolution logic with DB fallback
- `apps/api/src/ipns/delegated-routing.client.ts` -- Current routing client (3 retries, 10s timeout)
- `apps/api/src/ipfs/providers/ipfs-provider.interface.ts` -- 3-method provider abstraction
- `apps/api/src/metrics/metrics.service.ts` -- Existing Prometheus infrastructure
- `apps/api/src/republish/republish.service.ts` -- TEE republish via delegated routing
- `apps/web/public/recovery.html` -- Standalone recovery tool with direct IPNS resolution
- `docs/METADATA_SCHEMAS.md` and `docs/METADATA_EVOLUTION_PROTOCOL.md` -- Schema migration rules

---

_Research completed: 2026-03-07_
_Ready for roadmap: yes_

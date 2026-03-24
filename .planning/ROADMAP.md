# Roadmap: CipherBox v1.1 IPFS Infrastructure

## Overview

CipherBox v1.1 transforms the platform from "IPFS as a storage backend with database fallbacks" to "IPFS-native with the database serving only auth." The milestone establishes performance baselines before making changes, replaces the unreliable delegated-ipfs.dev dependency with self-hosted IPNS resolution, migrates rootFolderKey to an IPFS vault blob (achieving true zero-knowledge server), adds BYO-IPFS node support for data sovereignty, and completes performance baselines with client-side instrumentation and load testing after all features are stable.

## Milestones

- **v0.1 Staging MVP** - Phases 1-10 (shipped 2026-02-11)
- **v1.0 Production** - Phases 11-17.1 (shipped 2026-03-05)
- **v1.1 IPFS Infrastructure** - Phases 18-22 (in progress)

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 18: Performance Instrumentation** - Server-side Prometheus histograms and Kubo metrics scraping to establish baselines before any architectural changes (completed 2026-03-07)
- [x] **Phase 19: IPNS Resolution Improvement** - Replace delegated-ipfs.dev with self-hosted Someguy sidecar for reliable IPNS routing, add latency histograms for resolve/publish operations (completed 2026-03-07)
- [x] **Phase 19.2: IPFS Upload Performance Optimization** - Optimize Kubo pinning path (concurrent pins, worker tuning, pin batching) to reduce upload latency (INSERTED) (completed 2026-03-23)
- [x] **Phase 20: Vault Migration** - Move rootFolderKey to IPFS vault blob v2 format, making the server store zero crypto material (gap closure in progress) (completed 2026-03-24)
- [ ] **Phase 21: BYO-IPFS Node Support** - User-configurable IPFS pinning endpoint with dual-pin strategy, Settings UI, and connection testing
- [ ] **Phase 22: Performance Baselines Completion** - Client-side timing instrumentation, end-to-end journey timing, k6 load testing, and capacity documentation
- [x] **Phase 23: Rust SDK Extraction** - Extract five Rust crates (crypto, core, api-client, fuse, sdk) mirroring the TypeScript SDK hierarchy, replace duplicated logic in desktop FUSE code, enable unit testing at same granularity as TypeScript (completed 2026-03-24)

## Phase Details

### Phase 18: Performance Instrumentation

**Goal**: Operators can observe IPFS/IPNS latency and API performance in Prometheus/Grafana before any architectural changes are made
**Depends on**: Nothing (first phase of milestone)
**Requirements**: PERF-01, PERF-02, PERF-03, PERF-04
**Success Criteria** (what must be TRUE):

1. Prometheus exposes duration histograms for IPNS resolve, IPNS publish, IPFS pin, and IPFS cat operations with per-operation labels
2. API endpoint response times are captured at p50/p95/p99 for all critical routes (auth, IPNS resolve/publish, file upload/download, folder CRUD)
3. Kubo node health metrics (peer count, bandwidth, datastore size) are visible in Prometheus via scraped Kubo endpoint
4. TEE republish batch duration histogram captures per-batch timing with success/failure labels

**Plans:** 2/2 plans complete

Plans:

- [x] 18-01-PLAN.md -- Add IPFS/IPNS + TEE duration histograms to MetricsService and instrument service/controller timing
- [x] 18-02-PLAN.md -- Add Kubo scrape to Alloy, extend Grafana dashboard, create baseline benchmark script

### Phase 19: IPNS Resolution Improvement

**Goal**: Users experience reliable, fast IPNS resolution without dependency on external delegated-ipfs.dev service
**Depends on**: Phase 18 (baselines must exist to measure improvement)
**Requirements**: IPNS-01, IPNS-02, IPNS-03, IPNS-04
**Success Criteria** (what must be TRUE):

1. Self-hosted Someguy is deployed alongside Kubo and serves as the IPNS routing provider, with delegated-ipfs.dev fully removed from the resolution path
2. IPNS resolution completes within 2 seconds in the normal case (DB-first with async DHT verification) and degrades gracefully to DB-only when DHT is slow
3. The standalone recovery tool resolves IPNS records via self-hosted Someguy without depending on the CipherBox API or delegated-ipfs.dev
4. No user-visible errors or stale metadata when the DHT is temporarily unreachable (DB fallback serves correct data)
   **Plans**: 2 plans

Plans:

- [x] 19-01-PLAN.md -- Deploy Someguy Docker sidecar, update routing URL in deploy workflow and .env.example
- [x] 19-02-PLAN.md -- Add IPNS resolve/publish latency histograms and instrument IpnsService with timing

### Phase 19.1: Extract core crypto SDK as shared package (INSERTED)

**Goal:** Web app's crypto and file operation logic is extracted into a five-package layered SDK architecture (@cipherbox/crypto, @cipherbox/core, @cipherbox/api-client, @cipherbox/sdk-core, @cipherbox/sdk) enabling load testing, integration testing, and future CLI usage without a browser context
**Requirements**: SDK-01, SDK-02, SDK-03, SDK-04, SDK-05, SDK-06, SDK-07, SDK-08, SDK-09, SDK-10, SDK-11
**Depends on:** Phase 19
**Plans:** 6/6 plans complete

Plans:

- [ ] 19.1-01-PLAN.md -- Split crypto into crypto + core packages with transitional re-exports
- [ ] 19.1-02-PLAN.md -- Expand api-client package with orval generation and configurable instance
- [ ] 19.1-03-PLAN.md -- Create sdk-core with stateless folder/file/IPFS/IPNS operations
- [ ] 19.1-04-PLAN.md -- Create sdk with stateful CipherBoxClient, events, bin, and share operations
- [ ] 19.1-05-PLAN.md -- Rewire web app hooks and stores to use SDK
- [ ] 19.1-06-PLAN.md -- Remove re-exports, update imports, configure Release Please

### Phase 19.2: IPFS Upload Performance Optimization (INSERTED)

**Goal:** Upload operations are measurably faster by optimizing the Kubo IPFS pinning path — the dominant bottleneck consuming ~95% of upload endpoint latency (~1.73s mean per pin, 3 sequential pins per upload)
**Depends on:** Phase 19.1 (SDK needed for load test benchmarking)
**Requirements**: PERF-09
**Success Criteria** (what must be TRUE):

1. Independent pin operations within a single upload (ciphertext + file metadata) execute concurrently rather than sequentially, reducing per-upload server-side time from ~5.4s to ~3.5s at p50
2. Kubo pin worker configuration is tuned for concurrent load — pin latency under 50 concurrent clients does not exceed 2x the single-client baseline
3. Load test results (same mixed workload scenario, same staging hardware) show measurable throughput improvement over Phase 19 baselines (>15% ops/s increase at 50+ clients)
4. Latency improvements are validated with before/after Prometheus histogram comparisons and documented in baselines

**Plans:** 4/4 plans complete

Plans:

- [x] 19.2-01-PLAN.md -- Capture pre-optimization baselines, parallelize SDK upload pin orchestration with Promise.allSettled
- [x] 19.2-02-PLAN.md -- Switch Kubo datastore to pebbleds, capture post-optimization baselines with before/after comparison
- [x] 19.2-03-PLAN.md -- Register PERF-09 in REQUIREMENTS.md (gap closure)
- [x] 19.2-04-PLAN.md -- Three-point local performance baselines with matched-environment comparison (gap closure)

### Phase 20: Vault Migration

**Goal**: The server stores zero crypto material -- rootFolderKey lives in the IPFS vault blob, making the server a true zero-knowledge relay
**Depends on**: Phase 19 (IPNS must be reliable before making it a login-adjacent dependency)
**Requirements**: VAULT-01, VAULT-02, VAULT-03, VAULT-04, VAULT-05, VAULT-06
**Success Criteria** (what must be TRUE):

1. New users get vault blob v2 format on first login, with rootFolderKey ECIES-wrapped in the blob header and readable without any database round-trip
2. All vaults use v2 format — DB crypto columns (encryptedRootFolderKey, encryptedRootIpnsPrivateKey, migratedAt) dropped entirely
3. The standalone recovery tool parses vault blob v2 and extracts rootFolderKey without needing the CipherBox API or database
4. The desktop app (Rust) parses vault blob v2 and uses the embedded rootFolderKey for FUSE mount initialization
5. The encryptedRootIpnsPrivateKey column is dropped from the vaults table (HKDF derivation is the canonical path)

**Plans:** 6/6 plans complete

Plans:

- [x] 20-01-PLAN.md -- Vault blob v2 format module in @cipherbox/core with TDD tests and cross-platform test vectors
- [x] 20-02-PLAN.md -- API: DB migration, nullable columns, optional IPNS key on init, POST /vault/migrate endpoint
- [x] 20-03-PLAN.md -- Desktop Rust: v2 blob module, vault fetch for migrated users, root folder v2 publish
- [x] 20-04-PLAN.md -- Web client: v2 blob login read, lazy migration trigger, recovery tool v2 parsing
- [ ] 20-05-PLAN.md -- Gap closure: API cleanup -- drop crypto columns, remove migrate endpoint, simplify DTOs
- [ ] 20-06-PLAN.md -- Gap closure: Client cleanup -- remove dead migration paths, add v2 blob publish on new user init

### Phase 21: BYO-IPFS Node Support

**Goal**: Users can configure their own IPFS node for data sovereignty, with files pinned to both CipherBox and their personal node
**Depends on**: Phase 19 (stable IPNS resolution benefits BYO workflows)
**Requirements**: BYO-01, BYO-02, BYO-03, BYO-04, BYO-05, BYO-06, BYO-07
**Success Criteria** (what must be TRUE):

1. A user can enter their IPFS node endpoint and credentials in Settings, test the connection, and see a success/failure result
2. After configuring a BYO node, every file upload is pinned to both the CipherBox node (always) and the user's node (best-effort mirror)
3. All IPNS publishes still route through the CipherBox API regardless of BYO configuration (no bypass of optimistic concurrency)
4. BYO users see an advisory quota display (not enforced) with clear indication that storage is managed by their own node
5. The connection test endpoint validates reachability and API compatibility of the user's node before saving configuration
   **Plans**: TBD

### Phase 22: Performance Baselines Completion

**Goal**: Complete performance picture exists -- client-side timing, end-to-end journeys, load test results, and capacity recommendations are documented
**Depends on**: Phase 21 (all features must be stable to produce meaningful baselines)
**Requirements**: PERF-05, PERF-06, PERF-07, PERF-08
**Success Criteria** (what must be TRUE):

1. Client-side timing instrumentation captures encrypt/decrypt throughput, upload/download duration, and IPNS operation timing in the browser
2. End-to-end user journey timings are captured for login-to-vault, upload-to-visible, and share-to-accessible workflows
3. k6 load test scripts simulate concurrent users performing upload, download, publish, and resolve operations with documented pass/fail thresholds
4. Capacity thresholds are documented with scaling recommendations (max concurrent users, storage growth projections, IPNS publish throughput limits)
   **Plans**: TBD

### Phase 23: Rust SDK Extraction

**Goal:** Extract five Rust crates (`cipherbox-crypto`, `cipherbox-core`, `cipherbox-api-client`, `cipherbox-fuse`, `cipherbox-sdk`) mirroring the TypeScript SDK package hierarchy. Replace duplicated crypto/IPNS/metadata logic in desktop FUSE code with crate imports. Enable unit testing at the same granularity as TypeScript. Desktop app becomes a thin Tauri shell.
**Requirements**: RSDK-01, RSDK-02, RSDK-03, RSDK-04, RSDK-05, RSDK-06, RSDK-07, RSDK-08, RSDK-09, RSDK-10
**Depends on:** None (can run independently alongside other phases)
**Success Criteria** (what must be TRUE):

1. Five Rust crates compile independently under a Cargo workspace with centralized dependency versions
2. Desktop app is a thin Tauri shell (~1,500 LOC) with all logic delegated to workspace crates
3. Cross-language test vectors in `tests/vectors/` produce identical output in both Rust and TypeScript
4. CI runs workspace-level builds on macOS, Linux, and Windows with cross-language parity gate
5. No duplicated crypto, domain, or API logic remains in the desktop app

**Plans:** 8/8 plans complete

Plans:

- [ ] 23-01-PLAN.md -- Cargo workspace scaffold + cipherbox-crypto crate extraction
- [ ] 23-02-PLAN.md -- cipherbox-core crate extraction (domain types, metadata, IPNS records)
- [ ] 23-03-PLAN.md -- cipherbox-api-client crate + shared test vectors extraction
- [ ] 23-04-PLAN.md -- cipherbox-fuse crate extraction (platform-agnostic + platform modules)
- [x] 23-05-PLAN.md -- cipherbox-sdk crate extraction (sync, queue, state, registry)
- [ ] 23-06-PLAN.md -- Desktop app thin shell cleanup + full workspace verification
- [ ] 23-07-PLAN.md -- CI workspace builds + Release Please + cross-language parity gate
- [x] 23-08-PLAN.md -- Gap closure: Move Windows WinFsp operations to crates/fuse/src/platform/windows/

## Progress

**Execution Order:**
Phases execute in numeric order: 18 -> 19 -> 19.1 -> 19.2 -> 20 -> 21 -> 22

| Phase                                     | Milestone | Plans Complete | Status      | Completed  |
| ----------------------------------------- | --------- | -------------- | ----------- | ---------- |
| 18. Performance Instrumentation           | v1.1      | 2/2            | Complete    | 2026-03-07 |
| 19. IPNS Resolution Improvement           | v1.1      | 2/2            | Complete    | 2026-03-07 |
| 19.1 Extract Core Crypto SDK              | v1.1      | 6/6            | Complete    | 2026-03-20 |
| 19.2 IPFS Upload Performance Optimization | v1.1      | 4/4            | Complete    | 2026-03-23 |
| 20. Vault Migration                       | v1.1      | 6/6            | Complete    | 2026-03-24 |
| 21. BYO-IPFS Node Support                 | v1.1      | 0/?            | Not started | -          |
| 22. Performance Baselines Complete        | v1.1      | 0/?            | Not started | -          |
| 23. Rust SDK Extraction                   | v1.1      | 8/8            | Complete    | 2026-03-24 |

---

_Roadmap created: 2026-03-07_
_Last updated: 2026-03-24_

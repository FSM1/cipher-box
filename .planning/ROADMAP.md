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

- [ ] **Phase 18: Performance Instrumentation** - Server-side Prometheus histograms and Kubo metrics scraping to establish baselines before any architectural changes
- [ ] **Phase 19: IPNS Resolution Improvement** - Replace delegated-ipfs.dev with DB-first resolution and self-hosted Someguy, achieving sub-2s resolution with >99.5% availability
- [ ] **Phase 20: Vault Migration** - Move rootFolderKey to IPFS vault blob v2 format, making the server store zero crypto material
- [ ] **Phase 21: BYO-IPFS Node Support** - User-configurable IPFS pinning endpoint with dual-pin strategy, Settings UI, and connection testing
- [ ] **Phase 22: Performance Baselines Completion** - Client-side timing instrumentation, end-to-end journey timing, k6 load testing, and capacity documentation

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

**Plans:** 1/2 plans executed

Plans:

- [ ] 18-01-PLAN.md -- Add IPFS/IPNS + TEE duration histograms to MetricsService and instrument service/controller timing
- [ ] 18-02-PLAN.md -- Add Kubo scrape to Alloy, extend Grafana dashboard, create baseline benchmark script

### Phase 19: IPNS Resolution Improvement

**Goal**: Users experience reliable, fast IPNS resolution without dependency on external delegated-ipfs.dev service
**Depends on**: Phase 18 (baselines must exist to measure improvement)
**Requirements**: IPNS-01, IPNS-02, IPNS-03, IPNS-04
**Success Criteria** (what must be TRUE):

1. Self-hosted Someguy is deployed alongside Kubo and serves as the IPNS routing provider, with delegated-ipfs.dev fully removed from the resolution path
2. IPNS resolution completes within 2 seconds in the normal case (DB-first with async DHT verification) and degrades gracefully to DB-only when DHT is slow
3. The standalone recovery tool resolves IPNS records via self-hosted Someguy without depending on the CipherBox API or delegated-ipfs.dev
4. No user-visible errors or stale metadata when the DHT is temporarily unreachable (DB fallback serves correct data)
   **Plans**: TBD

### Phase 20: Vault Migration

**Goal**: The server stores zero crypto material -- rootFolderKey lives in the IPFS vault blob, making the server a true zero-knowledge relay
**Depends on**: Phase 19 (IPNS must be reliable before making it a login-adjacent dependency)
**Requirements**: VAULT-01, VAULT-02, VAULT-03, VAULT-04, VAULT-05, VAULT-06
**Success Criteria** (what must be TRUE):

1. New users get vault blob v2 format on first login, with rootFolderKey ECIES-wrapped in the blob header and readable without any database round-trip
2. Existing users are lazily migrated to vault blob v2 on their next folder metadata publish, with the DB copy retained as a permanent fallback
3. The standalone recovery tool parses vault blob v2 and extracts rootFolderKey without needing the CipherBox API or database
4. The desktop app (Rust) parses vault blob v2 and uses the embedded rootFolderKey for FUSE mount initialization
5. The encryptedRootIpnsPrivateKey column is deprecated from the vaults table (HKDF derivation is the canonical path)
   **Plans**: TBD

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

## Progress

**Execution Order:**
Phases execute in numeric order: 18 -> 19 -> 20 -> 21 -> 22

| Phase                              | Milestone | Plans Complete | Status      | Completed |
| ---------------------------------- | --------- | -------------- | ----------- | --------- |
| 18. Performance Instrumentation    | 1/2       | In Progress    |             | -         |
| 19. IPNS Resolution Improvement    | v1.1      | 0/?            | Not started | -         |
| 20. Vault Migration                | v1.1      | 0/?            | Not started | -         |
| 21. BYO-IPFS Node Support          | v1.1      | 0/?            | Not started | -         |
| 22. Performance Baselines Complete | v1.1      | 0/?            | Not started | -         |

---

_Roadmap created: 2026-03-07_
_Last updated: 2026-03-07_

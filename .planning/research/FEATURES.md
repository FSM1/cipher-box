# Feature Research: IPFS Infrastructure (v1.1)

**Domain:** IPFS/IPNS reliability, database minimization, BYO-IPFS, performance monitoring for zero-knowledge encrypted storage
**Researched:** 2026-03-07
**Confidence:** HIGH for IPNS resolution and performance monitoring (well-documented ecosystem), MEDIUM for DB-to-IPFS migration (app-specific trade-offs), MEDIUM for BYO-IPFS (standard exists but integration patterns are sparse)

## Context

CipherBox v1.0 ships with a working zero-knowledge encrypted vault backed by IPFS/IPNS. The current IPNS resolution path uses `delegated-ipfs.dev` which has known reliability issues (502 errors, stale records). A DB-cached CID fallback masks this, but the system has accumulated several centralized workarounds: the `folder_ipns` table caches CIDs and sequence numbers, the `vaults` table stores `encryptedRootFolderKey`, the `shares`/`share_keys` tables store the sharing graph, and `pinned_cids` tracks storage. Milestone 3 (v1.1) aims to make IPFS the primary data layer and reduce the database to auth-only.

---

## Feature Landscape

### Table Stakes (Users Expect These)

Features that any IPFS-native encrypted storage app must have to be credible. Missing these makes the product feel like a prototype relying on centralized crutches.

| Feature                                                | Why Expected                                                                                                                           | Complexity | Notes                                                                                                                                                 |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reliable IPNS resolution (<2s, >99.5% availability)    | Core functionality -- users cannot access their vault if IPNS fails. Current delegated-ipfs.dev has documented 502s and stale records. | MEDIUM     | Self-hosted Someguy is the clear path. Kubo already runs; Someguy adds HTTP delegated routing on top. DB-cached CID remains as fallback, not primary. |
| DB-cached CID fallback with sequence number comparison | Already built. When network returns stale data, DB is authoritative.                                                                   | DONE       | Implemented in PR after staging IPNS stale resolution issue (2026-02-25). Sequence number comparison picks freshest source.                           |
| IPNS publish latency monitoring                        | Users need to know if publishes propagated. Operations team needs to detect degradation before users notice.                           | LOW        | Prometheus histograms for publish/resolve latency already partially exist (`cipherbox_ipns_publishes_total` counter). Need duration histograms.       |
| API endpoint response time baselines                   | Standard operational practice. Without baselines, you cannot detect regressions or set SLOs.                                           | LOW        | HTTP request duration histogram exists. Need to define p50/p95/p99 baseline values and alert thresholds.                                              |
| Graceful degradation when IPFS/IPNS is slow            | Network is inherently variable (DHT lookups 0.3-0.4s median, but p95 can be 10s+). App must not hang.                                  | MEDIUM     | Timeout + fallback pattern. Already partially implemented with DB cache fallback and 10s request timeout in DelegatedRoutingClient.                   |

### Differentiators (Competitive Advantage)

Features that set CipherBox apart from typical IPFS-backed apps. These demonstrate true IPFS-native architecture rather than "IPFS as dumb blob store."

| Feature                                       | Value Proposition                                                                                                                                                                           | Complexity | Notes                                                                                                                                                                                                                                                                 |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Move rootFolderKey to IPFS vault record       | Server stores zero crypto material. True zero-knowledge relay -- the database becomes auth-mapping-only. No other encrypted storage app achieves this level of server-side key elimination. | HIGH       | Breaking change to vault bootstrap flow. Login now requires IPNS resolution before vault access. IPNS reliability is a hard prerequisite. Migration strategy needed per METADATA_EVOLUTION_PROTOCOL.                                                                  |
| BYO-IPFS node support                         | Users can pin encrypted data to their own IPFS node. Self-sovereignty over data persistence -- not relying on CipherBox's infrastructure for pinning. Unique among encrypted storage apps.  | HIGH       | Standard IPFS Pinning Service API exists (OpenAPI spec). Provider abstraction (`IpfsProvider` interface) already supports this. Two modes: server-relay (easier, quota tracking works) vs client-direct (true decentralization, CORS/connectivity issues).            |
| Migrate share discovery to IPFS/IPNS          | Sharing graph moves off server. Server no longer knows who shared with whom. Stronger privacy than any competitor (Tresorit, Proton Drive servers all know the sharing graph).              | VERY HIGH  | Requires solving IPNS multi-writer conflicts (CRDT approach). Currently deferred to research-only for v1.1. The `shares` table has complex state: revocation, key rotation, hidden flags. Moving this to IPFS is architecturally desirable but practically premature. |
| Migrate device registry to IPFS/IPNS          | Device approval workflow moves off server. Server no longer knows which devices a user has.                                                                                                 | HIGH       | Device registry is already an IPNS record (`DeviceRegistry` schema, Section 11 of METADATA_SCHEMAS.md). The DB tracks device approval state -- moving approval to client-side IPNS would require solving the approval handshake without server coordination.          |
| End-to-end user journey performance baselines | Measure real user flows (login-to-first-file, upload-to-visible, share-to-accessible) not just API endpoints. Enables data-driven optimization.                                             | MEDIUM     | Requires client-side timing instrumentation (Performance API / custom Prometheus pushgateway or structured logging). No standard IPFS tooling for this -- must be custom.                                                                                             |
| IPFS/IPNS latency histograms in Prometheus    | Granular per-operation latency (publish, resolve, pin, cat) with p50/p95/p99 breakdowns. Goes beyond counters to expose distribution.                                                       | LOW        | Extend existing MetricsService with Histogram metrics for each IPFS/IPNS operation. Kubo itself exposes Prometheus metrics at `/debug/metrics/prometheus` -- scrape those too.                                                                                        |

### Anti-Features (Commonly Requested, Often Problematic)

| Feature                                       | Why Requested                                                                               | Why Problematic                                                                                                                                                                                                                                                                                                                                                                                         | Alternative                                                                                                                                                                                                  |
| --------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Full database elimination (zero DB)           | Philosophical purity -- "everything on IPFS." Sounds clean.                                 | Auth-method-to-userId mapping requires indexed, queryable storage. IPFS is content-addressed immutable blobs -- not a database. Refresh tokens need server-side revocation. Session management needs server state. Forcing these into IPFS adds complexity without improving privacy (auth data is inherently server-known).                                                                            | Keep auth tables (users, auth_methods, refresh_tokens) in PostgreSQL. Migrate everything else to IPFS/IPNS. The remaining DB is ~3 tables with no crypto material.                                           |
| IPNS PubSub as primary resolution             | Faster than DHT after subscription (instant updates vs seconds). Sounds like the speed fix. | Only works when both publisher and resolver are connected to common PubSub peers. Not persistent -- if resolver was offline during publish, it misses the update and falls back to DHT. Adds connection overhead (6 connections per subscription by default). CipherBox has potentially thousands of IPNS names per user (folders + files). PubSub subscription per name is not feasible at that scale. | Use DHT via self-hosted Someguy as primary. PubSub is useful for real-time collab (future) but not for general IPNS resolution at CipherBox's scale.                                                         |
| CRDT-based IPNS for all metadata (v1.1 scope) | Solves multi-writer conflicts once as a horizontal concern. Theoretically clean.            | CRDTs require all writers to have the IPNS private key. For folder metadata, only the owner (and write-sharing recipients) should publish. CRDTs add state size growth (monotonic), compaction complexity, and merge semantics that must be correct across TypeScript and Rust implementations. Premature optimization for a problem that optimistic concurrency already solves.                        | Keep optimistic concurrency (sequence number checks) for v1.1. Research CRDTs for share inbox only (the one true multi-writer case). Implement in v1.2+ if research validates.                               |
| Client-direct IPFS upload as default          | True decentralization -- client talks directly to IPFS without server relay.                | Breaks quota tracking (server cannot meter what it does not relay). Breaks conflict detection (server cannot check sequence numbers on bypassed publishes). CORS issues with Kubo API. User's IPFS node may be behind NAT/firewall. Client needs to handle Kubo API directly -- fragile and version-dependent.                                                                                          | Server-relay as default. BYO-IPFS uses server-relay to user's configured node (server proxies to user's endpoint). Client-direct is an opt-in advanced mode with explicit "quota tracking disabled" warning. |
| DNSLink as IPNS alternative                   | Human-readable names, fast resolution, well-supported.                                      | Requires DNS infrastructure management per user. TXT record propagation is slow (minutes to hours). Not self-sovereign -- depends on DNS provider. Does not support the per-folder/per-file IPNS keypair model (would need a DNS record per folder). Not feasible at CipherBox's scale of IPNS names.                                                                                                   | Keep IPNS for all mutable pointers. DNSLink is useful for public web content, not for per-user encrypted vaults with thousands of mutable pointers.                                                          |

---

## Feature Dependencies

```text
[Self-hosted IPNS resolution (Someguy)]
    |
    |-- required by --> [Move rootFolderKey to IPFS]
    |                       |
    |                       |-- required by --> [Eliminate vault crypto from DB]
    |
    |-- required by --> [IPNS latency baselines]
    |
    |-- enhances --> [BYO-IPFS node support]

[Performance baselines (API + IPFS histograms)]
    |
    |-- independent (can proceed in parallel)

[BYO-IPFS node support]
    |
    |-- requires --> [IPFS Pinning Service API integration]
    |-- requires --> [Provider abstraction extension]
    |-- conflicts with --> [Server-side quota tracking]
    |                       (quota becomes advisory in BYO mode)

[Move rootFolderKey to IPFS]
    |
    |-- requires --> [Reliable IPNS resolution] (HARD prerequisite)
    |-- requires --> [Metadata schema version bump]
    |-- requires --> [Recovery tool update]

[Migrate folder/file IPNS tracking off DB]
    |
    |-- requires --> [Reliable IPNS resolution]
    |-- enhances --> [Move rootFolderKey to IPFS]

[Migrate shares to IPFS/IPNS]
    |
    |-- requires --> [CRDT research validated] (NOT in v1.1 scope)
    |-- conflicts with --> [v1.1 timeline]
```

### Dependency Notes

- **Self-hosted IPNS is the gating dependency.** Everything else either requires it or benefits from it. Without reliable IPNS, moving rootFolderKey to IPFS puts the vault bootstrap path at risk -- login would fail when IPNS is slow.
- **Performance baselines are independent.** They can proceed in parallel with any other feature. They are instrumenting existing behavior, not changing it.
- **BYO-IPFS and rootFolderKey migration are independent of each other** but both benefit from reliable IPNS. They can be phased in any order.
- **Share migration to IPFS conflicts with v1.1 timeline.** The CRDT approach is research-only this milestone. The `shares` table stays in PostgreSQL.
- **Folder/file IPNS tracking migration** depends on reliable IPNS but is lower risk than rootFolderKey migration because the DB already serves as a cache, and the migration makes the cache optional rather than eliminating a critical path.

---

## Feature Deep Dives

### 1. Self-Hosted IPNS Resolution

**Current state:** `DelegatedRoutingClient` points at `https://delegated-ipfs.dev/routing/v1`. This is a public good endpoint maintained by the IPFS Foundation, backed by Someguy. It proxies to the Amino DHT and IPNI (cid.contact indexer). Known issues: 502 errors, rate limiting (429), stale records due to caching.

**Recommendation: Self-host Someguy alongside Kubo.**

Someguy is the same software powering `delegated-ipfs.dev`. Self-hosting it gives:

- Full control over caching, rate limits, and availability
- Same DHT and IPNI backends, but without shared public infrastructure load
- Docker deployment: `ghcr.io/ipfs/someguy:latest`
- Minimum resources: runs alongside existing Kubo node, shares its DHT participation
- Configuration via environment variables (endpoints, caching, DHT toggles)

**Architecture:**

```text
Client -> CipherBox API -> Self-hosted Someguy -> Amino DHT / IPNI
                        -> DB cache (fallback, sequence-number-aware)
```

**Fallback chain:**

1. Self-hosted Someguy (primary)
2. DB-cached CID (always fresh for own publishes)
3. delegated-ipfs.dev (emergency fallback, best-effort)

**Performance expectations (from ProbeLab Week 07, 2026):**

- DHT lookup: 0.3-0.4s median across regions
- Self-hosted avoids public endpoint queuing -- expect lower variance
- Kubo 0.34+ default IPNS TTL: 5 minutes (down from 1 hour) -- faster propagation

**Complexity:** MEDIUM

- Docker Compose addition for Someguy
- Update `DELEGATED_ROUTING_URL` env var
- Update `DelegatedRoutingClient` for fallback chain
- Scrape Someguy's Prometheus metrics

**Confidence:** HIGH -- Someguy is the reference implementation for Routing V1. Self-hosting is explicitly documented.

### 2. Move rootFolderKey to IPFS Vault Record

**Current state:** `vaults` table stores `encryptedRootFolderKey` (ECIES-wrapped with user's publicKey) and `encryptedRootIpnsPrivateKey`. The IPNS private key is deterministically derivable via HKDF, so only `encryptedRootFolderKey` truly needs storage.

**Recommendation: Embed ECIES-wrapped rootFolderKey in the IPFS blob pointed to by the root vault IPNS record.**

**New bootstrap flow:**

1. Login with Web3Auth, derive secp256k1 keypair
2. Derive root IPNS private key via HKDF (deterministic, no storage needed)
3. Resolve root IPNS name to get CID
4. Fetch IPFS blob at CID
5. Blob contains: `{ encryptedRootFolderKey: <ECIES>, metadata: <AES-GCM encrypted FolderMetadata> }`
6. Unwrap rootFolderKey with privateKey
7. Decrypt FolderMetadata with rootFolderKey

**Migration strategy:**

- New blob format versioned (per METADATA_EVOLUTION_PROTOCOL)
- Dual-read period: client checks IPFS blob first, falls back to DB vault record
- Lazy migration: on next folder metadata publish, client writes new-format blob
- After migration period, `vaults.encrypted_root_folder_key` column becomes nullable/deprecated
- Recovery tool updated for new blob format

**What stays in DB:** `vaults` table retains `owner_id`, `root_ipns_name`, and timestamps. The `owner_public_key` column stays (needed for share ECIES wrapping lookups). Crypto material columns become nullable.

**Risk:** IPNS resolution failure during login is a hard blocker. Mitigated by:

- DB-cached CID fallback (server stores latest CID in `folder_ipns` table)
- Self-hosted Someguy improving baseline reliability
- Client retries with exponential backoff

**Complexity:** HIGH

- New IPFS blob envelope format
- Metadata schema version bump
- Migration path (dual-read, lazy migration)
- Recovery tool update
- Desktop app (Rust) must parse new format
- E2E test updates for new login flow

**Confidence:** MEDIUM -- The approach is sound, but the migration path has edge cases (what if user never logs in during dual-read period? stale recovery tools?).

### 3. BYO-IPFS Node Support

**Current state:** `IpfsProvider` interface (`pinFile`, `unpinFile`, `getFile`) with single `LocalProvider` implementation pointing at the server's Kubo instance via env var `IPFS_LOCAL_API_URL`.

**Recommendation: Add a `RemotePinningProvider` implementing `IpfsProvider` against the IPFS Pinning Service API standard, configured per-user.**

**The IPFS Pinning Service API** is a vendor-agnostic OpenAPI spec. Endpoints:

- `POST /pins` -- Pin by CID (with origins hint for faster retrieval)
- `GET /pins` -- List pins with filtering
- `GET /pins/{requestid}` -- Status of specific pin
- `DELETE /pins/{requestid}` -- Unpin
- Auth: Bearer token per service

**Supported services:** Filebase, Pinata (partial -- no IPNS), web3.storage, IPFS Cluster, any self-hosted Kubo with pinning API enabled.

**Architecture (server-relay mode -- recommended default):**

```text
Client -> CipherBox API -> Provider Router -> LocalProvider (default)
                                           -> RemotePinningProvider (user's node)
```

**Per-user configuration model:**

- New `user_ipfs_config` table or extend vault settings:
  - `pinning_endpoint_url` (e.g., `https://api.filebase.io/v1`)
  - `pinning_auth_token` (encrypted at rest with server key -- or ECIES-wrapped with user's publicKey for zero-knowledge)
  - `provider_type` enum: `default` | `pinning-api` | `kubo-direct`
- Settings UI: endpoint URL, auth token, "test connection" button

**Key design decisions:**

1. **Server-relay vs client-direct:** Server-relay because:
   - Quota tracking works (server meters bytes relayed)
   - Conflict detection works (server sees all publishes)
   - No CORS issues
   - User's auth token stored server-side (encrypted)
   - Tradeoff: server sees encrypted blobs transit (acceptable -- data is already encrypted client-side)

2. **Dual-pin strategy:** Pin to BOTH default node AND user's node. User's node is "additional persistence," not replacement. Ensures CipherBox can still serve the data if user's node goes down.

3. **IPNS implications:** IPNS publishing still goes through self-hosted Someguy/DHT, not user's node. IPNS is a naming layer, independent of pinning. User's node provides content persistence, not name resolution.

4. **Quota tracking:** When BYO-IPFS is configured, server-side quota is advisory ("you have X bytes on our node"). User's node quota is user's problem.

**Complexity:** HIGH

- New provider implementation against Pinning Service API
- Per-user configuration storage
- Provider routing logic (which user gets which provider)
- Settings UI
- "Test connection" flow
- Error handling for unreachable user nodes
- Dual-pin logic

**Confidence:** MEDIUM -- The Pinning Service API is well-specified, but per-user provider routing in a NestJS DI context needs careful design. Zero-knowledge storage of auth tokens (ECIES-wrapped) adds crypto complexity.

### 4. Database Minimization (Beyond rootFolderKey)

**Current DB tables and migration analysis:**

| Table                     | Rows Per User     | Contains Crypto?                                              | Can Move to IPFS?                                          | Recommendation                                |
| ------------------------- | ----------------- | ------------------------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------- |
| `users`                   | 1                 | No                                                            | No -- auth identity                                        | KEEP                                          |
| `auth_methods`            | 1-5               | No                                                            | No -- auth lookup                                          | KEEP                                          |
| `refresh_tokens`          | 1-10              | No                                                            | No -- session management                                   | KEEP                                          |
| `vaults`                  | 1                 | Yes (`encryptedRootFolderKey`, `encryptedRootIpnsPrivateKey`) | Partially -- crypto to IPFS, metadata stays                | MIGRATE crypto columns                        |
| `folder_ipns`             | N (folders+files) | Yes (`encryptedIpnsPrivateKey`)                               | Partially -- CID cache useful, TEE keys needed server-side | KEEP as cache, make optional                  |
| `pinned_cids`             | N (files)         | No                                                            | Could derive from IPFS pin list                            | DEFER -- `ipfs pin ls` is slow for large sets |
| `shares`                  | N (shares)        | Yes (`encryptedKey`)                                          | Theoretically via CRDT inbox                               | KEEP for v1.1, research CRDT for v1.2         |
| `share_keys`              | N (per-share)     | Yes (`encryptedKey`)                                          | Same as shares                                             | KEEP for v1.1                                 |
| `share_invites`           | N (pending)       | Yes                                                           | Same as shares                                             | KEEP for v1.1                                 |
| `ipns_republish_schedule` | N (folders)       | No                                                            | No -- TEE coordination needs server-side scheduling        | KEEP                                          |

**What realistically moves to IPFS in v1.1:**

1. `vaults.encryptedRootFolderKey` and `vaults.encryptedRootIpnsPrivateKey` -> IPFS blob
2. `folder_ipns.latestCid` becomes advisory cache, not authoritative source
3. `folder_ipns.encryptedIpnsPrivateKey` stays -- TEE needs server-accessible copy

**What stays in DB and why:**

- Auth tables: Indexed lookups required for login flow
- Shares: Complex query patterns (list by recipient, filter by status, revocation state)
- Pinned CIDs: Quota tracking requires fast aggregation queries
- Republish schedule: TEE coordination requires server-side cron state
- Folder IPNS: Sequence numbers needed for conflict detection; CID cache needed for IPNS fallback

**Realistic v1.1 DB state after migration:**

- Auth-only: `users`, `auth_methods`, `refresh_tokens` (3 tables, no crypto)
- Vault metadata: `vaults` with crypto columns nullable (1 table, crypto migrated)
- IPFS operations: `folder_ipns`, `pinned_cids`, `ipns_republish_schedule` (3 tables, operational cache)
- Sharing: `shares`, `share_keys`, `share_invites` (3 tables, unchanged)

**Reality check:** The goal of "reduce database to auth-only" is aspirational for v1.1. Realistically, v1.1 can eliminate crypto from `vaults` and make `folder_ipns` an advisory cache. Full share migration requires CRDT research. Full `pinned_cids` elimination requires alternative quota tracking.

**Complexity:** Per-table varies (see table above). Overall: HIGH for rootFolderKey migration, LOW for making `folder_ipns` advisory, VERY HIGH for share migration (deferred).

**Confidence:** MEDIUM -- rootFolderKey migration is well-understood. The gap between "auth-only DB" and "realistic v1.1" is significant.

### 5. Performance Baselines

**Current monitoring state:**

- Prometheus metrics: counters for uploads, downloads, publishes, resolves, logins
- HTTP request duration histogram (method, route, status_code)
- Grafana Cloud dashboard with overview, file ops, IPNS ops, TEE, auth, HTTP performance panels
- Better Stack uptime monitoring for health endpoint
- Kubo exposes Prometheus at `/debug/metrics/prometheus` (not currently scraped)

**What's missing for comprehensive baselines:**

| Metric Category                   | Current State      | Needed                                                                            | Priority |
| --------------------------------- | ------------------ | --------------------------------------------------------------------------------- | -------- |
| API endpoint latency              | Histogram exists   | Define p50/p95/p99 baselines per route                                            | P1       |
| IPFS pin latency                  | Counter only       | Histogram: time from upload request to CID returned                               | P1       |
| IPFS cat latency                  | Not measured       | Histogram: time from cat request to bytes returned                                | P1       |
| IPNS publish latency              | Counter only       | Histogram: time from publish request to DHT confirmation                          | P1       |
| IPNS resolve latency              | Counter only       | Histogram: time to resolve, labeled by source (network/db_cache/fallback)         | P1       |
| TEE republish duration            | Counter only       | Histogram: time per republish batch                                               | P2       |
| Client-side encryption throughput | Not measured       | Client-side Performance API timing (optional pushgateway)                         | P2       |
| End-to-end user journey timing    | Not measured       | Structured client logging: login-to-vault, upload-to-visible, share-to-accessible | P2       |
| Kubo node health                  | Not scraped        | Scrape Kubo Prometheus endpoint: peer count, bandwidth, datastore size            | P2       |
| Someguy routing latency           | N/A (not deployed) | Scrape Someguy metrics once deployed                                              | P2       |

**Recommended approach:**

1. Add Histogram metrics to existing MetricsService for all IPFS/IPNS operations
2. Instrument DelegatedRoutingClient with timing around publish/resolve calls
3. Instrument LocalProvider (and future RemotePinningProvider) with timing around pin/unpin/cat
4. Scrape Kubo's built-in Prometheus endpoint via Grafana Alloy
5. Run a baseline capture period (1-2 weeks on staging with synthetic load) to establish p50/p95/p99 values
6. Set alerting thresholds at 2x baseline p95
7. Client-side timing as stretch goal -- requires either structured logs shipped to Loki or a Prometheus pushgateway

**IPFS network baselines (from ProbeLab, Feb 2026):**

- DHT lookup: 0.3-0.4s median, regional variation (Europe faster than APAC)
- Kubo provide duration: <1s with Optimistic Provide (v0.39+), was 13s+ before
- IPNI ingestion: >5 minutes delay ~15% of the time
- Gateway TTFB (cached): ~0.75-1s improvement with Service Workers

**Complexity:** LOW for server-side histograms (extend existing MetricsService), MEDIUM for Kubo scraping and Grafana dashboard updates, HIGH for client-side instrumentation

**Confidence:** HIGH -- Prometheus histograms are well-understood. ProbeLab provides reference methodology.

---

## MVP Definition

### Launch With (v1.1)

- [ ] Self-hosted IPNS resolution via Someguy -- eliminates delegated-ipfs.dev dependency, gating prerequisite for all other features
- [ ] Move rootFolderKey to IPFS vault record -- eliminates server-side crypto material, largest zero-knowledge improvement
- [ ] IPFS/IPNS latency histograms -- extends existing Prometheus metrics with duration measurements
- [ ] API endpoint p50/p95/p99 baselines -- define SLO targets from measured staging data
- [ ] Kubo Prometheus scraping -- visibility into IPFS node health

### Add After Core (v1.1.x)

- [ ] BYO-IPFS node support -- requires provider abstraction, per-user config, Settings UI. Independent of other features but significant scope.
- [ ] End-to-end user journey timing -- requires client-side instrumentation, lower urgency than server-side baselines
- [ ] Make `folder_ipns` CID cache advisory (not authoritative) -- shifts primary source to IPNS resolution, requires confidence in self-hosted Someguy reliability

### Future Consideration (v1.2+)

- [ ] CRDT-based share discovery via IPNS inbox -- research-only in v1.1, implement if validated
- [ ] Migrate device registry fully off DB -- requires solving approval handshake without server coordination
- [ ] Eliminate `pinned_cids` table -- requires alternative quota tracking (e.g., IPFS MFS size, client-reported)
- [ ] Client-direct IPFS upload mode -- advanced option for power users

---

## Feature Prioritization Matrix

| Feature                      | User Value           | Implementation Cost | Risk                                 | Priority |
| ---------------------------- | -------------------- | ------------------- | ------------------------------------ | -------- |
| Self-hosted IPNS (Someguy)   | HIGH                 | MEDIUM              | LOW (reference impl, Docker)         | P1       |
| IPFS/IPNS latency histograms | MEDIUM               | LOW                 | LOW (extend existing metrics)        | P1       |
| API response time baselines  | MEDIUM               | LOW                 | LOW (measure existing)               | P1       |
| Kubo Prometheus scraping     | MEDIUM               | LOW                 | LOW (standard config)                | P1       |
| Move rootFolderKey to IPFS   | HIGH                 | HIGH                | MEDIUM (migration edge cases)        | P1       |
| Make folder_ipns advisory    | MEDIUM               | MEDIUM              | MEDIUM (depends on IPNS reliability) | P2       |
| BYO-IPFS node support        | HIGH (privacy users) | HIGH                | MEDIUM (new provider, UI)            | P2       |
| End-to-end journey baselines | MEDIUM               | MEDIUM              | LOW                                  | P2       |
| CRDT share inbox (research)  | LOW (research only)  | LOW (research)      | HIGH (may not pan out)               | P3       |
| Device registry off DB       | LOW                  | HIGH                | HIGH (approval handshake)            | P3       |

**Priority key:**

- P1: Must have for v1.1 launch
- P2: Should have, add when P1s are stable
- P3: Nice to have / research only, defer to v1.2

---

## Competitor Feature Analysis

| Capability                  | Proton Drive        | Tresorit              | CryptPad            | CipherBox v1.1 Plan                         |
| --------------------------- | ------------------- | --------------------- | ------------------- | ------------------------------------------- |
| IPFS-native storage         | No (proprietary)    | No (proprietary)      | No (own server)     | Yes -- IPFS for all data                    |
| Self-sovereign key recovery | No (Proton account) | No (Tresorit account) | Partial (IPFS seed) | Yes -- deterministic HKDF from secp256k1    |
| Server-side crypto material | Yes (encrypted)     | Yes (encrypted)       | Yes (encrypted)     | v1.1: No (rootFolderKey moves to IPFS)      |
| BYO storage backend         | No                  | No                    | Limited (self-host) | v1.1: Yes (IPFS Pinning Service API)        |
| Server knows sharing graph  | Yes                 | Yes                   | Yes                 | v1.1: Yes (v1.2: research CRDT alternative) |
| Performance observability   | Internal            | Internal              | Internal            | v1.1: Prometheus + Grafana, open            |

**Key insight:** No competitor offers BYO storage backend with a standard API. CipherBox's IPFS Pinning Service API integration is genuinely novel for encrypted storage. Moving rootFolderKey off-server is also unique -- competitors store encrypted key material server-side as standard practice.

---

## Sources

### IPNS Resolution and Routing

- [IPNS Concepts (IPFS Docs)](https://docs.ipfs.tech/concepts/ipns/) -- MEDIUM confidence (official docs)
- [Someguy GitHub](https://github.com/ipfs/someguy) -- HIGH confidence (reference implementation)
- [Public IPFS Utilities](https://docs.ipfs.tech/concepts/public-utilities/) -- HIGH confidence (official docs)
- [IPIP-0379: Delegated IPNS HTTP API](https://specs.ipfs.tech/ipips/ipip-0379/) -- HIGH confidence (spec)
- [Delegated Routing V1 HTTP API Spec](https://specs.ipfs.tech/routing/http-routing-v1/) -- HIGH confidence (spec)
- [Kubo v0.34 Release (IPNS TTL change)](https://github.com/ipfs/kubo/releases/tag/v0.34.0) -- HIGH confidence (release notes)
- [IP Shipyard 2025 Year in Review](https://ipshipyard.com/blog/2025-shipyard-ipfs-year-in-review/) -- MEDIUM confidence (blog)
- [Delegated Routing Caching Blog](https://blog.ipfs.tech/2025-delegated-routing-caching/) -- MEDIUM confidence (blog)

### IPFS Pinning Service API

- [IPFS Pinning Service API Spec](https://ipfs.github.io/pinning-services-api-spec/) -- HIGH confidence (official spec)
- [Pinning Service API OpenAPI YAML](https://github.com/ipfs/pinning-services-api-spec) -- HIGH confidence (canonical source)
- [Work with Pinning Services (IPFS Docs)](https://docs.ipfs.tech/how-to/work-with-pinning-services/) -- HIGH confidence (official docs)
- [Filebase vs Web3.Storage Comparison](https://filebase.com/web3-storage-alternative/) -- LOW confidence (vendor comparison)

### Performance and Monitoring

- [ProbeLab IPFS KPIs](https://www.probelab.io/ipfs/kpi/) -- HIGH confidence (official measurement)
- [ProbeLab Week 07, 2026 Results](https://discuss.ipfs.tech/t/probelabs-notable-ipfs-performance-results-week-07-2026/20048) -- HIGH confidence (published metrics)
- [Measuring the IPFS Network (IPFS Docs)](https://docs.ipfs.tech/concepts/measuring/) -- HIGH confidence (official docs)
- [IPFS Monitoring (Netdata)](https://www.netdata.cloud/monitoring-101/ipfs-monitoring/) -- MEDIUM confidence (third-party guide)
- [Kubo Prometheus Metrics Config](https://github.com/ipfs/kubo/blob/master/docs/config.md) -- HIGH confidence (official docs)
- [Kubo Prometheus Issue #5604](https://github.com/ipfs/kubo/issues/5604) -- MEDIUM confidence (issue discussion)

### Kubo and DHT Performance

- [DHT Provide Sweep](https://ipshipyard.com/blog/2025-dht-provide-sweep/) -- MEDIUM confidence (blog, technical detail)
- [Kubo v0.39 Release](https://github.com/ipfs/kubo/releases/tag/v0.39.0) -- HIGH confidence (release notes)
- [Kubo v0.40 Release](https://github.com/ipfs/kubo/releases/tag/v0.40.0) -- HIGH confidence (release notes)

### IPNS PubSub

- [IPNS over PubSub discussion](https://discuss.libp2p.io/t/how-is-ipns-over-pubsub-faster-than-dht/1722) -- MEDIUM confidence (forum)
- [Kubo Experimental Features](https://github.com/ipfs/kubo/blob/master/docs/experimental-features.md) -- HIGH confidence (official docs)

### CipherBox Internal

- `apps/api/src/ipns/delegated-routing.client.ts` -- current IPNS resolution implementation
- `apps/api/src/ipfs/providers/ipfs-provider.interface.ts` -- provider abstraction
- `apps/api/src/metrics/metrics.service.ts` -- current Prometheus metrics
- `docs/METADATA_SCHEMAS.md` -- metadata schema reference
- `docs/METADATA_EVOLUTION_PROTOCOL.md` -- schema migration rules
- `.learnings/2026-02-25-ipns-stale-resolution-staging.md` -- IPNS stale resolution debugging
- `.planning/todos/pending/2026-02-21-ipns-resolution-alternatives.md` -- IPNS research todo
- `.planning/todos/pending/2026-02-14-bring-your-own-ipfs-node.md` -- BYO-IPFS todo
- `.planning/todos/pending/2026-02-21-move-root-folder-key-to-ipfs.md` -- rootFolderKey migration todo
- `.planning/todos/pending/2026-02-22-crdt-ipns-inbox-sharing.md` -- CRDT inbox research todo

---

_Feature research for: IPFS Infrastructure improvements (CipherBox v1.1)_
_Researched: 2026-03-07_

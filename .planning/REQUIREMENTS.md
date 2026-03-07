# Requirements: CipherBox v1.1 IPFS Infrastructure

**Defined:** 2026-03-07
**Core Value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext

## v1.1 Requirements

Requirements for IPFS infrastructure milestone. Each maps to roadmap phases.

### IPNS Reliability

- [ ] **IPNS-01**: Self-hosted Someguy deployed alongside Kubo, replacing delegated-ipfs.dev as primary IPNS routing provider
- [ ] **IPNS-02**: IPNS resolution uses DB-first strategy with async Kubo DHT verification via self-hosted Someguy
- [ ] **IPNS-03**: Recovery tool resolves IPNS via self-hosted Someguy instead of delegated-ipfs.dev
- [ ] **IPNS-04**: System degrades gracefully when DHT resolution is slow (timeout + DB fallback within 2s)

### Vault Migration

- [ ] **VAULT-01**: rootFolderKey embedded in IPFS vault blob v2 format (ECIES-wrapped in blob header)
- [ ] **VAULT-02**: Client reads rootFolderKey from IPFS blob on login, falls back to DB vaults table
- [ ] **VAULT-03**: Lazy migration writes vault blob v2 on next folder metadata publish
- [ ] **VAULT-04**: encryptedRootIpnsPrivateKey column deprecated from vaults table (HKDF-derivable)
- [ ] **VAULT-05**: Recovery tool updated to parse vault blob v2 format
- [ ] **VAULT-06**: Desktop app (Rust) parses vault blob v2 format

### BYO-IPFS

- [ ] **BYO-01**: RemotePinningProvider implements standard IPFS Pinning Service API (pin/unpin/status)
- [ ] **BYO-02**: DualPinProvider pins to both CipherBox node and user's configured node
- [ ] **BYO-03**: Per-user IPFS config stored server-side (endpoint URL, encrypted auth token, provider type)
- [ ] **BYO-04**: Settings UI for configuring custom IPFS node endpoint and credentials
- [ ] **BYO-05**: Connection test endpoint validates user's IPFS node is reachable and API-compatible
- [ ] **BYO-06**: All IPNS publishes still route through CipherBox API regardless of BYO config
- [ ] **BYO-07**: Quota tracking becomes advisory for BYO users with clear UI indication

### Performance Baselines

- [x] **PERF-01**: IPFS/IPNS duration histograms added to Prometheus (publish, resolve, pin, cat)
- [x] **PERF-02**: API endpoint p50/p95/p99 baselines defined per critical route
- [x] **PERF-03**: Kubo Prometheus endpoint scraped for node health metrics (peers, bandwidth, datastore)
- [x] **PERF-04**: TEE republish batch duration histogram added
- [ ] **PERF-05**: Client-side timing instrumentation for encrypt/decrypt, upload/download, IPNS operations
- [ ] **PERF-06**: End-to-end user journey timing captured (login-to-vault, upload-to-visible, share-to-accessible)
- [ ] **PERF-07**: k6 load testing scripts simulating concurrent users (upload, download, publish, resolve)
- [ ] **PERF-08**: Capacity thresholds documented with scaling recommendations

## v1.2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### IPNS Enhancements

- **IPNS-05**: CRDT-based share discovery via IPNS inbox (replace server-side shares table)
- **IPNS-06**: folder_ipns CID cache made advisory (IPNS becomes primary source)

### Database Minimization

- **DB-01**: Device registry approval workflow migrated off database
- **DB-02**: pinned_cids table eliminated (alternative quota tracking via IPFS MFS or client-reported)

### BYO-IPFS Advanced

- **BYO-08**: Client-direct IPFS upload mode (bypass server relay for power users)

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature                             | Reason                                                                                                                                |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Full database elimination (zero DB) | Auth tables (users, auth_methods, refresh_tokens) require indexed queryable storage. IPFS is not a database.                          |
| IPNS PubSub as primary resolution   | Only works when publisher and resolver share PubSub peers. Not persistent. Doesn't scale to thousands of IPNS names per user.         |
| CRDT for all metadata               | Premature -- optimistic concurrency already solves folder conflicts. CRDTs add state size growth and cross-platform merge complexity. |
| DNSLink as IPNS alternative         | Requires DNS infrastructure per user. Propagation is slow. Doesn't support per-folder/per-file IPNS model.                            |
| Share migration to IPFS             | Requires CRDT inbox protocol (research-only this milestone). Complex query patterns (filter by recipient, status, revocation).        |
| Encrypted Productivity Suite        | Deferred to Milestone 4 (v2.0) -- billing, teams, doc editors, signing, AWS Nitro TEE                                                 |
| Mobile apps                         | Deferred to Milestone 4+                                                                                                              |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase    | Status   |
| ----------- | -------- | -------- |
| IPNS-01     | Phase 19 | Pending  |
| IPNS-02     | Phase 19 | Pending  |
| IPNS-03     | Phase 19 | Pending  |
| IPNS-04     | Phase 19 | Pending  |
| VAULT-01    | Phase 20 | Pending  |
| VAULT-02    | Phase 20 | Pending  |
| VAULT-03    | Phase 20 | Pending  |
| VAULT-04    | Phase 20 | Pending  |
| VAULT-05    | Phase 20 | Pending  |
| VAULT-06    | Phase 20 | Pending  |
| BYO-01      | Phase 21 | Pending  |
| BYO-02      | Phase 21 | Pending  |
| BYO-03      | Phase 21 | Pending  |
| BYO-04      | Phase 21 | Pending  |
| BYO-05      | Phase 21 | Pending  |
| BYO-06      | Phase 21 | Pending  |
| BYO-07      | Phase 21 | Pending  |
| PERF-01     | Phase 18 | Complete |
| PERF-02     | Phase 18 | Complete |
| PERF-03     | Phase 18 | Complete |
| PERF-04     | Phase 18 | Complete |
| PERF-05     | Phase 22 | Pending  |
| PERF-06     | Phase 22 | Pending  |
| PERF-07     | Phase 22 | Pending  |
| PERF-08     | Phase 22 | Pending  |

**Coverage:**

- v1.1 requirements: 25 total
- Mapped to phases: 25
- Unmapped: 0

---

_Requirements defined: 2026-03-07_
_Last updated: 2026-03-07 after roadmap creation (traceability populated)_

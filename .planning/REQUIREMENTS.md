# Requirements: CipherBox v1.1 IPFS Infrastructure

**Defined:** 2026-03-07
**Core Value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext

## v1.1 Requirements

Requirements for IPFS infrastructure milestone. Each maps to roadmap phases.

### IPNS Reliability

- [x] **IPNS-01**: Self-hosted Someguy deployed alongside Kubo, replacing delegated-ipfs.dev as primary IPNS routing provider
- [ ] **IPNS-02**: IPNS resolution uses DB-first strategy with async Kubo DHT verification via self-hosted Someguy
- [ ] **IPNS-03**: Recovery tool resolves IPNS via self-hosted Someguy instead of delegated-ipfs.dev
- [x] **IPNS-04**: System degrades gracefully when DHT resolution is slow (timeout + DB fallback within 2s)

### Vault Migration

- [x] **VAULT-01**: rootFolderKey embedded in IPFS vault blob v2 format (ECIES-wrapped in blob header)
- [x] **VAULT-02**: Client reads rootFolderKey exclusively from IPFS v2 blob on login (DB crypto columns dropped)
- [x] **VAULT-03**: All vaults migrated to v2 — dead migration code removed, DB columns dropped
- [x] **VAULT-04**: encryptedRootIpnsPrivateKey column dropped from vaults table (HKDF-derivable)
- [x] **VAULT-05**: Recovery tool updated to parse vault blob v2 format
- [x] **VAULT-06**: Desktop app (Rust) parses vault blob v2 format

### BYO-IPFS

- [x] **BYO-01**: RemotePinningProvider implements standard IPFS Pinning Service API (pin/unpin/status)
- [x] **BYO-02**: DualPinProvider pins to both CipherBox node and user's configured node
- [x] **BYO-03**: Per-user IPFS config stored server-side (endpoint URL, encrypted auth token, provider type)
- [x] **BYO-04**: Settings UI for configuring custom IPFS node endpoint and credentials
- [x] **BYO-05**: Connection test endpoint validates user's IPFS node is reachable and API-compatible
- [x] **BYO-06**: All IPNS publishes still route through CipherBox API regardless of BYO config
- [x] **BYO-07**: Quota tracking becomes advisory for BYO users with clear UI indication

### Performance Baselines

- [x] **PERF-01**: IPFS/IPNS duration histograms added to Prometheus (publish, resolve, pin, cat)
- [x] **PERF-02**: API endpoint p50/p95/p99 baselines defined per critical route
- [x] **PERF-03**: Kubo Prometheus endpoint scraped for node health metrics (peers, bandwidth, datastore)
- [x] **PERF-04**: TEE republish batch duration histogram added
- [x] **PERF-05**: Client-side timing instrumentation for encrypt/decrypt, upload/download, IPNS operations
- [x] **PERF-06**: End-to-end user journey timing captured (login-to-vault, upload-to-visible, share-to-accessible)
- [x] **PERF-07**: Vitest-based SDK load harness simulating concurrent users (upload, download, publish, resolve)
- [x] **PERF-08**: Capacity thresholds documented with scaling recommendations
- [x] **PERF-09**: Upload operations optimized via concurrent SDK pin orchestration (Promise.allSettled) and Kubo pebbleds datastore, with before/after baselines documented

### SDK Extraction (Phase 19.1)

- [x] **SDK-01**: @cipherbox/core package contains all CipherBox domain types, metadata schemas, validators, metadata encrypt/decrypt, vault init, IPNS record utilities (extracted from crypto)
- [x] **SDK-02**: @cipherbox/crypto package contains only pure crypto primitives and key derivation (no domain-aware functions after cleanup)
- [x] **SDK-03**: @cipherbox/api-client generates typed HTTP functions from openapi.json without React dependencies, with configurable instance factory
- [x] **SDK-04**: @cipherbox/sdk-core provides stateless folder-aware operations with explicit parameter passing (no Zustand/browser deps)
- [x] **SDK-05**: sdk-core IPFS/IPNS functions accept SdkContext (apiUrl + getAccessToken) instead of reading browser globals
- [x] **SDK-06**: @cipherbox/sdk provides stateful CipherBoxClient class with internal folder tree, key cache, and event emission
- [x] **SDK-07**: SDK bin operations (add, restore, permanent delete, empty) and share operations (create, revoke) work through stateful client
- [ ] **SDK-08**: Web app creates CipherBoxClient on vault load and destroys on logout; Zustand stores subscribe to SDK events
- [ ] **SDK-09**: React hooks refactored to thin wrappers calling SDK client methods instead of service functions directly
- [x] **SDK-10**: All transitional re-exports removed from @cipherbox/crypto; domain type imports enforced at compile time
- [x] **SDK-11**: Release Please configured for independent per-package versioning

### Rust SDK Extraction (Phase 23)

- [x] **RSDK-01**: Cargo workspace at repo root with centralized `[workspace.dependencies]` and all five Rust crates as members
- [x] **RSDK-02**: `cipherbox-crypto` crate contains pure crypto primitives (AES-GCM/CTR, ECIES, Ed25519, HKDF, IPNS name derivation) with no domain knowledge
- [x] **RSDK-03**: Shared JSON test vectors in `tests/vectors/` loaded by both Rust and TypeScript test suites for cross-language parity verification
- [x] **RSDK-04**: `cipherbox-core` crate contains domain types (FolderMetadata, FileMetadata, RecycleBinMetadata, DeviceRegistry), metadata encrypt/decrypt, vault blob v2, IPNS record creation
- [x] **RSDK-05**: `cipherbox-api-client` crate provides typed HTTP client for all CipherBox API endpoints used by desktop
- [x] **RSDK-06**: `cipherbox-fuse` crate contains platform-agnostic FUSE abstractions (InodeTable, caches, file handles) and platform-specific modules behind feature flags (fuse for macOS/Linux, winfsp for Windows)
- [x] **RSDK-07**: `cipherbox-sdk` crate contains stateful orchestration (SyncDaemon, WriteQueue, KeyState, device registry ops) with no Tauri dependency
- [x] **RSDK-08**: Desktop app is a thin Tauri shell (commands/, tray/, main.rs) with all logic delegated to workspace crates
- [x] **RSDK-09**: CI workflows use workspace-level cargo commands, cache root Cargo.lock, and include cross-language vector parity gate
- [x] **RSDK-10**: Release Please configured for independent versioning of all five Rust crates

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

| Requirement | Phase      | Status   |
| ----------- | ---------- | -------- |
| IPNS-01     | Phase 19   | Complete |
| IPNS-02     | Phase 19   | Pending  |
| IPNS-03     | Phase 19   | Pending  |
| IPNS-04     | Phase 19   | Complete |
| VAULT-01    | Phase 20   | Complete |
| VAULT-02    | Phase 20   | Complete |
| VAULT-03    | Phase 20   | Complete |
| VAULT-04    | Phase 20   | Complete |
| VAULT-05    | Phase 20   | Complete |
| VAULT-06    | Phase 20   | Complete |
| BYO-01      | Phase 21   | Complete |
| BYO-02      | Phase 21   | Complete |
| BYO-03      | Phase 21   | Complete |
| BYO-04      | Phase 21   | Complete |
| BYO-05      | Phase 21   | Complete |
| BYO-06      | Phase 21   | Complete |
| BYO-07      | Phase 21   | Complete |
| PERF-01     | Phase 18   | Complete |
| PERF-02     | Phase 18   | Complete |
| PERF-03     | Phase 18   | Complete |
| PERF-04     | Phase 18   | Complete |
| PERF-05     | Phase 22   | Complete |
| PERF-06     | Phase 22   | Complete |
| PERF-07     | Phase 22   | Complete |
| PERF-08     | Phase 22   | Complete |
| PERF-09     | Phase 19.2 | Complete |
| SDK-01      | Phase 19.1 | Complete |
| SDK-02      | Phase 19.1 | Complete |
| SDK-03      | Phase 19.1 | Complete |
| SDK-04      | Phase 19.1 | Complete |
| SDK-05      | Phase 19.1 | Complete |
| SDK-06      | Phase 19.1 | Complete |
| SDK-07      | Phase 19.1 | Complete |
| SDK-08      | Phase 19.1 | Pending  |
| SDK-09      | Phase 19.1 | Pending  |
| SDK-10      | Phase 19.1 | Complete |
| SDK-11      | Phase 19.1 | Complete |
| RSDK-01     | Phase 23   | Complete |
| RSDK-02     | Phase 23   | Complete |
| RSDK-03     | Phase 23   | Complete |
| RSDK-04     | Phase 23   | Complete |
| RSDK-05     | Phase 23   | Complete |
| RSDK-06     | Phase 23   | Complete |
| RSDK-07     | Phase 23   | Complete |
| RSDK-08     | Phase 23   | Complete |
| RSDK-09     | Phase 23   | Complete |
| RSDK-10     | Phase 23   | Complete |

**Coverage:**

- v1.1 requirements: 47 total
- Mapped to phases: 47
- Unmapped: 0

---

_Requirements defined: 2026-03-07_
_Last updated: 2026-03-24 after Phase 23 planning (RSDK-01 through RSDK-10 registered)_

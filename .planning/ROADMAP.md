# Roadmap: CipherBox v1.1 IPFS Infrastructure

## Overview

CipherBox v1.1 transformed the platform from "IPFS as a storage backend with database fallbacks" to "IPFS-native with the database serving only auth." It established performance baselines before making changes, replaced the unreliable delegated-ipfs.dev dependency with self-hosted Someguy IPNS resolution, migrated rootFolderKey to an IPFS vault blob v2 (achieving a true zero-knowledge server), added BYO-IPFS node support for data sovereignty, and completed performance baselines with client-side instrumentation and load testing.

Scope expanded well beyond those original four thrusts to include a layered TypeScript + Rust SDK extraction, writable shares, FUSE write-durability and data-loss hardening, the production Phala TEE migration, per-package release engineering, and SDK folder-state/sharing consolidation. **Completed 2026-06-18 — 34 phases (18–49), 151 plans.**

**Reopened 2026-06-19** to absorb a hardening block (Phases 50–55) — IPFS/IPNS data-integrity, crypto-signature and secret-leak hardening, desktop FUSE durability, release/supply-chain engineering, and code-health remediation surfaced during v1.1 verification and audits. Reopened into Milestone 3 rather than opening a v1.2, since Milestone 4 (v2.0) is already defined.

## Milestones

- **v0.1 Staging MVP** - Phases 1-10 (shipped 2026-02-11)
- **v1.0 Production** - Phases 11-17.1 (shipped 2026-03-05)
- **v1.1 IPFS Infrastructure** - Phases 18-55 (18-49 completed 2026-06-18; hardening block 50-55 reopened 2026-06-19)

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 18: Performance Instrumentation** - Server-side Prometheus histograms and Kubo metrics scraping to establish baselines before any architectural changes (completed 2026-03-07)
- [x] **Phase 19: IPNS Resolution Improvement** - Replace delegated-ipfs.dev with self-hosted Someguy sidecar for reliable IPNS routing, add latency histograms for resolve/publish operations (completed 2026-03-07)
- [x] **Phase 19.1: Extract Core Crypto SDK as Shared Package** - Split the web app's crypto/file logic into a five-package layered SDK (@cipherbox/crypto, core, api-client, sdk-core, sdk) (INSERTED) (completed 2026-03-21)
- [x] **Phase 19.2: IPFS Upload Performance Optimization** - Optimize Kubo pinning path (concurrent pins, worker tuning, pin batching) to reduce upload latency (INSERTED) (completed 2026-03-23)
- [x] **Phase 20: Vault Migration** - Move rootFolderKey to IPFS vault blob v2 format, making the server store zero crypto material (completed 2026-03-24)
- [x] **Phase 21: BYO-IPFS Node Support** - User-configurable IPFS pinning endpoint with dual-pin strategy, Settings UI, and connection testing (completed 2026-03-25)
- [x] **Phase 22: Performance Baselines Completion** - Client-side timing instrumentation, end-to-end journey timing, Vitest-based load testing, and capacity documentation (completed 2026-03-25)
- [x] **Phase 23: Rust SDK Extraction** - Extract five Rust crates (crypto, core, api-client, fuse, sdk) mirroring the TypeScript SDK hierarchy, replace duplicated logic in desktop FUSE code, enable unit testing at same granularity as TypeScript (completed 2026-03-24)
- [x] **Phase 24: Bug Fixes & Test Infrastructure** - Fix known bugs (bin IPNS 404, device registry format error) and strengthen test infrastructure (headless load tests, vault recovery E2E, load test auth refresh) (completed 2026-03-25)
- [x] **Phase 25: Desktop Enhancements** - Desktop auto-update mechanism and TEE file enrollment for new files (completed 2026-03-25)
- [x] **Phase 26: Observability & UX Tuning** - Grafana alerting thresholds from existing baselines and timeout tuning for sub-2s UX (completed 2026-03-26)
- [x] **Phase 27: Writable Shares (PoC)** - Write-permission shares with ECIES-wrapped IPNS key delivery, permission toggle UI, and multi-writer conflict retry (completed 2026-03-27)
- [x] **Phase 28: Code Hygiene & Logging** - Structured logger wrapper, replace 124 console.\* calls, fix silenced unpin failures, clean any casts, archive legacy POC (completed 2026-03-28)
- [x] **Phase 29: Infrastructure Hardening** - Wire up IPNS unenrollment on deletion, test login endpoint hardening, IPFS node access control (completed 2026-03-28)
- [x] **Phase 30: Web App Observability** - Error tracking service (Grafana Faro), error boundaries, client-side telemetry (completed 2026-03-28)
- [x] **Phase 31: Structural Decomposition** - Split monolithic files (useSharedNavigation, FileBrowser, folder.service) into focused modules (completed 2026-03-28)
- [x] **Phase 32: FUSE Async FilePointer Resolution** - Channel-based async resolution to prevent Finder disconnects from blocking FUSE thread (completed 2026-03-28)
- [x] **Phase 33: Windows Async FilePointer Resolution** - Port Phase 32's channel-based async FilePointer resolution to the WinFsp backend (completed 2026-03-28)
- [x] **Phase 34: E2E Test Expansion & Staging Baselines** - Streaming playback, media preview, batch download, and shared teardown E2E tests; BYO-IPFS load test and Faro metrics baselines on staging (completed 2026-03-29)
- [x] **Phase 35: Phala Testnet TEE Migration** - Replace staging TEE simulator with real Phala testnet CVM deployment, validate hardware-backed key derivation and IPNS republishing end-to-end (completed 2026-03-29)
- [x] **Phase 36: Inline Upload Progress** - Replace the floating upload modal with per-file inline progress rows in the file list (completed 2026-03-30)
- [x] **Phase 37: Parallel Batch Upload Pipeline** - Parallel encrypt+pin pipeline with a single folder IPNS publish and Web Worker encryption offload (completed 2026-03-30)
- [x] **Phase 38: Retire Deprecated Web Services** - Migrate all callers from folder.service.ts/bin.service.ts to @cipherbox/sdk and delete them (-2,030 LOC) (completed 2026-03-31)
- [x] **Phase 39: User-Configurable Vault Parameters** - End-user vault settings (recycle-bin retention, delete behavior, versioning) stored encrypted in vault metadata (completed 2026-04-01)
- [x] **Phase 40: Desktop Vault Settings Integration** - Propagate user-configurable vault settings to the desktop Rust SDK and FUSE layer (completed 2026-03-31)
- [x] **Phase 41: Package and App Versioning and Release Cycles** - Per-package semver driven by PR-time conventional-commit analysis, with date-based staging tags (completed 2026-04-01)
- [x] **Phase 42: API Unpin Integrity** - Ownership-guarded unpin with cross-user CID reference counting and a transactional pending-unpins outbox (completed 2026-06-13)
- [x] **Phase 43: FUSE Write Durability** - fsync'd ciphertext write journal with crash-recovery replay; fixes silent release() data loss and mkdir orphans (completed 2026-06-14)
- [x] **Phase 44: IPNS Conflict Handling** - Three-way merge (publishWithCas) for concurrent IPNS writes; loser-becomes-version for file conflicts (completed 2026-06-14)
- [x] **Phase 45: Desktop FUSE Write-Durability Cleanup** - Journal hygiene refactor (shared builders, typed resolve outcome) plus six crash-recovery safety-net tests (completed 2026-06-15)
- [x] **Phase 46: Desktop FUSE Data-Loss Bugs + Replay Hardening** - Close three data-loss bugs and add Linux stale-mount auto-recovery + replay hardening (completed 2026-06-15)
- [x] **Phase 47: SDK Folder-State and Publish-Path Consolidation** - Single SDK-owned folder state and a unified file/folder CAS-retry publish helper (completed 2026-06-17)
- [x] **Phase 48: SDK Self-Bootstrap Regression Fix and Shared-Folder/Metadata Consolidation** - Sequence-based reconcile, single-ownership shared writes, and ECIES-encrypted shared item names (completed 2026-06-17)
- [x] **Phase 49: Shared-Folder Move (Intra-Share) and useFolderNavigation Unwrap Consolidation** - Write-recipients move files between subfolders with FileMetadata re-encryption (completed 2026-06-18)

**v1.1 Hardening Block (reopened 2026-06-19):**

- [x] **Phase 50: IPFS/IPNS Data-Integrity Fixes** - Resolve Phase 42 unpin-integrity data-loss findings and unenroll nested IPNS records under unloaded subtrees (completed 2026-06-19)
- [ ] **Phase 51: Crypto-Signature & Secret-Leak Hardening** - Enforce IPNS signedRecord validation/verification and key zeroization; add web logger redaction interceptor and wire the Faro transport
- [ ] **Phase 52: Desktop FUSE Durability & At-Rest Safety** - Bound write-journal growth, stream large-file writes, add replay network timeouts, and scrub at-rest plaintext filenames
- [ ] **Phase 53: Release & Supply-Chain Engineering** - Pin GitHub Actions to immutable SHAs, regenerate Cargo.lock on release, and harden release-please release-as pin automation
- [ ] **Phase 54: E2E Test-Infra Typing** - Migrate untyped .mjs E2E helper scripts to TypeScript wired into typecheck and lint
- [ ] **Phase 55: Large Source-File Refactor** - Split/dedup oversized source files (client.ts, lib.rs, etc.) tier-by-tier without public-API changes

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

**Goal**: Users can configure their own IPFS node for data sovereignty, with a user-selectable pinning mode (CipherBox only, external only, or dual-pin), Settings UI, and connection testing
**Depends on**: Phase 19 (stable IPNS resolution benefits BYO workflows)
**Requirements**: BYO-01, BYO-02, BYO-03, BYO-04, BYO-05, BYO-06, BYO-07
**Success Criteria** (what must be TRUE):

1. A user can enter their IPFS node endpoint and credentials in Settings, test the connection, and see a success/failure result
2. After configuring a BYO node, uploads respect the user-selected pinning mode: cipherbox-only (default), external-only (direct to user's node), or dual-pin (both CipherBox and user's node)
3. All IPNS publishes still route through the CipherBox API regardless of BYO configuration (no bypass of optimistic concurrency)
4. BYO users see an advisory quota display (not enforced) with clear indication that storage is managed by their own node
5. The connection test endpoint validates reachability and API compatibility of the user's node before saving configuration
   **Plans**: 11 plans (7 original + 4 gap closure)

Plans:

- [x] 21-01-PLAN.md -- SDK pinning interface + KuboProvider, PsaProvider, connection test
- [x] 21-02-PLAN.md -- API CID registration endpoint + advisory quota mode
- [x] 21-03-PLAN.md -- DualPinProvider + SDK client pinning orchestration + vault config type
- [x] 21-04-PLAN.md -- Settings UI STORAGE tab with connection test and advisory badge
- [x] 21-05-PLAN.md -- TEE migration backend (entity, service, controller, BullMQ, TEE worker)
- [x] 21-06-PLAN.md -- Migration progress UI + final integration verification
- [x] 21-07-PLAN.md -- BYO performance benchmarking scenarios + baselines capture (task 4 deferred)
- [x] 21-08-PLAN.md -- Gap closure: Wire BYO config into SDK client lifecycle + source unpin after migration
- [x] 21-09-PLAN.md -- Gap closure: TEE-routed connection test endpoint (eliminates browser CORS issues)
- [x] 21-10-PLAN.md -- Gap closure: PinataProvider for Pinata native API (PSA endpoint deprecated)
- [x] 21-11-PLAN.md -- Gap closure: BYO performance baselines capture (deferred from 21-07)

### Phase 22: Performance Baselines Completion

**Goal**: Complete performance picture exists -- client-side timing, end-to-end journeys, load test results, and capacity recommendations are documented
**Depends on**: Phase 21 (all features must be stable to produce meaningful baselines)
**Requirements**: PERF-05, PERF-06, PERF-07, PERF-08
**Success Criteria** (what must be TRUE):

1. Client-side timing instrumentation captures encrypt/decrypt throughput, upload/download duration, and IPNS operation timing in the browser
2. End-to-end user journey timings are captured for login-to-vault, upload-to-visible, and share-to-accessible workflows
3. k6 load test scripts simulate concurrent users performing upload, download, publish, and resolve operations with documented pass/fail thresholds
4. Capacity thresholds are documented with scaling recommendations (max concurrent users, storage growth projections, IPNS publish throughput limits)

**Plans:** 3/3 plans complete

Plans:

- [x] 22-01-PLAN.md -- SDK Performance API instrumentation (perf.ts module + instrument 11 sdk-core functions)
- [x] 22-02-PLAN.md -- Playwright journey timing tests (login-to-vault, upload-to-visible, share-to-accessible)
- [x] 22-03-PLAN.md -- Load test thresholds + capacity model document (thresholds.ts, update scenarios, docs/CAPACITY.md)

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

**Plans:** 11/11 plans complete

Plans:

- [x] 23-01-PLAN.md -- Cargo workspace scaffold + cipherbox-crypto crate extraction
- [x] 23-02-PLAN.md -- cipherbox-core crate extraction (domain types, metadata, IPNS records)
- [x] 23-03-PLAN.md -- cipherbox-api-client crate + shared test vectors extraction
- [x] 23-04-PLAN.md -- cipherbox-fuse crate extraction (platform-agnostic + platform modules)
- [x] 23-05-PLAN.md -- cipherbox-sdk crate extraction (sync, queue, state, registry)
- [x] 23-06-PLAN.md -- Desktop app thin shell cleanup + full workspace verification
- [x] 23-07-PLAN.md -- CI workspace builds + Release Please + cross-language parity gate
- [x] 23-08-PLAN.md -- Gap closure: Move Windows WinFsp operations to crates/fuse/src/platform/windows/

### Phase 24: Bug Fixes & Test Infrastructure

**Goal**: Fix known bugs blocking user experience and strengthen test infrastructure with headless load tests, vault recovery E2E coverage, and load test auth refresh handling
**Depends on**: None (independent of other new phases)
**Requirements**: BUGFIX-01, BUGFIX-02, TEST-01, TEST-02, TEST-03
**Success Criteria** (what must be TRUE):

1. Bin IPNS name resolves correctly (no 404 errors on recycle bin operations)
2. Device registry parses without crypto format errors
3. Headless Node.js load tests call sdk-core functions directly without Playwright browser overhead
4. Vault v2 recovery tool has automated E2E test coverage
5. Load tests handle 401 responses with automatic token refresh instead of failing

**Plans:** 3/3 plans complete

Plans:

- [x] 24-01-PLAN.md -- Fix bin IPNS 404 (auto-repair + retry/verify) and device registry v2 schema migration
- [x] 24-02-PLAN.md -- Headless sdk-core load tests (3 scenarios) and 401 token refresh interceptor
- [x] 24-03-PLAN.md -- Recovery tool cleanup (remove export mode) and Playwright E2E test

### Phase 25: Desktop Enhancements

**Goal**: Desktop app auto-updates to new versions and enrolls newly created files with the TEE for automatic IPNS republishing
**Depends on**: None (independent of other new phases)
**Requirements**: DESKTOP-01, DESKTOP-02
**Success Criteria** (what must be TRUE):

1. Desktop app checks for updates on launch and notifies the user when a new version is available
2. Users can download and install updates from within the app (or auto-install on next restart)
3. Files created via the desktop FUSE mount are enrolled with the TEE for automatic 3-hour IPNS republishing
4. TEE enrollment works for both CipherBox-pinned and BYO-pinned files

**Plans:** 3/3 plans complete

Plans:

- [x] 25-01-PLAN.md -- TEE file enrollment on per-file IPNS publish (Unix + Windows)
- [x] 25-02-PLAN.md -- Tauri updater plugin integration (config, updater module, tray menu)
- [x] 25-03-PLAN.md -- CI desktop build workflow (cross-platform build, sign, upload to GitHub Release)

### Phase 26: Observability & UX Tuning

**Goal**: Alerting thresholds make performance baselines actionable and timeout tuning delivers sub-2s perceived latency for common operations
**Depends on**: Phase 22 (baselines must exist)
**Requirements**: OBS-01, OBS-02
**Success Criteria** (what must be TRUE):

1. Grafana alerts fire when IPNS resolve, IPFS pin, or API response times exceed p95 thresholds established in Phase 18/22
2. DB fallback rate alert triggers when IPNS resolution falls back to database above a configured threshold
3. Client-side timeouts and retry config are tuned based on Phase 18/22 baseline data for sub-2s UX on common operations
4. Timeout changes are validated against the journey timing tests from Phase 22

**Plans:** 2/2 plans complete

Plans:

- [x] 26-01-PLAN.md -- Grafana alert rule JSON definitions + provisioning script for five alert categories
- [x] 26-02-PLAN.md -- Client-side timeout and retry constant tuning across SDK providers and API services

### Phase 28: Code Hygiene & Logging

**Goal**: Production web app uses structured logging instead of raw console calls (log/warn/error), unpin failures are visible, type safety gaps are closed, and legacy POC is archived
**Depends on**: None
**Requirements**: None (tech debt reduction)
**Research flag**: Skip -- all items are mechanical find-replace or small wrapper creation
**Success Criteria** (what must be TRUE):

1. A `lib/logger.ts` module exists with level filtering (debug/info/warn/error) and all 127 console calls (log/warn/error) in production web code are replaced with logger calls
2. All `.catch(() => {})` patterns on IPFS unpin calls are replaced with `.catch(logger.warn)` so failures are visible in logs
3. All `as any` casts in production web code are replaced with typed alternatives (except acceptable polyfill shims)
4. `00-Preliminary-R&D/poc/` is archived (moved to branch or deleted) and no longer pollutes searches

**Plans**:

- [x] 28-01-PLAN.md -- Structured logger wrapper and console.\* replacement across 28 files
- [x] 28-02-PLAN.md -- Fix silenced .catch empty-block patterns on unpin calls
- [x] 28-03-PLAN.md -- Eliminate as-any casts with proper type declarations
- [x] 28-04-PLAN.md -- Archive legacy POC directory

### Phase 29: Infrastructure Hardening

**Goal**: Orphaned IPNS records are cleaned up on deletion, test login endpoint is hardened for staging, and IPFS node access is restricted
**Depends on**: None
**Requirements**: None (operational hygiene)
**Research flag**: Skip -- IPNS unenroll endpoint already exists, remaining items are config-level
**Success Criteria** (what must be TRUE):

1. Deleting a file or folder triggers IPNS unenrollment via the existing `unenrollIpns()` API, preventing orphaned TEE republish records from accumulating
2. Batch unenrollment works for folder deletes containing multiple files (single API call or batched)
3. `POST /auth/test-login` is verified to be unreachable when `NODE_ENV=production`, with a monitoring alert for staging usage
4. Kubo API (port 5001) is behind a reverse proxy with auth or Kubo ACL in staging/production deployments

**Plans**: 3 plans

Plans:

- [x] 29-01-PLAN.md -- IPNS batch unenroll API endpoint (POST /ipns/unenroll) + API client regeneration
- [x] 29-02-PLAN.md -- SDK IPNS unenrollment on delete (fireAndForgetUnenroll in deleteItem/deleteToBin/permanentDelete) + legacy TODO cleanup
- [x] 29-03-PLAN.md -- Test login Grafana monitoring alert + Kubo access verification

### Phase 30: Web App Observability

**Goal**: Errors and performance issues in the deployed web app are captured, tracked, and alertable rather than lost to console.error
**Depends on**: Phase 28 (logger must exist for the observability layer to build on)
**Requirements**: None (operational capability)
**Research flag**: NEEDS `/gsd:discuss-phase` -- service selection (Sentry vs self-hosted vs lightweight), privacy implications for a zero-knowledge product, scope beyond error tracking, integration with Phase 28 logger
**Success Criteria** (what must be TRUE):

1. Unhandled errors and rejected promises are captured by an error boundary and sent to a tracking service
2. Error reports include enough context (route, user action, stack trace) to diagnose issues without exposing encrypted content
3. Performance metrics (page load, time-to-interactive, core web vitals) are captured and visible in a dashboard
4. No PII or encrypted content is leaked to the error tracking service (privacy audit passes)

**Plans**: TBD

### Phase 31: Structural Decomposition

**Goal**: Monolithic files exceeding 900 lines are split into focused, testable modules without breaking existing functionality
**Depends on**: Phase 28 (logger available for decomposed modules)
**Requirements**: None (maintainability improvement)
**Research flag**: NEEDS `/gsd:discuss-phase` -- decomposition boundaries for useSharedNavigation (navigation vs key management vs write ops), container/presentational split for FileBrowser/SharedFileBrowser, alignment with SDK extraction direction for folder.service.ts
**Success Criteria** (what must be TRUE):

1. `useSharedNavigation.ts` (1199 lines) is split into 3+ focused hooks (navigation state, key unwrapping, write operations) with each under 400 lines
2. `FileBrowser.tsx` (964 lines) and `SharedFileBrowser.tsx` (943 lines) are split into container + presentational components
3. `folder.service.ts` (1089 lines) is decomposed into focused modules (CRUD, metadata, publish coordination)
4. All existing E2E tests pass after decomposition (sharing-workflow, writable-shares, full-workflow)
5. No new `any` casts or type regressions introduced

**Plans**: 3/3 plans executed

Plans:

- [x] 31-01-PLAN.md -- SDK-side module extraction (tree utils, error utils, share context)
- [x] 31-02-PLAN.md -- Web layer barrel re-exports and SDK adoption
- [x] 31-03-PLAN.md -- Hook split and component extraction

### Phase 32: FUSE Async FilePointer Resolution

**Goal**: FUSE FilePointer resolution no longer blocks the filesystem thread, eliminating Finder "connection lost" errors during metadata refresh
**Depends on**: None (can run in parallel with other phases)
**Requirements**: None (performance improvement)
**Research flag**: Skip -- channel-based async pattern is well-defined, contained to crates/fuse
**Success Criteria** (what must be TRUE):

1. FilePointer resolution spawns async tasks via a channel pair instead of blocking the FUSE callback thread
2. Finder operations (ls, open, copy) do not stall or disconnect during background metadata refresh
3. Resolution latency is bounded by a timeout rather than O(N \* network_timeout)
4. Desktop E2E tests pass with the async resolution path

**Plans:** 3/3 plans complete

Plans:

- [x] 32-01-PLAN.md -- Add PendingFilePointer channel infrastructure to CipherBoxFS (enum, channel pair, dedup guard, drain method)
- [x] 32-02-PLAN.md -- Refactor drain_refresh_completions to spawn async FilePointer resolution (replace block_with_timeout with rt.spawn)
- [x] 32-03-PLAN.md -- Handle open/read for unresolved FilePointers with poll-wait fallback (5s poll timeout, EIO on miss)

### Phase 33: Windows Async FilePointer Resolution

**Goal**: WinFsp FilePointer resolution no longer blocks the filesystem thread, eliminating Explorer hangs during metadata refresh on Windows
**Depends on**: Phase 32 (macOS implementation establishes the pattern; Windows ports it to platform/windows/)
**Requirements**: None (performance improvement, Windows parity)
**Research flag**: Skip -- direct port of Phase 32 pattern to Windows-specific code paths
**Success Criteria** (what must be TRUE):

1. FilePointer resolution in platform/windows/ spawns async tasks via channel pair instead of blocking
2. Windows Explorer operations do not hang during background metadata refresh
3. Resolution latency bounded by timeout rather than O(N \* network_timeout)
4. Windows desktop E2E tests pass with the async resolution path

**Plans:** 2/2 plans complete

Plans:

- [x] 33-01-PLAN.md -- Shared async FilePointer resolution infrastructure (PendingFilePointer, channel pair, drain method, modified drain_refresh_completions)
- [x] 33-02-PLAN.md -- Windows WinFsp callback wiring (drain calls in open/read/readdir, read-while-resolving poll, STATUS_DEVICE_NOT_READY)

### Phase 34: E2E Test Expansion & Staging Baselines

**Goal**: Expand E2E test coverage to untested features and capture staging baselines with new instrumentation
**Depends on**: Phase 33 (all code changes complete; this is a testing/validation phase)
**Requirements**: None (test coverage and baseline capture)
**Success Criteria** (what must be TRUE):

1. AES-CTR streaming playback E2E tests cover mode selection, SW interception, and progress
2. Batch download E2E tests cover multi-file selection and individual file download events
3. Media preview E2E tests cover PDF viewer, video player, and audio player
4. Shared deleteAccount teardown wired into all E2E spec afterAll hooks
5. BYO-IPFS load test plan documented (execution deferred pending provider infrastructure)
6. Staging metrics baselines captured with Phase 30 Faro instrumentation

**Todos consumed:**

- `.planning/todos/pending/2026-03-28-add-aes-ctr-streaming-playback-e2e-tests.md`
- `.planning/todos/pending/2026-03-28-add-batch-download-zip-e2e-tests.md`
- `.planning/todos/pending/2026-03-28-add-media-preview-e2e-test-suite.md`
- `.planning/todos/pending/2026-03-28-add-shared-deleteaccount-teardown-to-all-e2e-specs.md`
- `.planning/todos/pending/2026-03-28-byo-ipfs-load-test-baselines-on-staging.md`
- `.planning/todos/pending/2026-03-28-run-staging-metrics-baselines-with-new-instrumentation.md`

**Plans:** 4/4 plans complete

Plans:

- [x] 34-01-PLAN.md -- Shared deleteAccountViaPage helper + wiring into all 10 E2E spec afterAll hooks
- [x] 34-02-PLAN.md -- Media fixture generation + streaming-playback.spec.ts + media-preview.spec.ts E2E suites
- [x] 34-03-PLAN.md -- Batch download E2E tests (multi-select + individual file downloads)
- [x] 34-04-PLAN.md -- BYO-IPFS load test plan document + staging journey/load baselines capture

### Phase 35: Phala Testnet TEE Migration

**Goal**: Staging TEE republishing runs on real Phala testnet infrastructure with hardware-backed key derivation, replacing the local Docker simulator
**Depends on**: Phase 34 (staging baselines captured first to measure before/after)
**Requirements**: None (infrastructure migration -- moves from mock to real TEE)
**Research flag**: NEEDS `/gsd:research-phase` -- Phala testnet deployment process, dstack SDK CVM configuration, attestation verification, testnet resource provisioning
**Success Criteria** (what must be TRUE):

1. TEE worker is deployed as a Phala testnet CVM with `TEE_MODE=cvm`, using dstack SDK for hardware-backed secp256k1 key derivation (no more HKDF simulator seed)
2. Staging API connects to the Phala testnet TEE worker endpoint and successfully completes IPNS republish cycles (enroll, sign, publish) end-to-end
3. TEE key epoch initialization and rotation work correctly with CVM-derived keys (epoch state persists across worker restarts)
4. Republish latency on Phala testnet is within acceptable bounds (< 2x simulator latency per batch) and captured as new staging baselines
5. Staging docker-compose no longer runs a local `tee-worker` container -- the TEE is fully external on Phala testnet

**Plans:** 6/6 plans complete

### Phase 27: Writable Shares (PoC)

**Goal:** Extend Phase 14's read-only sharing to support read-write shares, leveraging existing server-side optimistic concurrency (expectedSequenceNumber / 409 conflict detection) to coordinate multi-writer IPNS publishes.
**Requirements**: SHARE-01, SHARE-02, SHARE-03, SHARE-04, SHARE-05, SHARE-06, SHARE-07, SHARE-08, SHARE-09, SHARE-10
**Depends on:** Phase 14 (User-to-User Sharing), Phase 16 (Advanced Sync -- conflict resolution)
**Success Criteria** (what must be TRUE):

1. Share entity supports permission levels (read/write) with default read for backward compatibility
2. Write-share recipients receive ECIES-wrapped IPNS private key alongside existing folder key
3. IPNS publish endpoint authorizes write-share recipients via shares table lookup
4. Owner can upgrade/downgrade share permission in-place via API endpoint
5. SharedFileBrowser shows [RW] badge, write toolbar, and full context menu for write shares
6. Write operations use withConflictRetry for multi-writer coordination (same as multi-device sync)

**Plans:** 3/3 plans executed

Plans:

- [x] 27-01-PLAN.md -- Share entity/migration, DTOs, service methods, IPNS publish authorization expansion, API client regeneration
- [x] 27-02-PLAN.md -- Share store types, ShareDialog permission toggle, IPNS key wrapping, recipient permission management
- [x] 27-03-PLAN.md -- SharedFileBrowser write UI (badges, toolbar, context menu), useSharedNavigation write ops, 30s polling

### Phase 36: Inline upload progress

**Goal:** Replace the floating UploadModal popup with inline upload progress rows integrated directly into the file browser list, providing in-context upload feedback
**Requirements**: None (UI refactor, no formal requirement IDs)
**Depends on:** Phase 35
**Plans:** 2/2 plans complete

Plans:

- [x] 36-01-PLAN.md -- Upload store refactor to per-file tracking, upload loop migration to per-file actions
- [x] 36-02-PLAN.md -- UploadListItem component, FileList virtual entry merging, inline CSS, delete UploadModal/UploadItem

### Phase 37: Parallel batch upload pipeline

**Goal:** Replace sequential per-file upload loop with parallel encrypt+pin pipeline and single folder metadata update, reducing N folder IPNS publishes to 1 and enabling concurrent file processing
**Requirements**: D-01, D-02, D-03, D-04, D-05, D-06, D-07, D-08, D-09, D-10, D-11, D-12
**Depends on:** Phase 36
**Plans:** 2/2 plans complete

Plans:

- [x] 37-01-PLAN.md -- SDK batch uploadFiles() method with p-limit concurrency pool, stale-children re-read, partial failure handling
- [x] 37-02-PLAN.md -- Web Worker encryption offloading, EncryptionWorkerService wrapper, useDropUpload rewire to batch API

### Phase 38: Retire deprecated web services [COMPLETE 2026-03-31]

**Goal:** Remove `folder.service.ts` (1,059 lines) and `bin.service.ts` (971 lines) by migrating all remaining callers to `@cipherbox/sdk` methods, eliminating the deprecated service layer. Also remove the circular devDependency from `@cipherbox/crypto` on `@cipherbox/core` by refactoring the vault-ipns test to use hardcoded test vectors instead of cross-package imports.
**Requirements**: None (tech debt cleanup, deferred from Phase 31)
**Depends on:** Phase 37

Plans:

- [x] 38-01-PLAN.md -- Extract addFileToFolder/addFilesToFolder/replaceFileInFolder to sdk-core, migrate all folder.service callers
- [x] 38-02-PLAN.md -- Add purgeExpired to SDK client, migrate bin.service callers (useBin, useAuth)
- [x] 38-03-PLAN.md -- Remove @cipherbox/crypto circular devDependency, replace with hardcoded test vectors
- [x] 38-04-PLAN.md -- Delete folder.service.ts (1,059 lines) and bin.service.ts (971 lines)

### Phase 39: User-configurable vault parameters

**Goal:** Add end-user vault settings stored in encrypted vault metadata, giving users control over: recycle bin retention period (default 30 days), delete behavior (soft delete to bin vs hard delete), and file versioning defaults (max versions per file, version cooldown period). Settings UI in the web app with sensible defaults matching current hardcoded values.
**Requirements**: None (deferred items from Phases 13, 17)
**Depends on:** Phase 38

**Plans:** 4 plans

Plans:

- [x] 39-01-PLAN.md — Core VaultSettings type, defaults, validation, and HKDF derivation
- [x] 39-02-PLAN.md — Zustand settings store and encrypted IPNS load/save service
- [x] 39-03-PLAN.md — Consumer integration: wire settings into delete, versioning, and retention
- [x] 39-04-PLAN.md — Vault settings tab UI in Settings page

### Phase 40: Desktop vault settings integration

**Goal:** Propagate user-configurable vault settings (from Phase 39) to the Rust SDK and desktop app. Add `deriveVaultSettingsIpnsKeypair()` to `crates/crypto`, add `VaultSettings` type to `crates/core`, load and decrypt settings during desktop login, and wire loaded values into FUSE operations replacing hardcoded `MAX_VERSIONS_PER_FILE` and `VERSION_COOLDOWN_MS` constants.
**Requirements**: None (follow-up to Phase 39)
**Depends on:** Phase 39

**Plans:** 2/2 plans complete

Plans:

- [x] 40-01-PLAN.md — HKDF vault settings derivation + VaultSettings type and validation in Rust crates
- [x] 40-02-PLAN.md — Load settings in desktop auth flow and wire into FUSE operations

### Phase 41: package and app versioning and release cycles

**Goal:** All monorepo components (apps, JS packages, Rust crates) version independently via conventional commit analysis at PR time, with Release Please consuming label-derived version targets for precise per-package releases
**Requirements**: D-01 through D-40
**Depends on:** Phase 40
**Plans:** 5/5 plans complete

Plans:

- [x] 41-01-PLAN.md — Restructure RP config for 15 independent packages + pre-create release labels
- [x] 41-02-PLAN.md — PR-time release preview action (commit analysis, cascade detection, auto-labeling)
- [x] 41-03-PLAN.md — Post-merge release-as injection action (label-to-version computation)
- [x] 41-04-PLAN.md — Staging tag format update (date-based) + Docker dual-tagging
- [x] 41-05-PLAN.md — Desktop release tags + RP batched release configuration

### Phase 42: API unpin integrity

**Goal:** Close the unpin-path gaps in `apps/api`: verify caller owns a `pinned_cids(userId, cid)` row before unpinning, reference-count CIDs across users before issuing global Kubo `pin/rm`, delete the caller's row, and decrement quota via `recordUnpin` so deletes stop leaking quota
**Requirements:** Todos `2026-06-11-ipfs-unpin-missing-ownership-check` + `2026-06-11-server-quota-never-decremented-on-unpin` (land together — unpin authorization, row deletion, and quota update must be consistent)
**Depends on:** Phase 41
**Plans:** 8/8 plans complete
Plans:
**Wave 1**

- [x] 42-01-PLAN.md — PendingUnpin entity, 2 migrations, app.module registration, 3 audit/drift/outbox metrics (wave 1)
- [x] 42-02-PLAN.md — Web quota reconcile: fetchQuota after removeUsage in deleteFile, D-12 (wave 1)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 42-03-PLAN.md — VaultService.guardedUnpin: ownership + advisory lock + refcount + outbox + audit (wave 2)
- [x] 42-04-PLAN.md — [BLOCKING] apply migrations to live DB; verify pending_unpins + idx_pinned_cids_cid exist (wave 2)
- [x] 42-08-PLAN.md — Grafana alert on cipherbox_unpin_cross_user_attempts_total, D-02/D-10 (wave 2)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 42-05-PLAN.md — IpfsController unpin delegation + upload compensation via guardedUnpin + api:generate (wave 3)
- [x] 42-06-PLAN.md — pending-unpins BullMQ drain worker + read-only drift report job, D-05/D-06 (wave 3)
- [x] 42-07-PLAN.md — One-shot non-BYO backfill script restoring honest quota, D-09 (wave 3)

### Phase 43: FUSE write durability

**Goal:** Make FUSE writes durable: persisted out-of-callback pending-upload journal so `release()` no longer falsely acks then silently loses data, and mkdir parent-publish conflicts actually enqueue a retry instead of orphaning the child folder
**Requirements:** Todos `2026-06-11-fuse-release-data-loss-before-remote-commit` + `2026-06-11-fuse-mkdir-parent-publish-orphan` (mkdir fix builds on the journal — both platforms, macOS + Windows)
**Depends on:** Phase 41
**Plans:** 8/8 plans complete
Plans:
**Wave 1**

- [x] 43-01-PLAN.md — Persist-backed WriteQueue journal in crates/sdk (JournalEntry/JournalOp, fsync, vault-scoped load, park-on-max-retry) + SyncStatus::WriteParked (TDD)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 43-02-PLAN.md — fuser wiring (macOS + Linux): release journal-fsync-before-ack, mkdir MkdirPublish entry + FsEvent::MkdirConflict retry signal

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 43-03-PLAN.md — WinFsp wiring (Windows): handle_cleanup + handle_create mirror the fuser journal/retry changes
- [x] 43-04-PLAN.md — Desktop: cb-journal dir injection, vault-scoped dependency-ordered replay on mount, WriteParked park notification + tray bridge

**Wave 4** *(gap closure — verification blockers from 43-VERIFICATION.md)*

- [x] 43-05-PLAN.md — Journal schema + replay core: add user-wrapped parent_ipns_key_hex, replay signs/publishes parent IPNS (CR-01), unwrap file/child IPNS keys (CR-02/CR-03), created_at_ms ordering + nested-parent resolve + atomic 0600 perms + drop WriteQueue::default (WR-01/02/03/09)

**Wave 5** *(blocked on Wave 4 — disjoint files, parallel)*

- [x] 43-06-PLAN.md — fuser write-side: handle_release EIO on prepare failure (CR-04), gate journal removal on confirmed parent publish (CR-08), journal user-wrapped child + parent IPNS keys (CR-03/CR-01), record_failure on background failure (CR-07)
- [x] 43-07-PLAN.md — Windows: fix UploadSpawnParams types so winfsp compiles (CR-05), Windows mount replay_for_vault (CR-06), mirror CR-03/CR-01/CR-04/CR-08/CR-07 in handle_cleanup + handle_create

**Wave 6** *(blocked on Waves 4-5)*

- [x] 43-08-PLAN.md — SyncDaemon wired to real cb-journal WriteQueue; sync_cycle emits SyncStatus::WriteParked from on-disk Failed counts, making the park/notify pipeline reachable (CR-07)

### Phase 44: IPNS conflict handling

**Goal:** Stop lost updates on concurrent IPNS writes in `packages/sdk-core`: on 409, re-fetch remote folder metadata and merge (children union, per-entry reconcile) before republishing, and extend CAS coverage to file records; full CRDT model explicitly deferred to the CRDT-inbox research todo
**Requirements:** Todo `2026-06-11-ipns-409-retry-lost-update` (discuss-phase: confirm whether the Rust SDK CAS-publish path has the same lost-update pattern)
**Depends on:** Phase 41
**Plans:** 7/7 plans complete
Plans:
**Wave 1**

- [x] 44-01-PLAN.md — Pure building blocks: mergeChildren three-way merge + ConflictError (TDD, wave 1)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 44-02-PLAN.md — Folder 4-attempt merge-and-republish retry loop wiring (wave 2)
- [x] 44-03-PLAN.md — File CAS publish + latest-wins loser-becomes-version + maxVersionsPerFile (TDD, wave 2)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 44-04-PLAN.md — SDK-package caller sweep: client.ts, bin, shared-write baseChildren (wave 3)
- [x] 44-05-PLAN.md — Web hooks caller sweep + file CAS rewire; D-09 no Rust (wave 3)

**Wave 4** *(gap closure — CR-01/CR-02 from 44-VERIFICATION.md)*

- [x] 44-06-PLAN.md — Return publishedChildren from updateFolderMetadataAndPublish + adopt at all 14 caller sites so the next write composes from the merged set (CR-01, WR-08 folder test)
- [x] 44-07-PLAN.md — Filter prunedCids against published mergedMetadata references before return so live version CIDs are never unpinned (CR-02, WR-08 file test)

### Phase 45: Desktop FUSE write-durability cleanup

**Goal:** Rust-only hygiene refactors and added test coverage for the Phase 43/44 FUSE write journal and crash-recovery replay code. No behavior change — pay down the structural debt that accumulated while shipping durable writes, and harden the replay path with tests. Explicitly excludes the desktop-fuse data-loss bugs (mkdir-orphan, release() silent loss, stale-mount recovery), which are tracked separately as bug work.
**Requirements:** Consolidate the duplicated `fuser`/`winfsp` journal write paths; extract a shared journal-dir + max-retries helper; replace stringly-typed code in replay (empty-string journal-key sentinel → `Option<String>`, not-found string match → typed error); reduce repeated work in replay (memoize `resolve_folder_key`, reuse `publish_file_metadata` + a cas-publish helper); raise Phase-43 rust write-durability test coverage. All changes must preserve current behavior and keep crash-recovery semantics intact.
**Depends on:** Phase 44
**Plans:** 6/6 plans complete

Scope (captured todos):

- [x] #11 — Consolidate `fuser` and `winfsp` journal write paths
- [x] #12 — Extract a shared journal-dir and max-retries helper
- [x] #15 — Memoize `resolve_folder_key` during replay
- [x] #18 — Replace empty-string journal key sentinel with `Option<String>`
- [x] #19 — Replace not-found string match with a typed error in replay
- [x] #20 — Reuse `publish_file_metadata` and a cas-publish helper in replay
- [ ] #14 — Improve Phase-43 rust write-durability test coverage (Tier 1 durability/replay tests landed in Phase 45; Tier 2 read_ops/write_ops harness still open — left in pending)

Out of scope (tracked as separate bug work):

- #7 FUSE mkdir orphans the new folder when parent publish conflicts
- #8 FUSE release() reports success then can silently lose data
- #17 Recover stale FUSE mount after crash on Linux startup

Plans:
**Wave 1**

- [x] 45-01-PLAN.md — Write-durability + replay test safety net (#14)
- [x] 45-02-PLAN.md — Shared journal-dir + max-retries helper (#12)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 45-03-PLAN.md — Option<String> file-meta-ipns sentinel + serde compat (#18)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 45-04-PLAN.md — Typed IpnsResolveOutcome in replay (#19)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 45-05-PLAN.md — Reuse publish_file_metadata + memoize resolve_folder_key in replay (#20, #15)

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 45-06-PLAN.md — Consolidate fuser/winfsp journal write paths into journal_helpers (#11)

### Phase 46: Desktop FUSE data-loss bugs + replay hardening

**Goal:** Close the desktop FUSE write-durability work that Phase 45 explicitly deferred — the three known data-loss bugs (mkdir orphan on parent-publish conflict, release() false-durability ack, stale-mount recovery on crash), the two replay-path hardening follow-ups from PR #491, and the remaining read_ops/write_ops + journal_helpers test coverage (Phase 45 Tier 2). Behavior-changing: these are correctness/durability fixes, not hygiene.
**Requirements:** (1) mkdir must durably retry the parent publish on conflict instead of warn-only, so the new child folder is never orphaned remotely; (2) release()/flush must not ack the OS or zeroize+delete the local temp file until the remote commit is durably confirmed or the write is journaled for replay; (3) Linux startup must auto-recover a stale/disconnected FUSE mount (EEXIST/ENOTCONN) instead of failing and notifying; (4) park legacy empty `file_meta_ipns_name` replay entries instead of publishing an empty FilePointer; (5) use a strict (cache-bypassing) IPNS resolve in replay classification so transient failures retain the entry; (6) add the read_ops/write_ops handler test harness (unblock the fuser `ReplySender` limitation) plus the `journal_helpers` builder tests. Preserve all existing crash-recovery semantics.
**Depends on:** Phase 45
**Plans:** 4 plans

Plans:

- [ ] 46-01-PLAN.md — REQ-6 test harness: vendored `ReplySender` export + `make_test_fs` + `CaptureSender` + journal_helpers builder tests (Wave 1, lands first)
- [ ] 46-02-PLAN.md — REQ-3 Linux stale-mount recovery: `recover_stale_mount` + mountinfo parser + EEXIST retry (Wave 2)
- [ ] 46-03-PLAN.md — REQ-4 park legacy empty-name replay entries + REQ-5 strict cache-bypassing replay resolve (Wave 2)
- [ ] 46-04-PLAN.md — REQ-1/REQ-2 mkdir + release durability characterization tests + Open Question A2 verification (Wave 3, tests-only)

Scope (captured todos):

- [x] FUSE mkdir orphans the new folder when parent publish conflicts (bug, high) — `2026-06-11-fuse-mkdir-parent-publish-orphan.md`
- [x] FUSE release() reports success then can silently lose data (bug, high) — `2026-06-11-fuse-release-data-loss-before-remote-commit.md`
- [x] Recover stale FUSE mount after crash on Linux startup (bug) — `2026-06-14-recover-stale-fuse-mount-after-crash-on-linux-startup.md`
- [x] Park legacy empty `file_meta_ipns_name` replay entries instead of empty FilePointer (PR #491 follow-up) — `2026-06-15-replay-empty-file-meta-ipns-name-publishes-empty-filepointer.md`
- [x] Use a strict (cache-bypassing) IPNS resolve in replay classification (PR #491 follow-up) — `2026-06-15-replay-resolve-ipns-strict-resolve-path-no-cache-fallback.md`
- [x] Improve Phase-43 rust write-durability test coverage — Tier 2 read_ops/write_ops harness + journal_helpers builders (Tier 1 landed in Phase 45) — `2026-06-14-improve-phase-43-rust-test-coverage.md`

### Phase 47: SDK folder-state and publish-path consolidation

**Goal:** Pay down the Phase-44 SDK structural debt surfaced by `/simplify` and `/code-review` — one owner for folder state, one CAS-retry engine shared by file and folder publishes, encapsulated child bookkeeping, and the `prunedCids` pin-leak fix on the shared-file path. Mostly refactor, plus one correctness fix (pin leak).
**Requirements:** (1) Unify folder-state ownership so the web Zustand `useFolderStore` and the SDK client `folderTree` can no longer drift — make the SDK client the single source of truth: route the two leaking web file hooks (`useFileOperations.updateFile`, `useFileVersions` restore/delete) through new SDK client methods that own publish + sequence bookkeeping + `folder:updated` emission, make `useFolderStore` a projection whose `children`/`sequenceNumber` are written only via `folder:updated` events (never from web mutation code), and delete the `reconcileFolderState` band-aid (dead by construction, closing the residual race). Scope is folder-state-*mutating* paths only — non-mutating sdk-core usage in the web app (crypto, uploads, metadata fetch/decrypt) stays. (2) unify the duplicated file/folder 409-CAS-retry loops into one `publishWithCas` helper in sdk-core so retry/backoff/sequence handling lives in one place; (3) encapsulate the `baseChildren`/`publishedChildren` snapshot-and-adopt ceremony inside `updateFolderMetadataAndPublish` so the ~14 call sites can't forget the base snapshot and resurrect deletes; (4) consume `prunedCids` in `updateSharedFile` and unpin them to stop the shared-file storage pin leak.
**Depends on:** Phase 44
**Plans:** 5/5 plans complete

Plans:
**Wave 1**

- [x] 47-01-PLAN.md -- publishWithCas generic CAS helper in sdk-core; delegate folder/file publishes + encapsulate baseChildren (REQ-2, REQ-3)

**Wave 2** *(blocked on Wave 1)*

- [x] 47-02-PLAN.md -- Drop updatedChildren from shared-write returns + unpin prunedCids in updateSharedFile (REQ-3, REQ-4)
- [x] 47-03-PLAN.md -- New client replaceFile/restoreFileVersion/deleteFileVersion methods + delete reconcileFolderState (REQ-1)

**Wave 3** *(blocked on Wave 2)*

- [x] 47-04-PLAN.md -- Route web file hooks through client methods + remove reconcileFolderState call (REQ-1)
- [x] 47-05-PLAN.md -- folder.store projection-only tests + full-suite green gate (REQ-1)

Scope (captured todos):

- [x] Unify folder-state ownership in the SDK client (medium) — `2026-06-14-unify-folder-state-ownership-in-sdk-client.md`
- [x] Unify file and folder IPNS CAS-retry into one publishWithCas helper (sdk-core) — `2026-06-14-unify-file-and-folder-ipns-cas-retry-into-one-publishwithcas.md`
- [x] Folder writes leak baseChildren/publishedChildren bookkeeping to call sites — `2026-06-14-folder-writes-leak-basechildren-and-publishedchildren-bookke.md`
- [x] updateSharedFile discards prunedCids from updateFileMetadata causing pin leak (medium) — `2026-06-14-updatesharedfile-discards-prunedcids-from-updatefilemetadata.md`

### Phase 48: SDK self-bootstrap regression fix and shared-folder/metadata consolidation

**Goal:** Restore a green `main` and finish the SDK-as-single-owner work that PR #494 (Phase 47) and PR #498 left open for the share/folder paths. PR #498 (`feat: self-bootstrap folder tree from root IPNS key`) regressed main's web-e2e: `loadFolder` unconditionally overwrites in-memory `folderTree` state with a stale IPNS-resolved snapshot, breaking bin-restore-after-reload and version-restore. Fix that clobber first (P0 — main is red, which blocks the staging E2E gate), then remove the now-redundant web folder-seeding the self-bootstrap was meant to replace, extend the same single-ownership model to shared-folder writes, and close the last Phase-14 share-metadata leak (plaintext `itemName`). Behavior-changing correctness + security work, plus the dead-code cleanup #498 deferred.
**Requirements:** (1) **[P0 regression]** Make self-bootstrap non-clobbering: `loadFolder`/`ensureFolderLoaded` (`packages/sdk/src/client.ts` ~361-470, `requireFolder` chokepoint ~500) must reconcile on IPNS `sequenceNumber` (keep the fresher state, never blindly `folderTree.set()` over a newer in-memory entry) and skip re-resolving folders already loaded, so `deleteToBin`/`restoreFromBin` (~1670-1718) and version-restore publish on top of the freshest local snapshot — both failing web-e2e specs (`bin-restore-after-reload.spec.ts`, `full-workflow.spec.ts:6.6.2 Restore a past version`) green; same sequenceNumber-as-version-clock pattern as PR #489. **Verification gate:** validate REQ-1 PRE-MERGE by dispatching web-e2e against the pushed fix branch — `gh workflow run web-e2e.yml --ref <fix-branch>` (web-e2e.yml is `workflow_dispatch`-enabled and checks out `inputs.ref || github.sha` = branch HEAD) — instead of relying on the post-merge `ci-e2e.yml` main-push run that let #498's regression land. (2) **[#9 — gated on REQ-1 + proven green]** Delete the ~16 web `ensureFolderRegistered` seed call sites (`apps/web/src/lib/sdk-provider.ts:96` + callers in `useFolderMutations`/`useFileOperations`/`useFileVersions`/`useDropUpload`) and the duplicate web-side key-unwrap in `useFolderNavigation.ts:233-240`, relying solely on the SDK chokepoint; verify each former call site works cold (reload → mutate into a never-navigated subfolder). (3) **[#8]** Teach the SDK client to own shared-folder state (a `sharedFolderTree` keyed by share, or extend `folderTree`) with client methods that own publish + sequence bookkeeping + a `folder:updated`-style emission, then route `useSharedWriteOps` (`uploadToSharedFolder`/`createSharedSubfolder`/`renameInSharedFolder`/`updateSharedFile`/`deleteFromSharedFolder`) through them so `useSharedNavigation`'s `folderChildrenRef`/`sequenceNumberRef` become event-fed projections never written from the write hook. (4) **[#5 / Phase-14 M1]** Encrypt share `itemName` at rest — ECIES-wrap with the recipient pubkey mirroring the existing `encryptedKey` flow, migrate the plaintext `shares.itemName` column (`share.entity.ts:45-50`) to ciphertext, store only ciphertext server-side (`shares.service.ts:96`), decrypt client-side for display. Out of scope: the CRDT-IPNS-inbox share-discovery research (`#2`) — it would subsume REQ-4 but is long-horizon and stays deferred.
**Depends on:** Phase 47
**Plans:** 7/7 plans complete

Plans:

**Wave 1**

- [x] 48-01-PLAN.md — REQ-1 P0: sequence-guarded loadFolder reconcile + PRE-MERGE web-e2e dispatch gate (TDD)

**Wave 2** *(blocked on Wave 1)*

- [x] 48-02-PLAN.md — REQ-2: delete 14 ensureFolderRegistered web seeders + useFolderNavigation pre-seed (gated on REQ-1 green)
- [x] 48-03-PLAN.md — REQ-3: sibling sharedFolderTree + sharedFolder:updated event + 5 client shared methods (TDD)
- [x] 48-05-PLAN.md — REQ-4 API: item_name_encrypted migration + entity/DTO/service ciphertext + invite path + [BLOCKING] migration run + api:generate (TDD)

**Wave 3** *(blocked on Wave 2)*

- [x] 48-04-PLAN.md — REQ-3: route useSharedWriteOps through client methods + event-fed useSharedNavigation projection (depends 48-03; Task 4 shared-write UAT deferred to end-of-phase web-e2e)
- [x] 48-06-PLAN.md — REQ-4 web: ShareDialog ECIES wrap + decrypt-for-display + lazy backfill (depends 48-05, TDD; Task 3 itemName-at-rest UAT deferred to end-of-phase web-e2e; lazy-backfill persist blocked on a missing API update endpoint — follow-up)

**Wave 4** *(follow-up consolidation)*

- [x] 48-07-PLAN.md — REQ-3: client.refreshSharedFolder (SDK-owned shared refresh, #489 sequence-guard) + route web 30s poller through it, delete inline IPNS/IPFS/decrypt (depends 48-03, 48-04, TDD) — closes the 48-04 poll-then-write desync note

Scope (captured todos):

- [ ] **[P0]** Self-bootstrap clobbers fresher folderTree state — regresses web-e2e (PR #498 follow-up; surfaced by run 27587113911, new this phase)
- [ ] Remove redundant web folder-seeding now that SDK self-bootstraps folderTree — `2026-06-16-remove-redundant-web-folder-seeding-now-that-sdk-self-bootst.md`
- [ ] Route shared-folder writes through the SDK client (medium) — `2026-06-15-route-shared-folder-writes-through-the-sdk-client.md`
- [ ] Encrypt share itemName at rest (Phase 14 security finding M1) — `2026-06-13-encrypt-share-itemname-at-rest.md`
- Deferred (NOT in this phase): Research CRDT-based IPNS inbox for serverless share discovery — `2026-02-22-crdt-ipns-inbox-sharing.md` (would subsume itemName encryption; long-horizon research)

### Phase 49: Shared-folder move (intra-share) and useFolderNavigation unwrap consolidation

**Goal:** Let a write-permission share recipient move a file between subfolders **within a single shared folder**, re-encrypting the file's `FileMetadata` IPNS record from the source subfolder's `folderKey` to the destination subfolder's `folderKey` (mirroring owner `CipherBoxClient.moveItem` and the #507 decrypt-fail-after-move fix) so the file stays decryptable for owner **and** recipient after the move — and consolidate the duplicated web-side ECIES key-unwrap in `useFolderNavigation` onto the SDK so the unwrap logic lives only in the SDK. Closes captured todos #8 (`2026-06-17-shared-folder-move-must-reencrypt-file-metadata`) and #7 (`2026-06-16-remove-redundant-web-folder-seeding-now-that-sdk-self-bootst`, remaining consolidation half). Builds directly on Phase 48's shipped shared-folder ownership (`sharedFolderTree` keyed by `shareId`, client shared methods, `adoptSharedFolderResult`, `sharedFolder:updated` event, and the key-agnostic `reencryptFileMetadataForFolderChange` helper). **Scope locked:** intra-share moves only (no cross-share, no share↔private-vault); destination picker spans the **entire shared subtree**; recipient-side capability.
**Requirements:** (1) **[#8 — SDK shared-subtree enumeration]** Add an SDK capability to lazily enumerate a shared folder's subtree for the recipient (DFS from the share root, resolving each subfolder's `folderKey` from `share_keys` `keyType: 'folder'` and write-capability from `keyType: 'folder-ipns'`, fetch+decrypt each `FolderMetadata` for children), returning `{id,name,ipnsName,writable}` nodes for a destination picker — `sharedFolderTree` holds only ONE depth at a time today and an anywhere-in-subtree picker needs the whole tree; mark folders the recipient lacks a `folder-ipns` (write) key for as non-writable destinations. (2) **[#8 — SDK move op + client method]** Add `moveInSharedFolder` in `packages/sdk/src/share/shared-write.ts` taking explicit source + destination shared contexts (each: `folderKey`, `ipnsPrivateKey`, `ipnsName`, `sequence`, `children`) + the moved `itemId`, and a `CipherBoxClient.moveInSharedFolder(shareId, args)` that resolves both contexts' keys from `share_keys` (dest may not be the loaded depth), mirrors owner `moveItem` ordering (publish DEST first → re-key `FileMetadata` via `reencryptFileMetadataForFolderChange` `createVersion:false` → publish SOURCE → adopt BOTH folders' `publishedChildren`+`newSequenceNumber` via `adoptSharedFolderResult` → emit `sharedFolder:updated`), and verifies recipient write capability on BOTH subfolders; confirm whether the moved file needs a fresh recipient `share_keys` entry under the dest (file keys are keyed by `itemId` and unchanged by a move, so likely valid — verify + handle). (3) **[#8 — web hook + UI]** Add a move handler to `useSharedWriteOps` (via `runWrite`, mirroring `deleteItemHandler`), a NEW shared `MoveDialog` rendering the lazily-loaded shared-subtree picker (the private `MoveDialog` reads the private `useFolderStore` tree and cannot be reused), and wire `onMove` into `SharedFileBrowser`'s folder-view `ContextMenu` (already has an optional `onMove` prop; keep it OFF the synthetic list-view top-level-shares menu); state refresh flows through the existing `sharedFolder:updated` projection — the write path reads nothing back. (4) **[#7 — useFolderNavigation consolidation]** Replace the hand-rolled ECIES unwrap + IPNS-resolve + decrypt in `useFolderNavigation.navigateTo` (`apps/web/src/hooks/useFolderNavigation.ts` ~242-302) with a single `client.ensureFolderLoaded(folderEntry.ipnsName)` call, mapping the returned `FolderState` into `FolderNode` (`id`/`name`/`parentId` stay local — `FolderState` has none); MUST preserve the existing 3×/2s IPNS-propagation retry tolerance via a thin web-side wrapper, and clone the SDK-owned `folderKey`/`ipnsPrivateKey` buffers into `FolderNode` to avoid use-after-zero on `client.destroy()`; DEFER the `ensureFolderLoaded` full-tree-re-walk negative-cache mitigation (MEDIUM, per the todo's own scoping); decide whether to drop `@internal` from `ensureFolderLoaded` or expose a dedicated public load-for-display method. (5) **[#8 — e2e]** Add a within-share move e2e mirroring `tests/web-e2e/tests/move-restore-content.spec.ts` + the two-account owner/recipient setup from `writable-shares.spec.ts`: Alice shares a parent folder (read-write) containing a file and a subfolder, Bob (recipient) moves the file into the subfolder via the new shared `MoveDialog`, asserting content still DECRYPTS (via the TextEditor decrypt-on-read path, not list visibility) for BOTH Bob and Alice after cross-client sync. (6) **[#8 — shared batch + drag move (parity with private vault)]** Bring the shared-view move UX to parity with the private vault, mirroring the existing analogs: add multi-select selection state to `SharedFileBrowser` (mirror `useFileBrowserActions` `selectedIds: Set<string>` + `SelectionActionBar` wiring); a batch-move path that **LOOPS `CipherBoxClient.moveInSharedFolder` per selected item** in the web handler (mirroring `useFolderMutations.handleMoveItems`, which loops the single-item op — there is NO dedicated SDK batch method on either side; validate name-collision + recipient write-capability per item, clear selection on success); make the NEW shared `MoveDialog` accept an `items` prop for the batch case (mirroring the private `MoveDialog` `item | items` shape, lines 20-21/174-179); and add internal drag-and-drop move onto `SharedFolderRow` destination rows (mirror `FileListItem` `handleDragStart`/`handleDrop` with the `application/json {items,parentId}` payload + multi-select-aware drag, dispatching through a `handleDropOnFolder`-equivalent that routes single→`moveInSharedFolder` and multi→the batch loop). Single-item context-menu move (REQ-3) remains the baseline; this adds batch + drag on top. **Out of scope:** cross-share + share↔private-vault moves; a dedicated batch/transactional SDK move op (web-layer loop matches the private pattern); the `ensureFolderLoaded` negative-cache / re-walk mitigation.
**Depends on:** Phase 48
**Plans:** 5/5 plans complete

Plans:

**Wave 1**

- [x] 49-01-PLAN.md — REQ-1 + REQ-2: SDK enumerateSharedSubtree + moveInSharedFolder op & client method (re-key FileMetadata to dest folderKey) (TDD)
- [x] 49-02-PLAN.md — REQ-4: consolidate useFolderNavigation ECIES unwrap onto client.ensureFolderLoaded (clone buffers, keep 3x/2s retry)

**Wave 2** *(blocked on Wave 1)*

- [x] 49-03-PLAN.md — REQ-3: useSharedWriteOps moveItemHandler + new SharedMoveDialog subtree picker + folder-view onMove wire + Pick allowlist (depends 49-01)

**Wave 3** *(blocked on Wave 2)*

- [x] 49-04-PLAN.md — REQ-6: shared batch + drag move (multi-select, SelectionActionBar, batch loop, MoveDialog items prop, SharedFolderRow drag-drop) (depends 49-03)
- [x] 49-05-PLAN.md — REQ-5: two-account within-share move e2e + decrypt-survival via TextEditor (depends 49-03)

Scope (captured todos):

- [x] **[#8]** Shared-folder move must re-encrypt file metadata to the destination folderKey — `2026-06-17-shared-folder-move-must-reencrypt-file-metadata.md`
- [x] **[#7]** Consolidate the web useFolderNavigation key-unwrap into the SDK — `2026-06-16-remove-redundant-web-folder-seeding-now-that-sdk-self-bootst.md`

### Phase 50: IPFS/IPNS Data-Integrity Fixes

**Goal:** No data loss and no permanently-undeletable CIDs — the Phase 42 unpin-integrity findings are resolved (INT_MIN-hash CID stays deletable; a re-pinned CID is never drained) and deleting a folder unenrolls every descendant IPNS record even when the subtree was never loaded.
**Requirements**: HARD-01
**Depends on:** Phase 49 (v1.1 baseline)
**Plans:** 5/5 plans complete

Scope (captured todos):

- [ ] **[#12]** Phase 42 unpin-integrity code-review findings (WR/IN) unresolved in current code — `2026-06-18-phase42-unpin-integrity-review-open-findings.md`
- [ ] **[#14]** collectSubtreeIpnsNames skips unloaded subtrees, leaving nested IPNS records un-unenrolled — `2026-06-18-unenroll-skips-unloaded-subtrees.md`

Plans:
**Wave 1**

- [x] 50-01-PLAN.md — D-01 (WR-01): drop abs() from guardedUnpin advisory-lock so INT_MIN-hash CIDs stay deletable (TDD, RED regression)
- [x] 50-02-PLAN.md — D-02 (WR-03): refcount-aware pending-unpin drain so re-pinned CIDs are not unpinned (TDD, RED regression)
- [x] 50-03-PLAN.md — D-03 (LOCKED): on-demand subtree IPNS collection so unloaded subtrees fully unenroll (TDD, RED regression)
- [x] 50-05-PLAN.md — D-04 dispositions in controller / UnpinDto+api:generate / backfill / modules (WR-02, IN-02, WR-05, WR-06, IN-04)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 50-04-PLAN.md — D-04 dispositions in vault.service.ts / pending-unpin.processor.ts (IN-01, IN-03, IN-06, WR-04, WR-07, IN-05)

### Phase 51: Crypto-Signature & Secret-Leak Hardening

**Goal:** [To be planned]
**Requirements**: HARD-02
**Depends on:** Phase 49 (v1.1 baseline)
**Plans:** 0 plans

Scope (captured todos):

- [ ] **[#5]** IPNS signature storage review: enforce signedRecord validation, verification, and key zeroization (S1, S2, S3) — `2026-06-13-ipns-signature-storage-review-deferred.md`
- [ ] **[#15]** Web logger redaction interceptor missing and Faro transport never wired — `2026-06-18-web-logger-redaction-and-faro-transport-unwired.md`

Plans:

- [ ] TBD (run /gsd:plan-phase 51 to break down)

### Phase 52: Desktop FUSE Durability & At-Rest Safety

**Goal:** [To be planned]
**Requirements**: HARD-03
**Depends on:** Phase 49 (v1.1 baseline)
**Plans:** 0 plans

Scope (captured todos):

- [ ] **[#9]** FUSE write-journal unbounded growth + ciphertext-in-JSON, and replay has no network timeout — `2026-06-18-fuse-journal-growth-and-replay-timeout.md`

Plans:

- [ ] TBD (run /gsd:plan-phase 52 to break down)

### Phase 53: Release & Supply-Chain Engineering

**Goal:** Harden the CI/release supply chain (HARD-04): SHA-pin all third-party GitHub Actions with a zizmor regression gate and least-privilege permissions, sync Cargo.lock with release-please crate bumps, and make the release-please pin recompute resilient to force-push clobber.
**Requirements**: HARD-04
**Depends on:** Phase 49 (v1.1 baseline)
**Plans:** 4 plans

Scope (captured todos):

- [ ] **[#6]** Pin GitHub Actions to immutable SHAs (CI supply-chain hardening) — `2026-06-14-pin-github-actions-to-immutable-shas.md`
- [ ] **[#13]** release-please bumps crate Cargo.toml versions but not Cargo.lock — `2026-06-18-releaseplease-does-not-bump-cargo-lock.md`
- [ ] **[#16]** Harden release-please release-as pin automation against force-push clobber and stale pins — `2026-06-19-harden-release-please-pin-automation.md`

Plans:
**Wave 1**

- [ ] 53-01-PLAN.md — SHA-pin all third-party action refs via pinact (all 14 workflows) + verify Dependabot github-actions block [wave 1]

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] 53-02-PLAN.md — zizmor CI hard gate (CLI mode) + least-privilege permissions blocks on all unscoped jobs/workflows [wave 2]
- [ ] 53-03-PLAN.md — Cargo.lock sync on release (cargo update --precise + stale-lock guard; cargo-workspace plugin rejected) [wave 2]

**Wave 3** *(blocked on Wave 2 completion)*

- [ ] 53-04-PLAN.md — release-please pin-automation resilience: stale-pin guard script (TDD), remove 3 stale release-as pins, cancel-in-progress safety-net, fetch+rebase discipline docs [wave 3]

### Phase 54: E2E Test-Infra Typing

**Goal:** [To be planned]
**Requirements**: HARD-05
**Depends on:** Phase 49 (v1.1 baseline)
**Plans:** 0 plans

Scope (captured todos):

- [ ] **[#11]** Migrate untyped .mjs E2E helper scripts to TypeScript — `2026-06-18-migrate-mjs-e2e-helper-scripts-to-typescript.md`

Plans:

- [ ] TBD (run /gsd:plan-phase 54 to break down)

### Phase 55: Large Source-File Refactor

**Goal:** [To be planned]
**Requirements**: HARD-06
**Depends on:** Phase 49 (v1.1 baseline)
**Plans:** 0 plans

Scope (captured todos):

- [ ] **[#17]** Large source-file refactor candidates (split/dedup survey of 26 files) — `2026-06-19-large-file-refactor-candidates.md`

Plans:

- [ ] TBD (run /gsd:plan-phase 55 to break down)

---

## Progress

**Execution Order:**
Phases execute in numeric order: 18 -> 19 -> 19.1 -> 19.2 -> 20 -> 21 -> 22 -> 23 -> 24 -> 25 -> 26 -> 27 -> 28 -> 29 -> 30 -> 31 -> 32 -> 33 -> 34 -> 35 -> 36 -> 37 -> 38 -> 39 -> 40 -> 41 -> 42 -> 43 -> 44 -> 45 -> 46 -> 47 -> 48 -> 49 -> 50 -> 51 -> 52 -> 53 -> 54 -> 55

| Phase                                     | Milestone | Plans Complete | Status   | Completed  |
| ----------------------------------------- | --------- | -------------- | -------- | ---------- |
| 18. Performance Instrumentation           | v1.1      | 2/2            | Complete | 2026-03-07 |
| 19. IPNS Resolution Improvement           | v1.1      | 2/2            | Complete | 2026-03-07 |
| 19.1 Extract Core Crypto SDK              | v1.1      | 6/6            | Complete | 2026-03-20 |
| 19.2 IPFS Upload Performance Optimization | v1.1      | 4/4            | Complete | 2026-03-23 |
| 20. Vault Migration                       | v1.1      | 6/6            | Complete | 2026-03-24 |
| 21. BYO-IPFS Node Support                 | v1.1      | 11/11          | Complete | 2026-03-25 |
| 22. Performance Baselines Complete        | v1.1      | 3/3            | Complete | 2026-03-25 |
| 23. Rust SDK Extraction                   | v1.1      | 8/8            | Complete | 2026-03-24 |
| 24. Bug Fixes & Test Infrastructure       | v1.1      | 3/3            | Complete | 2026-03-25 |
| 25. Desktop Enhancements                  | v1.1      | 3/3            | Complete | 2026-03-25 |
| 26. Observability & UX Tuning             | v1.1      | 2/2            | Complete | 2026-03-26 |
| 27. Writable Shares (PoC)                 | v1.1      | 3/3            | Complete | 2026-03-26 |
| 28. Code Hygiene & Logging                | v1.1      | 4/4            | Complete | 2026-03-28 |
| 29. Infrastructure Hardening              | v1.1      | 3/3            | Complete | 2026-03-28 |
| 30. Web App Observability                 | v1.1      | 4/4            | Complete | 2026-03-28 |
| 31. Structural Decomposition              | v1.1      | 3/3            | Complete | 2026-03-28 |
| 32. FUSE Async FilePointer Resolution     | v1.1      | 3/3            | Complete | 2026-03-28 |
| 33. Windows Async FilePointer Resolution  | v1.1      | 2/2            | Complete | 2026-03-28 |
| 34. E2E Test Expansion & Baselines        | v1.1      | 4/4            | Complete | 2026-03-29 |
| 35. Phala Testnet TEE Migration           | v1.1      | 6/6            | Complete | 2026-03-29 |
| 36. Inline Upload Progress                | v1.1      | 2/2            | Complete | 2026-03-29 |
| 37. Parallel Batch Upload Pipeline        | v1.1      | 2/2            | Complete | 2026-03-30 |
| 38. Retire Deprecated Web Services        | v1.1      | 4/4            | Complete | 2026-03-31 |
| 39. User-Configurable Vault Parameters    | v1.1      | 4/4            | Complete | 2026-04-01 |
| 40. Desktop Vault Settings Integration    | v1.1      | 2/2            | Complete | 2026-03-31 |
| 41. Package & App Versioning              | v1.1      | 5/5            | Complete | 2026-04-01 |
| 42. API Unpin Integrity                   | v1.1      | 8/8            | Complete | 2026-06-13 |
| 43. FUSE Write Durability                 | v1.1      | 8/8            | Complete | 2026-06-14 |
| 44. IPNS Conflict Handling                | v1.1      | 7/7            | Complete | 2026-06-14 |
| 45. Desktop FUSE Write-Durability Cleanup | v1.1      | 6/6            | Complete | 2026-06-15 |
| 46. Desktop FUSE Data-Loss + Replay       | v1.1      | 4/4            | Complete | 2026-06-15 |
| 47. SDK Folder-State Consolidation        | v1.1      | 5/5            | Complete | 2026-06-17 |
| 48. SDK Self-Bootstrap + Shared Metadata  | v1.1      | 7/7            | Complete | 2026-06-17 |
| 49. Shared-Folder Move (Intra-Share)      | v1.1      | 5/5            | Complete | 2026-06-18 |
| 50. IPFS/IPNS Data-Integrity Fixes        | v1.1-hardening | 5/5 | Complete    | 2026-06-19 |
| 51. Crypto-Signature & Secret-Leak Hardening | v1.1-hardening | -      | Planned  | -          |
| 52. Desktop FUSE Durability & At-Rest Safety | v1.1-hardening | -      | Planned  | -          |
| 53. Release & Supply-Chain Engineering    | v1.1-hardening | -         | Planned  | -          |
| 54. E2E Test-Infra Typing                 | v1.1-hardening | -         | Planned  | -          |
| 55. Large Source-File Refactor            | v1.1-hardening | -         | Planned  | -          |

_Roadmap created: 2026-03-07_
_Last updated: 2026-06-18 — added phase 49 (shared-folder intra-share move + useFolderNavigation unwrap consolidation; closes todos #8 + #7, builds on phase 48 shared-folder ownership)_
_Last updated: 2026-06-19 — reopened v1.1 with hardening block; added phases 50–55 (HARD-01..06); backfilled progress table for phases 40–55; corrected phases 38/39 status to Complete_
_Total M1.1 phases: 18 (18-35 complete) | Concern resolution: 5 phases | Post-milestone: 5 phases (36-40) | Gap closure: 3 phases (42-44) | Hardening block: 6 phases (50-55)_

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
- [x] **Phase 21: BYO-IPFS Node Support** - User-configurable IPFS pinning endpoint with dual-pin strategy, Settings UI, and connection testing (gap closure in progress) (completed 2026-03-25)
- [x] **Phase 22: Performance Baselines Completion** - Client-side timing instrumentation, end-to-end journey timing, Vitest-based load testing, and capacity documentation (completed 2026-03-25)
- [x] **Phase 23: Rust SDK Extraction** - Extract five Rust crates (crypto, core, api-client, fuse, sdk) mirroring the TypeScript SDK hierarchy, replace duplicated logic in desktop FUSE code, enable unit testing at same granularity as TypeScript (completed 2026-03-24)
- [x] **Phase 24: Bug Fixes & Test Infrastructure** - Fix known bugs (bin IPNS 404, device registry format error) and strengthen test infrastructure (headless load tests, vault recovery E2E, load test auth refresh) (completed 2026-03-25)
- [x] **Phase 25: Desktop Enhancements** - Desktop auto-update mechanism and TEE file enrollment for new files (completed 2026-03-25)
- [x] **Phase 26: Observability & UX Tuning** - Grafana alerting thresholds from existing baselines and timeout tuning for sub-2s UX (completed 2026-03-26)
- [x] **Phase 28: Code Hygiene & Logging** - Structured logger wrapper, replace 124 console.\* calls, fix silenced unpin failures, clean any casts, archive legacy POC (completed 2026-03-28)
- [x] **Phase 29: Infrastructure Hardening** - Wire up IPNS unenrollment on deletion, test login endpoint hardening, IPFS node access control (completed 2026-03-28)
- [x] **Phase 30: Web App Observability** - Error tracking service, error boundaries, client-side telemetry (completed 2026-03-28)
- [x] **Phase 31: Structural Decomposition** - Split monolithic files (useSharedNavigation, FileBrowser, folder.service) into focused modules (completed 2026-03-28)
- [x] **Phase 32: FUSE Async FilePointer Resolution** - Channel-based async resolution to prevent Finder disconnects from blocking FUSE thread (completed 2026-03-28)
- [x] **Phase 33: Windows Async FilePointer Resolution** - Port Phase 32's channel-based async FilePointer resolution to the WinFsp backend (completed 2026-03-28)
- [x] **Phase 34: E2E Test Expansion & Staging Baselines** - Streaming playback, media preview, batch download, and shared teardown E2E tests; BYO-IPFS load test and Faro metrics baselines on staging (completed 2026-03-29)
- [x] **Phase 35: Phala Testnet TEE Migration** - Replace staging TEE simulator with real Phala testnet CVM deployment, validate hardware-backed key derivation and IPNS republishing end-to-end (completed 2026-03-29)

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

## Progress

**Execution Order:**
Phases execute in numeric order: 18 -> 19 -> 19.1 -> 19.2 -> 20 -> 21 -> 22 -> 23 -> 24 -> 25 -> 26 -> 27 -> 28 -> 29 -> 30 -> 31 -> 32 -> 33 -> 34 -> 35

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
| 36. Inline Upload Progress                | post-v1.1 | 2/2            | Complete | 2026-03-29 |
| 37. Parallel Batch Upload Pipeline        | post-v1.1 | 2/2            | Complete | 2026-03-30 |
| 38. Retire Deprecated Web Services        | post-v1.1 | -              | Planned  | -          |
| 39. User-Configurable Vault Parameters    | post-v1.1 | -              | Planned  | -          |

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

---

_Roadmap created: 2026-03-07_
_Last updated: 2026-03-31_
_Total M1.1 phases: 18 (18-35 complete) | Concern resolution: 5 phases | Post-milestone: 5 phases (36-40)_

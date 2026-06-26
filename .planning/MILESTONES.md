# Milestones: CipherBox

## v1.1 IPFS Infrastructure (Shipped: 2026-06-27)

**Phases completed:** 45 phases, 198 plans, 342 tasks

**Known deferred items at close:** see STATE.md § Deferred Items (Phase 39 D-02/D-06 deviations, Phase 59/HARD-11 staging smoke-test, 26 legacy quick-tasks, 5 forward-looking todos, 1 seed).

**Key accomplishments:**

- Prometheus duration histograms for IPFS/IPNS operations (resolve/publish/pin/cat) and TEE republish batches with operation/result/source label dimensions
- Kubo scrape target in Alloy, IPFS/IPNS/TEE duration dashboard panels with p50/p95/p99 PromQL queries, Kubo Health row, and synthetic baseline benchmark script
- Self-hosted Someguy v0.11.1 as Docker Compose sidecar replacing unreliable delegated-ipfs.dev for IPNS delegated routing
- Prometheus latency histograms for IPNS resolve (source-labeled) and publish (outcome-labeled) operations with process.hrtime.bigint() timing
- Split @cipherbox/crypto into pure primitives + new @cipherbox/core domain package with transitional re-exports preserving 47 web app import sites
- @cipherbox/api-client package with orval-generated typed axios functions, configurable instance factory, and zero React/Zustand dependencies
- @cipherbox/sdk-core package with stateless folder/file/upload/download/IPFS/IPNS operations, SdkContext injection, and 28 unit tests -- zero Zustand or browser dependencies
- CipherBoxClient with stateful folder/file/bin/share operations, event system, and 19 passing unit tests
- Removed all transitional re-exports from @cipherbox/crypto, updated 42 import sites across web and SDK, configured Release Please per-package versioning and Codecov coverage for all 5 packages
- Pre-optimization baselines captured from Phase 19 load tests, SDK uploadFile parallelized with Promise.allSettled saving ~1.73s per upload
- Kubo configured with pebbleds LSM-tree datastore in Docker Compose, post-optimization load test baselines captured showing p50 upload latency of 1.5s (vs 1.4s pre-optimization at higher concurrency), with p95 tail latency improved by 22.5%
- PERF-09 requirement registered in REQUIREMENTS.md with definition, traceability entry, and updated coverage count (36 to 37) to close verification gap
- Concurrency probe identified 50-client ceiling, three-point local comparison proved SDK concurrent pins require pebbleds (synergistic, not additive): combined +7% throughput, -13% p95, -15% p99
- Pure-byte vault blob v2 binary format with TDD: serialize/deserialize/detect functions in @cipherbox/core, 19 tests including cross-platform hex vectors for Rust parity
- DB migration for migrated_at column, POST /vault/migrate endpoint, optional IPNS key on init, and nullable crypto columns across entity/DTOs/service/export
- Rust vault blob v2 serialize/deserialize with 10 cross-platform tests, desktop vault fetch supporting migrated users via IPFS v2 blob, root folder v2 publish, and transparent v1/v2 decrypt
- Web login reads rootFolderKey from IPFS v2 blob for migrated users, triggers non-blocking lazy migration for non-migrated users, and recovery tool parses v2 blobs independently via IPFS gateway
- DB migration dropping 3 crypto columns, removal of POST /vault/migrate endpoint, simplified vault entity/DTOs/service to zero-crypto-material schema, regenerated API client
- Removed all migration/DB-fallback code from web, desktop, and recovery tool -- clients now treat IPFS v2 blob as sole source of rootFolderKey
- PinningProvider abstraction with KuboProvider (Kubo RPC), PsaProvider (PSA), and connection test with protocol auto-detection and CORS validation
- POST /ipfs/register-cid endpoint with BYO-user gate, advisory quota mode bypassing enforcement for BYO users, and isByoUser vault flag with migration
- DualPinProvider for primary+secondary orchestration, mode-aware upload flow in CipherBoxClient with pinFn injection, ByoIpfsConfig type for vault metadata
- Settings STORAGE tab with pinning mode radio selector, encrypted IPNS-based BYO config persistence, TEE-wrapped migration trigger, connection test with protocol auto-detection, and advisory quota badge
- TEE-based pin migration infrastructure with BullMQ orchestration, ECIES credential decryption, SSRF-protected provider transfer, and 17 unit tests
- MigrationProgress component with 5s polling, progress bar, pause/resume/cancel controls, and full BYO-IPFS feature end-to-end verification via Playwright
- BYO-IPFS load test scenarios with per-operation latency breakdown, stepped capacity ceiling, and mixed CB+BYO workload reporting -- benchmark execution deferred pending external provider infrastructure
- SDK client initialized with BYO pinning config at login, StorageTab saves trigger runtime reconfiguration, and TEE migration worker unpins source CIDs after verified transfer
- Server-side connection test via TEE worker eliminates browser CORS blocking; credentials ECIES-encrypted before leaving browser, decrypted only in-enclave
- PinataProvider implementing Pinata v3 native API with direct upload, pinByHash, auto-detection in connection test, and SDK client routing
- BYO-IPFS performance baselines captured against Pinata: pin p50=2.0s (10 clients), 98% CipherBox API load reduction per file, tail latency 13.5% better than local Kubo
- Performance API marks/measures added to 10 sdk-core async functions with environment-gated withPerf wrapper and TDD-verified cleanup
- Playwright E2E journey timing spec with 3 timed user journeys (login-to-vault, upload-to-visible, share-to-accessible) and baselines template document
- Automated pass/fail thresholds integrated into all 5 load test scenarios with checkThresholds module, plus comprehensive capacity document consolidating Phase 18/19/19.2 baselines into growth projections and scaling recommendations
- Cargo workspace established at repo root with cipherbox-crypto crate containing all pure cryptographic primitives; desktop app rewired to use workspace dependency with all 174 tests passing
- cipherbox-core crate with folder metadata, file metadata, bin metadata, vault blob v2, IPNS records, device registry, and decrypt bridge; desktop app rewired with all 162 tests passing
- Typed HTTP client crate (cipherbox-api-client) with auth/IPFS/IPNS modules, and 9 shared JSON test vector files powering 5 cross-language parity tests
- Extracted cipherbox-fuse crate with InodeTable, MetadataCache, ContentCache, FUSE operations, and platform mount/unmount -- desktop app rewired as thin bridge
- Extracted stateful SDK crate (SyncDaemon, WriteQueue, KeyState, registry) with generic callbacks, desktop app rewired as thin Tauri shell wrapping Arc<KeyState>
- Desktop app finalized as thin Tauri shell -- removed api/ and crypto/ directories, cleaned all unused imports, zero duplicated logic remains
- Workspace-level cargo CI builds on all platforms, cross-language vector parity gate, and Release Please config for 5 Rust crates
- Windows WinFsp operation code (2,340 LOC) moved from desktop app to cipherbox-fuse crate, closing the last verification gap for complete platform module coverage
- Bin IPNS auto-repair with publishWithVerify + device registry v2 schema migration with lenient v1 read
- Headless sdk-core load tests with 401 interceptor for IPNS contention, upload pipeline, and folder read bottleneck isolation
- Simplified recovery.html to IPFS-direct v2 blob-only mode (removed dead export file path) and added Playwright E2E test that seeds a real vault and verifies end-to-end recovery
- TEE enrollment for per-file IPNS publishes on both Unix and Windows FUSE mounts using ECIES key wrapping on first publish
- Tauri v2 updater plugin with 5s-delayed launch check, manual tray trigger, and GitHub Releases endpoint for Ed25519-signed updates
- 17 Grafana-managed alert rules covering IPNS resolve/publish latency, IPFS pin latency, 5 API endpoint routes, and DB fallback rate with thresholds derived from Phase 18/22 baselines
- Tuned 6 timeout/retry constants across 5 files using 2-3x p99 formula from Phase 18/22 baselines for sub-2s perceived latency
- Share entity extended with permission/encryptedIpnsKey columns, IPNS publish authorization expanded for write-share recipients, API client regenerated with UpdatePermissionDto types
- ShareDialog with permission toggle (read-only/read-write radio group), IPNS key wrapping for write shares, and inline recipient permission upgrade/downgrade controls
- SharedFileBrowser with conditional [RW]/[RO] badges, write toolbar (upload/mkdir), full context menu (rename/delete), IPNS key unwrapping, 30s polling, and per-file IPNS dual-wrapping for shared uploads
- POST /ipns/unenroll endpoint with BatchUnenrollIpnsDto validation, IpnsService.unenrollBatch, and regenerated API client
- Fire-and-forget IPNS unenrollment in CipherBoxClient's 4 delete paths + recursive subtree collection for folder deletes
- Grafana alert for test-login rate monitoring on staging, with verified production guard and Kubo port binding
- Faro SDK with beforeSend privacy gate stripping keys, tokens, emails, and hex-encoded secrets from all telemetry
- React error boundary with terminal-aesthetic fallback UI that reassures users their encrypted data is safe
- Vite source map upload to Grafana Cloud with hidden maps (never served to browser) and staging env vars in all build steps
- Faro user identity wired into auth flow (publicKey only) with logger transport ready for Phase 28 integration
- Windows WinFsp callbacks drain FilePointer completions on entry; handle_read polls 5s for in-flight resolution and returns STATUS_DEVICE_NOT_READY on timeout for Explorer auto-retry
- Shared deleteAccountViaPage helper wired into all 10 web-e2e specs to prevent orphaned test accounts in the database
- AES-CTR streaming playback and media preview dialog E2E suites with 11 tests covering video/audio/PDF preview, CTR encrypted badge, GCM blob fallback, and corrupt file error handling
- 5-test Playwright suite covering multi-file selection, selection action bar counts, batch download event trigger, and batch context menu verification
- Staging performance baselines captured; BYO load test plan upgraded to ACTIVE with Pinata
- Moved TEE worker to apps/tee-worker/, replaced vendored eciesjs/ipns/ed25519 with @cipherbox/crypto and @cipherbox/core, added fetchFn injection to KuboProvider/PsaProvider for SSRF-safe TEE operations
- Vitest test suite for TEE-specific business logic: key derivation, epoch fallback, auth middleware, and batch republish route
- dstack SDK installed with defensive CVM key derivation, Phala CVM docker-compose, Prometheus metrics (HTTP duration + operation counters), and structured JSON logging
- Staging TEE worker migrated from local Docker container to external Phala Cloud CVM with CI/CD deployment pipeline
- Updated STACK.md, ENVIRONMENTS.md, and STRUCTURE.md to document Phala Cloud CVM deployment, shared package integration, and tee-worker relocation to apps/
- Phala Cloud CVM deployed (production infra, free tier — no separate testnet exists), epoch key persistence verified across restarts, IPNS republish cycle validated end-to-end
- Refactored upload Zustand store from batch-level to per-file Map tracking with independent cancel tokens, progress, and error state per file
- Inline UploadListItem component with progress bar, cancel/retry/dismiss buttons, wired into FileList with virtual entry merging and old popup components deleted
- Batch uploadFiles() method with p-limit concurrency pool of 3, single folder IPNS publish per batch, stale-children re-read, and ExternalEncryptFn support for Web Worker offloading
- Web Worker encryption offloading with Transferable zero-copy transfers, wired into SDK batch uploadFiles() via ExternalEncryptFn
- HKDF vault-settings IPNS derivation in cipherbox-crypto and VaultSettings domain type with validation in cipherbox-core, cross-language parity verified via shared test vectors
- Wired vault settings into desktop auth flow with ECIES-encrypted IPNS load and replaced hardcoded FUSE versioning constants with user-configurable values
- Per-package RP config for all 15 monorepo components with 61 color-coded GitHub release labels
- PR-time GitHub Action analyzing conventional commits, mapping files to packages, detecting dependency cascades, and auto-applying release labels with CI enforcement
- Post-merge GitHub Action reads merged PR labels, computes semver target versions with lock group sync and monotonic handling, and injects release-as overrides into release-please-config.json
- Date-based staging tags (staging-YYYYMMDD-release-N) and Docker triple-tagging with component versions for version-agnostic staging deploys
- Batched RP releases with desktop-specific tag workflow and latest-flag management for Tauri updater resolution
- AddPendingUnpins and AddPinnedCidCidIndex applied to live dev Postgres; pending_unpins table + both indexes confirmed present via to_regclass()
- One-shot quota-repair script diffing non-BYO pinned_cids rows against live Kubo pin/ls, with mandatory empty-Kubo abort guard, --dry-run preview mode, and unit-tested D-09 BYO-exclusion predicate
- handle_release now replies EIO on prepare failure and calls record_failure on background upload failure; journal entry removal deferred to replay so no orphan window between upload success and parent pointer publish
- Replay path refactored: 80-line inline publish block replaced by shared publish_file_metadata call (#20) and N-BFS per entry cut to one-BFS-per-distinct-parent via a per-call memoizing cache seeded with root key (#15)
- Additive nullable item_name_encrypted bytea on shares and share_invites with DTO/service plumbing that persists client-supplied ECIES ciphertext on share-create, invite-create and invite-claim while the server stays zero-knowledge, plus a regenerated api-client.
- ECIES-wrap the share/invite display name with the recipient (or ephemeral) pubkey on create so only ciphertext leaves the browser, decrypt itemNameEncrypted into the store's plaintext projection on received-share load (display sites unchanged), and add the lazy-backfill decision logic for legacy plaintext rows — completing REQ-4 / Phase-14 M1 on the web.
- Added `client.refreshSharedFolder(shareId)` — a sequence-guarded IPNS re-resolve that adopts into `sharedFolderTree` and emits `sharedFolder:updated` — then routed the web 30s poller through it and deleted the hook's inline IPNS/IPFS/decrypt path so the projection subscription is the sole ref writer on both write and poll paths.
- SDK crypto core for intra-share file move — dual-context stateless op with DEST-first publish, recipient file-ipns key re-encryption, and DFS shared-subtree enumeration with write-capability flags.
- Collapsed duplicated ECIES unwrap + IPNS-resolve + decrypt in useFolderNavigation onto SDK's ensureFolderLoaded, preserving 3x/2s retry and cloning key buffers into FolderNode
- Single-item intra-share file move UX: moveItemHandler via runWrite->SDK, SharedMoveDialog with enumerateSharedSubtree picker, and onMove wired into SharedFileBrowser folder-view ContextMenu
- Multi-select selection state + batch move loop + SharedMoveDialog items prop + drag-and-drop onto SharedFolderRow — all mirroring private vault analogs without new SDK ops
- Two-account Alice/Bob e2e: Bob moves a file between subfolders of a read-write shared folder via SharedMoveDialog; content decrypts via TextEditorDialogPage.getContent() for both Bob and Alice after IPNS cross-client sync (T-49-14 mitigated)
- Typed metadata-decode errors with CID context, zeroize-on-wrapKey-throw for registration keys, copy-success-gated UI state, and surfaced version-download error for missing vault key (four D-13/D-14 correctness fixes with vitest coverage)
- Shared CID_REGEX constant extracted to cid.constants.ts; RegisterCidDto tightened to reject CIDv0 overflow and oversized strings; LocalProvider Kubo URLs percent-encode CID via URLSearchParams; openapi.json gains maxLength:255 and regenerated api-client is committed.
- Triplicated IPFS_PROVIDER factory and duplicated advisory-lock SQL consolidated into a single leaf IpfsProviderModule and withCidLock/refcountAndMaybeUnpin helpers, routing all three unpin sites through one INT_MIN-safe lock primitive
- CBOR cid/sequence binding added to all 9 FUSE resolve sites and sdk-core resolveIpnsRecord, closing the CID/sequence-swap MITM gap via resolve_ipns_verified chokepoint and cborg decode
- Single shared JSON fixture (7 cases) consumed by both Rust cargo test and sdk-core vitest, closing the Rust-JS byte-construction drift gap per D-11/D-12
- Verified-resolve chokepoint relocated from crates/fuse to cipherbox-api-client with D-04 strict removal of the Legacy variant + skew allowance, and D-07 EOL/expiry enforcement with a 5-minute clock-skew buffer
- TS `resolveIpnsRecord` converted to strict fail-closed: absent-sig throws (D-05), skew disjunct removed (D-05), CBOR Validity EOL enforced with 5-min buffer (D-07).
- verify.rs deleted, all 9 FUSE crate::verify imports re-pointed, 2 SDK bypasses and 6 desktop Tauri resolve sites routed through resolve_ipns_verified — zero raw resolves remain in Rust resolve paths
- API strict first-publish gate (D-03: only embedded sequence 1 accepted) and null-signed-record returns 404 via parseCachedRecord (D-06), with legacy resolve enrich branches removed
- Cross-language IPNS verify vectors aligned to strict regime: legacy-absent and first-publish-skew reclassified to "invalid" in the generator, verify.json regenerated, and Rust classifier updated to strict equality + absent-fields-invalid so the parity gate is green
- Strict fail-closed IPNS verification is live on staging via the deploy → wipe → smoke lockstep; adversarial closeout verification surfaced and fixed a missed first-publish producer (StorageTab BYO config) that the strict gate would otherwise 400.

---

## Completed Milestones

### Milestone 2: Production v1.0 (Shipped: 2026-03-05)

**Delivered:** Production-grade zero-knowledge encrypted storage with user-to-user sharing, link sharing, client-side search, MFA, file versioning, conflict detection, recycle bin, and cross-platform desktop apps (macOS, Windows, Linux).

**Phases completed:** 11-17.1 (20 phases, 83 plans total)
**Duration:** 22 days (2026-02-11 to 2026-03-05)
**Execution Time:** ~10.8 hours

**Key accomplishments:**

- Cross-platform desktop clients with FUSE/WinFsp virtual filesystem mount (macOS, Windows, Linux)
- MPC Core Kit identity provider with MFA enrollment, recovery phrases, and cross-device approval
- AES-256-CTR streaming encryption for in-browser media playback via Service Worker decrypt proxy
- User-to-user file/folder sharing with ECIES key re-wrapping and invite link sharing
- Optimistic concurrency conflict detection on IPNS folder publishes with automatic re-sync
- Recycle bin with 30-day soft-delete retention, restore, and CID unpinning on permanent delete
- Client-side encrypted search index with MiniSearch + IndexedDB persistence
- File version history with retention policy and restore capability
- Per-file IPNS metadata split decoupling content updates from folder publishes
- Cross-platform E2E test matrix (3 platforms, native Postgres + IPFS per runner)

**Stats:**

- 573 files changed, 81,253 insertions, 8,505 deletions
- 423,869 lines of TypeScript + Rust
- 20 phases, 83 plans, 160 commits
- 22 days from M1 ship to M2 ship

**Archived:**

- Roadmap: `.planning/milestones/m2/m2-v1.0-ROADMAP.md`
- Requirements: `.planning/milestones/m2/m2-v1.0-REQUIREMENTS.md`
- Audit: `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`

---

### Milestone 1: Staging MVP (v0.1.0 - v0.6.0)

**Goal:** Deliver a working zero-knowledge encrypted storage demo deployed to staging
**Completed:** 2026-02-11
**Phases:** 1-10 (plus inserted phases 4.1, 4.2, 6.1, 6.2, 6.3, 7.1, 9.1)
**Total Plans:** 72 executed across 15 phase directories
**Total Execution Time:** ~5.6 hours

**What shipped:**

- Web3Auth authentication (email, OAuth, magic link, external wallet)
- Client-side AES-256-GCM encryption + ECIES key wrapping
- IPFS file storage via Kubo with IPNS metadata
- Full file/folder CRUD with 20-level folder hierarchy
- File browser web UI with terminal aesthetic
- Multi-device sync via IPNS polling (30s interval)
- TEE auto-republishing via Phala Cloud (6-hour interval)
- macOS desktop client with Tauri + FUSE mount
- Vault export with standalone recovery tool
- CI/CD pipeline with staging deployment to VPS
- Grafana Cloud log aggregation + Better Stack uptime monitoring
- Comprehensive unit tests (85%+ coverage) and E2E test framework

**Last phase number:** 10 (Phase 11 MFA was scoped but not executed -- absorbed into Milestone 2)

**Archived:**

- Roadmap: `.planning/milestones/m1/m1-mvp-ROADMAP.md`
- Requirements: `.planning/milestones/m1/m1-mvp-REQUIREMENTS.md`
- Audit: `.planning/milestones/m1/m1-mvp-MILESTONE-AUDIT.md`

---

## Active Milestone

### Milestone 3: IPFS Infrastructure v1.1 (in progress)

**Goal:** Make CipherBox IPFS-native -- replace delegated-ipfs.dev, migrate server-side state to IPFS/IPNS, add BYO-IPFS node support, and establish performance baselines
**Depends on:** Milestone 2
**Phases:** 18-22
**Requirements:** 25 (4 IPNS + 6 VAULT + 7 BYO + 8 PERF)

**Phase structure:**

- Phase 18: Performance Instrumentation (PERF-01 to PERF-04)
- Phase 19: IPNS Resolution Improvement (IPNS-01 to IPNS-04)
- Phase 20: Vault Migration (VAULT-01 to VAULT-06)
- Phase 21: BYO-IPFS Node Support (BYO-01 to BYO-07)
- Phase 22: Performance Baselines Completion (PERF-05 to PERF-08)

---

## Future Milestones

### Milestone 4: Encrypted Productivity Suite (planned)

**Goal:** Full encrypted productivity suite -- docs/sheets/slides editors, team accounts, billing (Stripe or crypto), secure document signing, AWS Nitro TEE
**Depends on:** Milestone 3
**Phases:** 23+

---

Created: 2026-02-11
Last updated: 2026-03-07 after v1.1 IPFS Infrastructure roadmap created

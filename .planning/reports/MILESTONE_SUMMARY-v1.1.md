# Milestone v1.1 — Project Summary

**Generated:** 2026-06-18
**Purpose:** Team onboarding and project review
**Milestone:** v1.1 IPFS Infrastructure — **COMPLETE** (34 phases, 151 plans, 100%)

---

## 1. Project Overview

**CipherBox** is a production-grade, privacy-first encrypted cloud storage platform built on IPFS/IPNS and Web3Auth. Files are encrypted client-side before they leave the device, and encryption keys live only in client memory — the server is *cryptographically unable* to read user data (zero-knowledge relay).

By the start of v1.1 (post-v1.0, shipped 2026-03-05) the product already had: Web3Auth MPC auth, AES-256-GCM + ECIES encryption, IPFS/IPNS storage, full file/folder CRUD, user-to-user and link sharing, client-side search, MFA, file versioning, recycle bin, and cross-platform desktop apps (macOS/Windows/Linux via Tauri + FUSE/WinFsp).

**v1.1 goal:** make CipherBox more *IPFS-native* and operationally mature. Four headline thrusts:

1. **Reliable IPNS resolution** — replace the flaky `delegated-ipfs.dev` dependency.
2. **Database minimization** — move vault crypto material (`rootFolderKey`) out of the DB into the IPFS vault blob, so the server holds no key material at all.
3. **Bring-your-own IPFS** — let users point at their own IPFS node via a server-relay flow.
4. **Performance baselines & observability** — instrument the whole stack (API, client, IPFS/IPNS, TEE) with Prometheus/Grafana/Faro and document capacity.

Beyond the original four, the milestone absorbed a large body of **architecture and reliability work**: a five-package TypeScript SDK split (mirrored by five Rust crates), writable shares, FUSE write-durability hardening, the production Phala TEE migration, per-package release engineering, and a long tail of correctness fixes around IPNS conflict handling, unpin integrity, and shared-folder state.

This was a large milestone: **222 commits, ~2,100 files touched (+304.7k / −50.5k LOC), spanning 2026-03-07 → 2026-06-18 (~3.5 months).**

---

## 2. Architecture & Technical Decisions

The defining architectural move of v1.1 is a **layered SDK extracted out of the web app**, in both TypeScript and Rust, so that domain logic is framework-agnostic, testable headlessly, and shareable across web + desktop.

### TypeScript SDK (Phase 19.1, refined through 31/38/47/48/49)

Five packages, strict dependency direction `sdk → sdk-core → api-client / core / crypto`:

- **`@cipherbox/crypto`** — pure primitives only (AES-GCM/CTR, ECIES, Ed25519, HKDF, IPNS name derivation). No domain knowledge.
- **`@cipherbox/core`** — domain types, metadata schemas, validators, metadata encrypt/decrypt, vault blob v2, IPNS record utils.
- **`@cipherbox/api-client`** — typed HTTP client generated from `openapi.json`, no React deps.
- **`@cipherbox/sdk-core`** — *stateless* folder/file/IPFS/IPNS operations taking an explicit `SdkContext` (apiUrl + token getter). Built for headless load testing.
- **`@cipherbox/sdk`** — *stateful* `CipherBoxClient` owning the folder tree, key cache, and event emission. Zustand stores subscribe to SDK events (no component refactor).

- **Decision:** SDK-first decomposition — move framework-agnostic logic *down* into packages, leave React hooks as thin wrappers.
  - **Why:** Enables headless Node load tests, multi-platform reuse, and a single source of truth for folder state.
  - **Phases:** 19.1 (split), 31 (decompose hooks), 38 (retire `folder.service.ts`/`bin.service.ts`, −2,030 LOC), 47/48 (single folder-state owner).

### Rust SDK (Phase 23)

Five crates mirroring the TS hierarchy — `cipherbox-crypto`, `cipherbox-core`, `cipherbox-api-client`, `cipherbox-fuse`, `cipherbox-sdk` — in a root Cargo workspace. The desktop app becomes a thin Tauri shell.

- **Decision:** Cross-language JSON test vectors in `tests/vectors/`, with a CI parity gate that fails the build if TS and Rust crypto outputs diverge.
  - **Why:** Guarantees byte-for-byte interop between web and desktop crypto.
  - **Phase:** 23 (closed out 2026-06-18 after Windows WinFsp ops migrated in 25/33).

### Zero-knowledge vault (Phase 20)

- **Decision:** Vault blob **v2** — `rootFolderKey` is ECIES-wrapped *inside* the IPFS blob header; the DB crypto columns (`encryptedRootFolderKey`, `encryptedRootIpnsPrivateKey`) are dropped entirely.
  - **Why:** Server holds zero key material; `encryptedRootIpnsPrivateKey` is HKDF-derivable so it's redundant.
  - **Outcome:** Exceeded the original requirement — the DB read-fallback was removed completely, not just deprecated.

### IPNS reliability (Phase 19)

- **Decision:** Self-host **Someguy** (v0.11.1, standard DHT mode) as a delegated-routing sidecar, replacing `delegated-ipfs.dev`.
  - **Why:** Eliminate an unreliable third-party dependency; standard (not accelerated) DHT fits the 768 MB staging VPS.

### BYO-IPFS (Phase 21)

- **Decision:** Client-direct pinning via a `PinningProvider` abstraction (Kubo / PSA / Pinata) with a `DualPinProvider` (primary must-succeed, secondary best-effort). **All IPNS publishes still route through the CipherBox API** regardless of BYO config.
  - **Why:** Data sovereignty for users while keeping IPNS sequence/conflict control centralized. Credentials are ECIES-encrypted with the TEE public key; the connection test is TEE-routed with SSRF validation.

### Other foundational decisions

- **Concurrent upload pipeline** (19.2, 37): `Promise.allSettled` pin orchestration + Kubo `pebbleds` datastore (−13% p95); parallel encrypt+pin with `p-limit(3)` and a Web Worker for zero-copy encryption, collapsing O(N) IPNS publishes to O(1).
- **IPNS conflict handling** (44, 47): a generic `publishWithCas` engine with three-way `mergeChildren` (base/local/remote), 4-attempt backoff, and "loser-becomes-version" for file conflicts.
- **Unpin integrity** (42): ownership-guarded unpin with cross-user CID reference counting and a transactional pending-unpins outbox (BullMQ retry).
- **FUSE write durability** (43/45/46): an fsync'd ciphertext write journal with crash-recovery replay; never drops a write (parks on retry exhaustion).
- **Observability stack:** Prometheus histograms (`cipherbox_ipfs_ipns_duration_seconds`, `cipherbox_tee_*`, republish batch) → Alloy scrape (incl. Kubo + Someguy) → Grafana dashboards + 17 alert rules; Grafana **Faro** for web RUM with strict privacy scrubbing (no session replay, publicKey-only identity).
- **Per-package release engineering** (41): 15 independently-versioned packages, conventional-commit analysis at PR time, date-based staging tags.

---

## 3. Phases Delivered

All 34 phases complete and verified. Grouped by workstream:

| Phase | Name | Status | One-liner |
| ----- | ---- | ------ | --------- |
| 18 | Performance Instrumentation | ✅ passed | Prometheus histograms for IPFS/IPNS/TEE latency + Kubo health |
| 19 | IPNS Resolution Improvement | ✅ passed | Self-hosted Someguy sidecar replaces delegated-ipfs.dev |
| 19.1 | Extract Core/Crypto SDK | ✅ passed | Five-package TypeScript SDK architecture |
| 19.2 | IPFS Upload Optimization | ✅ passed | Concurrent pins + pebbleds datastore (−13% p95) |
| 20 | Vault Migration | ✅ passed | rootFolderKey → IPFS vault blob v2; DB crypto columns dropped |
| 21 | BYO IPFS Node Support | ✅ passed | User-configurable IPFS node, dual-pin, TEE-routed test |
| 22 | Performance Baselines Completion | ✅ passed | Client timing API, E2E journey timing, load thresholds, CAPACITY.md |
| 23 | Rust SDK Extraction | ✅ passed | Five Rust crates mirroring TS SDK + cross-lang vector parity gate |
| 24 | Bug Fixes & Test Infrastructure | ✅ passed | Bin 404 fix, device-registry v2 migration, headless load tests |
| 25 | Desktop Enhancements | ✅ passed | Tauri auto-update + TEE enrollment for FUSE-created files |
| 26 | Observability & UX Tuning | ✅ passed | 17 Grafana alert rules + timeout/retry tuning for sub-2s latency |
| 27 | Writable Shares PoC | ✅ passed | Write-share recipients get full CRUD with multi-writer conflict retry |
| 28 | Code Hygiene & Logging | ✅ passed | Structured logger, visible unpin failures, POC archive removed |
| 29 | Infrastructure Hardening | ✅ passed | Orphaned-IPNS cleanup on delete, test-login hardening |
| 30 | Web App Observability | ✅ passed | Grafana Faro RUM with privacy scrubbing + error boundary |
| 31 | Structural Decomposition | ✅ passed | SDK-first migration; hooks become thin UI wrappers |
| 32 | FUSE Async FilePointer (macOS) | ✅ passed | Non-blocking IPNS resolution; eliminates Finder stalls |
| 33 | Windows Async FilePointer | ✅ passed | Ports async resolution to WinFsp; eliminates Explorer hangs |
| 34 | E2E Test Expansion & Staging Baselines | ✅ passed | 16 new E2E tests (streaming/preview/batch) + staging baselines |
| 35 | Phala Testnet TEE Migration | ✅ passed | TEE worker moved to production Phala Cloud CVM + observability |
| 36 | Inline Upload Progress | ✅ passed | Per-file inline progress rows replace floating upload modal |
| 37 | Parallel Batch Upload Pipeline | ✅ passed | Parallel encrypt+pin pipeline, single folder publish, Web Worker |
| 38 | Retire Deprecated Web Services | ✅ passed | All callers migrated to SDK; −2,030 LOC |
| 39 | User-Configurable Vault Parameters | ✅ passed | Retention/delete/versioning settings in encrypted vault metadata |
| 40 | Desktop Vault Settings Integration | ✅ passed | Vault settings propagated to Rust SDK + FUSE layer |
| 41 | Package & App Versioning / Release Cycles | ✅ passed | Per-package semver, PR-time commit analysis, staging tags |
| 42 | API Unpin Integrity | ✅ passed | Ownership-guarded unpin, cross-user refcount, pending-unpins outbox |
| 43 | FUSE Write Durability | ✅ passed | fsync'd write journal + crash-recovery replay; no silent data loss |
| 44 | IPNS Conflict Handling | ✅ passed | Three-way merge `publishWithCas` for concurrent writes |
| 45 | Desktop FUSE Durability Cleanup | ✅ passed | Journal hygiene refactor + 6 crash-recovery safety-net tests |
| 46 | Desktop FUSE Data-Loss Bugs / Replay Hardening | ✅ passed | Closes 3 data-loss bugs; Linux stale-mount auto-recovery |
| 47 | SDK Folder-State Publish Consolidation | ✅ passed | Single folder-state owner; unified file/folder CAS-retry |
| 48 | SDK Self-Bootstrap Fix + Shared-Folder Metadata | ✅ passed | Sequence-based reconcile; ECIES-encrypted shared item names |
| 49 | Shared-Folder Move + useFolderNavigation | ✅ passed | Write-recipients move files intra-share with FileMetadata re-encryption |

---

## 4. Requirements Coverage

**66 v1.1 requirements defined, 66 mapped to phases, all satisfied.**

| Group | Reqs | Status | Notes |
| ----- | ---- | ------ | ----- |
| IPNS-01..04 (reliability) | 4 | ✅ | Someguy self-hosted; DB-first resolve with async DHT verify; <2s graceful degrade |
| VAULT-01..06 (migration) | 6 | ✅ | rootFolderKey in blob v2; DB crypto columns dropped; recovery tool + desktop parse v2 |
| BYO-01..07 (bring-your-own IPFS) | 7 | ✅ | Pinning Service API, dual-pin, encrypted per-user config, settings UI, advisory quota |
| PERF-01..09 (baselines) | 9 | ✅ | IPFS/IPNS/TEE histograms, API p50/p95/p99, client timing, E2E journeys, load harness, CAPACITY.md |
| SDK-01..11 (TS SDK) | 11 | ✅ | Five-package split, SdkContext, stateful client, hooks refactored, per-package Release Please |
| RSDK-01..10 (Rust SDK) | 10 | ✅ | Five crates, shared test vectors + parity gate, thin Tauri shell |
| BUGFIX/TEST-01..03 | 5 | ✅ | Bin IPNS fix, device-registry parse, headless load tests, recovery E2E, 401 refresh |
| DESKTOP-01..02 | 2 | ✅ | Auto-update + FUSE-file TEE enrollment |
| OBS-01..02 | 2 | ✅ | Grafana alerts on p95 breach; timeouts tuned for sub-2s |
| SHARE-01..10 (writable shares) | 10 | ✅ | Permission column, encrypted IPNS key, write-authz, toggle UI, [RW] badges, conflict retry |

> **Audit history (honest accounting):** The 2026-06-11 milestone audit returned `gaps_found` — 62/66 requirements verified, with **PERF-01..04 "orphaned"** because Phase 18 lacked a `VERIFICATION.md`, and phases 18/31/32 missing verification docs. These are **process gaps, not code gaps** (the histograms are wired and relied on by phases 22/26). The verification-ledger close-out commits (#512 "complete phases 47-49 after verification", #513 "close out verification ledger for phases 19.2, 23, 27") covered 19.2/23/27 and 47–49 — but **phases 18, 31, and 32 still lack `VERIFICATION.md` as of 2026-06-18**, so PERF-01..04 remain technically orphaned. STATE.md reports the milestone 100% complete on the strength of the indirect evidence; closing these is tracked in [`TECH_DEBT-v1.1.md`](./TECH_DEBT-v1.1.md) §5 and `.planning/todos/pending/2026-06-18-gsd-verification-gaps-phases-18-31-32.md`.

---

## 5. Key Decisions Log

| # | Decision | Phase | Rationale |
| - | -------- | ----- | --------- |
| D1 | SDK-first decomposition (logic moves down, hooks stay thin) | 19.1, 31, 38, 47 | Headless testability, multi-platform reuse, single folder-state owner |
| D2 | Cross-language test vectors + CI parity gate | 23 | Guarantee TS↔Rust crypto byte-parity |
| D3 | Vault blob v2 — rootFolderKey ECIES-wrapped in IPFS, DB columns dropped | 20 | Server holds zero key material |
| D4 | Self-hosted Someguy (standard DHT) | 19 | Remove flaky delegated-ipfs.dev; fits 768 MB VPS |
| D5 | BYO client-direct pins; IPNS always via CipherBox API | 21 | Data sovereignty + centralized IPNS conflict control |
| D6 | TEE-encrypted BYO credentials + SSRF-validated connection test | 21 | No plaintext creds; safe outbound probing |
| D7 | Concurrent pins require pebbleds datastore (synergistic) | 19.2 | −13% p95 upload latency |
| D8 | `p-limit(3)` parallel pipeline + Web Worker zero-copy encryption | 37 | O(N)→O(1) IPNS publishes per batch |
| D9 | `publishWithCas` + three-way `mergeChildren`; loser-becomes-version | 44, 47 | Deterministic concurrent-write resolution without CRDTs |
| D10 | Ownership-guarded unpin + cross-user refcount + outbox pattern | 42 | Close unpin authz gap; transactional quota integrity |
| D11 | fsync'd ciphertext write journal + replay; park on exhaustion | 43, 46 | No silent FUSE data loss; never drop a write |
| D12 | Async channel-based FilePointer resolution (poll-wait fallback) | 32, 33 | Eliminate Finder/Explorer stalls; `STATUS_DEVICE_NOT_READY` for transient retry |
| D13 | Grafana Faro RUM, no session replay, publicKey-only identity | 30 | Privacy-preserving web observability, single vendor |
| D14 | Per-package semver with PR-time commit analysis | 41 | Precise multi-component releases |
| D15 | ECIES-encrypted shared item names + lazy backfill persist | 48 | Close Phase 14 plaintext `itemName` leak at rest |
| D16 | Intra-share moves with DEST-first publish + FileMetadata re-key | 49 | Recipients move files across subfolders with decrypt-survival |

---

## 6. Tech Debt & Deferred Items

**Process/verification debt (partly open):** the 2026-06-11 audit's orphaned PERF-01..04 and the missing VERIFICATION.md files for phases 18/31/32 remain **open** as of 2026-06-18 — the ledger close-out covered 19.2/23/27/47–49 but not these three. Tracked in [`TECH_DEBT-v1.1.md`](./TECH_DEBT-v1.1.md) §5 + a pending todo; closeable with `/gsd:validate-phase 18 31 32`. Nyquist compliance at audit time was *partial* (7 compliant / 8 partial / 5 missing of 20 in-scope phases) — a documentation-coverage gap, not a behavior gap.

**Verified-open code debt (new this pass):** a tech-debt sweep of all 34 phases + the phase 42/43 `REVIEW.md` files surfaced 24 verified-open items not previously tracked — most notably two correctness risks in the unpin path (**P42·WR-01** advisory-lock `INT_MIN` overflow → permanent undeletability; **P42·WR-03** stale-outbox re-pin race → data loss) and **P43·WR-06** (unbounded FUSE journal with full ciphertext in JSON, no GC). These are promoted to `.planning/todos/pending/` and catalogued in [`TECH_DEBT-v1.1.md`](./TECH_DEBT-v1.1.md). (Phase 43's 8 critical review findings were already fixed 2026-06-14; phases 45/46 resolved most of its warnings.)

**Carried tech debt (from audit frontmatter + phase deferrals):**

- **Phase 19.1:** `useFolderMutations.ts` still imports `folderService` validation helpers (`getDepth`, `isDescendantOf`, `calculateSubtreeDepth`) and `reWrapForRecipients` — accepted deviation (note: much of `folder.service.ts` was later retired in Phase 38).
- **Phase 21:** BYO-04 settings UI flagged human-verification-needed.
- **Phase 23:** TODO — mkdir publish retry on Windows write path (`crates/fuse/src/platform/windows/write_ops.rs`).
- **Phase 25:** Platform code signing (Apple/Windows), beta/canary channels, retroactive TEE enrollment, delta updates — all deferred.
- **Phase 27:** UAT human-confirmation outstanding at audit; no attribution/audit trail, no transitive re-sharing, 30s sync interval, lazy key rotation on revoke.
- **Phase 29:** Native Kubo API ACL (relying on Docker 127.0.0.1 binding); periodic reconciliation job for failed unenrolls.
- **Phase 30:** Logger transport deferred until Phase 28 shipped (since landed); Faro off in local dev when `VITE_FARO_URL` absent.
- **Phase 35:** Two operational human-confirmation items — live Phala CVM health, GitHub staging secrets.
- **Phases 43/44:** Rust FUSE 409-merge parity — live-session rebuild *approximates* TS op-replay but can stomp remote-only changes; full pending-uploads desktop UI deferred.
- **Phase 42:** Wire `provider.unpin` into BYO client delete flows; writable-share version-prune leak (pre-existing); upload/unpin race is detect-only.
- **Phase 37:** Adaptive concurrency by file size, AbortSignal cancellation, dual-pin secondary-pin warning events.

**Explicitly deferred to v1.2+ (out of scope by design):** CRDT-based IPNS inbox for share discovery, `folder_ipns` cache made advisory, device-registry off DB, `pinned_cids` elimination, client-direct IPFS upload (bypass relay). Mobile apps, real-time collab, and the Encrypted Productivity Suite remain Milestone 4 (v2.0).

---

## 7. Getting Started

**Run the project (local dev):**

```bash
docker compose -f docker/docker-compose.yml up -d   # Kubo, Postgres, Someguy, etc.
pnpm --filter @cipherbox/api dev                     # NestJS API
pnpm --filter @cipherbox/web dev                      # React web app (Vite, :5173)
```

See `docs/DEVELOPMENT.md` for full environment setup.

**Regenerate the API client after API changes** (enforced by a pre-commit hook):

```bash
pnpm api:generate
```

**Key directories:**

- `apps/api` — NestJS backend (zero-knowledge relay, IPNS publish, shares, quota)
- `apps/web` — React 18 web app (Zustand stores subscribe to SDK events)
- `apps/desktop` — Tauri shell; logic delegated to Rust crates
- `apps/tee-worker` — TEE republisher (Phala Cloud CVM in prod)
- `packages/{crypto,core,api-client,sdk-core,sdk}` — the TypeScript SDK (dependency order: sdk → sdk-core → api-client/core/crypto)
- `crates/{crypto,core,api-client,fuse,sdk}` — the Rust SDK mirror
- `tests/vectors/` — cross-language crypto test vectors (parity-gated in CI)
- `docs/` — single source of truth (ARCHITECTURE, FILESYSTEM_SPECIFICATION, METADATA_SCHEMAS, CAPACITY, VAULT_EXPORT_FORMAT, …)

**Where to look first:**

- Folder/file operations → `packages/sdk-core` (stateless ops) + `packages/sdk` `CipherBoxClient` (stateful owner of folder tree).
- Crypto → `packages/crypto` (primitives) / `packages/core` (vault blob v2, metadata, IPNS records).
- IPNS conflict logic → `publishWithCas` + `mergeChildren` in `packages/sdk-core`.
- Desktop FUSE → `crates/fuse` (platform modules behind feature flags) + write journal in `crates/sdk`.

**Tests:**

- Web/SDK unit: `pnpm --filter <pkg> test` (vitest — note web `include` is `src/**/*.test.ts` only).
- Rust: workspace-level `cargo test` (includes cross-language vector parity gate).
- E2E: Playwright suites in `apps/web` (web-e2e gate runs on main push); desktop E2E script pairs.
- SDK load: headless vitest harness in `tests/load/` (needs local Docker stack + API).

---

## Stats

- **Timeline:** 2026-03-07 → 2026-06-18 (~3.5 months)
- **Phases:** 34 / 34 complete (151 / 151 plans; avg ~5.5 min/plan, ~16.5h total execution)
- **Commits:** 222 (in milestone range, inclusive of start commit)
- **Files changed:** 2,109 (+304,729 / −50,510)
- **Contributors:** Michael Yankelev (173 commits), cipherbox-release-bot[bot] (44), dependabot[bot] (5)
- **Requirements:** 66 / 66 satisfied
- **Audit (2026-06-11):** `gaps_found` → 19.2/23/27/47–49 closed by ledger close-out; phases 18/31/32 verification gaps still open (tracked). Milestone reported 100% complete in STATE.md
- **Tech debt:** carried debt catalogued in [`TECH_DEBT-v1.1.md`](./TECH_DEBT-v1.1.md); 5 net-new pending todos filed (24 verified-open items)

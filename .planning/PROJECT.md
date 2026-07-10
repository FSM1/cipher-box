# CipherBox

## What This Is

CipherBox is a production-grade, privacy-first encrypted cloud storage platform using IPFS/IPNS and Web3Auth. It provides zero-knowledge file storage with user-to-user sharing (read-only and writable), link sharing, client-side search, multi-factor authentication, file versioning, conflict detection, recycle bin, and cross-platform desktop apps (macOS, Windows, Linux). Storage runs on self-hosted IPFS infrastructure (Kubo + self-hosted Someguy IPNS routing) with optional bring-your-own IPFS node support, and the platform ships a TypeScript and Rust SDK extracted from a unified monorepo. The server is cryptographically unable to access user data.

## Core Value

**Zero-knowledge privacy**: Files are encrypted client-side before leaving the device, and encryption keys exist only in client memory. The server is cryptographically unable to access user data.

## Current Milestone: v2.0 Metadata and Sharing Refactor

**Goal:** Replace the DB-driven `share_keys` sharing model with metadata-driven read key-chaining (`node/v3`), and close the two confirmed revocation gaps — lazy/unsound read-revocation and un-rotatable write delegation.

**Target features:**

- Unified `Node` metadata model (folder/file/root) with two independently sealed bodies (read-body + write-body) and content self-sealing — replaces `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` and enables single-file shares
- AAD-bound AES-GCM seal primitive (`sealAesGcmAad`/`unsealAesGcmAad` + `buildNodeAad`) with a frozen byte encoding and a TS↔Rust cross-language KAT
- Read key-chaining: one ECIES at the share-root, then `O(depth)` symmetric AES down the tree — no `share_keys` fan-out, `O(recipients)` grant rows only
- Resumable read-rotation engine (`rotateReadFromNode`) backing read-revoke and every scope-exit mutation — crash-safe, idempotent, with CRIT-1 content-key rotation, M1 generation downgrade defense, HIGH-3 multi-rooted grant re-mint, HIGH-4 add-during-rotation merge
- Unified scope-exit rule (rotate iff a node leaves a grantee's reachable scope; no covering grant ⇒ pure relink) across delete/move/rename, including bin re-link and invite claim re-wrap
- Write-revocation via (c) full Ed25519 rotation (ADR 0001) with rotated-out IPNS name tombstoning
- Resolve/republish/TEE contract rewrite: DB-canonical resolve with `generation` + seq-floor as anti-rollback authority, TEE as a record-lease-renewer (no CID origination, no sequence increment), atomic publish CAS, hardened enclave bindings
- Schema/DB cutover: delete `share_keys`, slim `shares` to `readDescriptorRef`/`writeDescriptorRef`, rename `folder_ipns` → `ipns_records`, drop `folder_ipns.public_key`

**Source of truth:** `.planning/design/2026-06-26-sharing-read-keychaining-design.md`, [`docs/adr/0001`](../docs/adr/0001-write-revocation-full-ed25519-rotation.md), [`docs/adr/0002`](../docs/adr/0002-read-revocation-protects-future-content-only.md), and the [`CONTEXT.md`](../CONTEXT.md) glossary. Greenfield — no production data, staging wiped — so `node/v3` is the sole codec (no dual-codec bridge, terminology renamed cleanly).

## Current State

**v1.1 IPFS Infrastructure — SHIPPED 2026-06-27** (Milestone 3; 45 phases, 198 plans). All 77 requirements (66 formal v1.1 + 11 HARD) code-satisfied; integration 12/12 WIRED, E2E flows 4/4 INTACT. Delivered self-hosted Someguy IPNS routing (replacing delegated-ipfs.dev), vault blob v2 with DB crypto columns dropped, BYO-IPFS server-relay support, performance baselines + instrumentation, TS+Rust SDK extraction, writable shares, and a cross-layer fail-closed IPNS signature-verify hardening block. See `.planning/milestones/v1.1-MILESTONE-AUDIT.md` for the close-out verdict.

**In progress:** Milestone 4 — v2.0 Metadata and Sharing Refactor. **Phase 62 (Unified Node Codec — the keystone) complete 2026-06-29:** the `Node`/`SealedChildRef`/`PublishedNode` codec (two independently sealed bodies, `generation`-as-AAD) + vault recovery blob v3 (two ECIES keys) shipped in `packages/core`; legacy `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` retired; frozen wire-format golden vectors committed; all downstream packages typecheck (consumers brought to compile-only, behavioral paths stubbed to their owning phases per D-01). Scope locked to Tier 1 (read chain + rotation) + Tier 2 (write-revocation + TEE/resolve contract) of the read key-chaining design; Tier 3 capability layer and the Encrypted Productivity Suite are deferred.

**Phase 73 (Shared Write/Navigation Correctness — Web) complete 2026-07-10 — final v2.0 phase, verification 7/7.** Nested write-shares keep their `writeKey`+`publishedNode` across navigate-up/breadcrumb restore (SC1); nav-stack restore re-resolves via `refreshSharedFolder` instead of serving frozen child snapshots (SC2); the non-listing read facades (`resolveNodeIdentity`/`resolveFileMetadata`/`downloadFromIpns`) are routed through the ROT-07 anti-rollback floor via `gatedResolveChild` (SC3); the WRITE-03 co-writer stale-write path has a real production trigger — 410 tombstone → `CannotWriteUntilRefetchError` → `runWithFailureUx` refresh-access UX (SC4); shared drag-payload kind classified via the resolved listing (SC5); plus nav-hook restore dedup (SC6) and dead `getShareKeys`/folder-IPNS path removal (SC7). Milestone v2.0 is ready for close-out (`/gsd-complete-milestone`).

## Requirements

### Validated (Milestone 1 — Staging MVP)

- Web3Auth authentication (email, OAuth, magic link, external wallet) — v0.1
- Client-side AES-256-GCM encryption + ECIES key wrapping — v0.1
- IPFS file storage via Kubo with IPNS metadata — v0.1
- Full file/folder CRUD with 20-level hierarchy — v0.1
- File browser web UI with terminal aesthetic — v0.1
- Multi-device sync via IPNS polling (30s) — v0.1
- TEE auto-republishing via Phala Cloud — v0.1
- macOS desktop client with Tauri + FUSE mount — v0.1
- Vault export with standalone recovery tool — v0.1
- CI/CD pipeline with staging deployment — v0.1

### Validated (Milestone 2 — Production v1.0)

- User-to-user file/folder sharing with ECIES key re-wrapping (read-only, instant via public key) — v1.0
- Link sharing with URL-fragment decryption keys (authenticated invite model) — v1.0
- Client-side encrypted search index (MiniSearch + IndexedDB) — v1.0
- MFA via Core Kit MPC (device shares, recovery phrase, cross-device approval) — v1.0
- File version history with restore and retention policy — v1.0
- Optimistic concurrency conflict detection on IPNS publishes — v1.0
- Recycle bin with 30-day soft-delete retention and CID unpinning — v1.0
- Windows desktop app with WinFsp virtual filesystem — v1.0
- Linux desktop app with FUSE mount (AppImage + deb) — v1.0
- AES-256-CTR streaming encryption for in-browser media playback — v1.0
- Per-file IPNS metadata split (content updates decoupled from folder publishes) — v1.0
- Cross-platform E2E test matrix (macOS, Windows, Linux) — v1.0

### Validated (Milestone 3 — v1.1 IPFS Infrastructure)

Full requirement IDs archived in `.planning/milestones/v1.1-REQUIREMENTS.md` (77/77 satisfied). Grouped:

- ✓ Self-hosted Someguy IPNS routing + DB-first resolve (replaced delegated-ipfs.dev, sub-2s timeout + DB fallback) — v1.1
- ✓ Vault blob v2 (rootFolderKey ECIES-wrapped in blob, DB crypto columns dropped, HKDF-derivable IPNS key) — v1.1
- ✓ BYO-IPFS node support (Pinning-Service-API relay, dual-pin, advisory quota, settings UI) — v1.1
- ✓ Performance baselines + instrumentation (IPFS/IPNS histograms, API p50/p95/p99, client throughput, E2E journeys, load harness) — v1.1
- ✓ TypeScript SDK extraction (core / crypto / api-client / sdk-core / sdk) with per-package release automation — v1.1
- ✓ Rust SDK workspace (crypto / core / api-client / fuse / sdk) + thin Tauri shell — v1.1
- ✓ Writable shares (write-permission column, IPNS-key wrapping, multi-writer conflict retry, terminal-style UI) — v1.1
- ✓ FUSE write durability + IPNS conflict handling (fsynced journal, replay-on-mount, three-way folder merge, file-record CAS) — v1.1
- ✓ Cross-layer IPNS signature-verify hardening (HARD-01..11 — fail-closed verified-resolver chokepoint across web/sdk-core/API/Rust) — v1.1

### Active

v2.0 Metadata and Sharing Refactor — full requirement list with REQ-IDs in `.planning/REQUIREMENTS.md` (NODE / CRYPTO / READ / ROT / WRITE / TEE / DATA categories). Scope: Tier 1 + Tier 2 of the read key-chaining design.

Carried from v1.1 (deferred, not yet retired):

- [ ] Phase 39 D-02 — add a confirmation dialog before permanent/hard delete (data-safety UX gap; captured todo). Note: the bin re-link rework under `node/v3` (DATA-/ROT-) touches this surface.
- [ ] Phase 39 D-06 — remove or document the residual server-side `RECYCLE_BIN_RETENTION_DAYS` endpoint/env var (dead backend surface)
- [ ] HARD-11 — complete the Phase 60 staging operational smoke-test (D-12 lockstep checkpoint), or accept as an infra-limited override

### Out of Scope (Milestone 4 — v2.0)

- Tier 3 capability layer (read-side TTL, op-count caps, `capabilityId`) — read-side TTL/op-caps are cryptographically unenforceable; do not add `ttl`/`opCap`/`capabilityId` to `Node` or `SealedChildRef`
- Data migration / dual-codec bridge — greenfield (no prod data, staging wiped); `node/v3` is the sole codec
- Mediated write signing — approach (a)/(d) `POST /ipns/sign` endpoint — runner-up only; (c) full Ed25519 rotation is ratified (ADR 0001)
- Retroactive content protection — read-revoke protects future content/navigation only; already-distributed CIDs and prior versions stay readable (ADR 0002)
- Lazy rotation *walk* (rotate-on-next-write across a subtree) — eager walk is the committed model; the `rotateOne` primitive stays amortizable later
- SEED-001 Phala TEE on-demand cost cycling — separable infra-cost optimization; deferred to a future infra milestone (stays dormant in `.planning/seeds/`)
- Encrypted Productivity Suite (billing, teams, doc editors, signing) — deferred to a later milestone (was tentatively v2.0; v2.0 is now the sharing refactor)

### Out of Scope (Milestone 3 — v1.1)

- Encrypted Productivity Suite (billing, teams, doc editors, signing) — deferred to a post-v2.0 milestone
- Mobile apps (iOS/Android) — deferred to Milestone 4+
- Real-time collaborative editing — deferred to Milestone 4+
- Offline write queue / selective sync — deferred to Milestone 4+
- Full-text content search — encrypted index leaks access patterns
- CRDT-based IPNS inbox — research only this milestone, implement in future if viable
- eIDAS/QES compliance — requires certified CA
- SSO/LDAP — enterprise scope

## Context

**Current State (v1.0 shipped 2026-03-05):**

- 423,869 lines of TypeScript + Rust across 698 source files
- NestJS API, React 18 web app, Tauri desktop (macOS/Windows/Linux)
- 155 plans executed across 35 phase directories (M1 + M2)
- Staging deployed at api-staging.cipherbox.cc / app-staging.cipherbox.cc
- 8 Playwright E2E test suites + 4 desktop E2E script pairs

**Technical Environment:**

- IPFS via Kubo for file storage and pinning
- IPNS for mutable metadata pointers (per-folder + per-file)
- Web3Auth Core Kit MPC for deterministic ECDSA key derivation
- Phala Cloud for TEE auto-republishing (3-hour interval)

**Key Architecture (evolved through M1 + M2):**

- Client-side encryption only — server is zero-knowledge relay
- Per-folder + per-file IPNS keypairs (HKDF-derived)
- ECIES key re-wrapping for zero-knowledge sharing
- Optimistic concurrency on IPNS publishes (sequence number checks)
- Deterministic vault IPNS derivation (self-sovereign recovery)
- FUSE-T SMB backend on macOS (NFS had kernel bugs)

## Constraints

- **File size**: 100 MB max — browser memory limits
- **Storage quota**: 500 MiB free tier — IPFS storage management
- **Files per folder**: 1,000 max — UI performance
- **Folder depth**: 20 levels max — traversal performance
- **Sync latency**: ~30 seconds — IPNS polling interval
- **Tech stack**: NestJS backend, React 18 frontend, Tauri desktop — per specifications
- **Auth provider**: Web3Auth Core Kit MPC — deterministic key derivation requirement
- **IPFS provider**: Kubo (self-hosted), BYO-IPFS support (Kubo, PSA, Pinata)

## Key Decisions

| Decision                                    | Rationale                                                  | Outcome |
| ------------------------------------------- | ---------------------------------------------------------- | ------- |
| Full-stack vertical build order             | Test features end-to-end as they're built                  | Good    |
| Web + cross-platform desktop for v1.0       | Complete user experience across all platforms              | Good    |
| TEE republishing required for v1.0          | Zero-downtime vault access guarantee                       | Good    |
| Core Kit MPC replaces PnP Modal             | Self-hosted identity provider, MFA foundation              | Good    |
| Per-file IPNS metadata split                | Decouple content updates from folder publishes             | Good    |
| AES-256-CTR for streaming media             | Byte-range decryption enables in-browser playback          | Good    |
| Optimistic concurrency via sequence numbers | Lightweight conflict detection without distributed locks   | Good    |
| FUSE-T SMB backend (not NFS)                | macOS NFS kernel bug blocked WRITE RPCs for new files      | Good    |
| Encrypted recycle bin on IPFS               | Client-side retention enforcement, CID unpinning on delete | Good    |
| SIWE wallet login with hashed identifiers   | Privacy-preserving auth, unified identity across methods   | Good    |
| Decimal phase numbering for insertions      | Clear insertion semantics without renumbering              | Good    |
| Self-hosted Someguy over delegated-ipfs.dev | Own the IPNS routing path; sub-2s resolve with DB fallback | ✓       |
| Vault blob v2 — zero DB crypto              | rootFolderKey in IPFS blob, all DB crypto columns dropped  | ✓       |
| Monorepo SDK extraction (TS + Rust)         | Reusable core shared across web, desktop, recovery tooling | ✓       |
| Strict fail-closed IPNS verified-resolver   | Single signature-verify chokepoint across all layers       | ✓       |
| Metadata-driven read key-chaining (node/v3) | One ECIES at share-root + O(depth) AES; kills share_keys fan-out | — Pending |
| Two sealed bodies per node (read + write)   | Structural read/write separation; read grant never conveys signing key | — Pending |
| Write-revocation = (c) full Ed25519 rotation | No new TEE/relay trust; key-possession auth (ADR 0001)    | — Pending |
| Read-revoke protects future content only    | IPFS is content-addressed; honest threat model (ADR 0002)  | — Pending |
| TEE = record-lease-renewer (no CID, no seq++) | Closes republisher stale-CID rollback structurally        | — Pending |
| Greenfield node/v3 sole codec               | No prod data, staging wiped; no dual-codec/migration bridge | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):

1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):

1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---

Last updated: 2026-07-10 (Phase 73 complete — shared write/navigation correctness, web; final v2.0 phase)

# CipherBox

## What This Is

CipherBox is a production-grade, privacy-first encrypted cloud storage platform using IPFS/IPNS and Web3Auth. It provides zero-knowledge file storage with user-to-user sharing, link sharing, client-side search, multi-factor authentication, file versioning, conflict detection, recycle bin, and cross-platform desktop apps (macOS, Windows, Linux). The server is cryptographically unable to access user data.

## Core Value

**Zero-knowledge privacy**: Files are encrypted client-side before leaving the device, and encryption keys exist only in client memory. The server is cryptographically unable to access user data.

## Current Milestone: v1.1 IPFS Infrastructure

**Goal:** Make CipherBox more IPFS-native — replace delegated-ipfs.dev, migrate selected vault state to IPFS/IPNS, add BYO-IPFS server-relay support, and establish performance baselines.

**Target features:**

- Reliable IPNS resolution (replace delegated-ipfs.dev with self-hosted or alternative provider)
- Reduce database dependence where feasible — migrate vault crypto material to IPFS while retaining `folder_ipns`, shares, device approvals, quota tracking, and the DB fallback for `encryptedRootFolderKey` in v1.1
- Bring-your-own IPFS node support via server-relay flow (client-direct deferred to v1.2)
- Comprehensive performance baselines (API, client, IPFS/IPNS latency, end-to-end user journeys)

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

### Active (Milestone 3 — IPFS Infrastructure v1.1)

See `.planning/REQUIREMENTS.md` for full requirements.

#### IPNS Reliability

- [ ] Replace delegated-ipfs.dev with reliable IPNS resolution
- [ ] Sub-2s resolution latency, >99.5% availability

#### Database Minimization

- [x] Move rootFolderKey to IPFS vault blob v2 format (DB crypto columns dropped entirely) — Validated in Phase 20: Vault Migration
- [x] Deprecate encryptedRootIpnsPrivateKey (HKDF-derivable, DB column dropped) — Validated in Phase 20: Vault Migration

#### BYO-IPFS

- [ ] User-configurable IPFS node endpoint
- [ ] Server-relay upload to user's node (client-direct deferred to v1.2)
- [ ] Quota and conflict detection strategy for BYO mode

#### Performance Baselines

- [ ] API endpoint response time baselines
- [ ] IPFS/IPNS publish and resolve latency baselines
- [ ] Client-side encryption throughput baselines
- [ ] End-to-end user journey timing baselines

### Out of Scope (Milestone 3 — v1.1)

- Encrypted Productivity Suite (billing, teams, doc editors, signing) — deferred to Milestone 4 (v2.0)
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

---

Last updated: 2026-03-26 after Phase 25 Desktop Enhancements completed

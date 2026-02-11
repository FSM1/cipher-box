# CipherBox

## What This Is

CipherBox is an ambitious demonstration of privacy-first encrypted cloud storage using IPFS/IPNS and Web3Auth. It provides zero-knowledge file storage where the server never has access to plaintext files or encryption keys. The platform targets developers and privacy-conscious users who want encrypted storage with sharing, search, and multi-factor authentication.

## Core Value

**Zero-knowledge privacy**: Files are encrypted client-side before leaving the device, and encryption keys exist only in client memory. The server is cryptographically unable to access user data.

## Current Milestone: v1.0 Production-Grade Storage

**Goal:** Elevate the staging MVP into a production-ready encrypted storage platform with sharing, search, MFA, file versioning, and cross-platform desktop support.

**Target features:**

- File/folder sharing with encrypted key exchange (user-to-user)
- Client-side encrypted search index
- Multi-factor authentication (passkey, TOTP, recovery phrase)
- File version history with restore
- Advanced sync (conflict resolution, offline queue, selective sync)
- Cross-platform desktop apps (Linux and Windows, extending macOS from M1)
- AWS Nitro TEE as fallback republishing provider

## Requirements

### Validated (Milestone 1 — Staging MVP)

- Web3Auth authentication (email, OAuth, magic link, external wallet) — M1
- Client-side AES-256-GCM encryption + ECIES key wrapping — M1
- IPFS file storage via Pinata with IPNS metadata — M1
- Full file/folder CRUD with 20-level hierarchy — M1
- File browser web UI with terminal aesthetic — M1
- Multi-device sync via IPNS polling (30s) — M1
- TEE auto-republishing via Phala Cloud — M1
- macOS desktop client with Tauri + FUSE mount — M1
- Vault export with standalone recovery tool — M1
- CI/CD pipeline with staging deployment — M1

### Active (Milestone 2 — Production v1.0)

#### File Sharing

- [ ] User can share files/folders with other CipherBox users
- [ ] User can generate shareable link for file
- [ ] User can set password on shared link
- [ ] User can set expiration on shared link
- [ ] Recipient can download shared file without CipherBox account

#### Search

- [ ] User can search file names across vault
- [ ] Search index is encrypted client-side

#### Multi-Factor Authentication

- [ ] User can enable MFA in settings
- [ ] User can enroll passkey/WebAuthn as second factor
- [ ] User can enroll TOTP authenticator as second factor
- [ ] User can generate recovery phrase for account recovery

#### File Versioning

- [ ] System keeps previous versions of files
- [ ] User can view version history
- [ ] User can restore previous version

#### Advanced Sync

- [ ] Conflict detection with user resolution UI
- [ ] Offline write queue with retry on reconnect
- [ ] Selective sync (choose folders to sync locally)

#### TEE Enhancements

- [ ] AWS Nitro as fallback TEE provider

### Out of Scope (Milestone 2)

- Billing/payments — deferred to Milestone 3
- Docs/sheets/slides editors — deferred to Milestone 3
- Team accounts / org structure — deferred to Milestone 3
- Secure document signing — deferred to Milestone 3
- Mobile apps (iOS/Android) — deferred to Milestone 3+
- Linux/Windows desktop — moved to Milestone 2 (Phase 11)
- Collaborative editing — deferred to Milestone 3+
- AES-256-CTR streaming encryption — complexity, future enhancement

## Context

**Existing Codebase:**

- Complete specifications in `00-Preliminary-R&D/Documentation/` (PRD, API spec, technical architecture, data flows, client spec, implementation roadmap)
- Working PoC console harness in `00-Preliminary-R&D/poc/` that validates IPFS/IPNS and encryption flows
- Codebase mapping in `.planning/codebase/`

**Technical Environment:**

- IPFS via Pinata for file storage and pinning
- IPNS for mutable metadata pointers
- Web3Auth for deterministic ECDSA key derivation
- Phala Cloud (primary) / AWS Nitro (fallback) for TEE republishing

**Key Architecture Decisions (from specs):**

- Client-side encryption only — server is zero-knowledge relay
- Per-folder IPNS keypairs — enables future modular sharing
- Backend relays signed IPNS records — never holds signing keys
- TEE receives ECIES-encrypted IPNS keys — decrypts in hardware only

## Constraints

- **File size**: 100 MB max — browser memory limits
- **Storage quota**: 500 MiB free tier — Pinata cost management
- **Files per folder**: 1,000 max — UI performance
- **Folder depth**: 20 levels max — traversal performance
- **Sync latency**: ~30 seconds — IPNS polling interval
- **Tech stack**: NestJS backend, React 18 frontend, Tauri desktop — per specifications
- **Auth provider**: Web3Auth only — deterministic key derivation requirement
- **IPFS provider**: Pinata — managed pinning service

## Key Decisions

| Decision                           | Rationale                                 | Outcome   |
| ---------------------------------- | ----------------------------------------- | --------- |
| Full-stack vertical build order    | Test features end-to-end as they're built | — Pending |
| Web + macOS desktop for v1.0       | Complete user experience across platforms | — Pending |
| TEE republishing required for v1.0 | Zero-downtime vault access guarantee      | — Pending |
| Implement specs as documented      | Specs are finalized and comprehensive     | — Pending |

---

Last updated: 2026-02-11 after Milestone 2 initialization

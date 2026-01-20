# CipherBox

## What This Is

CipherBox is a technology demonstrator for privacy-first encrypted cloud storage using IPFS/IPNS and Web3Auth. It provides zero-knowledge file storage where the server never has access to plaintext files or encryption keys. The target audience is developers and technical users interested in cryptography and decentralized systems.

## Core Value

**Zero-knowledge privacy**: Files are encrypted client-side before leaving the device, and encryption keys exist only in client memory. The server is cryptographically unable to access user data.

## Requirements

### Validated

- PoC IPFS/IPNS integration works end-to-end — validated via console harness
- AES-256-GCM encryption for files — validated via PoC
- ECIES key wrapping for folder/file keys — validated via PoC
- Per-folder IPNS keypairs for modular metadata — validated via PoC
- File operations (upload, download, rename, move, delete) — validated via PoC
- Folder hierarchy traversal — validated via PoC

### Active

**Authentication (Web3Auth)**
- [ ] Email/password authentication via Web3Auth
- [ ] OAuth authentication (Google/Apple/GitHub) via Web3Auth
- [ ] Magic link (passwordless) authentication via Web3Auth
- [ ] External wallet (MetaMask/WalletConnect) via Web3Auth
- [ ] Account linking (multiple auth methods → same vault)
- [ ] Backend token management (access + refresh tokens)

**Backend API (NestJS)**
- [ ] Auth endpoints (nonce, login, refresh, logout)
- [ ] Vault management endpoints (initialize, get)
- [ ] IPFS relay endpoints (add, unpin)
- [ ] IPNS relay endpoints (publish signed records)
- [ ] TEE key management endpoints
- [ ] Storage quota enforcement (500 MiB free tier)

**Web UI (React)**
- [ ] Web3Auth modal integration for login
- [ ] File browser with folder tree and file list
- [ ] Drag-drop file upload
- [ ] Context menus (rename, delete, move)
- [ ] Settings page (linked accounts, vault export)
- [ ] Storage usage indicator
- [ ] Responsive design

**Desktop App (macOS)**
- [ ] Tauri app with Web3Auth login
- [ ] FUSE mount at ~/CipherVault
- [ ] Transparent read/write through encrypted layer
- [ ] Background sync daemon (30s polling)
- [ ] System tray integration

**Multi-Device Sync**
- [ ] IPNS polling for metadata updates (~30s latency)
- [ ] Conflict detection (last-write-wins for v1)
- [ ] Offline queueing with retry on reconnect

**TEE IPNS Republishing**
- [ ] Phala Cloud TEE contract for IPNS signing
- [ ] Encrypted IPNS private key storage (ECIES with TEE public key)
- [ ] 3-hour republish interval
- [ ] Key epoch rotation with 4-week grace period
- [ ] AWS Nitro fallback

**Data Portability**
- [ ] Vault export (JSON with encrypted keys + metadata)
- [ ] Independent recovery without CipherBox backend

### Out of Scope

- Billing/payments — tech demo focus, defer to v1.1
- AES-256-CTR streaming encryption — complexity, defer to v1.1
- File versioning — complexity, defer to v2.0
- File/folder sharing — requires key sharing infrastructure, defer to v2.0
- Mobile apps — platform expansion, defer to v2.0
- Search/indexing — client-side search complexity, defer to v2.0
- Collaborative editing — real-time sync complexity, defer to v3.0
- Team accounts — permission management, defer to v3.0
- Linux/Windows desktop — macOS first, others v1.1

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

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Full-stack vertical build order | Test features end-to-end as they're built | — Pending |
| Web + macOS desktop for v1.0 | Complete user experience across platforms | — Pending |
| TEE republishing required for v1.0 | Zero-downtime vault access guarantee | — Pending |
| Implement specs as documented | Specs are finalized and comprehensive | — Pending |

---
*Last updated: 2026-01-20 after initialization*

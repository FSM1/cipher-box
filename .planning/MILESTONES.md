# Milestones: CipherBox

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

- Roadmap: `.planning/milestones/v1.0-ROADMAP.md`
- Requirements: `.planning/milestones/v1.0-REQUIREMENTS.md`
- Audit: `.planning/milestones/v1.0-production-MILESTONE-AUDIT.md`

**What's next:** Milestone 3 — Encrypted Productivity Suite (billing, team accounts, document editors, document signing, AWS Nitro TEE)

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

**Last phase number:** 10 (Phase 11 MFA was scoped but not executed — absorbed into Milestone 2)

**Archived roadmap:** `.planning/archive/m1-ROADMAP.md`

---

## Future Milestones

### Milestone 3: Encrypted Productivity Suite (planned)

**Goal:** Full encrypted productivity suite — docs/sheets/slides editors, team accounts, billing (Stripe or crypto), secure document signing, AWS Nitro TEE
**Depends on:** Milestone 2
**Phases:** 18-22

---

Created: 2026-02-11
Last updated: 2026-03-05 after v1.0 Production milestone

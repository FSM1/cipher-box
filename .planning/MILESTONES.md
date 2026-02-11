# Milestones: CipherBox

## Completed Milestones

### Milestone 1: Staging MVP (v0.1.0 - v0.6.0)

**Goal:** Deliver a working zero-knowledge encrypted storage demo deployed to staging
**Completed:** 2026-02-11
**Phases:** 1-10 (plus inserted phases 4.1, 4.2, 6.1, 6.2, 6.3, 7.1, 9.1)
**Total Plans:** 72 executed across 15 phase directories
**Total Execution Time:** ~5.6 hours

**What shipped:**

- Web3Auth authentication (email, OAuth, magic link, external wallet)
- Client-side AES-256-GCM encryption + ECIES key wrapping
- IPFS file storage via Pinata with IPNS metadata
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

## Active Milestone

### Milestone 2: Production v1.0 (v0.7.0+)

**Goal:** Production-grade encrypted storage with sharing, search, MFA, and file versioning
**Started:** 2026-02-11
**Phases:** Starting from Phase 12

See ROADMAP.md for current phase structure.

---

## Future Milestones

### Milestone 3: Productivity Platform (planned)

**Goal:** Full encrypted productivity suite — docs/sheets/slides editors, team accounts, billing (Stripe or crypto), secure document signing
**Depends on:** Milestone 2

---

Created: 2026-02-11

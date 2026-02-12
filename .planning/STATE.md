# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-02-11)

**Core value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext
**Current focus:** Milestone 2 -- Phase 12: Core Kit Identity Provider Foundation

## Current Position

Phase: 12 (first of 11 M2 phases: 11-17 + decimal insertions)
Plan: Not yet planned (outdated PnP-based plans deleted, needs replanning)
Status: Context finalized, ready for research and planning
Last activity: 2026-02-12 -- Phase 12 architectural discussion and scope refinement

Progress: [##########..........] 50% (M1 complete, M2 0/11 phases)

## Performance Metrics

**Velocity:**

- Total plans completed: 72
- Average duration: 4.7 min
- Total execution time: 5.6 hours

**By Phase (M1 summary):**

| Phase          | Plans | Total   | Avg/Plan |
| -------------- | ----- | ------- | -------- |
| M1 (17 phases) | 72/72 | 5.6 hrs | 4.7 min  |

**Recent Trend:**

- Last 5 plans: 3m, 2m, 3m, 90m, 4m
- Trend: Stable (Phase 10 plans executing quickly)

Updated after each plan completion.

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

| Decision                                                  | Phase    | Rationale                                              |
| --------------------------------------------------------- | -------- | ------------------------------------------------------ |
| Replace PnP Modal SDK with MPC Core Kit                   | Phase 12 | Full MFA control, custom UX, programmatic factor mgmt  |
| CipherBox as identity provider (sub=userId)               | Phase 12 | Enables multi-auth linking, less data to Web3Auth      |
| Identity trilemma: chose (wallet-only + unified) w/ SPOF  | Phase 12 | No mandatory email; SPOF mitigated by key export+IPFS  |
| Phase 12 split into 12, 12.2, 12.3, 12.4                  | Phase 12 | Foundation→device registry→SIWE→MFA dependency chain   |
| ECIES re-wrapping for sharing (not proxy re-encryption)   | Research | Same wrapKey() function, server sees only ciphertexts  |
| Versioning = stop unpinning old CIDs + metadata extension | Research | Nearly free on IPFS, no new crypto needed              |
| Read-only sharing only (no multi-writer IPNS)             | Research | Unsolved problem, deferred to v3                       |
| minisearch + idb for client-side search                   | Research | ~8KB total, TypeScript-native, zero server interaction |

### Pending Todos

3 pending todo(s):

- `2026-01-23-simple-text-file-editor-modal.md` -- Add simple text file editor modal (area: ui)
- `2026-02-07-web-worker-large-file-encryption.md` -- Offload large file encryption to Web Worker (area: ui)
- `2026-02-10-remove-debug-eprintln-statements.md` -- Remove debug eprintln! statements from FUSE code (area: desktop)

### Roadmap Evolution

- Phase 12.1 inserted after Phase 12: AES-256-CTR streaming encryption for media files (INSERTED) — previously deferred as "future enhancement," promoted to M2 for early delivery after MFA stabilizes key derivation
- Phase 12 rescoped from "MFA config" to "Core Kit Identity Provider Foundation" — PnP Modal SDK rejected for insufficient control
- Phase 12.2 inserted: Encrypted Device Registry on IPFS — infrastructure for cross-device approval
- Phase 12.3 inserted: SIWE + Unified Identity — wallet login unification, multi-auth linking
- Phase 12.4 inserted: MFA + Cross-Device Approval — the actual MFA enrollment and device approval features

### Blockers/Concerns

- Web3Auth custom JWT verifier: requires Growth Plan for production (free on devnet). Verify pricing before committing.
- CipherBox as identity SPOF: backend is trust anchor for auth. Mitigated by encrypted key export + IPFS device registry. One-way door — verifierId scheme is permanent.
- Versioning + Sharing interaction: When shared folder has version history, should recipient see all versions? Decide during Phase 14 planning.

### Quick Tasks Completed

| #   | Description                   | Date       | Commit  | Directory                                                                       |
| --- | ----------------------------- | ---------- | ------- | ------------------------------------------------------------------------------- |
| 009 | Fix footer GitHub link        | 2026-02-11 | c13036d | [009-fix-footer-github-link](./quick/009-fix-footer-github-link/)               |
| 010 | Matrix effect visibility      | 2026-02-11 | 74d27b5 | [010-matrix-effect-visibility](./quick/010-matrix-effect-visibility/)           |
| 011 | Login footer status indicator | 2026-02-11 | 9745251 | [011-login-footer-status-indicator](./quick/011-login-footer-status-indicator/) |

### Research Flags

- Phase 11 (Desktop): NEEDS `/gsd:research-phase` -- Linux FUSE (libfuse), Windows virtual drive (WinFsp/Dokany), Tauri cross-compilation
- Phase 14 (Sharing): NEEDS `/gsd:research-phase` -- revocation key rotation protocol
- Phase 15 (Link Sharing): NEEDS `/gsd:research-phase` -- unauthenticated web viewer security
- Phase 16 (Advanced Sync): NEEDS `/gsd:research-phase` -- three-way merge edge cases
- Phase 12 (Core Kit Foundation): NEEDS `/gsd:research-phase` -- Core Kit initialization, custom JWT verifier, PnP→Core Kit key migration, email passwordless
- Phase 12.1 (AES-CTR Streaming): NEEDS `/gsd:research-phase` -- MediaSource/Service Worker decryption, byte-range IPFS, CTR nonce management
- Phase 12.2 (Device Registry): NEEDS `/gsd:research-phase` -- device registry schema, encryption with user key, IPFS pinning strategy
- Phase 12.3 (SIWE + Identity): NEEDS `/gsd:research-phase` -- SIWE message format, wallet address hashing, multi-auth linking, ADR-001 migration
- Phase 12.4 (MFA + Cross-Device): NEEDS `/gsd:research-phase` -- enableMFA() flow, bulletin board API, ECIES ephemeral key exchange
- Phase 17 (Nitro TEE): NEEDS `/gsd:research-phase` -- Rust enclave, highest risk item

## Session Continuity

Last session: 2026-02-12
Stopped at: Phase 12 architectural discussion complete, context and roadmap updated
Resume file: None
Next: `/gsd:plan-phase 12` (Core Kit Identity Provider Foundation)

---

_State initialized: 2026-01-20_
_Last updated: 2026-02-12 after Phase 12 scope refinement_

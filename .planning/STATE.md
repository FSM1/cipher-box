# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-02-11)

**Core value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext
**Current focus:** Milestone 2 -- Phase 12.2 complete (Encrypted Device Registry)

## Current Position

Phase: 12.2 (Encrypted Device Registry)
Plan: 3 of 3 complete
Status: Phase complete
Last activity: 2026-02-13 -- Completed 12.2-PLAN-03 (auth flow integration, Zustand store, polling)

Progress: [############........] 58% (M1 complete, M2 Phase 12 complete, Phase 12.2 complete)

## Performance Metrics

**Velocity:**

- Total plans completed: 81
- Average duration: 4.6 min
- Total execution time: 6.47 hours

**By Phase (M1 summary):**

| Phase          | Plans | Total   | Avg/Plan |
| -------------- | ----- | ------- | -------- |
| M1 (17 phases) | 72/72 | 5.6 hrs | 4.7 min  |
| M2 Phase 12    | 5/5   | 45 min  | 9.0 min  |
| M2 Phase 12.2  | 3/3   | 10 min  | 3.3 min  |

**Recent Trend:**

- Last 5 plans: 6m, 7m, 3m, 4m, 3m
- Trend: Stable

Updated after each plan completion.

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

| Decision                                                  | Phase    | Rationale                                                                                                       |
| --------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| Replace PnP Modal SDK with MPC Core Kit                   | Phase 12 | Full MFA control, custom UX, programmatic factor mgmt                                                           |
| CipherBox as identity provider (sub=userId)               | Phase 12 | Enables multi-auth linking, less data to Web3Auth                                                               |
| Identity trilemma: chose (wallet-only + unified) w/ SPOF  | Phase 12 | No mandatory email; SPOF mitigated by key export+IPFS                                                           |
| Phase 12 split into 12, 12.2, 12.3, 12.4                  | Phase 12 | Foundation->device registry->SIWE->MFA dependency chain                                                         |
| Core Kit WEB3AUTH_NETWORK uses DEVNET/MAINNET keys        | 12-02    | Different from PnP SDK's SAPPHIRE_DEVNET/SAPPHIRE_MAINNET                                                       |
| CipherBox JWT for backend auth (not coreKit.signatures)   | 12-04    | Core Kit signatures are session tokens, not verifiable JWTs. Pass CipherBox-issued JWT with loginType 'corekit' |
| importTssKey via localStorage one-time read-and-delete    | 12-05    | PnP migration key consumed once then removed                                                                    |
| E2E uses CipherBox login UI directly (no modal iframe)    | 12-05    | Simpler, more reliable than Web3Auth modal automation                                                           |
| jose library for identity JWTs (not @nestjs/jwt)          | 12-01    | Separate signing keys (RS256) and audience from internal                                                        |
| Cross-auth-method email linking                           | 12-01    | Same email across Google/email auth -> same user account                                                        |
| ECIES re-wrapping for sharing (not proxy re-encryption)   | Research | Same wrapKey() function, server sees only ciphertexts                                                           |
| Versioning = stop unpinning old CIDs + metadata extension | Research | Nearly free on IPFS, no new crypto needed                                                                       |
| Read-only sharing only (no multi-writer IPNS)             | Research | Unsolved problem, deferred to v3                                                                                |
| minisearch + idb for client-side search                   | Research | ~8KB total, TypeScript-native, zero server interaction                                                          |

### Pending Todos

2 pending todo(s):

- `2026-02-07-web-worker-large-file-encryption.md` -- Offload large file encryption to Web Worker (area: ui)
- `2026-02-10-fix-flaky-post-reload-e2e-tests.md` -- Fix flaky post-reload e2e tests (3.8, 3.10) (area: testing)

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

| #   | Description                               | Date       | Commit  | Directory                                                                                                   |
| --- | ----------------------------------------- | ---------- | ------- | ----------------------------------------------------------------------------------------------------------- |
| 009 | Fix footer GitHub link                    | 2026-02-11 | c13036d | [009-fix-footer-github-link](./quick/009-fix-footer-github-link/)                                           |
| 010 | Matrix effect visibility                  | 2026-02-11 | 74d27b5 | [010-matrix-effect-visibility](./quick/010-matrix-effect-visibility/)                                       |
| 011 | Login footer status indicator             | 2026-02-11 | 9745251 | [011-login-footer-status-indicator](./quick/011-login-footer-status-indicator/)                             |
| 012 | Fix double-outline focus style            | 2026-02-11 | 78ca2fe | [012-input-focus-outline-style](./quick/012-input-focus-outline-style/)                                     |
| 013 | Move multi-select bar bottom              | 2026-02-13 | 956c527 | [013-move-multi-select-bar-bottom](./quick/013-move-multi-select-bar-bottom/)                               |
| 014 | Fix multiselect button visibility         | 2026-02-13 | 33a56c8 | [014-fix-multiselect-button-visibility](./quick/014-fix-multiselect-button-visibility/)                     |
| 015 | SendGrid email OTP + Google OAuth staging | 2026-02-13 | 2589aa0 | [015-sendgrid-email-otp-and-google-oauth-staging](./quick/015-sendgrid-email-otp-and-google-oauth-staging/) |

### Research Flags

- Phase 11 (Desktop): NEEDS `/gsd:research-phase` -- Linux FUSE (libfuse), Windows virtual drive (WinFsp/Dokany), Tauri cross-compilation
- Phase 14 (Sharing): NEEDS `/gsd:research-phase` -- revocation key rotation protocol
- Phase 15 (Link Sharing): NEEDS `/gsd:research-phase` -- unauthenticated web viewer security
- Phase 16 (Advanced Sync): NEEDS `/gsd:research-phase` -- three-way merge edge cases
- Phase 12 (Core Kit Foundation): NEEDS `/gsd:research-phase` -- Core Kit initialization, custom JWT verifier, PnP->Core Kit key migration, email passwordless
- Phase 12.1 (AES-CTR Streaming): NEEDS `/gsd:research-phase` -- MediaSource/Service Worker decryption, byte-range IPFS, CTR nonce management
- Phase 12.2 (Device Registry): NEEDS `/gsd:research-phase` -- device registry schema, encryption with user key, IPFS pinning strategy
- Phase 12.3 (SIWE + Identity): NEEDS `/gsd:research-phase` -- SIWE message format, wallet address hashing, multi-auth linking, ADR-001 migration
- Phase 12.4 (MFA + Cross-Device): NEEDS `/gsd:research-phase` -- enableMFA() flow, bulletin board API, ECIES ephemeral key exchange
- Phase 17 (Nitro TEE): NEEDS `/gsd:research-phase` -- Rust enclave, highest risk item

## Session Continuity

Last session: 2026-02-13
Stopped at: Completed 12.2-PLAN-03 (auth flow integration, Zustand store, polling)
Resume file: None
Next: Phase 12.3 (SIWE + Unified Identity) — needs /gsd:research-phase first

---

_State initialized: 2026-01-20_
_Last updated: 2026-02-13 after completing 12.2-PLAN-03 (Phase 12.2 complete)_

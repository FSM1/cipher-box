# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-02-11)

**Core value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext
**Current focus:** Milestone 2 -- Phase 12.1 in progress (AES-CTR Streaming Encryption)

## Current Position

Phase: 12.1 (AES-CTR Streaming Encryption) -- In progress
Plan: 3 of TBD planned
Status: In progress
Last activity: 2026-02-17 -- Completed 12.1-03-PLAN.md (Service Worker Decrypt Proxy)

Progress: [####################] (M1 complete, M2 Phase 12 complete, Phase 12.2 complete, Phase 12.3 complete, Phase 12.3.1 complete, Phase 12.4 complete, Phase 12.5 complete, Phase 12.6 complete, Phase 12.1 plans 01-03 complete)

## Performance Metrics

**Velocity:**

- Total plans completed: 105
- Average duration: 5.3 min
- Total execution time: 9.46 hours

**By Phase (M1 summary):**

| Phase           | Plans | Total   | Avg/Plan |
| --------------- | ----- | ------- | -------- |
| M1 (17 phases)  | 72/72 | 5.6 hrs | 4.7 min  |
| M2 Phase 12     | 5/5   | 45 min  | 9.0 min  |
| M2 Phase 12.2   | 3/3   | 10 min  | 3.3 min  |
| M2 Phase 12.3   | 4/4   | 39 min  | 9.8 min  |
| M2 Phase 12.3.1 | 4/4   | 38 min  | 9.5 min  |
| M2 Phase 12.4   | 5/5   | 47 min  | 9.4 min  |
| M2 Phase 12.5   | 3/3   | 9 min   | 3.0 min  |
| M2 Phase 12.6   | 5/5   | 29 min  | 5.8 min  |
| M2 Phase 12.1   | 3/?   | 21 min  | 7.0 min  |

**Recent Trend:**

- Last 5 plans: 3m, 10m, 4m, 5m, 12m
- Trend: Stable

Updated after each plan completion.

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

| Decision                                                         | Phase     | Rationale                                                                                                        |
| ---------------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------- |
| Replace PnP Modal SDK with MPC Core Kit                          | Phase 12  | Full MFA control, custom UX, programmatic factor mgmt                                                            |
| CipherBox as identity provider (sub=userId)                      | Phase 12  | Enables multi-auth linking, less data to Web3Auth                                                                |
| Identity trilemma: chose (wallet-only + unified) w/ SPOF         | Phase 12  | No mandatory email; SPOF mitigated by key export+IPFS                                                            |
| Phase 12 split into 12, 12.2, 12.3, 12.4                         | Phase 12  | Foundation->device registry->SIWE->MFA dependency chain                                                          |
| Core Kit WEB3AUTH_NETWORK uses DEVNET/MAINNET keys               | 12-02     | Different from PnP SDK's SAPPHIRE_DEVNET/SAPPHIRE_MAINNET                                                        |
| CipherBox JWT for backend auth (not coreKit.signatures)          | 12-04     | Core Kit signatures are session tokens, not verifiable JWTs. Pass CipherBox-issued JWT with loginType 'corekit'  |
| importTssKey via localStorage one-time read-and-delete           | 12-05     | PnP migration key consumed once then removed                                                                     |
| E2E uses CipherBox login UI directly (no modal iframe)           | 12-05     | Simpler, more reliable than Web3Auth modal automation                                                            |
| jose library for identity JWTs (not @nestjs/jwt)                 | 12-01     | Separate signing keys (RS256) and audience from internal                                                         |
| Cross-auth-method email linking                                  | 12-01     | Same email across Google/email auth -> same user account                                                         |
| ECIES re-wrapping for sharing (not proxy re-encryption)          | Research  | Same wrapKey() function, server sees only ciphertexts                                                            |
| Versioning = stop unpinning old CIDs + metadata extension        | Research  | Nearly free on IPFS, no new crypto needed                                                                        |
| Read-only sharing only (no multi-writer IPNS)                    | Research  | Unsolved problem, deferred to v3                                                                                 |
| minisearch + idb for client-side search                          | Research  | ~8KB total, TypeScript-native, zero server interaction                                                           |
| Wallet addr: SHA-256 hash + truncated display (no encrypt)       | 12.3-01   | Simpler than hash+encrypted; full plaintext never stored                                                         |
| Auth types: email_passwordless->email, external_wallet->wallet   | 12.3-01   | Clean method-based naming for simplified auth type system                                                        |
| derivationVersion removed (ADR-001 clean break)                  | 12.3-01   | DB will be wiped, no migration needed, clean Core Kit-only schema                                                |
| Web3AuthVerifierService decoupled from auth.service              | 12.3-02   | No longer injected; all login/link flows use CipherBox JWT verification                                          |
| LinkMethodDto uses auth method types directly                    | 12.3-02   | google/email/wallet instead of routing through social/external_wallet loginType                                  |
| Vault export derivationInfo simplified to derivationMethod       | 12.3-02   | Always 'web3auth' for Core Kit users; no derivationVersion needed                                                |
| connectAsync for wallet SIWE flow (not useEffect-based)          | 12.3-03   | Simpler async flow; avoids address-watching complexity                                                           |
| Disconnect wagmi after SIWE verification                         | 12.3-03   | No persistent wallet connection needed; Core Kit handles ongoing auth                                            |
| vaultKeypair naming for auth store keypair                       | 12.3-03   | Clear purpose naming; replaces misleading ADR-001 derivedKeypair                                                 |
| Reuse login components in link mode (settings)                   | 12.3-04   | GoogleLoginButton/EmailLoginForm reused via callback props; no separate link components                          |
| Multiple wallets allowed per account                             | 12.3-04   | Wallet always shows as available to link; CONTEXT.md requirement                                                 |
| Cross-account collision via TypeORM Not()                        | 12.3-04   | Check same identifier with different userId before allowing link                                                 |
| Vault IPNS: same salt, different HKDF info for domain separation | 12.3.1-01 | HKDF info is primary domain separator; "cipherbox-vault-ipns-v1" vs registry's info                              |
| rootIpnsPublicKey removed from EncryptedVaultKeys                | 12.3.1-01 | Derivable from private key; reduces stored data, eliminates inconsistency                                        |
| Google login hashes sub (not email) for identifierHash           | 12.3.1-02 | Sub is immutable Google user ID; email can change. Privacy-preserving lookup.                                    |
| Cross-method email auto-linking removed                          | 12.3.1-02 | Each auth method is independent; users link explicitly via Settings, not auto-linked by email match              |
| identifier column stores hash for all auth types                 | 12.3.1-02 | identifier=identifierHash for consistency; identifierDisplay holds human-readable value                          |
| rootIpnsPublicKey removed from vault entity/DTO/API/frontend     | 12.3.1-03 | Derivable from privateKey via HKDF; reduces schema, eliminates inconsistency                                     |
| Plan 04 work completed by Plan 03 broader scope                  | 12.3.1-04 | Desktop Rust, E2E helpers, controller spec changes committed in Plan 03 execution                                |
| Auto-expire on read (no cron for 5min TTL)                       | 12.4-01   | Pending requests past TTL marked expired on getStatus; simpler than background cleanup                           |
| Hard delete on cancel (not status change)                        | 12.4-01   | Cancelled requests have no audit value; 5min TTL keeps table small                                               |
| loginWithCoreKit returns typed union (not void)                  | 12.4-02   | 'logged_in' or 'required_share' enables callers to branch without catching errors                                |
| Placeholder publicKey for REQUIRED_SHARE temp auth               | 12.4-02   | 'pending-core-kit-{userId}' allows bulletin board API access before TSS key available                            |
| Pending auth state in React useState (not Zustand)               | 12.4-02   | Component-scoped, cleared on unmount or logout; no need for global persistence                                   |
| FactorInfo extended with additionalMetadata for device matching  | 12.4-03   | Core Kit shareDescriptions parsed to expose deviceId for factor-to-device matching                               |
| ARIA tablist/tabpanel for Settings tab navigation                | 12.4-03   | Proper accessibility roles for tab switching between Linked Methods and Security                                 |
| Inline confirm pattern for destructive MFA actions               | 12.4-03   | Revoke/regenerate use inline confirm/cancel, not modal dialog, matching terminal aesthetic                       |
| secp256k1.keygen() for ephemeral keypair generation              | 12.4-04   | Noble secp256k1 v3 API uses keygen() returning { secretKey, publicKey } instead of v2's utils.randomPrivateKey() |
| MFA prompt dismissal persisted in localStorage by user email     | 12.4-04   | Key is cipherbox*mfa_prompt_dismissed*{email} for cross-session persistence, fallback to 'default'               |
| DeviceApprovalModal mounted in AppShell after AppFooter          | 12.4-04   | Fixed overlay visible on all authenticated pages regardless of current route                                     |
| LoginFooter extracted to avoid duplication in Login.tsx          | 12.4-04   | Three render paths (normal, waiting, recovery) share the same footer component                                   |
| Generated client wrapper pattern for device-approval service     | 12.4-05   | deviceApprovalApi wraps Orval-generated functions for backward-compatible import surface                         |
| tssPubKey defensive check as permanent enableMfa() guard         | 12.4-05   | Logs CRITICAL if keypair changes after MFA enrollment; does not throw (enrollment already succeeded)             |
| VaultExport below tabs, not as a third tab                       | 12.5-01   | VaultExport is a utility action always visible, not a settings category                                          |
| Merge Settings.tsx into SettingsPage (not re-route)              | 12.5-01   | SettingsPage is canonical routed component with AppShell; merging preserves existing routing and layout          |
| Hardhat account #0 for wallet E2E test key                       | 12.5-02   | Well-known deterministic key; reproducible tests without real wallet funds                                       |
| Wallet E2E tests validate UI flow independently of Core Kit      | 12.5-02   | TC09 accepts both redirect-to-files and error as valid; tests frontend wallet interaction                        |
| UAT quality gate: 16 PASS / 19 SKIP / 1 NOTE (all documented)    | 12.5-03   | Destructive and multi-device tests skipped with reasons; all 4 issues resolved; gate passed for Phase 12.1       |
| File metadata encrypted with parent folderKey (not file's key)   | 12.6-01   | Consistent with folder metadata access control pattern; parent key controls child access                         |
| encryptionMode optional with GCM default in validator            | 12.6-01   | Phase 12.1 AES-CTR files set 'CTR' explicitly; omission defaults to 'GCM' for backward compat                    |
| fileId minimum 10 chars validation                               | 12.6-01   | Ensures UUID-length identifiers; prevents accidental short strings in HKDF info                                  |
| Partial success for batch publish (per-record results)           | 12.6-02   | Failed records logged and counted, not re-thrown; batch returns totalSucceeded/totalFailed                       |
| Concurrency=10 for batch delegated routing calls                 | 12.6-02   | Promise.allSettled in groups of 10 to avoid overwhelming delegated-ipfs.dev                                      |
| Orphaned TEE enrollment on file delete left to expire            | 12.6-03   | No unenrollIpns REST API yet; 24h IPNS lifetime, Phase 14 adds explicit cleanup                                  |
| deleteFolder returns fileMetaIpnsName list (not CIDs) for v2     | 12.6-03   | v2 FilePointers have no inline CID; caller resolves IPNS to get CID for unpinning                                |
| replaceFileInFolder publishes only file IPNS (folder untouched)  | 12.6-03   | Primary optimization of per-file IPNS: content update skips folder metadata entirely                             |
| DetailsDialog parentFolderId prop removed                        | 12.6-04   | IPNS resolution uses item's own IPNS name directly; parent folder lookup no longer needed                        |
| Inline base36 + protobuf for IPNS name in recovery.html          | 12.6-05   | No libp2p CDN dependency needed; self-contained BigInt-based implementation                                      |
| IPNS failures non-blocking in recovery tool                      | 12.6-05   | Warn and continue; collect failures, report at end with IPNS names for manual recovery                           |
| Post-build script for SW compilation (not Vite plugin)           | 12.1-03   | Vite 7 Environment API breaks Rollup output hooks in standard plugins; build-sw.mjs via Vite lib-mode is simpler |
| Separate tsconfig.sw.json for WebWorker lib types                | 12.1-03   | SW runs in ServiceWorkerGlobalScope, needs WebWorker lib; excluded from main tsconfig to avoid type conflicts    |
| Dev mode serves SW as raw TS, production as compiled IIFE        | 12.1-03   | Vite dev server transforms TS on-the-fly; production uses minified 2.8KB IIFE at /decrypt-sw.js                  |

### Pending Todos

7 pending todo(s):

- `2026-02-07-web-worker-large-file-encryption.md` -- Offload large file encryption to Web Worker (area: ui)
- `2026-02-14-bring-your-own-ipfs-node.md` -- Add bring-your-own IPFS node support (area: api)
- `2026-02-14-file-metadata-evolution-v2.md` -- Split file metadata into per-file IPNS objects (area: crypto)
- `2026-02-14-erc-1271-contract-wallet-authentication.md` -- Add ERC-1271 contract wallet authentication support (area: auth)
- `2026-02-14-fix-orval-generated-client-any-warnings.md` -- Fix no-explicit-any warnings in generated API client (area: tooling)
- `2026-02-15-security-review-short-term-fixes.md` -- Security review short-term fixes: H-01, H-06, H-07, M-01, M-04, M-06 (area: auth)
- `2026-02-15-security-review-medium-term-fixes.md` -- Security review medium-term fixes: H-08, M-07, M-11 (area: auth)

### Roadmap Evolution

- Phase 12.1 inserted after Phase 12: AES-256-CTR streaming encryption for media files (INSERTED) — previously deferred as "future enhancement," promoted to M2 for early delivery after MFA stabilizes key derivation
- Phase 12 rescoped from "MFA config" to "Core Kit Identity Provider Foundation" — PnP Modal SDK rejected for insufficient control
- Phase 12.2 inserted: Encrypted Device Registry on IPFS — infrastructure for cross-device approval
- Phase 12.3 inserted: SIWE + Unified Identity — wallet login unification, multi-auth linking
- Phase 12.4 inserted: MFA + Cross-Device Approval — the actual MFA enrollment and device approval features
- Phase 12.3.1 inserted after Phase 12.3: Pre-Wipe Identity Cleanup — deterministic IPNS derivation, SHA-256 hashed identifiers for all auth methods, remove cross-method email auto-linking. Done before DB wipe to avoid migration code.
- Phase 12.5 inserted after Phase 12.4: MFA Polishing, UAT & E2E Testing — polish auth flows, add wallet E2E with mock EIP-1193/6963 provider, fix bugs from CoreKit auth UAT
- Phase 12.6 inserted after Phase 12.5: Per-File IPNS Metadata Split — split file metadata into per-file IPNS records before vault wipe (clean break, no dual-schema). Phase 12.1 (AES-CTR) moved to after 12.6.

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
| 016 | Refine wallet and MFA UI elements         | 2026-02-16 | d004eb0 | [016-refine-wallet-and-mfa-ui-elements](./quick/016-refine-wallet-and-mfa-ui-elements/)                     |

### Research Flags

- Phase 11 (Desktop): NEEDS `/gsd:research-phase` -- Linux FUSE (libfuse), Windows virtual drive (WinFsp/Dokany), Tauri cross-compilation
- Phase 14 (Sharing): NEEDS `/gsd:research-phase` -- revocation key rotation protocol
- Phase 15 (Link Sharing): NEEDS `/gsd:research-phase` -- unauthenticated web viewer security
- Phase 16 (Advanced Sync): NEEDS `/gsd:research-phase` -- three-way merge edge cases
- Phase 12 (Core Kit Foundation): NEEDS `/gsd:research-phase` -- Core Kit initialization, custom JWT verifier, PnP->Core Kit key migration, email passwordless
- Phase 12.1 (AES-CTR Streaming): IN PROGRESS -- Plans 01-03 complete (crypto primitives, streaming upload pipeline, service worker decrypt proxy), research done
- Phase 12.2 (Device Registry): COMPLETE -- research and execution done
- Phase 12.3 (SIWE + Identity): COMPLETE -- all 4 plans done (backend SIWE, wallet endpoints, ADR-001 cleanup, frontend wallet login, linked methods UI)
- Phase 12.4 (MFA + Cross-Device): COMPLETE -- all 5 plans done (bulletin board API, MFA hooks, enrollment wizard, cross-device approval, integration verification)
- Phase 12.5 (MFA Polishing, UAT & E2E): COMPLETE -- all 3 plans done (SecurityTab wiring, wallet E2E tests, UAT final verification)
- Phase 12.6 (Per-File IPNS Metadata): COMPLETE -- all 5 plans done (crypto primitives, batch publish backend, frontend service layer, hooks & components, recovery tool + docs)
- Phase 17 (Nitro TEE): NEEDS `/gsd:research-phase` -- Rust enclave, highest risk item

## Session Continuity

Last session: 2026-02-17
Stopped at: Completed 12.1-03-PLAN.md (Service Worker Decrypt Proxy)
Resume file: None
Next: Phase 12.1 Plan 04 (media playback hooks or integration)

---

_State initialized: 2026-01-20_
_Last updated: 2026-02-17 after completing Phase 12.1 Plan 03 (Service Worker Decrypt Proxy) -- Phase 12.1 in progress_

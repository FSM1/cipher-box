# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-02-11)

**Core value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext
**Current focus:** Milestone 2 -- Phase 13 COMPLETE (File Versioning)

## Current Position

Phase: 13 (File Versioning)
Plan: 5 of 5
Status: Phase complete
Last activity: 2026-02-21 -- Completed quick task 019 (Metadata Schema Evolution Protocol)

Progress: [#########################] (M1 complete, M2 Phase 12 complete, Phase 12.2 complete, Phase 12.3 complete, Phase 12.3.1 complete, Phase 12.4 complete, Phase 12.5 complete, Phase 12.6 complete, Phase 12.1 complete, Phase 11.1: 7/7 COMPLETE, Phase 11.2: 3/3 COMPLETE, Phase 13: 5/5 COMPLETE)

## Performance Metrics

**Velocity:**

- Total plans completed: 121
- Average duration: 5.4 min
- Total execution time: 11.2 hours

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
| M2 Phase 12.1   | 4/4   | 27 min  | 6.8 min  |
| M2 Phase 11.1   | 7/7   | 36 min  | 5.1 min  |
| M2 Phase 11.2   | 3/3   | 30 min  | 10.0 min |
| M2 Phase 13     | 5/5   | 31 min  | 6.2 min  |

**Recent Trend:**

- Last 5 plans: 5m, 4m, 6m, 7m, 9m
- Trend: Stable

Updated after each plan completion.

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

| Decision                                                          | Phase     | Rationale                                                                                                        |
| ----------------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------- |
| Replace PnP Modal SDK with MPC Core Kit                           | Phase 12  | Full MFA control, custom UX, programmatic factor mgmt                                                            |
| CipherBox as identity provider (sub=userId)                       | Phase 12  | Enables multi-auth linking, less data to Web3Auth                                                                |
| Identity trilemma: chose (wallet-only + unified) w/ SPOF          | Phase 12  | No mandatory email; SPOF mitigated by key export+IPFS                                                            |
| Phase 12 split into 12, 12.2, 12.3, 12.4                          | Phase 12  | Foundation->device registry->SIWE->MFA dependency chain                                                          |
| Core Kit WEB3AUTH_NETWORK uses DEVNET/MAINNET keys                | 12-02     | Different from PnP SDK's SAPPHIRE_DEVNET/SAPPHIRE_MAINNET                                                        |
| CipherBox JWT for backend auth (not coreKit.signatures)           | 12-04     | Core Kit signatures are session tokens, not verifiable JWTs. Pass CipherBox-issued JWT with loginType 'corekit'  |
| importTssKey via localStorage one-time read-and-delete            | 12-05     | PnP migration key consumed once then removed                                                                     |
| E2E uses CipherBox login UI directly (no modal iframe)            | 12-05     | Simpler, more reliable than Web3Auth modal automation                                                            |
| jose library for identity JWTs (not @nestjs/jwt)                  | 12-01     | Separate signing keys (RS256) and audience from internal                                                         |
| Cross-auth-method email linking                                   | 12-01     | Same email across Google/email auth -> same user account                                                         |
| ECIES re-wrapping for sharing (not proxy re-encryption)           | Research  | Same wrapKey() function, server sees only ciphertexts                                                            |
| Versioning = stop unpinning old CIDs + metadata extension         | Research  | Nearly free on IPFS, no new crypto needed                                                                        |
| Read-only sharing only (no multi-writer IPNS)                     | Research  | Unsolved problem, deferred to v3                                                                                 |
| minisearch + idb for client-side search                           | Research  | ~8KB total, TypeScript-native, zero server interaction                                                           |
| Wallet addr: SHA-256 hash + truncated display (no encrypt)        | 12.3-01   | Simpler than hash+encrypted; full plaintext never stored                                                         |
| Auth types: email_passwordless->email, external_wallet->wallet    | 12.3-01   | Clean method-based naming for simplified auth type system                                                        |
| derivationVersion removed (ADR-001 clean break)                   | 12.3-01   | DB will be wiped, no migration needed, clean Core Kit-only schema                                                |
| Web3AuthVerifierService decoupled from auth.service               | 12.3-02   | No longer injected; all login/link flows use CipherBox JWT verification                                          |
| LinkMethodDto uses auth method types directly                     | 12.3-02   | google/email/wallet instead of routing through social/external_wallet loginType                                  |
| Vault export derivationInfo simplified to derivationMethod        | 12.3-02   | Always 'web3auth' for Core Kit users; no derivationVersion needed                                                |
| connectAsync for wallet SIWE flow (not useEffect-based)           | 12.3-03   | Simpler async flow; avoids address-watching complexity                                                           |
| Disconnect wagmi after SIWE verification                          | 12.3-03   | No persistent wallet connection needed; Core Kit handles ongoing auth                                            |
| vaultKeypair naming for auth store keypair                        | 12.3-03   | Clear purpose naming; replaces misleading ADR-001 derivedKeypair                                                 |
| Reuse login components in link mode (settings)                    | 12.3-04   | GoogleLoginButton/EmailLoginForm reused via callback props; no separate link components                          |
| Multiple wallets allowed per account                              | 12.3-04   | Wallet always shows as available to link; CONTEXT.md requirement                                                 |
| Cross-account collision via TypeORM Not()                         | 12.3-04   | Check same identifier with different userId before allowing link                                                 |
| Vault IPNS: same salt, different HKDF info for domain separation  | 12.3.1-01 | HKDF info is primary domain separator; "cipherbox-vault-ipns-v1" vs registry's info                              |
| rootIpnsPublicKey removed from EncryptedVaultKeys                 | 12.3.1-01 | Derivable from private key; reduces stored data, eliminates inconsistency                                        |
| Google login hashes sub (not email) for identifierHash            | 12.3.1-02 | Sub is immutable Google user ID; email can change. Privacy-preserving lookup.                                    |
| Cross-method email auto-linking removed                           | 12.3.1-02 | Each auth method is independent; users link explicitly via Settings, not auto-linked by email match              |
| identifier column stores hash for all auth types                  | 12.3.1-02 | identifier=identifierHash for consistency; identifierDisplay holds human-readable value                          |
| rootIpnsPublicKey removed from vault entity/DTO/API/frontend      | 12.3.1-03 | Derivable from privateKey via HKDF; reduces schema, eliminates inconsistency                                     |
| Plan 04 work completed by Plan 03 broader scope                   | 12.3.1-04 | Desktop Rust, E2E helpers, controller spec changes committed in Plan 03 execution                                |
| Auto-expire on read (no cron for 5min TTL)                        | 12.4-01   | Pending requests past TTL marked expired on getStatus; simpler than background cleanup                           |
| Hard delete on cancel (not status change)                         | 12.4-01   | Cancelled requests have no audit value; 5min TTL keeps table small                                               |
| loginWithCoreKit returns typed union (not void)                   | 12.4-02   | 'logged_in' or 'required_share' enables callers to branch without catching errors                                |
| Placeholder publicKey for REQUIRED_SHARE temp auth                | 12.4-02   | 'pending-core-kit-{userId}' allows bulletin board API access before TSS key available                            |
| Pending auth state in React useState (not Zustand)                | 12.4-02   | Component-scoped, cleared on unmount or logout; no need for global persistence                                   |
| FactorInfo extended with additionalMetadata for device matching   | 12.4-03   | Core Kit shareDescriptions parsed to expose deviceId for factor-to-device matching                               |
| ARIA tablist/tabpanel for Settings tab navigation                 | 12.4-03   | Proper accessibility roles for tab switching between Linked Methods and Security                                 |
| Inline confirm pattern for destructive MFA actions                | 12.4-03   | Revoke/regenerate use inline confirm/cancel, not modal dialog, matching terminal aesthetic                       |
| secp256k1.keygen() for ephemeral keypair generation               | 12.4-04   | Noble secp256k1 v3 API uses keygen() returning { secretKey, publicKey } instead of v2's utils.randomPrivateKey() |
| MFA prompt dismissal persisted in localStorage by user email      | 12.4-04   | Key is cipherbox*mfa_prompt_dismissed*{email} for cross-session persistence, fallback to 'default'               |
| DeviceApprovalModal mounted in AppShell after AppFooter           | 12.4-04   | Fixed overlay visible on all authenticated pages regardless of current route                                     |
| LoginFooter extracted to avoid duplication in Login.tsx           | 12.4-04   | Three render paths (normal, waiting, recovery) share the same footer component                                   |
| Generated client wrapper pattern for device-approval service      | 12.4-05   | deviceApprovalApi wraps Orval-generated functions for backward-compatible import surface                         |
| tssPubKey defensive check as permanent enableMfa() guard          | 12.4-05   | Logs CRITICAL if keypair changes after MFA enrollment; does not throw (enrollment already succeeded)             |
| VaultExport below tabs, not as a third tab                        | 12.5-01   | VaultExport is a utility action always visible, not a settings category                                          |
| Merge Settings.tsx into SettingsPage (not re-route)               | 12.5-01   | SettingsPage is canonical routed component with AppShell; merging preserves existing routing and layout          |
| Hardhat account #0 for wallet E2E test key                        | 12.5-02   | Well-known deterministic key; reproducible tests without real wallet funds                                       |
| Wallet E2E tests validate UI flow independently of Core Kit       | 12.5-02   | TC09 accepts both redirect-to-files and error as valid; tests frontend wallet interaction                        |
| UAT quality gate: 16 PASS / 19 SKIP / 1 NOTE (all documented)     | 12.5-03   | Destructive and multi-device tests skipped with reasons; all 4 issues resolved; gate passed for Phase 12.1       |
| File metadata encrypted with parent folderKey (not file's key)    | 12.6-01   | Consistent with folder metadata access control pattern; parent key controls child access                         |
| encryptionMode optional with GCM default in validator             | 12.6-01   | Phase 12.1 AES-CTR files set 'CTR' explicitly; omission defaults to 'GCM' for backward compat                    |
| fileId minimum 10 chars validation                                | 12.6-01   | Ensures UUID-length identifiers; prevents accidental short strings in HKDF info                                  |
| Partial success for batch publish (per-record results)            | 12.6-02   | Failed records logged and counted, not re-thrown; batch returns totalSucceeded/totalFailed                       |
| Concurrency=10 for batch delegated routing calls                  | 12.6-02   | Promise.allSettled in groups of 10 to avoid overwhelming delegated-ipfs.dev                                      |
| Orphaned TEE enrollment on file delete left to expire             | 12.6-03   | No unenrollIpns REST API yet; 24h IPNS lifetime, Phase 14 adds explicit cleanup                                  |
| deleteFolder returns fileMetaIpnsName list (not CIDs) for v2      | 12.6-03   | v2 FilePointers have no inline CID; caller resolves IPNS to get CID for unpinning                                |
| replaceFileInFolder publishes only file IPNS (folder untouched)   | 12.6-03   | Primary optimization of per-file IPNS: content update skips folder metadata entirely                             |
| DetailsDialog parentFolderId prop removed                         | 12.6-04   | IPNS resolution uses item's own IPNS name directly; parent folder lookup no longer needed                        |
| Inline base36 + protobuf for IPNS name in recovery.html           | 12.6-05   | No libp2p CDN dependency needed; self-contained BigInt-based implementation                                      |
| IPNS failures non-blocking in recovery tool                       | 12.6-05   | Warn and continue; collect failures, report at end with IPNS names for manual recovery                           |
| Post-build script for SW compilation (not Vite plugin)            | 12.1-03   | Vite 7 Environment API breaks Rollup output hooks in standard plugins; build-sw.mjs via Vite lib-mode is simpler |
| Separate tsconfig.sw.json for WebWorker lib types                 | 12.1-03   | SW runs in ServiceWorkerGlobalScope, needs WebWorker lib; excluded from main tsconfig to avoid type conflicts    |
| Dev mode serves SW as raw TS, production as compiled IIFE         | 12.1-03   | Vite dev server transforms TS on-the-fly; production uses minified 2.8KB IIFE at /decrypt-sw.js                  |
| Dual-hook pattern for streaming vs blob URL preview               | 12.1-04   | Both useStreamingPreview and useFilePreview called; open flag controls which is active                           |
| isCtr return from useStreamingPreview for mode detection          | 12.1-04   | Caller knows if file is CTR-encrypted without separate metadata lookup                                           |
| SW body streaming with getReader() for progress tracking          | 12.1-04   | Changed from arrayBuffer() to chunk-by-chunk reading for postMessage progress                                    |
| Ctr64BE matches Web Crypto AES-CTR length:64                      | 11.1-01   | Cross-platform compatibility for desktop decrypting web-encrypted CTR files                                      |
| FileMetadata encryptionMode serde default "GCM"                   | 11.1-01   | Matches TypeScript optional field behavior for backward compat                                                   |
| sanitize_error uses char-walking (not regex crate)                | 11.1-02   | Avoids adding regex dependency for simple path/token replacement                                                 |
| dev_key field always present in AppState (not cfg-gated)          | 11.1-02   | Simplifies struct; only CLI parsing is cfg(debug_assertions) gated                                               |
| Keep v1 write-back format for build_folder_metadata               | 11.1-03   | SUPERSEDED by 11.2: Desktop now creates per-file IPNS records and writes v2 format exclusively                   |
| Synthetic v1 cache entries for v2 folders (version='v2')          | 11.1-03   | Preserves MetadataCache staleness-check API without storing AnyFolderMetadata                                    |
| Eager FilePointer resolution before NFS mount                     | 11.1-03   | NFS caches READDIR aggressively; first response must be complete and correct                                     |
| AnyFolderMetadata Clone/Debug + to_v1() for FUSE compat           | 11.1-04   | Converts v2 FilePointers to placeholder FileEntries for backward-compatible FUSE layer                           |
| Dev-key auth via test-login endpoint for CI/debug                 | 11.1-04   | Debug builds use POST /auth/test-login to get JWT, bypassing Core Kit entirely                                   |
| Manual EIP-4361 SIWE message (no viem dependency for desktop)     | 11.1-07   | Raw string construction avoids heavy viem/wagmi deps; backend parseSiweMessage accepts standard format           |
| Typed enums for DeviceAuthStatus/DevicePlatform (not raw strings) | 11.1-06   | Compile-time safety with serde rename_all lowercase for JSON compatibility                                       |
| Fire-and-forget tokio::spawn for device registry                  | 11.1-06   | Non-blocking: failures logged but never block login flow                                                         |
| Keychain-backed persistent device ID with UUID v4                 | 11.1-06   | keyring crate with delete-before-write pattern to avoid macOS "already exists" error                             |
| ECIES key exchange for desktop device approval (not plaintext)    | 11.1-05   | Matches web app pattern; ephemeral secp256k1 keypair + wrapKey/unwrapKey from @cipherbox/crypto                  |
| Module-level JWT/token state for MFA flow (not localStorage)      | 11.1-05   | Sensitive tokens cleared on auth completion; avoids persisting temporary access tokens                           |
| isFilePointer simplified to type discriminant only                | 11.2-01   | All file children are FilePointer; no need to check for fileMetaIpnsName presence                                |
| validateFolderMetadata rejects v1 with CryptoError                | 11.2-01   | Strict enforcement: only v2 schema accepted, not silent v1 acceptance                                            |
| decrypt_folder_metadata rejects non-v2 with version check         | 11.2-02   | Strict validation: parses JSON, checks version field is "v2", rejects anything else with DeserializationFailed   |
| FilePointer with None ipns_name uses empty string placeholder     | 11.2-02   | Newly created files before IPNS publish use "" with warning log; Plan 03 addresses deriving IPNS in create()     |
| file_ipns_private_key stored on InodeKind::File                   | 11.2-03   | Option<Zeroizing<Vec<u8>>> for IPNS signing; matches folder IPNS key pattern                                     |
| build_folder_metadata skips files without file_meta_ipns_name     | 11.2-03   | Error log + continue instead of empty placeholder; create() always derives IPNS name                             |
| Per-file IPNS publish reuses PublishCoordinator                   | 11.2-03   | Same monotonic sequence number management as folder publishes                                                    |
| VersionEntry encryptionMode is required (not optional)            | 13-01     | Past versions always record explicit encryption mode; no default needed                                          |
| versions array omitted when undefined/empty (not null/[])         | 13-01     | Clean JSON for non-versioned files; backward compatible                                                          |
| shouldCreateVersion returns true for first version (no prior)     | 13-02     | First save always creates baseline version even without forceVersion                                             |
| Text editor cooldown, web re-upload forceVersion                  | 13-02     | Text editor defaults to 15min cooldown; re-upload passes forceVersion: true when added                           |
| prunedCids returned from service, caller handles unpinning        | 13-02     | Separation of concerns: service determines what to prune, caller does I/O                                        |
| VERSION_COOLDOWN_MS=15min, MAX_VERSIONS_PER_FILE=10 in FUSE       | 13-03     | Desktop FUSE versioning constants match CONTEXT.md spec and web behavior                                         |
| Old file CID preserved on FUSE update (not unpinned)              | 13-03     | Enables version history referencing pinned IPFS content; only pruned excess unpinned                             |
| InodeKind::File extended with versions field                      | 13-03     | Carries version history from IPNS resolution through inode lifecycle to release()                                |
| parentFolderId re-added to DetailsDialog for version operations   | 13-04     | Needed for useFolder restoreVersion/deleteVersion which require parent context                                   |
| Version numbering: v1=oldest, vN=newest in display                | 13-04     | Intuitive for users; reversed from array order where index 0=newest                                              |
| metadataRefresh counter for post-action IPNS re-resolution        | 13-04     | Simple useEffect dependency to force re-fetch after restore/delete                                               |
| AES-CTR decrypt added to recovery tool for version support        | 13-05     | Versions may use CTR encryption mode; recovery tool needs both GCM and CTR decryption                            |

### Pending Todos

8 pending todo(s):

- `2026-02-07-web-worker-large-file-encryption.md` -- Offload large file encryption to Web Worker (area: ui)
- `2026-02-14-bring-your-own-ipfs-node.md` -- Add bring-your-own IPFS node support (area: api)
- `2026-02-14-erc-1271-contract-wallet-authentication.md` -- Add ERC-1271 contract wallet authentication support (area: auth)
- `2026-02-15-security-review-medium-term-fixes.md` -- Security review medium-term fixes: H-08, M-07, M-11 (area: auth)
- `2026-02-20-desktop-auto-update.md` -- Add auto-update to desktop app via Tauri updater plugin (area: desktop)
- `2026-02-21-move-root-folder-key-to-ipfs.md` -- Move rootFolderKey to IPFS vault record, eliminate server-side key storage (area: crypto)
- `2026-02-21-ipns-resolution-alternatives.md` -- Investigate alternatives to delegated-ipfs.dev for IPNS resolution (area: api)
- `2026-02-21-desktop-tee-enrollment-for-new-files.md` -- Desktop TEE enrollment for new files (area: desktop)

### Roadmap Evolution

- Phase 12.1 inserted after Phase 12: AES-256-CTR streaming encryption for media files (INSERTED) — previously deferred as "future enhancement," promoted to M2 for early delivery after MFA stabilizes key derivation
- Phase 12 rescoped from "MFA config" to "Core Kit Identity Provider Foundation" — PnP Modal SDK rejected for insufficient control
- Phase 12.2 inserted: Encrypted Device Registry on IPFS — infrastructure for cross-device approval
- Phase 12.3 inserted: SIWE + Unified Identity — wallet login unification, multi-auth linking
- Phase 12.4 inserted: MFA + Cross-Device Approval — the actual MFA enrollment and device approval features
- Phase 12.3.1 inserted after Phase 12.3: Pre-Wipe Identity Cleanup — deterministic IPNS derivation, SHA-256 hashed identifiers for all auth methods, remove cross-method email auto-linking. Done before DB wipe to avoid migration code.
- Phase 12.5 inserted after Phase 12.4: MFA Polishing, UAT & E2E Testing — polish auth flows, add wallet E2E with mock EIP-1193/6963 provider, fix bugs from CoreKit auth UAT
- Phase 12.6 inserted after Phase 12.5: Per-File IPNS Metadata Split — split file metadata into per-file IPNS records before vault wipe (clean break, no dual-schema). Phase 12.1 (AES-CTR) moved to after 12.6.
- Phase 11.2 inserted after Phase 11.1: Remove v1 Folder Metadata — eliminate v1/v2 dual-schema code, make v2 FilePointer canonical everywhere, add per-file IPNS publishing to desktop FUSE. Triggered by cross-device format oscillation bug (desktop writes v1, web re-saves as v2 hybrid, desktop rejects).

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
| 017 | Desktop binary staging release            | 2026-02-19 | 8351fd2 | [017-desktop-binary-staging-release](./quick/017-desktop-binary-staging-release/)                           |
| 018 | E2E versioning tests                      | 2026-02-19 | 3fd131e | [018-e2e-versioning-tests](./quick/018-e2e-versioning-tests/)                                               |
| 019 | Metadata schema evolution protocol        | 2026-02-21 | dcb49e1 | [019-metadata-schema-evolution-protocol](./quick/019-metadata-schema-evolution-protocol/)                   |

### Research Flags

- Phase 11 (Desktop): NEEDS `/gsd:research-phase` -- Linux FUSE (libfuse), Windows virtual drive (WinFsp/Dokany), Tauri cross-compilation
- Phase 14 (Sharing): NEEDS `/gsd:research-phase` -- revocation key rotation protocol
- Phase 15 (Link Sharing): NEEDS `/gsd:research-phase` -- unauthenticated web viewer security
- Phase 16 (Advanced Sync): NEEDS `/gsd:research-phase` -- three-way merge edge cases
- Phase 12 (Core Kit Foundation): NEEDS `/gsd:research-phase` -- Core Kit initialization, custom JWT verifier, PnP->Core Kit key migration, email passwordless
- Phase 12.1 (AES-CTR Streaming): COMPLETE -- all 4 plans done (CTR crypto primitives, streaming upload pipeline, service worker decrypt proxy, media playback integration)
- Phase 12.2 (Device Registry): COMPLETE -- research and execution done
- Phase 12.3 (SIWE + Identity): COMPLETE -- all 4 plans done (backend SIWE, wallet endpoints, ADR-001 cleanup, frontend wallet login, linked methods UI)
- Phase 12.4 (MFA + Cross-Device): COMPLETE -- all 5 plans done (bulletin board API, MFA hooks, enrollment wizard, cross-device approval, integration verification)
- Phase 12.5 (MFA Polishing, UAT & E2E): COMPLETE -- all 3 plans done (SecurityTab wiring, wallet E2E tests, UAT final verification)
- Phase 12.6 (Per-File IPNS Metadata): COMPLETE -- all 5 plans done (crypto primitives, batch publish backend, frontend service layer, hooks & components, recovery tool + docs)
- Phase 13 (File Versioning): COMPLETE -- all 5 plans done (version entry types, creation service, desktop FUSE, version history UI, recovery tool + build verification)
- Phase 17 (Nitro TEE): NEEDS `/gsd:research-phase` -- Rust enclave, highest risk item

## Session Continuity

Last session: 2026-02-21
Stopped at: Completed quick task 019: Metadata Schema Evolution Protocol
Resume file: None
Next: Run /gsd:discuss-phase 14 or /gsd:plan-phase 14 for User-to-User Sharing.

---

_State initialized: 2026-01-20_
_Last updated: 2026-02-21 after completing quick task 019 (Metadata Schema Evolution Protocol)_

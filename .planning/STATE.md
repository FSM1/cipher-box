# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-02-11)

**Core value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext
**Current focus:** Milestone 2 -- all phases complete, ready for milestone audit

## Current Position

Phase: 17.1 (Recycle Bin Integration Fixes) -- COMPLETE
Plan: 3 of 3 (all plans complete)
Status: Phase complete
Last activity: 2026-03-05 -- Completed 17.1-03-PLAN.md (E2E tests for bin integration)

Progress: [#########################] (M1 complete, M2 Phase 12 complete, Phase 12.2 complete, Phase 12.3 complete, Phase 12.3.1 complete, Phase 12.4 complete, Phase 12.5 complete, Phase 12.6 complete, Phase 12.1 complete, Phase 11.1: 7/7 COMPLETE, Phase 11.2: 3/3 COMPLETE, Phase 13: 5/5 COMPLETE, Phase 14: 6/6 COMPLETE, Phase 11: 3/3 COMPLETE, Phase 15: 4/4 COMPLETE, Phase 15.1: 3/3 COMPLETE, Phase 11.3: 3/3 COMPLETE, Phase 11.4: 3/3 COMPLETE, Phase 16: 5/5 COMPLETE, Phase 17: 5/5 COMPLETE, Phase 17.1: 3/3 COMPLETE)

## Performance Metrics

**Velocity:**

- Total plans completed: 154
- Average duration: 5.5 min
- Total execution time: 16.4 hours

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
| M2 Phase 14     | 6/6   | 42 min  | 7.0 min  |
| M2 Phase 11     | 3/3   | 35 min  | 11.7 min |
| M2 Phase 15     | 4/4   | 35 min  | 8.8 min  |
| M2 Phase 15.1   | 3/3   | 17 min  | 5.7 min  |
| M2 Phase 11.3   | 3/3   | 104 min | 34.7 min |
| M2 Phase 11.4   | 3/3   | 20 min  | 6.7 min  |
| M2 Phase 16     | 5/5   | 18 min  | 3.6 min  |
| M2 Phase 17     | 5/5   | 35 min  | 7.0 min  |
| M2 Phase 17.1   | 3/3   | 24 min  | 8.0 min  |

**Recent Trend:**

- Last 5 plans: 9m, 7m, 5m, 11m, 4m
- Trend: Stable

Updated after each plan completion.

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

| Decision                                                               | Phase     | Rationale                                                                                                            |
| ---------------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------- |
| Replace PnP Modal SDK with MPC Core Kit                                | Phase 12  | Full MFA control, custom UX, programmatic factor mgmt                                                                |
| CipherBox as identity provider (sub=userId)                            | Phase 12  | Enables multi-auth linking, less data to Web3Auth                                                                    |
| Identity trilemma: chose (wallet-only + unified) w/ SPOF               | Phase 12  | No mandatory email; SPOF mitigated by key export+IPFS                                                                |
| Phase 12 split into 12, 12.2, 12.3, 12.4                               | Phase 12  | Foundation->device registry->SIWE->MFA dependency chain                                                              |
| Core Kit WEB3AUTH_NETWORK uses DEVNET/MAINNET keys                     | 12-02     | Different from PnP SDK's SAPPHIRE_DEVNET/SAPPHIRE_MAINNET                                                            |
| CipherBox JWT for backend auth (not coreKit.signatures)                | 12-04     | Core Kit signatures are session tokens, not verifiable JWTs. Pass CipherBox-issued JWT with loginType 'corekit'      |
| importTssKey via localStorage one-time read-and-delete                 | 12-05     | PnP migration key consumed once then removed                                                                         |
| E2E uses CipherBox login UI directly (no modal iframe)                 | 12-05     | Simpler, more reliable than Web3Auth modal automation                                                                |
| jose library for identity JWTs (not @nestjs/jwt)                       | 12-01     | Separate signing keys (RS256) and audience from internal                                                             |
| Cross-auth-method email linking                                        | 12-01     | Same email across Google/email auth -> same user account                                                             |
| ECIES re-wrapping for sharing (not proxy re-encryption)                | Research  | Same wrapKey() function, server sees only ciphertexts                                                                |
| Versioning = stop unpinning old CIDs + metadata extension              | Research  | Nearly free on IPFS, no new crypto needed                                                                            |
| Read-only sharing only (no multi-writer IPNS)                          | Research  | Unsolved problem, deferred to v3                                                                                     |
| minisearch + idb for client-side search                                | Research  | ~8KB total, TypeScript-native, zero server interaction                                                               |
| Wallet addr: SHA-256 hash + truncated display (no encrypt)             | 12.3-01   | Simpler than hash+encrypted; full plaintext never stored                                                             |
| Auth types: email_passwordless->email, external_wallet->wallet         | 12.3-01   | Clean method-based naming for simplified auth type system                                                            |
| derivationVersion removed (ADR-001 clean break)                        | 12.3-01   | DB will be wiped, no migration needed, clean Core Kit-only schema                                                    |
| Web3AuthVerifierService decoupled from auth.service                    | 12.3-02   | No longer injected; all login/link flows use CipherBox JWT verification                                              |
| LinkMethodDto uses auth method types directly                          | 12.3-02   | google/email/wallet instead of routing through social/external_wallet loginType                                      |
| Vault export derivationInfo simplified to derivationMethod             | 12.3-02   | Always 'web3auth' for Core Kit users; no derivationVersion needed                                                    |
| connectAsync for wallet SIWE flow (not useEffect-based)                | 12.3-03   | Simpler async flow; avoids address-watching complexity                                                               |
| Disconnect wagmi after SIWE verification                               | 12.3-03   | No persistent wallet connection needed; Core Kit handles ongoing auth                                                |
| vaultKeypair naming for auth store keypair                             | 12.3-03   | Clear purpose naming; replaces misleading ADR-001 derivedKeypair                                                     |
| Reuse login components in link mode (settings)                         | 12.3-04   | GoogleLoginButton/EmailLoginForm reused via callback props; no separate link components                              |
| Multiple wallets allowed per account                                   | 12.3-04   | Wallet always shows as available to link; CONTEXT.md requirement                                                     |
| Cross-account collision via TypeORM Not()                              | 12.3-04   | Check same identifier with different userId before allowing link                                                     |
| Vault IPNS: same salt, different HKDF info for domain separation       | 12.3.1-01 | HKDF info is primary domain separator; "cipherbox-vault-ipns-v1" vs registry's info                                  |
| rootIpnsPublicKey removed from EncryptedVaultKeys                      | 12.3.1-01 | Derivable from private key; reduces stored data, eliminates inconsistency                                            |
| Google login hashes sub (not email) for identifierHash                 | 12.3.1-02 | Sub is immutable Google user ID; email can change. Privacy-preserving lookup.                                        |
| Cross-method email auto-linking removed                                | 12.3.1-02 | Each auth method is independent; users link explicitly via Settings, not auto-linked by email match                  |
| identifier column stores hash for all auth types                       | 12.3.1-02 | identifier=identifierHash for consistency; identifierDisplay holds human-readable value                              |
| rootIpnsPublicKey removed from vault entity/DTO/API/frontend           | 12.3.1-03 | Derivable from privateKey via HKDF; reduces schema, eliminates inconsistency                                         |
| Plan 04 work completed by Plan 03 broader scope                        | 12.3.1-04 | Desktop Rust, E2E helpers, controller spec changes committed in Plan 03 execution                                    |
| Auto-expire on read (no cron for 5min TTL)                             | 12.4-01   | Pending requests past TTL marked expired on getStatus; simpler than background cleanup                               |
| Hard delete on cancel (not status change)                              | 12.4-01   | Cancelled requests have no audit value; 5min TTL keeps table small                                                   |
| loginWithCoreKit returns typed union (not void)                        | 12.4-02   | 'logged_in' or 'required_share' enables callers to branch without catching errors                                    |
| Placeholder publicKey for REQUIRED_SHARE temp auth                     | 12.4-02   | 'pending-core-kit-{userId}' allows bulletin board API access before TSS key available                                |
| Pending auth state in React useState (not Zustand)                     | 12.4-02   | Component-scoped, cleared on unmount or logout; no need for global persistence                                       |
| FactorInfo extended with additionalMetadata for device matching        | 12.4-03   | Core Kit shareDescriptions parsed to expose deviceId for factor-to-device matching                                   |
| ARIA tablist/tabpanel for Settings tab navigation                      | 12.4-03   | Proper accessibility roles for tab switching between Linked Methods and Security                                     |
| Inline confirm pattern for destructive MFA actions                     | 12.4-03   | Revoke/regenerate use inline confirm/cancel, not modal dialog, matching terminal aesthetic                           |
| secp256k1.keygen() for ephemeral keypair generation                    | 12.4-04   | Noble secp256k1 v3 API uses keygen() returning { secretKey, publicKey } instead of v2's utils.randomPrivateKey()     |
| MFA prompt dismissal persisted in localStorage by user email           | 12.4-04   | Key is cipherbox*mfa_prompt_dismissed*{email} for cross-session persistence, fallback to 'default'                   |
| DeviceApprovalModal mounted in AppShell after AppFooter                | 12.4-04   | Fixed overlay visible on all authenticated pages regardless of current route                                         |
| LoginFooter extracted to avoid duplication in Login.tsx                | 12.4-04   | Three render paths (normal, waiting, recovery) share the same footer component                                       |
| Generated client wrapper pattern for device-approval service           | 12.4-05   | deviceApprovalApi wraps Orval-generated functions for backward-compatible import surface                             |
| tssPubKey defensive check as permanent enableMfa() guard               | 12.4-05   | Logs CRITICAL if keypair changes after MFA enrollment; does not throw (enrollment already succeeded)                 |
| VaultExport below tabs, not as a third tab                             | 12.5-01   | VaultExport is a utility action always visible, not a settings category                                              |
| Merge Settings.tsx into SettingsPage (not re-route)                    | 12.5-01   | SettingsPage is canonical routed component with AppShell; merging preserves existing routing and layout              |
| Hardhat account #0 for wallet E2E test key                             | 12.5-02   | Well-known deterministic key; reproducible tests without real wallet funds                                           |
| Wallet E2E tests validate UI flow independently of Core Kit            | 12.5-02   | TC09 accepts both redirect-to-files and error as valid; tests frontend wallet interaction                            |
| UAT quality gate: 16 PASS / 19 SKIP / 1 NOTE (all documented)          | 12.5-03   | Destructive and multi-device tests skipped with reasons; all 4 issues resolved; gate passed for Phase 12.1           |
| File metadata encrypted with parent folderKey (not file's key)         | 12.6-01   | Consistent with folder metadata access control pattern; parent key controls child access                             |
| encryptionMode optional with GCM default in validator                  | 12.6-01   | Phase 12.1 AES-CTR files set 'CTR' explicitly; omission defaults to 'GCM' for backward compat                        |
| fileId minimum 10 chars validation                                     | 12.6-01   | Ensures UUID-length identifiers; prevents accidental short strings in HKDF info                                      |
| Partial success for batch publish (per-record results)                 | 12.6-02   | Failed records logged and counted, not re-thrown; batch returns totalSucceeded/totalFailed                           |
| Concurrency=10 for batch delegated routing calls                       | 12.6-02   | Promise.allSettled in groups of 10 to avoid overwhelming delegated-ipfs.dev                                          |
| Orphaned TEE enrollment on file delete left to expire                  | 12.6-03   | No unenrollIpns REST API yet; 24h IPNS lifetime, Phase 14 adds explicit cleanup                                      |
| deleteFolder returns fileMetaIpnsName list (not CIDs) for v2           | 12.6-03   | v2 FilePointers have no inline CID; caller resolves IPNS to get CID for unpinning                                    |
| replaceFileInFolder publishes only file IPNS (folder untouched)        | 12.6-03   | Primary optimization of per-file IPNS: content update skips folder metadata entirely                                 |
| DetailsDialog parentFolderId prop removed                              | 12.6-04   | IPNS resolution uses item's own IPNS name directly; parent folder lookup no longer needed                            |
| Inline base36 + protobuf for IPNS name in recovery.html                | 12.6-05   | No libp2p CDN dependency needed; self-contained BigInt-based implementation                                          |
| IPNS failures non-blocking in recovery tool                            | 12.6-05   | Warn and continue; collect failures, report at end with IPNS names for manual recovery                               |
| Post-build script for SW compilation (not Vite plugin)                 | 12.1-03   | Vite 7 Environment API breaks Rollup output hooks in standard plugins; build-sw.mjs via Vite lib-mode is simpler     |
| Separate tsconfig.sw.json for WebWorker lib types                      | 12.1-03   | SW runs in ServiceWorkerGlobalScope, needs WebWorker lib; excluded from main tsconfig to avoid type conflicts        |
| Dev mode serves SW as raw TS, production as compiled IIFE              | 12.1-03   | Vite dev server transforms TS on-the-fly; production uses minified 2.8KB IIFE at /decrypt-sw.js                      |
| Dual-hook pattern for streaming vs blob URL preview                    | 12.1-04   | Both useStreamingPreview and useFilePreview called; open flag controls which is active                               |
| isCtr return from useStreamingPreview for mode detection               | 12.1-04   | Caller knows if file is CTR-encrypted without separate metadata lookup                                               |
| SW body streaming with getReader() for progress tracking               | 12.1-04   | Changed from arrayBuffer() to chunk-by-chunk reading for postMessage progress                                        |
| Ctr64BE matches Web Crypto AES-CTR length:64                           | 11.1-01   | Cross-platform compatibility for desktop decrypting web-encrypted CTR files                                          |
| FileMetadata encryptionMode serde default "GCM"                        | 11.1-01   | Matches TypeScript optional field behavior for backward compat                                                       |
| sanitize_error uses char-walking (not regex crate)                     | 11.1-02   | Avoids adding regex dependency for simple path/token replacement                                                     |
| dev_key field always present in AppState (not cfg-gated)               | 11.1-02   | Simplifies struct; only CLI parsing is cfg(debug_assertions) gated                                                   |
| Keep v1 write-back format for build_folder_metadata                    | 11.1-03   | SUPERSEDED by 11.2: Desktop now creates per-file IPNS records and writes v2 format exclusively                       |
| Synthetic v1 cache entries for v2 folders (version='v2')               | 11.1-03   | Preserves MetadataCache staleness-check API without storing AnyFolderMetadata                                        |
| Eager FilePointer resolution before NFS mount                          | 11.1-03   | NFS caches READDIR aggressively; first response must be complete and correct                                         |
| AnyFolderMetadata Clone/Debug + to_v1() for FUSE compat                | 11.1-04   | Converts v2 FilePointers to placeholder FileEntries for backward-compatible FUSE layer                               |
| Dev-key auth via test-login endpoint for CI/debug                      | 11.1-04   | Debug builds use POST /auth/test-login to get JWT, bypassing Core Kit entirely                                       |
| Manual EIP-4361 SIWE message (no viem dependency for desktop)          | 11.1-07   | Raw string construction avoids heavy viem/wagmi deps; backend parseSiweMessage accepts standard format               |
| Typed enums for DeviceAuthStatus/DevicePlatform (not raw strings)      | 11.1-06   | Compile-time safety with serde rename_all lowercase for JSON compatibility                                           |
| Fire-and-forget tokio::spawn for device registry                       | 11.1-06   | Non-blocking: failures logged but never block login flow                                                             |
| Keychain-backed persistent device ID with UUID v4                      | 11.1-06   | keyring crate with delete-before-write pattern to avoid macOS "already exists" error                                 |
| ECIES key exchange for desktop device approval (not plaintext)         | 11.1-05   | Matches web app pattern; ephemeral secp256k1 keypair + wrapKey/unwrapKey from @cipherbox/crypto                      |
| Module-level JWT/token state for MFA flow (not localStorage)           | 11.1-05   | Sensitive tokens cleared on auth completion; avoids persisting temporary access tokens                               |
| isFilePointer simplified to type discriminant only                     | 11.2-01   | All file children are FilePointer; no need to check for fileMetaIpnsName presence                                    |
| validateFolderMetadata rejects v1 with CryptoError                     | 11.2-01   | Strict enforcement: only v2 schema accepted, not silent v1 acceptance                                                |
| decrypt_folder_metadata rejects non-v2 with version check              | 11.2-02   | Strict validation: parses JSON, checks version field is "v2", rejects anything else with DeserializationFailed       |
| FilePointer with None ipns_name uses empty string placeholder          | 11.2-02   | Newly created files before IPNS publish use "" with warning log; Plan 03 addresses deriving IPNS in create()         |
| file_ipns_private_key stored on InodeKind::File                        | 11.2-03   | Option<Zeroizing<Vec<u8>>> for IPNS signing; matches folder IPNS key pattern                                         |
| build_folder_metadata skips files without file_meta_ipns_name          | 11.2-03   | Error log + continue instead of empty placeholder; create() always derives IPNS name                                 |
| Per-file IPNS publish reuses PublishCoordinator                        | 11.2-03   | Same monotonic sequence number management as folder publishes                                                        |
| VersionEntry encryptionMode is required (not optional)                 | 13-01     | Past versions always record explicit encryption mode; no default needed                                              |
| versions array omitted when undefined/empty (not null/[])              | 13-01     | Clean JSON for non-versioned files; backward compatible                                                              |
| shouldCreateVersion returns true for first version (no prior)          | 13-02     | First save always creates baseline version even without forceVersion                                                 |
| Text editor cooldown, web re-upload forceVersion                       | 13-02     | Text editor defaults to 15min cooldown; re-upload passes forceVersion: true when added                               |
| prunedCids returned from service, caller handles unpinning             | 13-02     | Separation of concerns: service determines what to prune, caller does I/O                                            |
| VERSION_COOLDOWN_MS=15min, MAX_VERSIONS_PER_FILE=10 in FUSE            | 13-03     | Desktop FUSE versioning constants match CONTEXT.md spec and web behavior                                             |
| Old file CID preserved on FUSE update (not unpinned)                   | 13-03     | Enables version history referencing pinned IPFS content; only pruned excess unpinned                                 |
| InodeKind::File extended with versions field                           | 13-03     | Carries version history from IPNS resolution through inode lifecycle to release()                                    |
| parentFolderId re-added to DetailsDialog for version operations        | 13-04     | Needed for useFolder restoreVersion/deleteVersion which require parent context                                       |
| Version numbering: v1=oldest, vN=newest in display                     | 13-04     | Intuitive for users; reversed from array order where index 0=newest                                                  |
| metadataRefresh counter for post-action IPNS re-resolution             | 13-04     | Simple useEffect dependency to force re-fetch after restore/delete                                                   |
| AES-CTR decrypt added to recovery tool for version support             | 13-05     | Versions may use CTR encryption mode; recovery tool needs both GCM and CTR decryption                                |
| KEY_REWRAP_FAILED added to CryptoErrorCode                             | 14-01     | Specific error code for ECIES re-wrapping failures in sharing flows                                                  |
| itemName stored as plaintext in share record                           | 14-01     | Minimal privacy impact per RESEARCH.md; server already knows user IDs                                                |
| revokedAt soft-delete for lazy key rotation                            | 14-01     | Avoids separate tracking table; revoked shares marked then hard-deleted after rotation                               |
| OpenAPI generator needs manual controller registration                 | 14-02     | generate-openapi.ts uses lightweight module; new controllers must be added with mock providers                       |
| Lookup endpoint under /shares/lookup (not /users/lookup)               | 14-02     | Keeps all sharing-related endpoints under shares controller for API cohesion                                         |
| Buffer-to-hex serialization in controller response mapping             | 14-02     | Service layer works with raw TypeORM Buffers; controller converts to hex for API responses                           |
| CSS in App.css for settings pubkey styles (not separate file)          | 14-03     | All existing settings styles live in App.css; consistent location                                                    |
| Public key hex with 0x prefix from bytesToHex(vaultKeypair.publicKey)  | 14-03     | Uncompressed secp256k1 format matching CONTEXT.md 0x04... spec                                                       |
| Orval void-typed responses cast with as unknown as                     | 14-03     | Generated client types endpoints returning data as void; cast needed for type safety                                 |
| Direct API calls for share creation (not React Query hooks)            | 14-04     | Sharing is imperative (click submit, run, display result), not declarative query-based                               |
| Folder key re-wrapping via unwrapKey + wrapKey (not reWrapKey)         | 14-04     | Clearer control over key material zeroing in multi-step folder traversal                                             |
| Recipients filtered client-side by ipnsName from getSentShares         | 14-04     | No per-item endpoint needed at current scale; simple client-side filter                                              |
| Navigation stack with useRef for shared subfolder browsing             | 14-05     | In-memory browsing without URL state; user navigates back to /shared list                                            |
| Breadcrumbs built inline in SharedFileBrowser (not existing component) | 14-05     | Existing Breadcrumbs tightly coupled to folder.store; separate inline rendering avoids coupling                      |
| readOnly prop on ContextMenu for shared context                        | 14-05     | Same component serves owned and shared contexts; clean conditional without separate component                        |
| NavItem icon map with Unicode characters                               | 14-05     | Consistent with terminal aesthetic; no SVG icons needed for sidebar navigation                                       |
| Dynamic import() for checkAndRotateIfNeeded circular dep               | 14-06     | share.service imports folder.store; folder.service importing share.service creates circular; dynamic import() defers |
| Lazy rotation defers parent metadata update to caller                  | 14-06     | checkAndRotateIfNeeded returns new key + rotated flag; caller handles parent folderKeyEncrypted update               |
| Post-upload re-wrapping is fire-and-forget                             | 14-06     | Non-blocking: failures logged but never delay upload completion UI                                                   |
| FileAttrs with to_fuse_attr() boundary conversion                      | 11-01     | Core uses platform-agnostic FileAttrs; uid/gid injected at operations layer, not stored in shared structs            |
| AccessMode enum replaces libc POSIX flags                              | 11-01     | Platform-independent ReadOnly/WriteOnly/ReadWrite instead of O_RDONLY/O_WRONLY/O_RDWR                                |
| cfg(any(fuse, winfsp)) for shared filesystem code                      | 11-01     | Shared types available to both platforms; mount/unmount remain feature-specific                                      |
| Self-contained decrypt functions per platform module                   | 11-02     | Windows module has own decrypt_metadata_from_ipfs; fuse::operations gated to fuse-only, can't be cross-referenced    |
| Arc<Mutex<CipherBoxFS>> for WinFsp interior mutability                 | 11-02     | WinFsp callbacks receive &self; Mutex wraps shared state for safe mutation from any thread                           |
| OnceLock<AtomicBool> stop signal for WinFsp unmount                    | 11-02     | Avoids storing FileSystemHost globally; stop flag coordinates shutdown across threads                                |
| WinFsp creates mount directory (no pre-create)                         | 11-02     | WinFsp uses reparse point for mount; pre-existing directory causes mount failure                                     |
| Platform dispatch via cfg re-exports in fuse/mod.rs                    | 11-02     | Same function names (mount_filesystem/unmount_filesystem) resolve to correct impl via feature flags                  |
| WinFsp runtime detection via winreg at startup                         | 11-03     | Registry check + DLL existence verification; notification if missing, app still launches                             |
| NSIS ExecWait for WinFsp MSI install (not nsExec)                      | 11-03     | Simpler exit code handling; MSI installed silently with INSTALLLEVEL=1000                                            |
| WinFsp MSI downloaded in CI, not committed to git                      | 11-03     | Binary files not suitable for source control; CI downloads from official GitHub release                              |
| cfg(any(fuse, winfsp)) in entry point files                            | 11-03     | Compound feature gate enables same mount/unmount code paths on both platforms                                        |
| Two controller classes for mixed auth invite endpoints                 | 15-01     | InvitesController (no class guard) at /invites, ShareInvitesController (JwtAuthGuard) at /shares/invites             |
| Authenticated GET /invites/:token/data for claim flow                  | 15-01     | Separate from public status check; returns encryptedKey + encryptedChildKeys for unwrap/re-wrap                      |
| Hard-delete expired invites on read (not soft-delete)                  | 15-01     | Consistent with DeviceApproval auto-expire pattern; invites have no audit value                                      |
| collectChildKeys extracted to shared lib/crypto/key-wrapping.ts        | 15-02     | Same folder traversal logic needed by both ShareDialog (direct) and invite.service.ts (link); prevents duplication   |
| secp256k1.keygen() for ephemeral invite keypairs                       | 15-02     | Noble v3 API uses keygen() returning { secretKey, publicKey }; matches useDeviceApproval pattern                     |
| Orval void-typed claim response cast as unknown as { shareId }         | 15-02     | OpenAPI spec 201 has no response schema; backend returns { shareId: string } but Orval types as void                 |
| Auto-claim via useEffect watching isAuthenticated state                | 15-03     | navigate(/shared, replace:true) overrides useAuth's navigate(/files); claimingRef prevents double-claim              |
| Ephemeral key in useRef (not useState) on InvitePage                   | 15-03     | Prevents re-render loss and accidental serialization; zeroed to null after claim                                     |
| MFA/REQUIRED_SHARE support on InvitePage                               | 15-03     | Same DeviceWaitingScreen and RecoveryInput as Login.tsx; after MFA resolves, auto-claim fires normally               |
| Raw IndexedDB API for search index (not idb library)                   | 15.1-01   | Consistent with device/identity.ts pattern; number[] serialization for cross-browser compat                          |
| HKDF info "cipherbox-search-index-v1" for search key derivation        | 15.1-01   | Domain separation from vault IPNS key and other derived keys using same private key                                  |
| Web Crypto HKDF+AES-GCM directly (not @cipherbox/crypto)               | 15.1-01   | HKDF produces CryptoKey; crypto package expects raw Uint8Array, would need unnecessary conversion                    |
| SearchIndexService as pure TS class (no React deps)                    | 15.1-01   | Clean separation; React hooks consume singleton instance, service is testable without React                          |
| Module-level callback for cross-component search rebuild               | 15.1-02   | registerRebuildCallback/triggerSearchIndexRebuild avoids prop drilling from AppShell to FileBrowser                  |
| Auth state transition watcher for search index cleanup                 | 15.1-02   | useRef tracks prev isAuthenticated; true->false triggers clearIndex; self-contained in useSearch hook                |
| Unicode file type icons in search results                              | 15.1-02   | Terminal aesthetic consistency; no additional icon library needed                                                    |
| WinFsp resource glob left as-is for Linux builds                       | 11.3-02   | Placeholder MSI tracked in git; glob matches harmlessly on all platforms                                             |
| ubuntu-22.04 pinned for Linux CI (not ubuntu-latest)                   | 11.3-02   | Ensures glibc 2.35 compatibility; prevents drift to 24.04                                                            |
| AutoUnmount removed from Linux mount options                           | 11.3-03   | Requires user_allow_other in /etc/fuse.conf; explicit fusermount3 -u is more portable                                |
| FOPEN_DIRECT_IO + write_generation for O_TRUNC race                    | 11.3-03   | Linux kernel page cache causes stale reads after truncation; DIRECT_IO bypasses cache for written files              |
| Green tray icon for Linux, icon_as_template macOS-only                 | 11.3-03   | Black template icons invisible on dark panels; macOS tinting does not work on Linux                                  |
| ikalnytskyi/action-setup-postgres for cross-platform Postgres          | 11.4-03   | Only action that works on Linux/macOS/Windows without Docker service containers                                      |
| Separate platform-conditional steps for CI clarity                     | 11.4-03   | Each platform gets own steps for Kubo, Redis, FUSE, API, tests instead of complex conditionals                       |
| Application-level read-compare-write for optimistic concurrency        | 16-01     | Sufficient for v1; TOCTOU mitigated by per-folder publish lock + sequential single-user API requests                 |
| Backward compat: omitting expectedSequenceNumber = unconditional       | 16-01     | Existing clients and TEE republishes unaffected by new conflict detection                                            |
| Batch publish aborts entirely on folder conflict                       | 16-01     | Clear signal for client to re-sync; no partial success ambiguity                                                     |
| isConflictError checks .status === 409 on Error object (not wrapper)   | 16-02     | Orval custom-instance attaches status as property on thrown Error; no response wrapper needed                        |
| handleUpdateFile no conflict detection (file-only publish)             | 16-02     | File content update publishes only per-file IPNS; no folder metadata touched, no 409 possible from that path         |
| resyncFolder helper: resolveIpnsRecord + fetchAndDecryptMetadata       | 16-02     | Re-sync works for root and subfolders identically; called with specific folder's ipnsName (not hardcoded root)       |
| Single retry with 100-500ms jitter on 409 conflict                     | 16-02     | Breaks symmetry between concurrent clients; persistent conflict after retry surfaces error to user                   |
| bumpServerSequence uses unconditional publish (omit expectedSeq)       | 16-04     | Simpler than matching exact sequence for bump; no IPNS key material needed in tests                                  |
| Dummy base64 record for test sequence bumps (delegated routing warn)   | 16-04     | Only DB sequence bump needed; delegated routing warning expected and documented                                      |
| PublishResult enum (Success/Conflict) returned by Rust publish_ipns    | 16-03     | Compiler enforces exhaustive match; no silent failure possible on conflict detection                                 |
| merge_folder_children uses IPNS name as stable child key               | 16-03     | ipns_name for FolderEntry, file_meta_ipns_name for FilePointer; survives rename (same IPNS key, new name field)      |
| OS notification for desktop conflict detection deferred                | 16-03     | AppHandle not easily accessible from background thread; tray status change visible to user; TODO for v2              |
| Bin metadata uses ECIES (same as DeviceRegistry, not AES-GCM)          | 17-01     | Single user-scoped record, no per-record symmetric key to manage                                                     |
| HKDF info cipherbox-recycle-bin-ipns-v1 for bin IPNS derivation        | 17-01     | Domain separation from vault and registry IPNS keys; same salt CipherBox-v1                                          |
| GET /vault/config synchronous (no DB query)                            | 17-01     | Reads RECYCLE_BIN_RETENTION_DAYS from ConfigService with default 30                                                  |
| addToBin fire-and-forget from delete flow                              | 17-02     | Folder metadata already updated; bin write is best-effort, non-blocking                                              |
| Folder size 0 in bin entries (resolved on permanent delete)            | 17-02     | Avoids expensive IPNS resolution at delete time; CID cleanup resolves size lazily                                    |
| Recursive parent restore max depth 5                                   | 17-02     | Prevents infinite loops when parent chain is deep; falls back to root                                                |
| Inline generate_uuid_v4 in bin.rs (no uuid crate)                      | 17-04     | Same pattern as registry/mod.rs; avoid new dependency for simple function                                            |
| Inline guess_mime_type mapping (no mime_guess crate)                   | 17-04     | Best-effort MIME for bin display; application/octet-stream fallback acceptable for unknown extensions                |
| Bin IPNS conflict = log + preserve CID (no retry)                      | 17-04     | Fire-and-forget publish; data preserved via pinned CID; next delete or web session creates fresh bin state           |
| Store CID+size in BinEntry at soft-delete (not re-decrypt at delete)   | 17.1-01   | Avoids GAP-1 bug: parsing AES-GCM encrypted metadata as plain JSON; capture when data is in memory                   |
| cleanupFolderCids receives FolderEntry for direct folderKey unwrapping | 17.1-01   | Changed from IPNS name string to full FolderEntry; enables ECIES unwrap + AES-GCM decrypt for nested files           |

### Pending Todos

13 pending todo(s):

- `2026-02-07-web-worker-large-file-encryption.md` -- Offload large file encryption to Web Worker (area: ui)
- `2026-02-14-bring-your-own-ipfs-node.md` -- Add bring-your-own IPFS node support (area: api)
- `2026-02-14-erc-1271-contract-wallet-authentication.md` -- Add ERC-1271 contract wallet authentication support (area: auth)
- `2026-02-15-security-review-medium-term-fixes.md` -- Security review medium-term fixes: H-08, M-07, M-11 (area: auth)
- `2026-02-20-desktop-auto-update.md` -- Add auto-update to desktop app via Tauri updater plugin (area: desktop)
- `2026-02-21-move-root-folder-key-to-ipfs.md` -- Move rootFolderKey to IPFS vault record, eliminate server-side key storage (area: crypto)
- `2026-02-21-ipns-resolution-alternatives.md` -- Investigate alternatives to delegated-ipfs.dev for IPNS resolution (area: api)
- `2026-02-21-desktop-tee-enrollment-for-new-files.md` -- Desktop TEE enrollment for new files (area: desktop)
- `2026-02-21-phase14-security-review-deferred.md` -- Phase 14 security review: deferred findings M1, M5, L1, L4 (area: shares)
- `2026-02-22-crdt-ipns-inbox-sharing.md` -- CRDT IPNS inbox for sharing (area: architecture)
- `2026-02-24-async-incremental-search-index.md` -- Make search index build async/incremental for large vaults (area: ui)
- `2026-02-26-alternative-mfa-factor-types.md` -- Add alternative MFA factor types: passkey (WebAuthn PRF), password-derived key, secondary OAuth (area: auth)
- `2026-02-27-ci-migration-drift-check.md` -- Add CI migration drift check via TypeORM migration:generate (area: api)

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
- Phase 15 split: "Link Sharing and Search" split into Phase 15 (Link Sharing) and Phase 15.1 (Client-Side Search). Independent features with different security surfaces.
- Phase 17 added to M2: Recycle Bin -- soft-delete with time-limited retention, file/folder recovery, manual bin emptying. AWS Nitro TEE moved from M2 Phase 17 to M3 Phase 22 (Phala mock still in use on staging). M3 phases: 18-22.
- Phase 17.1 inserted after Phase 17: Recycle Bin Integration Fixes -- milestone audit found bin permanent delete can't unpin CIDs (encrypted metadata parsed as plain JSON) and Windows desktop deletes bypass bin. Closes GAP-1 (CRITICAL) and GAP-2 (MODERATE).

### Blockers/Concerns

- Web3Auth custom JWT verifier: requires Growth Plan for production (free on devnet). Verify pricing before committing.
- CipherBox as identity SPOF: backend is trust anchor for auth. Mitigated by encrypted key export + IPFS device registry. One-way door — verifierId scheme is permanent.
- Versioning + Sharing interaction: RESOLVED -- Recipients see only current version (per RESEARCH.md recommendation). Version history not shared in Phase 14.

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
| 020 | Fix shared items rendering                | 2026-02-25 | 96b7591 | [020-fix-shared-items-rendering](./quick/020-fix-shared-items-rendering/)                                   |
| 021 | Account deletion (GDPR)                   | 2026-02-25 | 8ae01dd | [021-account-deletion-gdpr](./quick/021-account-deletion-gdpr/)                                             |
| 022 | Fix MFA status detection false positive   | 2026-02-26 | ff850e0 | [022-fix-mfa-status-detection-false-positive](./quick/022-fix-mfa-status-detection-false-positive/)         |
| 023 | M2 tech debt: store logout cleanup        | 2026-03-04 | a8febeb | [023-m2-tech-debt-store-logout-cleanup](./quick/023-m2-tech-debt-store-logout-cleanup/)                     |

### Research Flags

- Phase 11 (Desktop): NEEDS `/gsd:research-phase` -- Linux FUSE (libfuse), Windows virtual drive (WinFsp/Dokany), Tauri cross-compilation
- Phase 14 (Sharing): COMPLETE -- research done, 6 plans created, all 6 executed
- Phase 15 (Link Sharing): COMPLETE -- ephemeral key bridge pattern, HashRouter fragment handling, unauthenticated endpoint design researched; 4 plans created
- Phase 15.1 (Client-Side Search): COMPLETE -- 3 plans done (search index service, search UI & integration, E2E search tests)
- Phase 16 (Advanced Sync): COMPLETE -- 5/5 plans done (API optimistic concurrency, web client conflict handling, desktop FUSE conflict, E2E web tests, E2E desktop tests)
- Phase 12 (Core Kit Foundation): NEEDS `/gsd:research-phase` -- Core Kit initialization, custom JWT verifier, PnP->Core Kit key migration, email passwordless
- Phase 12.1 (AES-CTR Streaming): COMPLETE -- all 4 plans done (CTR crypto primitives, streaming upload pipeline, service worker decrypt proxy, media playback integration)
- Phase 12.2 (Device Registry): COMPLETE -- research and execution done
- Phase 12.3 (SIWE + Identity): COMPLETE -- all 4 plans done (backend SIWE, wallet endpoints, ADR-001 cleanup, frontend wallet login, linked methods UI)
- Phase 12.4 (MFA + Cross-Device): COMPLETE -- all 5 plans done (bulletin board API, MFA hooks, enrollment wizard, cross-device approval, integration verification)
- Phase 12.5 (MFA Polishing, UAT & E2E): COMPLETE -- all 3 plans done (SecurityTab wiring, wallet E2E tests, UAT final verification)
- Phase 12.6 (Per-File IPNS Metadata): COMPLETE -- all 5 plans done (crypto primitives, batch publish backend, frontend service layer, hooks & components, recovery tool + docs)
- Phase 13 (File Versioning): COMPLETE -- all 5 plans done (version entry types, creation service, desktop FUSE, version history UI, recovery tool + build verification)
- Phase 11.3 (Linux Desktop): COMPLETE -- 3/3 plans done (Rust platform support, packaging & CI, local UAT 18/18 pass)
- Phase 11.4 (Cross-Platform E2E Testing): COMPLETE -- 3/3 plans done (CI debug artifacts + crypto vectors, FUSE/API test scripts, e2e-desktop.yml workflow)
- Phase 16 (Advanced Sync): COMPLETE -- 5/5 plans done (API concurrency control, web sync service, desktop conflict handling, web E2E tests, desktop E2E tests)
- Phase 17 (Recycle Bin): COMPLETE -- 5/5 plans done (crypto, store/service, web UI, desktop FUSE, E2E testing)
- Phase 17.1 (Bin Integration Fixes): COMPLETE -- 3/3 plans done (bin CID capture fix, Windows WinFsp bin integration, E2E test coverage)
- Phase 22 (Nitro TEE): Moved to M3. NEEDS `/gsd:research-phase` -- Rust enclave, highest risk item

## Session Continuity

Last session: 2026-03-05
Stopped at: Phase 17.1 complete (3/3 plans, verified 7/7 must-haves)
Resume file: None
Next: Audit Milestone 2 via /gsd:audit-milestone

---

_State initialized: 2026-01-20_
_Last updated: 2026-03-05 after Phase 17.1 complete (bin integration fixes verified)_

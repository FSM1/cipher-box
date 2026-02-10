# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-20)

**Core value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext
**Current focus:** Phase 10 - Data Portability (next)

## Current Position

Phase: 9.1 of 11 (Environment Changes, DevOps & Staging Deployment)
Plan: 6 of 6 in Phase 9.1 complete
Status: Complete
Last activity: 2026-02-10 - Completed quick task 006: Add file/folder details modal

Progress: [##########] 100% (69 of 69 plans)

## Performance Metrics

**Velocity:**

- Total plans completed: 69
- Average duration: 4.7 min
- Total execution time: 5.5 hours

**By Phase:**

| Phase                      | Plans | Total   | Avg/Plan |
| -------------------------- | ----- | ------- | -------- |
| 01-foundation              | 3/3   | 20 min  | 7 min    |
| 02-authentication          | 4/4   | 18 min  | 4.5 min  |
| 03-core-encryption         | 3/3   | 18 min  | 6 min    |
| 04-file-storage            | 4/4   | 17 min  | 4.3 min  |
| 04.1-api-service-testing   | 3/3   | 11 min  | 3.7 min  |
| 04.2-local-ipfs-testing    | 2/2   | 14 min  | 7 min    |
| 05-folder-system           | 4/4   | 18 min  | 4.5 min  |
| 06-file-browser-ui         | 4/4   | 19 min  | 4.8 min  |
| 06.1-webapp-automation     | 6/6   | 25 min  | 4.2 min  |
| 06.3-ui-structure-refactor | 5/5   | 16 min  | 3.2 min  |
| 07-multi-device-sync       | 4/4   | 17 min  | 4.3 min  |
| 07.1-atomic-file-upload    | 2/2   | 6 min   | 3 min    |
| 08-tee-integration         | 4/4   | 21 min  | 5.3 min  |
| 09-desktop-client          | 7/7   | 49 min  | 7.0 min  |
| 09.1-env-devops-staging    | 6/6   | 101 min | 16.8 min |

**Recent Trend:**

- Last 5 plans: 2m, 3m, 2m, 3m, 90m
- Trend: Plan 09.1-05 was interactive infrastructure provisioning with iterative deployment fixes

Updated after each plan completion.

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

| Decision                                               | Phase   | Rationale                                                                 |
| ------------------------------------------------------ | ------- | ------------------------------------------------------------------------- |
| Override moduleResolution to 'node' for NestJS apps    | 01-01   | Base tsconfig uses bundler which is incompatible with CommonJS            |
| Generate OpenAPI spec using minimal module             | 01-01   | Avoids requiring live database during build                               |
| Pre-configure API tags in OpenAPI                      | 01-01   | Placeholder tags for Auth, Vault, Files, IPFS, IPNS                       |
| Use React 18.3.1 per project spec                      | 01-02   | Not React 19 - staying on stable LTS version                              |
| orval tags-split mode for API client                   | 01-02   | Generates separate files per API tag for better organization              |
| Custom fetch instance for API calls                    | 01-02   | Allows future auth header injection without modifying generated code      |
| ESLint 9 flat config format                            | 01-03   | Modern, simpler configuration at monorepo root                            |
| CI api-spec job verifies generated files               | 01-03   | Ensures OpenAPI spec and API client stay in sync                          |
| PostgreSQL 16-alpine for Docker                        | 01-03   | Lightweight image with latest stable Postgres                             |
| Detect social vs wallet via authConnection             | 02-02   | Web3Auth v10 uses authConnection, not deprecated typeOfLogin              |
| Auth token in memory only (Zustand)                    | 02-02   | XSS prevention - no localStorage for sensitive tokens                     |
| Token refresh queue pattern                            | 02-02   | Handle concurrent 401s without race conditions                            |
| Dual JWKS endpoints for Web3Auth                       | 02-01   | Different endpoints for social vs external wallet logins                  |
| Refresh tokens searchable without access token         | 02-01   | Better UX - can refresh even with expired access token                    |
| Token rotation on every refresh                        | 02-01   | Security - prevents token reuse attacks                                   |
| HTTP-only cookie with path=/auth for refresh token     | 02-03   | Refresh token only sent to auth endpoints, XSS prevention                 |
| CORS credentials enabled                               | 02-03   | Cross-origin cookie handling between frontend and backend                 |
| ADR-001: Signature-derived keys for external wallets   | 02-04   | EIP-712 signature + HKDF derives secp256k1 keypair for ECIES              |
| Chain-agnostic EIP-712 domain                          | 02-04   | No chainId ensures consistent key derivation across networks              |
| Memory-only derived key storage                        | 02-04   | Re-derive keypair on page refresh, never persist to storage               |
| Account linking via Web3Auth grouped connections       | 02-04   | No custom implementation needed - handled at authentication layer         |
| ADR-002: Web3Auth MFA scoped for post-v1.0             | 02-04   | Phase 11 - passkey, TOTP, recovery phrase via tKey SDK                    |
| eciesjs for ECIES operations                           | 03-01   | Built on audited @noble/curves, single function API                       |
| Buffer to Uint8Array conversion in crypto              | 03-01   | eciesjs returns Buffer; convert for consistent API                        |
| ArrayBuffer casting for TypeScript 5.9                 | 03-01   | Web Crypto API requires explicit ArrayBuffer type                         |
| Uncompressed public keys (65 bytes, 0x04 prefix)       | 03-01   | secp256k1 standard format, validated before crypto ops                    |
| Generic error messages in crypto                       | 03-01   | Prevent oracle attacks - all failures say "Encryption/Decryption failed"  |
| Ed25519 verification returns false for invalid         | 03-02   | Returns boolean, not exception - consistent with oracle attack prevention |
| IPNS signature prefix per IPFS spec                    | 03-02   | "ipns-signature:" concatenated before signing CBOR data                   |
| Deterministic Ed25519 signatures                       | 03-02   | Same key + same message always produces identical signature               |
| CipherBox-v1 salt for HKDF                             | 03-03   | Static salt provides domain separation for all key derivations            |
| Folder keys are random not derived                     | 03-03   | Per CONTEXT.md, folder keys randomly generated then ECIES-wrapped         |
| File keys random per-file                              | 03-03   | No deduplication per CRYPT-06 - each file gets unique random key          |
| VaultInit vs EncryptedVaultKeys separation             | 03-03   | Clear distinction between in-memory keys and server storage format        |
| fetch + form-data for Pinata API                       | 04-01   | SDK adds overhead; direct API calls are simpler                           |
| CIDv1 always for IPFS pins                             | 04-01   | Modern IPFS standard, future-proof                                        |
| 404 as success for unpin                               | 04-01   | Idempotent behavior - if already unpinned, operation succeeded            |
| Vault stores encrypted keys as BYTEA                   | 04-02   | Direct binary storage, hex encoding only at API boundary                  |
| PinnedCid sizeBytes as bigint                          | 04-02   | TypeORM returns as string to avoid JavaScript precision issues            |
| Quota calculated on-demand via SUM                     | 04-02   | No cached field, acceptable for 500 MiB limit                             |
| VaultService exported from module                      | 04-02   | Allows IpfsModule to use recordPin/recordUnpin                            |
| Sequential file uploads                                | 04-03   | One file at a time per CONTEXT.md (parallel deferred)                     |
| ArrayBuffer cast for TypeScript 5.9                    | 04-03   | Uint8Array.buffer returns ArrayBufferLike, explicit cast for Blob         |
| Pre-check quota before upload                          | 04-03   | Fail fast if total file size exceeds remaining quota                      |
| axios CancelToken for upload cancellation              | 04-03   | Standard pattern for aborting in-flight requests                          |
| Pinata gateway direct fetch for downloads              | 04-04   | No backend relay needed for reading public IPFS content                   |
| Stream progress only with Content-Length               | 04-04   | Falls back to simple arrayBuffer if header not present                    |
| File key cleared after decryption                      | 04-04   | Security - clearBytes() called in finally block                           |
| Jose module mock via moduleNameMapper                  | 04.1-01 | ESM jose module mocked to avoid transformation issues                     |
| Real argon2 in tests for correctness                   | 04.1-01 | Per TESTING.md, don't mock crypto - accept slower tests for correctness   |
| Test.createTestingModule for constructor tests         | 04.1-01 | Validates constructor throws when config missing                          |
| Controller tests mock service layer completely         | 04.1-03 | Controllers are thin wiring layers; tests verify request handling         |
| Auth service branch threshold 84% (actual 84.61%)      | 04.1-03 | One edge case in derivationVersion null check uncovered                   |
| Controller branch threshold 65%                        | 04.1-03 | Swagger decorators inflate uncovered branches in coverage                 |
| Coverage exclusions for modules, DTOs, entities        | 04.1-03 | These are configuration/definitions, not logic requiring tests            |
| Provider pattern for IPFS backends                     | 04.2-01 | IpfsProvider interface with PinataProvider and LocalProvider              |
| @Inject(IPFS_PROVIDER) token injection                 | 04.2-01 | Avoids silent failures with class-based injection                         |
| Kubo API POST for all operations                       | 04.2-01 | Kubo RPC uses POST (not REST), even for cat and unpin                     |
| IPFS_PROVIDER env var for backend selection            | 04.2-01 | 'local' or 'pinata' switches provider implementation                      |
| Kubo API port localhost-only                           | 04.2-01 | 5001 bound to 127.0.0.1 for security (admin-level access)                 |
| Unique (userId, ipnsName) constraint                   | 05-01   | Ensures each folder tracked uniquely per user                             |
| sequenceNumber as bigint string                        | 05-01   | TypeORM returns bigint as string; service uses BigInt() for increment     |
| encryptedIpnsPrivateKey only on first publish          | 05-01   | Reduces payload; key stored once for TEE republishing                     |
| Exponential backoff for delegated routing              | 05-01   | Max 3 retries with increasing delay for rate limits                       |
| ipns npm package for record creation                   | 05-02   | Handles CBOR/protobuf/signatures correctly - don't hand-roll              |
| Ed25519 64-byte libp2p format                          | 05-02   | concat(privateKey, publicKey) for libp2p compatibility                    |
| V1+V2 compatible IPNS signatures                       | 05-02   | v1Compatible: true for maximum network compatibility                      |
| IPNS names base32 (bafzaa...)                          | 05-02   | libp2p default; both base32 and base36 (k51...) are valid                 |
| FolderMetadata JSON serialization                      | 05-02   | Simple, debuggable; size overhead acceptable for metadata                 |
| VaultStore memory-only keys                            | 05-03   | Security - never persist sensitive keys to storage                        |
| FolderNode includes decrypted keys                     | 05-03   | Enable folder operations without re-deriving                              |
| Local IPNS signing with backend relay                  | 05-03   | Server never sees IPNS private keys                                       |
| MAX_FOLDER_DEPTH=20 in createFolder                    | 05-03   | Enforces FOLD-03 depth limit                                              |
| deleteFileFromFolder renamed                           | 05-04   | Avoid export conflict with delete.service.ts                              |
| add-before-remove pattern for moves                    | 05-04   | Prevents data loss - add to dest first, then remove from source           |
| Fire-and-forget unpin on delete                        | 05-04   | Don't block user on IPFS cleanup                                          |
| isDescendantOf prevents circular moves                 | 05-04   | Prevents moving folder into itself or descendants                         |
| Single selection mode per CONTEXT.md                   | 06-01   | No multi-select for v1 - keep UI simple                                   |
| Folders sorted first then files alphabetically         | 06-01   | Standard file manager behavior using localeCompare                        |
| CSS Grid for file list columns                         | 06-01   | Name flex, size 100px, date 150px - responsive layout                     |
| Mobile sidebar overlay at 768px breakpoint             | 06-01   | Per CONTEXT.md auto-collapse on mobile                                    |
| Portal-based Modal renders outside component tree      | 06-02   | Avoid z-index and overflow issues                                         |
| Focus trap in Modal                                    | 06-02   | Accessibility - prevent tab from leaving modal                            |
| 100MB maxSize in react-dropzone                        | 06-02   | Per FILE-01 spec, enforced at library level                               |
| V1 simplified upload modal                             | 06-02   | Per CONTEXT.md "keep v1 simple" - shows current file only                 |
| floating-ui/react for context menu positioning         | 06-03   | Built-in flip/shift middleware handles edge detection                     |
| Delete always confirms with modal dialog               | 06-03   | Per CONTEXT.md - prevents accidental data loss                            |
| Folder delete warning includes contents                | 06-03   | Users need to know subfolders/files will also be deleted                  |
| FileEntry to FileMetadata field mapping                | 06-03   | Download service expects different field names than folder metadata       |
| Simple back arrow breadcrumbs for v1                   | 06-04   | Per CONTEXT.md, full path dropdown deferred to future enhancement         |
| 768px mobile breakpoint for responsive design          | 06-04   | Standard tablet breakpoint, sidebar overlay on mobile                     |
| 500ms long-press for touch context menu                | 06-04   | Touch gesture threshold for mobile context menu activation                |
| Storage state pattern for E2E auth                     | 06.1-03 | Manual login once, save state, reuse for fast tests                       |
| Skip interactive Web3Auth tests in CI                  | 06.1-03 | Email OTP requires manual entry; CI uses pre-generated storage state      |
| ESM for E2E test files                                 | 06.1-03 | Consistent with monorepo type:module, avoids require() issues             |
| Separate E2E workspace package                         | 06.1-03 | Isolated dependencies, independent test execution from unit tests         |
| Multi-browser testing (Chromium/Firefox/WebKit)        | 06.1-03 | Cross-browser compatibility validation catches browser-specific bugs      |
| CSS Grid with 180px sidebar                            | 06.3-01 | Fixed layout with header/sidebar/main/footer areas, only main scrolls     |
| Hover-triggered UserMenu dropdown                      | 06.3-01 | Per CONTEXT.md decision, onMouseEnter/Leave not onClick                   |
| Terminal ASCII icons [DIR] [CFG]                       | 06.3-01 | Nav items use bracket-wrapped labels for terminal aesthetic               |
| Mobile breakpoint 768px hides sidebar                  | 06.3-01 | Single column layout on mobile, sidebar removed from grid                 |
| URL-based folder navigation via useParams              | 06.3-02 | Browser back/forward works for folder navigation history                  |
| /files/:folderId? route pattern                        | 06.3-02 | Root folder at /files, subfolders at /files/:folderId                     |
| 3-column file list layout (Name/Size/Modified)         | 06.3-03 | TYPE column removed per CONTEXT.md decision                               |
| Parent navigation via [..] row not breadcrumb          | 06.3-03 | Back button removed from breadcrumbs, [..] row for parent navigation      |
| Breadcrumbs show full path ~/root/path lowercase       | 06.3-03 | Terminal aesthetic with lowercase folder names                            |
| ASCII art folder icon for empty state                  | 06.3-03 | Terminal-style ASCII art instead of emoji for empty state                 |
| FileBrowser removes FolderTree entirely                | 06.3-04 | Sidebar removed, in-place navigation via [..] row                         |
| Deprecated components marked with @deprecated          | 06.3-04 | FolderTree, FolderTreeNode, ApiStatusIndicator for future cleanup         |
| 2-column mobile file list                              | 06.3-04 | Date column hidden on mobile for space efficiency                         |
| AppShell overlay sidebar pattern                       | 06.3-04 | Fixed position with translateX for mobile slide-in animation              |
| Visual verification via Playwright MCP                 | 06.3-05 | All must_haves verified programmatically before approval                  |
| [..] row absent in empty folders accepted              | 06.3-05 | Minor UX issue - users can navigate via breadcrumbs or browser back       |
| Pause polling when tab backgrounded                    | 07-02   | Battery optimization per RESEARCH.md, set delay to null when hidden       |
| Immediate sync on focus regain                         | 07-02   | Per RESEARCH.md recommendation, poll immediately when user returns        |
| Immediate sync on reconnect                            | 07-02   | Per CONTEXT.md auto-sync when connection returns                          |
| useRef for callback tracking                           | 07-02   | Prevents stale callback closure issue in setInterval                      |
| SSR guards on visibility/online hooks                  | 07-02   | typeof document/navigator checks prevent SSR errors                       |
| resolveIpnsRecord uses generated API client            | 07-03   | Type-safe IPNS resolution via backend, null for 404/not found             |
| SyncIndicator in toolbar actions area                  | 07-03   | Compact 16px icons next to upload, matches terminal aesthetic             |
| Offline banner terminal colors                         | 07-03   | Amber on dark (#3d2e0a bg, #fcd34d text) for offline state                |
| Full metadata refresh deferred                         | 07-03   | Sync detection complete; refresh requires decryption logic extraction     |
| Sequence number comparison for sync                    | 07-04   | Used sequenceNumber instead of CID - local CID not cached, seq always inc |
| useFolderStore.getState() in async callback            | 07-04   | Avoid stale closure issues when accessing store from async handleSync     |
| Silent sync error handling                             | 07-04   | Log errors but don't crash - 30s interval auto-retries                    |
| Atomic upload: quota + pin + record in one request     | 7.1-01  | Eliminates gap where file can be pinned but never recorded for quota      |
| VaultModule imported into IpfsModule                   | 7.1-01  | Cross-module import for VaultService access in IpfsController             |
| Batch addFiles coexists with single addFile            | 7.1-02  | Both remain exported from useFolder for different code paths              |
| Server-authoritative quota via fetchQuota              | 7.1-02  | fetchQuota after upload replaces optimistic per-file addUsage             |
| All-or-nothing batch folder registration               | 7.1-02  | Single IPNS publish for N files, no partial failure handling              |
| Singleton-row pattern for tee_key_state                | 08-01   | One row tracks current/previous epoch, queried with find({ take: 1 })     |
| DataSource.transaction for epoch rotation              | 08-01   | Atomic shift current->previous + rotation log insert                      |
| 4-week grace period for TEE key rotation               | 08-01   | GRACE_PERIOD_MS constant, matches spec for seamless migration             |
| Base64 encoding for TEE worker public key transport    | 08-01   | TEE worker returns base64, backend decodes and validates 65-byte format   |
| TEE_WORKER_URL defaults to localhost:3001              | 08-01   | Local dev with simulator, configurable for production                     |
| Graceful TEE initialization via OnModuleInit           | 08-01   | Try/catch in module init, log warning if TEE unavailable, never crash     |
| TEE keys delivered via vault endpoint                  | 08-03   | No separate endpoint; delivered in GET/POST vault response                |
| wrapKey reused for TEE key encryption                  | 08-03   | Same ECIES as user key wrapping; TEE public key is secp256k1              |
| Initial empty IPNS publish on folder creation          | 08-03   | Immediately enrolls new folder for TEE republishing                       |
| Root folder TEE enrollment deferred                    | 08-03   | Handled only for subfolders in v1; root deferred to follow-up             |
| BATCH_SIZE=50 for TEE republish requests               | 08-02   | Avoid CVM proxy timeout per RESEARCH.md pitfall 4                         |
| MAX_CONSECUTIVE_FAILURES=10 before stale               | 08-02   | Balance between retry persistence and giving up on broken entries         |
| Separate TEE signing from IPNS publishing              | 08-02   | Independent retry per RESEARCH.md pitfall 6                               |
| BullModule.forRootAsync globally, registerQueue local  | 08-02   | Redis connection shared, queue scoped to RepublishModule                  |
| Graceful cron registration on Redis unavailability     | 08-02   | Warn and continue, never crash API if Redis is down                       |
| Admin health uses JwtAuthGuard only (no admin role)    | 08-02   | Full admin role check deferred for v1 tech demo                           |
| Redis 7-alpine bound to 127.0.0.1 only                 | 08-02   | Security: local dev only, not exposed to network                          |
| Type declarations for @phala/dstack-sdk in dev         | 08-04   | SDK only available in CVM at runtime, not needed for compilation          |
| Timing-safe auth comparison in TEE worker              | 08-04   | Prevent timing attacks on shared secret comparison                        |
| 48-hour IPNS record lifetime for TEE republish         | 08-04   | Comfortable margin with 6-hour republish interval (vs 24h client)         |
| Per-entry error handling in batch republish            | 08-04   | One failure does not block other entries in the batch                     |
| Public key cache in TEE worker memory                  | 08-04   | Map<epoch, publicKey> avoids repeated HKDF for same epoch                 |
| ESM module type for TEE worker                         | 08-04   | type:module with bundler moduleResolution for standalone deployment       |
| X-Client-Type: desktop header for body-based tokens    | 09-03   | Desktop clients send refreshToken in body instead of cookie               |
| Controller-only auth changes for desktop support       | 09-03   | AuthService unchanged; controller switches token delivery based on header |
| fuser optional via cargo feature flag                  | 09-01   | FUSE-T required on macOS to compile fuser; optional until plan 09-03      |
| multihash 0.19 without identity feature                | 09-01   | Identity hash code is a constant, not a feature gate in multihash 0.19    |
| Tauri v2 top-level identifier (not bundle.identifier)  | 09-01   | Tauri v2 moved identifier to top-level config                             |
| Placeholder icons for Tauri compile-time validation    | 09-01   | generate_context!() macro requires icon files to exist at build time      |
| Manual protobuf encoding for IPNS records              | 09-02   | Direct byte encoding for exact field number control without .proto file   |
| Manual base36 encoding via big-integer division        | 09-02   | Simple algorithm, avoids multibase crate dependency                       |
| CBOR field order matches ipns npm package              | 09-02   | TTL,Value,Sequence,Validity,ValidityType ordering for compatibility       |
| ecies crate v0.2 cross-compatible with eciesjs         | 09-02   | Verified via cross-language test vector (TS wrap, Rust unwrap)            |
| Pre-computed test vectors from TypeScript              | 09-02   | Generate once with script, hardcode hex constants in Rust tests           |
| Web3Auth in webview, not system browser                | 09-04   | Private key stays in-process via Tauri IPC, no insecure URL transit       |
| Silent refresh is API-only on cold start               | 09-04   | Private key not restorable from Keychain; full Web3Auth login needed      |
| JWT sub extraction without verification                | 09-04   | Server already verified; manual base64url decode avoids JWT library       |
| Dynamic Web3Auth SDK import in desktop webview         | 09-04   | Graceful handling when SDK not installed via await import()               |
| secp256k1 pubkey derivation via ecies crate exports    | 09-04   | Reuses ecies SecretKey/PublicKey, avoids additional crypto dependency     |
| fuser optional via cargo feature flag for FUSE         | 09-05   | FUSE-T must be installed on macOS; cache/inode modules compile without    |
| Cache and inode modules always compiled                | 09-05   | Not gated behind fuse feature; unit tests run on any machine              |
| EncryptedFolderMetadata JSON with hex IV + base64 data | 09-05   | Rust decodes hex IV, base64 ciphertext, then AES-256-GCM decrypts         |
| open() is read-only; EACCES for write flags            | 09-05   | Write support deferred to plan 09-06                                      |
| block_on for FUSE-thread operations                    | 09-05   | Init and read use rt.block_on(); background refresh uses rt.spawn()       |
| IpnsPublishRequest matches backend PublishIpnsDto      | 09-06   | Backend expects ipnsName, record (base64), metadataCid, not plan fields   |
| Encrypted metadata JSON: { iv: hex, data: base64 }     | 09-06   | seal_aes_gcm split: iv=hex(sealed[..12]), data=base64(sealed[12..])       |
| name_to_ino made public for rename manipulation        | 09-06   | Rename operations need direct HashMap access for index updates            |
| Temp-file commit model for FUSE writes                 | 09-06   | Writes buffer to local temp file, encrypt+upload only on release()        |
| Per-folder IPNS signing from inode data                | 09-06   | Each folder's Ed25519 key stored in InodeKind, not global state           |
| Baseline migration timestamp 1700000000000             | 09.1-03 | Precedes incremental migrations; fresh DB gets full schema first          |
| Full schema includes final column states               | 09.1-03 | tokenPrefix and nullable TEE fields already present; incrementals no-op   |
| Multi-stage Dockerfile (deps/build/production)         | 09.1-02 | Minimal image size, non-root user, monorepo root as build context         |
| GHCR image references with OWNER variable              | 09.1-02 | Deploy workflow substitutes actual GitHub repository owner at runtime     |
| All non-public ports bound to 127.0.0.1                | 09.1-02 | Security: only 80, 443, 4001 (IPFS swarm) exposed to internet             |
| Caddy with Cloudflare Origin CA (auto_https off)       | 09.1-02 | Cloudflare handles browser TLS; Caddy serves origin cert for CF-to-VPS    |
| NestJS Logger instead of nestjs-pino                   | 09.1-01 | Simpler, no new dependency; Grafana Alloy can ingest plain text logs      |
| TypeORM logging as array not boolean                   | 09.1-01 | Targeted: errors+warnings+migrations in dev, errors+migrations in prod    |
| CIPHERBOX_ENVIRONMENT for TEE simulator guard          | 09.1-01 | Decouples deployment tier from NODE_ENV for staging compatibility         |
| HashRouter for IPFS-hosted web app                     | 09.1-01 | IPFS gateways serve files by path; hash routing keeps routes in fragment  |
| VITE_ENVIRONMENT for frontend env detection            | 09.1-01 | NETWORK_CONFIG map selects devnet/mainnet based on deployment tier        |
| Grafana Alloy via Docker socket for log collection     | 09.1-06 | Read-only socket mount discovers containers and ships logs to Loki        |
| x-logging YAML anchor for DRY log rotation             | 09.1-06 | json-file driver, 10m max-size, 3 files applied to all 7 services         |
| Alloy credentials via environment variables            | 09.1-06 | GRAFANA_LOKI_URL/USERNAME/API_KEY from .env.staging, GitHub Secrets       |
| Programmatic migration runner for Docker containers    | 09.1-04 | run-migrations.ts with JS glob paths; production image lacks ts-node/npx  |
| Multi-stage TEE worker Dockerfile builds from source   | 09.1-04 | CI builds without separate pre-build step; node user for security         |
| curl-based Pinata directory upload in deploy workflow  | 09.1-04 | Portable, no CLI dependency; multipart form with CID capture              |
| SCP then SSH pattern for VPS deployment                | 09.1-04 | Separates file transfer from service orchestration for clarity            |

### Pending Todos

6 pending todo(s):

- `2026-01-23-simple-text-file-editor-modal.md` — Add simple text file editor modal (area: ui)
- `2026-02-07-web-worker-large-file-encryption.md` — Offload large file encryption to Web Worker (area: ui)
- `2026-02-09-client-side-ipns-signature-validation.md` — Add client-side IPNS signature validation (area: crypto) — GitHub #71
- `2026-02-10-fix-tee-critical-integration-bugs.md` — Fix TEE critical integration bugs C1/C2/H1 (area: api) — CRITICAL
- `2026-02-10-ipns-sequence-fallback-to-zero.md` — Fix IPNS sequence number fallback to 0 (area: desktop) — HIGH data integrity
- `2026-02-10-remove-debug-eprintln-statements.md` — Remove debug eprintln! statements from FUSE code (area: desktop)

### Completed Todos

- ~~`2026-01-22-atomic-file-upload-flow.md`~~ — Atomic file upload flow (**Resolved by Phase 7.1**)
- ~~`2026-01-23-pre-upload-file-validation.md`~~ — Pre-upload file name validation and duplicate prevention (**In progress**)
- ~~`2026-02-07-upload-modal-no-dismiss.md`~~ — Upload modal dismiss + button text stuck (**Fixed in PR #57**)
- ~~`2026-02-07-upload-button-text-stuck.md`~~ — (**Merged with above**)
- ~~`2026-02-07-auth-refresh-race-condition.md`~~ — Auth token refresh race condition (**Done**)
- ~~`2026-02-07-ipns-resolve-502-fallback.md`~~ — IPNS resolve 502 fallback (**Done**)
- ~~`2026-02-07-registering-state-stuck-on-error.md`~~ — Upload store stuck in "registering" (**Done**)
- ~~`2026-02-07-orphaned-ipfs-pins-on-failed-registration.md`~~ — Orphaned IPFS pins on failed registration (**Done**)

### Blockers/Concerns

**E2E Auth State Setup (06.1-03):**

- E2E tests require `.auth/user.json` with authenticated session
- Must be generated once manually via `pnpm test:headed` and completing Web3Auth login
- CI environments need pre-generated auth state or API-based test authentication
- Options: (1) commit auth state as CI secret, (2) create test auth endpoint, (3) mock Web3Auth

### Quick Tasks Completed

| #   | Description                            | Date       | Commit  | Directory                                                                                   |
| --- | -------------------------------------- | ---------- | ------- | ------------------------------------------------------------------------------------------- |
| 001 | Add API status indicator on login page | 2026-01-22 | 929143e | [001-login-page-api-status-indicator](./quick/001-login-page-api-status-indicator/)         |
| 002 | Fix empty state ASCII art              | 2026-02-07 | ff97f12 | [002-fix-empty-state-ascii-art](./quick/002-fix-empty-state-ascii-art/)                     |
| 003 | Fix subfolder navigation and upload    | 2026-02-09 | 95666db | [003-fix-subfolder-navigation-and-upload](./quick/003-fix-subfolder-navigation-and-upload/) |
| 004 | Add staging environment banner         | 2026-02-09 | 839179e | [004-add-staging-environment-banner](./quick/004-add-staging-environment-banner/)           |
| 005 | Align Pencil design with staging app   | 2026-02-09 | 3d0574b | [005-align-pencil-design-with-app](./quick/005-align-pencil-design-with-app/)               |
| 006 | Add file/folder details modal          | 2026-02-10 | 612c9f6 | [006-file-folder-details-modal](./quick/006-file-folder-details-modal/)                     |

### Research Flags (from research phase)

- IPNS resolution latency (~30s) may need deeper investigation during Phase 7
- Phala Cloud API integration may need deeper research during Phase 8
- macOS FUSE complexity - consider FUSE-T for Phase 9

### Roadmap Evolution

- Phase 4.1 inserted after Phase 4: API Service Testing (URGENT) - Add unit tests for backend services per .planning/codebase/TESTING.md coverage thresholds before continuing to Phase 5
- Phase 4.2 inserted: Local IPFS Testing Infrastructure - Add local IPFS node to Docker for offline testing (parallel work via worktree at ../cipher-box-phase-4.2)
- Phase 6.1 inserted after Phase 6: Webapp Automation Testing - E2E UI testing with automation framework
- Phase 6.2 inserted after Phase 6.1: Restyle App with Pencil Design - Complete UI redesign using Pencil design tool
- Phase 6.3 inserted after Phase 6.2: UI Structure Refactor - Page layouts, component hierarchy, toolbars, and navigation using Pencil MCP for design-first approach
- Phase 7.1 inserted after Phase 7: Atomic File Upload - Refactor multi-request upload into single atomic backend call with batch IPNS publishing (URGENT)
- Phase 9.1 inserted after Phase 9: Environment Changes, DevOps & Staging Deployment - CI/CD pipeline, environment config, staging deploy

## Session Continuity

Last session: 2026-02-10
Stopped at: Quick Task 006 complete — File/folder details modal added
Resume file: None
Next phase: Phase 10 - Data Portability

---

_State initialized: 2026-01-20_
_Last updated: 2026-02-10 after completing Quick Task 006 (Add file/folder details modal)_

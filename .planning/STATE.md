# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-20)

**Core value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext
**Current focus:** Phase 6.3 - UI Structure Refactor (inserted)

## Current Position

Phase: 6.3 of 11 (UI Structure Refactor)
Plan: 5 of 5 in Phase 6.3 complete
Status: Phase complete - UI restructure verified and approved
Last activity: 2026-01-30 - Completed 06.3-05-PLAN.md

Progress: [########..] 83% (39 of 47 plans)

## Performance Metrics

**Velocity:**

- Total plans completed: 39
- Average duration: 4.9 min
- Total execution time: 3.17 hours

**By Phase:**

| Phase                      | Plans | Total  | Avg/Plan |
| -------------------------- | ----- | ------ | -------- |
| 01-foundation              | 3/3   | 20 min | 7 min    |
| 02-authentication          | 4/4   | 18 min | 4.5 min  |
| 03-core-encryption         | 3/3   | 18 min | 6 min    |
| 04-file-storage            | 4/4   | 17 min | 4.3 min  |
| 04.1-api-service-testing   | 3/3   | 11 min | 3.7 min  |
| 04.2-local-ipfs-testing    | 2/2   | 14 min | 7 min    |
| 05-folder-system           | 4/4   | 18 min | 4.5 min  |
| 06-file-browser-ui         | 4/4   | 19 min | 4.8 min  |
| 06.1-webapp-automation     | 6/6   | 25 min | 4.2 min  |
| 06.3-ui-structure-refactor | 5/5   | 16 min | 3.2 min  |

**Recent Trend:**

- Last 5 plans: 2m, 3m, 4m, 6m, 3m
- Trend: Consistent, stable

Updated after each plan completion.

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

| Decision                                             | Phase   | Rationale                                                                 |
| ---------------------------------------------------- | ------- | ------------------------------------------------------------------------- |
| Override moduleResolution to 'node' for NestJS apps  | 01-01   | Base tsconfig uses bundler which is incompatible with CommonJS            |
| Generate OpenAPI spec using minimal module           | 01-01   | Avoids requiring live database during build                               |
| Pre-configure API tags in OpenAPI                    | 01-01   | Placeholder tags for Auth, Vault, Files, IPFS, IPNS                       |
| Use React 18.3.1 per project spec                    | 01-02   | Not React 19 - staying on stable LTS version                              |
| orval tags-split mode for API client                 | 01-02   | Generates separate files per API tag for better organization              |
| Custom fetch instance for API calls                  | 01-02   | Allows future auth header injection without modifying generated code      |
| ESLint 9 flat config format                          | 01-03   | Modern, simpler configuration at monorepo root                            |
| CI api-spec job verifies generated files             | 01-03   | Ensures OpenAPI spec and API client stay in sync                          |
| PostgreSQL 16-alpine for Docker                      | 01-03   | Lightweight image with latest stable Postgres                             |
| Detect social vs wallet via authConnection           | 02-02   | Web3Auth v10 uses authConnection, not deprecated typeOfLogin              |
| Auth token in memory only (Zustand)                  | 02-02   | XSS prevention - no localStorage for sensitive tokens                     |
| Token refresh queue pattern                          | 02-02   | Handle concurrent 401s without race conditions                            |
| Dual JWKS endpoints for Web3Auth                     | 02-01   | Different endpoints for social vs external wallet logins                  |
| Refresh tokens searchable without access token       | 02-01   | Better UX - can refresh even with expired access token                    |
| Token rotation on every refresh                      | 02-01   | Security - prevents token reuse attacks                                   |
| HTTP-only cookie with path=/auth for refresh token   | 02-03   | Refresh token only sent to auth endpoints, XSS prevention                 |
| CORS credentials enabled                             | 02-03   | Cross-origin cookie handling between frontend and backend                 |
| ADR-001: Signature-derived keys for external wallets | 02-04   | EIP-712 signature + HKDF derives secp256k1 keypair for ECIES              |
| Chain-agnostic EIP-712 domain                        | 02-04   | No chainId ensures consistent key derivation across networks              |
| Memory-only derived key storage                      | 02-04   | Re-derive keypair on page refresh, never persist to storage               |
| Account linking via Web3Auth grouped connections     | 02-04   | No custom implementation needed - handled at authentication layer         |
| ADR-002: Web3Auth MFA scoped for post-v1.0           | 02-04   | Phase 11 - passkey, TOTP, recovery phrase via tKey SDK                    |
| eciesjs for ECIES operations                         | 03-01   | Built on audited @noble/curves, single function API                       |
| Buffer to Uint8Array conversion in crypto            | 03-01   | eciesjs returns Buffer; convert for consistent API                        |
| ArrayBuffer casting for TypeScript 5.9               | 03-01   | Web Crypto API requires explicit ArrayBuffer type                         |
| Uncompressed public keys (65 bytes, 0x04 prefix)     | 03-01   | secp256k1 standard format, validated before crypto ops                    |
| Generic error messages in crypto                     | 03-01   | Prevent oracle attacks - all failures say "Encryption/Decryption failed"  |
| Ed25519 verification returns false for invalid       | 03-02   | Returns boolean, not exception - consistent with oracle attack prevention |
| IPNS signature prefix per IPFS spec                  | 03-02   | "ipns-signature:" concatenated before signing CBOR data                   |
| Deterministic Ed25519 signatures                     | 03-02   | Same key + same message always produces identical signature               |
| CipherBox-v1 salt for HKDF                           | 03-03   | Static salt provides domain separation for all key derivations            |
| Folder keys are random not derived                   | 03-03   | Per CONTEXT.md, folder keys randomly generated then ECIES-wrapped         |
| File keys random per-file                            | 03-03   | No deduplication per CRYPT-06 - each file gets unique random key          |
| VaultInit vs EncryptedVaultKeys separation           | 03-03   | Clear distinction between in-memory keys and server storage format        |
| fetch + form-data for Pinata API                     | 04-01   | SDK adds overhead; direct API calls are simpler                           |
| CIDv1 always for IPFS pins                           | 04-01   | Modern IPFS standard, future-proof                                        |
| 404 as success for unpin                             | 04-01   | Idempotent behavior - if already unpinned, operation succeeded            |
| Vault stores encrypted keys as BYTEA                 | 04-02   | Direct binary storage, hex encoding only at API boundary                  |
| PinnedCid sizeBytes as bigint                        | 04-02   | TypeORM returns as string to avoid JavaScript precision issues            |
| Quota calculated on-demand via SUM                   | 04-02   | No cached field, acceptable for 500 MiB limit                             |
| VaultService exported from module                    | 04-02   | Allows IpfsModule to use recordPin/recordUnpin                            |
| Sequential file uploads                              | 04-03   | One file at a time per CONTEXT.md (parallel deferred)                     |
| ArrayBuffer cast for TypeScript 5.9                  | 04-03   | Uint8Array.buffer returns ArrayBufferLike, explicit cast for Blob         |
| Pre-check quota before upload                        | 04-03   | Fail fast if total file size exceeds remaining quota                      |
| axios CancelToken for upload cancellation            | 04-03   | Standard pattern for aborting in-flight requests                          |
| Pinata gateway direct fetch for downloads            | 04-04   | No backend relay needed for reading public IPFS content                   |
| Stream progress only with Content-Length             | 04-04   | Falls back to simple arrayBuffer if header not present                    |
| File key cleared after decryption                    | 04-04   | Security - clearBytes() called in finally block                           |
| Jose module mock via moduleNameMapper                | 04.1-01 | ESM jose module mocked to avoid transformation issues                     |
| Real argon2 in tests for correctness                 | 04.1-01 | Per TESTING.md, don't mock crypto - accept slower tests for correctness   |
| Test.createTestingModule for constructor tests       | 04.1-01 | Validates constructor throws when config missing                          |
| Controller tests mock service layer completely       | 04.1-03 | Controllers are thin wiring layers; tests verify request handling         |
| Auth service branch threshold 84% (actual 84.61%)    | 04.1-03 | One edge case in derivationVersion null check uncovered                   |
| Controller branch threshold 65%                      | 04.1-03 | Swagger decorators inflate uncovered branches in coverage                 |
| Coverage exclusions for modules, DTOs, entities      | 04.1-03 | These are configuration/definitions, not logic requiring tests            |
| Provider pattern for IPFS backends                   | 04.2-01 | IpfsProvider interface with PinataProvider and LocalProvider              |
| @Inject(IPFS_PROVIDER) token injection               | 04.2-01 | Avoids silent failures with class-based injection                         |
| Kubo API POST for all operations                     | 04.2-01 | Kubo RPC uses POST (not REST), even for cat and unpin                     |
| IPFS_PROVIDER env var for backend selection          | 04.2-01 | 'local' or 'pinata' switches provider implementation                      |
| Kubo API port localhost-only                         | 04.2-01 | 5001 bound to 127.0.0.1 for security (admin-level access)                 |
| Unique (userId, ipnsName) constraint                 | 05-01   | Ensures each folder tracked uniquely per user                             |
| sequenceNumber as bigint string                      | 05-01   | TypeORM returns bigint as string; service uses BigInt() for increment     |
| encryptedIpnsPrivateKey only on first publish        | 05-01   | Reduces payload; key stored once for TEE republishing                     |
| Exponential backoff for delegated routing            | 05-01   | Max 3 retries with increasing delay for rate limits                       |
| ipns npm package for record creation                 | 05-02   | Handles CBOR/protobuf/signatures correctly - don't hand-roll              |
| Ed25519 64-byte libp2p format                        | 05-02   | concat(privateKey, publicKey) for libp2p compatibility                    |
| V1+V2 compatible IPNS signatures                     | 05-02   | v1Compatible: true for maximum network compatibility                      |
| IPNS names base32 (bafzaa...)                        | 05-02   | libp2p default; both base32 and base36 (k51...) are valid                 |
| FolderMetadata JSON serialization                    | 05-02   | Simple, debuggable; size overhead acceptable for metadata                 |
| VaultStore memory-only keys                          | 05-03   | Security - never persist sensitive keys to storage                        |
| FolderNode includes decrypted keys                   | 05-03   | Enable folder operations without re-deriving                              |
| Local IPNS signing with backend relay                | 05-03   | Server never sees IPNS private keys                                       |
| MAX_FOLDER_DEPTH=20 in createFolder                  | 05-03   | Enforces FOLD-03 depth limit                                              |
| deleteFileFromFolder renamed                         | 05-04   | Avoid export conflict with delete.service.ts                              |
| add-before-remove pattern for moves                  | 05-04   | Prevents data loss - add to dest first, then remove from source           |
| Fire-and-forget unpin on delete                      | 05-04   | Don't block user on IPFS cleanup                                          |
| isDescendantOf prevents circular moves               | 05-04   | Prevents moving folder into itself or descendants                         |
| Single selection mode per CONTEXT.md                 | 06-01   | No multi-select for v1 - keep UI simple                                   |
| Folders sorted first then files alphabetically       | 06-01   | Standard file manager behavior using localeCompare                        |
| CSS Grid for file list columns                       | 06-01   | Name flex, size 100px, date 150px - responsive layout                     |
| Mobile sidebar overlay at 768px breakpoint           | 06-01   | Per CONTEXT.md auto-collapse on mobile                                    |
| Portal-based Modal renders outside component tree    | 06-02   | Avoid z-index and overflow issues                                         |
| Focus trap in Modal                                  | 06-02   | Accessibility - prevent tab from leaving modal                            |
| 100MB maxSize in react-dropzone                      | 06-02   | Per FILE-01 spec, enforced at library level                               |
| V1 simplified upload modal                           | 06-02   | Per CONTEXT.md "keep v1 simple" - shows current file only                 |
| floating-ui/react for context menu positioning       | 06-03   | Built-in flip/shift middleware handles edge detection                     |
| Delete always confirms with modal dialog             | 06-03   | Per CONTEXT.md - prevents accidental data loss                            |
| Folder delete warning includes contents              | 06-03   | Users need to know subfolders/files will also be deleted                  |
| FileEntry to FileMetadata field mapping              | 06-03   | Download service expects different field names than folder metadata       |
| Simple back arrow breadcrumbs for v1                 | 06-04   | Per CONTEXT.md, full path dropdown deferred to future enhancement         |
| 768px mobile breakpoint for responsive design        | 06-04   | Standard tablet breakpoint, sidebar overlay on mobile                     |
| 500ms long-press for touch context menu              | 06-04   | Touch gesture threshold for mobile context menu activation                |
| Storage state pattern for E2E auth                   | 06.1-03 | Manual login once, save state, reuse for fast tests                       |
| Skip interactive Web3Auth tests in CI                | 06.1-03 | Email OTP requires manual entry; CI uses pre-generated storage state      |
| ESM for E2E test files                               | 06.1-03 | Consistent with monorepo type:module, avoids require() issues             |
| Separate E2E workspace package                       | 06.1-03 | Isolated dependencies, independent test execution from unit tests         |
| Multi-browser testing (Chromium/Firefox/WebKit)      | 06.1-03 | Cross-browser compatibility validation catches browser-specific bugs      |
| CSS Grid with 180px sidebar                          | 06.3-01 | Fixed layout with header/sidebar/main/footer areas, only main scrolls     |
| Hover-triggered UserMenu dropdown                    | 06.3-01 | Per CONTEXT.md decision, onMouseEnter/Leave not onClick                   |
| Terminal ASCII icons [DIR] [CFG]                     | 06.3-01 | Nav items use bracket-wrapped labels for terminal aesthetic               |
| Mobile breakpoint 768px hides sidebar                | 06.3-01 | Single column layout on mobile, sidebar removed from grid                 |
| URL-based folder navigation via useParams            | 06.3-02 | Browser back/forward works for folder navigation history                  |
| /files/:folderId? route pattern                      | 06.3-02 | Root folder at /files, subfolders at /files/:folderId                     |
| 3-column file list layout (Name/Size/Modified)       | 06.3-03 | TYPE column removed per CONTEXT.md decision                               |
| Parent navigation via [..] row not breadcrumb        | 06.3-03 | Back button removed from breadcrumbs, [..] row for parent navigation      |
| Breadcrumbs show full path ~/root/path lowercase     | 06.3-03 | Terminal aesthetic with lowercase folder names                            |
| ASCII art folder icon for empty state                | 06.3-03 | Terminal-style ASCII art instead of emoji for empty state                 |
| FileBrowser removes FolderTree entirely              | 06.3-04 | Sidebar removed, in-place navigation via [..] row                         |
| Deprecated components marked with @deprecated        | 06.3-04 | FolderTree, FolderTreeNode, ApiStatusIndicator for future cleanup         |
| 2-column mobile file list                            | 06.3-04 | Date column hidden on mobile for space efficiency                         |
| AppShell overlay sidebar pattern                     | 06.3-04 | Fixed position with translateX for mobile slide-in animation              |
| Visual verification via Playwright MCP               | 06.3-05 | All must_haves verified programmatically before approval                  |
| [..] row absent in empty folders accepted            | 06.3-05 | Minor UX issue - users can navigate via breadcrumbs or browser back       |

### Pending Todos

4 pending todo(s):

- `2026-01-22-atomic-file-upload-flow.md` — Atomic file upload flow with client-side CID (area: api)
- `2026-01-23-pre-upload-file-validation.md` — Pre-upload file name validation and duplicate prevention (area: ui)
- `2026-01-23-simple-text-file-editor-modal.md` — Add simple text file editor modal (area: ui)
- ~~`2026-01-21-local-ipfs-node-for-testing.md` — Add local IPFS node to Docker stack for testing (area: api)~~ - **COMPLETED: Phase 4.2**

### Blockers/Concerns

**E2E Auth State Setup (06.1-03):**

- E2E tests require `.auth/user.json` with authenticated session
- Must be generated once manually via `pnpm test:headed` and completing Web3Auth login
- CI environments need pre-generated auth state or API-based test authentication
- Options: (1) commit auth state as CI secret, (2) create test auth endpoint, (3) mock Web3Auth

### Quick Tasks Completed

| #   | Description                            | Date       | Commit  | Directory                                                                           |
| --- | -------------------------------------- | ---------- | ------- | ----------------------------------------------------------------------------------- |
| 001 | Add API status indicator on login page | 2026-01-22 | 929143e | [001-login-page-api-status-indicator](./quick/001-login-page-api-status-indicator/) |

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

## Session Continuity

Last session: 2026-01-30
Stopped at: Completed 06.3-05-PLAN.md - Phase 6.3 complete (visual verification passed)
Resume file: None
Next plan: Phase 7 (TEE Integration) or next priority phase

---

_State initialized: 2026-01-20_
_Last updated: 2026-01-30 after 06.3-05 completion (Phase 6.3 complete)_

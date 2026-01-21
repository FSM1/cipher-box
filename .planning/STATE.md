# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-20)

**Core value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext
**Current focus:** Phase 5 Folder System - COMPLETE

## Current Position

Phase: 5 of 11 (Folder System) - COMPLETE
Plan: 4 of 4 in Phase 5 complete
Status: Phase 5 complete - folder system infrastructure ready
Last activity: 2026-01-21 - Phase 5 verified and complete

Progress: [#####.....] 51% (23 of 45 plans)

## Performance Metrics

**Velocity:**

- Total plans completed: 23
- Average duration: 4.4 min
- Total execution time: 1.7 hours

**By Phase:**

| Phase                    | Plans | Total  | Avg/Plan |
| ------------------------ | ----- | ------ | -------- |
| 01-foundation            | 3/3   | 20 min | 7 min    |
| 02-authentication        | 4/4   | 18 min | 4.5 min  |
| 03-core-encryption       | 3/3   | 18 min | 6 min    |
| 04-file-storage          | 4/4   | 17 min | 4.3 min  |
| 04.1-api-service-testing | 3/3   | 11 min | 3.7 min  |
| 04.2-local-ipfs-testing  | 2/2   | 14 min | 7 min    |
| 05-folder-system         | 4/4   | 18 min | 4.5 min  |

**Recent Trend:**

- Last 5 plans: 6m, 4m, 6m, 4m, 4m
- Trend: Consistent

_Updated after each plan completion_

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

### Pending Todos

0 pending todo(s):

- ~~`2026-01-21-local-ipfs-node-for-testing.md` — Add local IPFS node to Docker stack for testing (area: api)~~ - **COMPLETED: Phase 4.2**

### Blockers/Concerns

None yet.

### Research Flags (from research phase)

- IPNS resolution latency (~30s) may need deeper investigation during Phase 7
- Phala Cloud API integration may need deeper research during Phase 8
- macOS FUSE complexity - consider FUSE-T for Phase 9

### Roadmap Evolution

- Phase 4.1 inserted after Phase 4: API Service Testing (URGENT) - Add unit tests for backend services per .planning/codebase/TESTING.md coverage thresholds before continuing to Phase 5
- Phase 4.2 inserted: Local IPFS Testing Infrastructure - Add local IPFS node to Docker for offline testing (parallel work via worktree at ../cipher-box-phase-4.2)

## Session Continuity

Last session: 2026-01-21
Stopped at: Completed Phase 5 (Folder System)
Resume file: None

---

_State initialized: 2026-01-20_
_Last updated: 2026-01-21 after Phase 5 completion_

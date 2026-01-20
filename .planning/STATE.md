# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-20)

**Core value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext
**Current focus:** Phase 4 - File Storage (in progress)

## Current Position

Phase: 4 of 11 (File Storage in progress)
Plan: 2 of 4 in Phase 4 complete
Status: Phase 4 in progress
Last activity: 2026-01-20 - Completed 04-02-PLAN.md (VaultModule with quota tracking)

Progress: [####......] 27% (11 of 41 plans)

## Performance Metrics

**Velocity:**

- Total plans completed: 11
- Average duration: 5.2 min
- Total execution time: 1.0 hours

**By Phase:**

| Phase              | Plans | Total  | Avg/Plan |
| ------------------ | ----- | ------ | -------- |
| 01-foundation      | 3/3   | 20 min | 7 min    |
| 02-authentication  | 4/4   | 18 min | 4.5 min  |
| 03-core-encryption | 3/3   | 18 min | 6 min    |
| 04-file-storage    | 1/4   | 6 min  | 6 min    |

**Recent Trend:**

- Last 5 plans: 5m, 6m, 7m, 5m, 6m
- Trend: Consistent

_Updated after each plan completion_

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

| Decision                                             | Phase | Rationale                                                                 |
| ---------------------------------------------------- | ----- | ------------------------------------------------------------------------- |
| Override moduleResolution to 'node' for NestJS apps  | 01-01 | Base tsconfig uses bundler which is incompatible with CommonJS            |
| Generate OpenAPI spec using minimal module           | 01-01 | Avoids requiring live database during build                               |
| Pre-configure API tags in OpenAPI                    | 01-01 | Placeholder tags for Auth, Vault, Files, IPFS, IPNS                       |
| Use React 18.3.1 per project spec                    | 01-02 | Not React 19 - staying on stable LTS version                              |
| orval tags-split mode for API client                 | 01-02 | Generates separate files per API tag for better organization              |
| Custom fetch instance for API calls                  | 01-02 | Allows future auth header injection without modifying generated code      |
| ESLint 9 flat config format                          | 01-03 | Modern, simpler configuration at monorepo root                            |
| CI api-spec job verifies generated files             | 01-03 | Ensures OpenAPI spec and API client stay in sync                          |
| PostgreSQL 16-alpine for Docker                      | 01-03 | Lightweight image with latest stable Postgres                             |
| Detect social vs wallet via authConnection           | 02-02 | Web3Auth v10 uses authConnection, not deprecated typeOfLogin              |
| Auth token in memory only (Zustand)                  | 02-02 | XSS prevention - no localStorage for sensitive tokens                     |
| Token refresh queue pattern                          | 02-02 | Handle concurrent 401s without race conditions                            |
| Dual JWKS endpoints for Web3Auth                     | 02-01 | Different endpoints for social vs external wallet logins                  |
| Refresh tokens searchable without access token       | 02-01 | Better UX - can refresh even with expired access token                    |
| Token rotation on every refresh                      | 02-01 | Security - prevents token reuse attacks                                   |
| HTTP-only cookie with path=/auth for refresh token   | 02-03 | Refresh token only sent to auth endpoints, XSS prevention                 |
| CORS credentials enabled                             | 02-03 | Cross-origin cookie handling between frontend and backend                 |
| ADR-001: Signature-derived keys for external wallets | 02-04 | EIP-712 signature + HKDF derives secp256k1 keypair for ECIES              |
| Chain-agnostic EIP-712 domain                        | 02-04 | No chainId ensures consistent key derivation across networks              |
| Memory-only derived key storage                      | 02-04 | Re-derive keypair on page refresh, never persist to storage               |
| Account linking via Web3Auth grouped connections     | 02-04 | No custom implementation needed - handled at authentication layer         |
| ADR-002: Web3Auth MFA scoped for post-v1.0           | 02-04 | Phase 11 - passkey, TOTP, recovery phrase via tKey SDK                    |
| eciesjs for ECIES operations                         | 03-01 | Built on audited @noble/curves, single function API                       |
| Buffer to Uint8Array conversion in crypto            | 03-01 | eciesjs returns Buffer; convert for consistent API                        |
| ArrayBuffer casting for TypeScript 5.9               | 03-01 | Web Crypto API requires explicit ArrayBuffer type                         |
| Uncompressed public keys (65 bytes, 0x04 prefix)     | 03-01 | secp256k1 standard format, validated before crypto ops                    |
| Generic error messages in crypto                     | 03-01 | Prevent oracle attacks - all failures say "Encryption/Decryption failed"  |
| Ed25519 verification returns false for invalid       | 03-02 | Returns boolean, not exception - consistent with oracle attack prevention |
| IPNS signature prefix per IPFS spec                  | 03-02 | "ipns-signature:" concatenated before signing CBOR data                   |
| Deterministic Ed25519 signatures                     | 03-02 | Same key + same message always produces identical signature               |
| CipherBox-v1 salt for HKDF                           | 03-03 | Static salt provides domain separation for all key derivations            |
| Folder keys are random not derived                   | 03-03 | Per CONTEXT.md, folder keys randomly generated then ECIES-wrapped         |
| File keys random per-file                            | 03-03 | No deduplication per CRYPT-06 - each file gets unique random key          |
| VaultInit vs EncryptedVaultKeys separation           | 03-03 | Clear distinction between in-memory keys and server storage format        |
| Vault stores encrypted keys as BYTEA                 | 04-02 | Direct binary storage, hex encoding only at API boundary                  |
| PinnedCid sizeBytes as bigint                        | 04-02 | TypeORM returns as string to avoid JavaScript precision issues            |
| Quota calculated on-demand via SUM                   | 04-02 | No cached field, acceptable for 500 MiB limit                             |
| VaultService exported from module                    | 04-02 | Allows IpfsModule to use recordPin/recordUnpin                            |

### Pending Todos

None yet.

### Blockers/Concerns

None yet.

### Research Flags (from research phase)

- IPNS resolution latency (~30s) may need deeper investigation during Phase 7
- Phala Cloud API integration may need deeper research during Phase 8
- macOS FUSE complexity - consider FUSE-T for Phase 9

## Session Continuity

Last session: 2026-01-20
Stopped at: Completed 04-02-PLAN.md (VaultModule with quota tracking)
Resume file: None

---

_State initialized: 2026-01-20_
_Last updated: 2026-01-20 after 04-02 completion_

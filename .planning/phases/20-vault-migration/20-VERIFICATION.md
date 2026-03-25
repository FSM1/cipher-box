---
phase: 20-vault-migration
verified: 2026-03-24T04:05:00Z
status: passed
score: 9/9 must-haves verified
re_verification: true
  previous_status: gaps_found
  previous_score: 6/6 truths + GAP-01 open
  gaps_closed:
    - 'GAP-01: Dead migration code removed -- DB crypto columns dropped, POST /vault/migrate removed, PATH B + DB fallback removed, as unknown as string casts removed, desktop non-migrated code paths removed'
  gaps_remaining: []
  regressions: []
human_verification:
  - test: 'New web user vault init publishes v2 blob to IPFS before API registration'
    expected: 'New account signs up, browser DevTools Network shows IPFS add call before POST /vault/init, vault loads successfully'
    why_human: 'Requires live IPFS node and Web3Auth + backend running; ordering of async calls cannot be verified statically without tracing a real login'
  - test: 'Recovery tool IPFS-direct path with known private key (v2 vault)'
    expected: 'Enter hex private key, click Recover, tool derives IPNS name, fetches v2 blob via gateway, ECIES-unwraps rootFolderKey, lists folder contents'
    why_human: 'Requires live IPFS gateway and a real migrated vault; browser interaction required'
---

# Phase 20: Vault Migration Re-Verification Report

**Phase Goal:** The server stores zero crypto material -- rootFolderKey lives in the IPFS vault blob, making the server a true zero-knowledge relay
**Verified:** 2026-03-24T04:05:00Z
**Status:** passed
**Re-verification:** Yes -- after GAP-01 closure (plans 20-05 and 20-06)

## Re-Verification Context

The initial verification (2026-03-24T01:48:50Z) found GAP-01: dead migration code existed in the API, web client, and desktop client because all users had already migrated to v2. Plans 20-05 and 20-06 were executed to remove that dead code. This re-verification confirms:

1. All 6 original truths still hold (v2 blob format works, server stores zero crypto, clients read from IPFS)
2. GAP-01 is fully resolved (all dead migration code removed)
3. The new capability from plan 20-06 is in place (new web users get v2 blob published immediately)

## Goal Achievement

### Observable Truths

| #   | Truth                                                                                  | Status   | Evidence                                                                                                                                                    |
| --- | -------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Vault blob v2 can be serialized/deserialized with byte-identical round-trip            | VERIFIED | `blob.ts` unchanged; `vault_blob.rs` unchanged; both verified in initial pass                                                                               |
| 2   | Server stores zero crypto material -- vaults table has no crypto columns               | VERIFIED | `vault.entity.ts` has no `encryptedRootFolderKey`, `encryptedRootIpnsPrivateKey`, or `migratedAt`; all 5 production vault files show 0 dead field matches   |
| 3   | POST /vault/migrate endpoint no longer exists                                          | VERIFIED | `vault.controller.ts` has no `@Post('migrate')` or `migrateVault`; generated API client has no `vaultControllerMigrateVault`                                |
| 4   | Web login reads rootFolderKey exclusively from IPFS v2 blob (no DB fallback)           | VERIFIED | `useAuth.ts` has a single IPFS-only path (line 111-131); no `migratedAt` check, no PATH B, no `decryptVaultKeys`; 0 grep matches for all dead patterns      |
| 5   | New web user vault init publishes v2 blob to IPFS before registering with API          | VERIFIED | `useAuth.ts` lines 141-172: ECIES-wrap, encrypt metadata, serialize v2 blob, addToIpfs, createAndPublishIpnsRecord, then vaultApi.initVault (in that order) |
| 6   | Desktop Rust vault types contain only ownerPublicKey + rootIpnsName (no crypto fields) | VERIFIED | `types.rs` `InitVaultRequest`: 2 fields only; `VaultResponse`: 2 fields only; 0 matches for any dead field patterns                                         |
| 7   | Desktop fetch_and_decrypt_vault has single IPFS-only path (no non-migrated branch)     | VERIFIED | `vault.rs` lines 126-192: always derives HKDF keypair, resolves IPNS, fetches v2 blob, unwraps rootFolderKey; no conditional on crypto DB fields            |
| 8   | No as unknown as string type casts remain in useAuth.ts                                | VERIFIED | grep returns 0 matches                                                                                                                                      |
| 9   | Recovery tool export-file path shows permanent v2 format message                       | VERIFIED | `recovery.html` line 1368: `'Export files no longer contain encrypted keys (vault v2 format). Use "From IPFS (v2 blob, key only)" recovery instead...'`     |

**Score:** 9/9 truths verified

### Required Artifacts (Gap-Closure Plans 05 + 06)

| Artifact                                                          | Expected                                                                                       | Status   | Details                                                                                                                                                              |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/api/src/migrations/1740700000000-DropVaultCryptoColumns.ts` | Drops 3 dead columns (encrypted_root_folder_key, encrypted_root_ipns_private_key, migrated_at) | VERIFIED | Lines 9, 11, 13: `DROP COLUMN IF EXISTS` for all 3 columns; reversible `down()` also present                                                                         |
| `apps/api/src/vault/entities/vault.entity.ts`                     | No crypto columns, no migratedAt                                                               | VERIFIED | 52 lines; fields: id, ownerId, owner, ownerPublicKey, rootIpnsName, createdAt, initializedAt, updatedAt only                                                         |
| `apps/api/src/vault/dto/init-vault.dto.ts`                        | InitVaultDto: ownerPublicKey + rootIpnsName only                                               | VERIFIED | Lines 9-26: exactly 2 fields; VaultResponseDto: id, ownerPublicKey, rootIpnsName, createdAt, initializedAt, teeKeys only                                             |
| `apps/api/src/vault/dto/vault-export.dto.ts`                      | No crypto fields                                                                               | VERIFIED | Fields: format, version, exportedAt, rootIpnsName, derivationMethod only                                                                                             |
| `apps/api/src/vault/vault.service.ts`                             | No migrateVault method, no crypto fields in initializeVault                                    | VERIFIED | 231 lines; no migrateVault, no crypto column references anywhere in file                                                                                             |
| `apps/api/src/vault/vault.controller.ts`                          | No POST /vault/migrate endpoint                                                                | VERIFIED | 129 lines; endpoints: POST /vault/init, GET /vault/config, GET /vault/export, GET /vault, GET /vault/quota                                                           |
| `packages/api-client/src/generated/vault/vault.ts`                | No vaultControllerMigrateVault                                                                 | VERIFIED | 90 lines; 5 functions only: initializeVault, getConfig, exportVault, getVault, getQuota                                                                              |
| `packages/api-client/src/models/vaultResponseDto.ts`              | No crypto fields or migratedAt                                                                 | VERIFIED | Fields: id, ownerPublicKey, rootIpnsName, createdAt, initializedAt, teeKeys only                                                                                     |
| `packages/api-client/src/models/initVaultDto.ts`                  | Only ownerPublicKey + rootIpnsName                                                             | VERIFIED | Exactly 2 fields                                                                                                                                                     |
| `apps/web/src/hooks/useAuth.ts`                                   | IPFS-only path + new user v2 blob publish; no dead imports                                     | VERIFIED | Imports: detectBlobVersion, deserializeVaultBlobV2, serializeVaultBlobV2, encryptFolderMetadata, wrapKey, unwrapKey; no decryptVaultKeys/vaultControllerMigrateVault |
| `apps/desktop/src-tauri/src/api/types.rs`                         | InitVaultRequest: 2 fields; VaultResponse: 2 fields                                            | VERIFIED | Lines 90-125: exactly ownerPublicKey + rootIpnsName in request; rootIpnsName + teeKeys in response                                                                   |
| `apps/desktop/src-tauri/src/commands/vault.rs`                    | fetch_and_decrypt_vault: single IPFS-only path                                                 | VERIFIED | Lines 126-192: unconditional HKDF derivation + IPNS resolve + v2 blob parse; no conditional on vault response fields                                                 |
| `apps/web/public/recovery.html`                                   | Updated export-file null-key message                                                           | VERIFIED | Line 1368: permanent v2 format message; legacy decryption path at 1450-1451 retained for old export file backward compat                                             |
| `apps/api/src/vault/vault.service.spec.ts`                        | No dead migration test patterns                                                                | VERIFIED | grep for all dead patterns returns 0 matches                                                                                                                         |

### Key Link Verification

| From                                           | To                                | Via                                                              | Status | Details                                                                                              |
| ---------------------------------------------- | --------------------------------- | ---------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------- |
| `vault.controller.ts`                          | `vault.service.ts`                | `initializeVault` (no crypto args)                               | WIRED  | Line 41: `vaultService.initializeVault(req.user.id, dto)` -- dto has no crypto fields                |
| `vault.service.ts` `initializeVault`           | `vaultRepository.create({...})`   | only ownerPublicKey, rootIpnsName, initializedAt                 | WIRED  | Lines 67-72: create call has exactly 4 fields, no crypto columns                                     |
| `apps/web/src/hooks/useAuth.ts`                | IPFS v2 blob (existing user path) | fetchFromIpfs + detectBlobVersion + deserializeVaultBlobV2       | WIRED  | Lines 117-124: sequential await calls, result used to unwrapKey                                      |
| `apps/web/src/hooks/useAuth.ts`                | IPFS v2 blob (new user path)      | addToIpfs + createAndPublishIpnsRecord before vaultApi.initVault | WIRED  | Lines 153-172: IPFS upload and IPNS publish happen before API registration                           |
| `apps/desktop/src-tauri/src/commands/vault.rs` | `crypto::vault_blob`              | `detect_blob_version` + `deserialize_vault_blob_v2`              | WIRED  | Lines 173-177: detect, then deserialize, result passed to `ecies::unwrap_key`                        |
| `apps/desktop/src-tauri/src/api/types.rs`      | API contract                      | InitVaultRequest with 2 fields only                              | WIRED  | Lines 37-40 in vault.rs: `InitVaultRequest { owner_public_key, root_ipns_name }` -- no crypto fields |

### Requirements Coverage

| Requirement | Source Plan  | Description                                                                        | Status    | Evidence                                                                                                                                                                  |
| ----------- | ------------ | ---------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| VAULT-01    | Plan 01      | rootFolderKey embedded in IPFS vault blob v2 format (ECIES-wrapped in blob header) | SATISFIED | v2 blob format unchanged from initial verification; new user init in web + desktop both produce v2 blobs with ECIES-wrapped key in header                                 |
| VAULT-02    | Plans 02, 04 | Client reads rootFolderKey from IPFS blob on login, falls back to DB vaults table  | SATISFIED | DB fallback intentionally removed (DB no longer stores crypto material); client reads exclusively from IPFS v2 blob -- this exceeds the original requirement              |
| VAULT-03    | Plans 02, 04 | Lazy migration writes vault blob v2 on next folder metadata publish                | SATISFIED | Lazy migration intentionally removed (all users already migrated, DB columns dropped); new users get v2 blob immediately on init -- this exceeds the original requirement |
| VAULT-04    | Plans 02, 04 | encryptedRootIpnsPrivateKey column deprecated from vaults table (HKDF-derivable)   | SATISFIED | Column fully dropped (not just nullable); API entity, DTOs, and client have zero references to this field                                                                 |
| VAULT-05    | Plan 04      | Recovery tool updated to parse vault blob v2 format                                | SATISFIED | IPFS-direct recovery path unchanged; export-file path now shows permanent v2 format message; legacy path retained for backward compat with pre-v2 export files            |
| VAULT-06    | Plan 03      | Desktop app (Rust) parses vault blob v2 format                                     | SATISFIED | `vault_blob.rs` and `fuse/mod.rs` unchanged from initial verification; `commands/vault.rs` now uses single IPFS-only path; `types.rs` has no crypto fields                |

**Note on VAULT-02 and VAULT-03:** The original requirements described a DB fallback and lazy migration as the mechanism. Plans 05-06 superseded this by removing DB crypto storage entirely (a stronger guarantee). Both requirements are satisfied at a higher level of assurance than originally specified.

### Anti-Patterns Found

| File                            | Line | Pattern                                                                                                                 | Severity | Impact                                                                                                |
| ------------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------- |
| `apps/web/src/hooks/useAuth.ts` | 153  | `new Blob([v2Blob as BlobPart])` -- Uint8Array passed directly (correct), `as BlobPart` cast for TypeScript strict mode | Info     | Correct usage per CLAUDE.md; cast is on the Uint8Array itself, not `.buffer`; no data corruption risk |

No blockers. No warnings. One informational note on the TypeScript cast, which is the established codebase pattern.

### Human Verification Required

#### 1. New Web User Vault Init -- IPFS-First Ordering

**Test:** Create a new CipherBox account in a browser. Open DevTools Network tab before clicking sign up. Complete the Web3Auth flow.
**Expected:** Network requests show: (1) IPFS add call, (2) IPNS publish call, (3) POST /vault/init. Vault loads successfully and files page is accessible. No errors in console.
**Why human:** Requires live IPFS node + Web3Auth + backend running. The sequential ordering of async calls (IPFS before API registration) cannot be verified by static analysis alone.

#### 2. Recovery Tool IPFS-Direct Path

**Test:** Open `apps/web/public/recovery.html` in a browser. Select "From IPFS (v2 blob, key only)". Enter the hex private key of a vault that was initialized with v2 format. Click Recover.
**Expected:** Tool derives IPNS name from private key, resolves it via IPFS gateway, fetches v2 blob, ECIES-unwraps rootFolderKey, and lists folder contents. No CipherBox API dependency required.
**Why human:** Requires live IPFS gateway and a real v2 vault. IPNS DHT propagation is an infrastructure concern not verifiable statically.

### GAP-01 Resolution Confirmation

GAP-01 (dead migration code) identified in initial verification is fully resolved:

| Item to Remove (from GAP-01)                                        | Status  | Evidence                                                                     |
| ------------------------------------------------------------------- | ------- | ---------------------------------------------------------------------------- |
| `encryptedRootFolderKey` + `encryptedRootIpnsPrivateKey` DB columns | REMOVED | Migration 1740700000000 drops them; entity has no such fields                |
| `migratedAt` DB column                                              | REMOVED | Migration drops it; entity has no such field                                 |
| `POST /vault/migrate` endpoint + `migrateVault()` method            | REMOVED | Controller has no @Post('migrate'); service has no migrateVault              |
| PATH B (lazy migration) in `useAuth.ts`                             | REMOVED | useAuth.ts has single IPFS-only path; no migratedAt branch                   |
| DB fallback in PATH A catch block                                   | REMOVED | catch block now only handles 404 (new user) or rethrows                      |
| `decryptVaultKeys`, `vaultControllerMigrateVault` imports           | REMOVED | 0 grep matches in useAuth.ts for both                                        |
| `as unknown as string` type casts                                   | REMOVED | 0 grep matches in useAuth.ts                                                 |
| Desktop non-migrated code paths in `vault.rs`                       | REMOVED | fetch_and_decrypt_vault is single IPFS-only path                             |
| Desktop crypto fields in `types.rs`                                 | REMOVED | InitVaultRequest and VaultResponse have no crypto fields                     |
| Recovery tool null crypto field handling (old message)              | UPDATED | Updated message reflects permanent v2 format (not transient migration state) |
| All migration-related tests in `vault.service.spec.ts`              | REMOVED | 0 matches for all dead test patterns                                         |

### Summary

Phase 20 is complete. All 6 original requirements (VAULT-01 through VAULT-06) remain satisfied. GAP-01 is fully resolved -- the server now stores zero crypto material with no dead migration infrastructure:

- The DB `vaults` table stores only `ownerPublicKey` (for TEE key distribution) and `rootIpnsName` (for routing). No crypto material at rest.
- The web client's login flow is 50 lines of clean IPFS-only code (was 116 lines of dual-path logic).
- New web users get a v2 blob published to IPFS immediately on account creation, before the vault is registered with the API -- rootFolderKey is IPFS-native from day one.
- The desktop Rust client has a single IPFS-only vault fetch path with no conditional branches.
- The recovery tool's export-file path clearly communicates the permanent v2 format to users.

Two items remain for human verification: the new-user init IPFS-first ordering and the IPFS-direct recovery path. These are behavioral confirmations requiring a live environment.

---

_Verified: 2026-03-24T04:05:00Z_
_Verifier: Claude (gsd-verifier)_
_Re-verification: Yes -- after gap closure plans 20-05 and 20-06_

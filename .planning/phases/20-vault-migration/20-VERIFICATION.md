---
phase: 20-vault-migration
verified: 2026-03-24T01:48:50Z
status: gaps_found
score: 6/6 must-haves verified
re_verification: false
human_verification:
  - test: 'Login with non-migrated account on web app triggers lazy migration'
    expected: 'Console shows vault successfully migrated, subsequent login reads from IPFS v2 blob, DB crypto columns become NULL'
    why_human: 'Requires live API + IPFS node; migration is async fire-and-forget inside login flow'
  - test: 'Recovery tool IPFS-direct path with known private key'
    expected: 'Entering private key, clicking Recover, tool derives IPNS name, fetches v2 blob, decrypts rootFolderKey, lists folder contents'
    why_human: 'Standalone HTML tool; requires live IPFS gateway and a real migrated vault'
---

# Phase 20: Vault Migration Verification Report

**Phase Goal:** Move rootFolderKey to IPFS vault blob v2 format, making the server store zero crypto material
**Verified:** 2026-03-24T01:48:50Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #   | Truth                                                                            | Status   | Evidence                                                                                                                                                                                                                                    |
| --- | -------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| 1   | Vault blob v2 can be serialized from encryptedRootFolderKey + encrypted metadata | VERIFIED | `blob.ts` exports `serializeVaultBlobV2`; 14 unit tests + 5 vector tests pass (165 total core tests pass)                                                                                                                                   |
| 2   | Vault blob v2 can be deserialized back with byte-identical round-trip            | VERIFIED | `deserializeVaultBlobV2` implemented; cross-platform hex vector test matches Rust output exactly                                                                                                                                            |
| 3   | Server stores zero crypto material for migrated users                            | VERIFIED | `POST /vault/migrate` NULLs both `encryptedRootFolderKey` and `encryptedRootIpnsPrivateKey` columns; entity uses `Buffer                                                                                                                    | null`; export returns `null` for migrated users |
| 4   | Clients read rootFolderKey from IPFS v2 blob on login (migrated path)            | VERIFIED | `useAuth.ts` PATH A: branches on `existingVault.migratedAt`, fetches blob via `fetchFromIpfs`, detects v2, ECIES-unwraps key from header                                                                                                    |
| 5   | Non-migrated users are lazily migrated to v2 on next login                       | VERIFIED | `useAuth.ts` PATH B: fire-and-forget async IIFE writes v2 blob to IPFS, publishes IPNS with `createAndPublishIpnsRecord` + `expectedSequenceNumber`, calls `vaultControllerMigrateVault` only after confirmed write                         |
| 6   | Desktop Rust app reads and writes v2 blob format                                 | VERIFIED | `vault_blob.rs` serialize/deserialize/detect; 10 tests pass including exact hex vector; `fuse/mod.rs` uses `encrypt_root_metadata_to_v2_blob` for root folder publishes; `fuse/decrypt.rs` transparently strips v2 header before JSON parse |

**Score:** 6/6 truths verified

### Required Artifacts

| Artifact                                                      | Expected                                                                                 | Status   | Details                                                                                                                                                             |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- | ------------------------ | ----- |
| `packages/core/src/vault/blob.ts`                             | `serializeVaultBlobV2`, `deserializeVaultBlobV2`, `detectBlobVersion`, `BLOB_V2_VERSION` | VERIFIED | All 4 exports present; pure byte manipulation, zero external deps                                                                                                   |
| `packages/core/src/vault/types.ts`                            | `VaultBlobV2` type                                                                       | VERIFIED | Type declared with `encryptedRootFolderKey` and `encryptedMetadataJson` fields                                                                                      |
| `packages/core/src/vault/index.ts`                            | Re-exports blob functions and type                                                       | VERIFIED | Exports all 4 functions + `VaultBlobV2` type                                                                                                                        |
| `packages/core/src/__tests__/vault-blob.test.ts`              | Unit tests (min 50 lines)                                                                | VERIFIED | 154 lines, 14 test cases                                                                                                                                            |
| `packages/core/src/__tests__/vault-blob-vectors.test.ts`      | Cross-platform hex vectors (min 30 lines)                                                | VERIFIED | 107 lines, 5 test cases with hardcoded hex                                                                                                                          |
| `apps/api/src/migrations/1740600000000-AddVaultMigratedAt.ts` | DB migration for migrated_at + nullable columns                                          | VERIFIED | All 3 DDL statements present: `ADD COLUMN IF NOT EXISTS migrated_at`, `DROP NOT NULL` on both crypto columns                                                        |
| `apps/api/src/vault/entities/vault.entity.ts`                 | Nullable crypto columns + migratedAt                                                     | VERIFIED | `encryptedRootFolderKey: Buffer                                                                                                                                     | null`, `encryptedRootIpnsPrivateKey: Buffer | null`, `migratedAt: Date | null` |
| `apps/api/src/vault/dto/init-vault.dto.ts`                    | Optional IPNS key + migratedAt in response                                               | VERIFIED | `encryptedRootIpnsPrivateKey?: string` with `@IsOptional()`; `VaultResponseDto.migratedAt: Date                                                                     | null`                                       |
| `apps/api/src/vault/vault.service.ts`                         | `migrateVault` method with idempotency                                                   | VERIFIED | Method checks `vault.migratedAt`, returns early if set; otherwise updates with `new Date()` and nulls both columns                                                  |
| `apps/api/src/vault/vault.controller.ts`                      | `POST /vault/migrate` endpoint                                                           | VERIFIED | `@Post('migrate')` at line 44, before `@Get()` at line 109; delegates to `vaultService.migrateVault`                                                                |
| `apps/desktop/src-tauri/src/crypto/vault_blob.rs`             | Rust serialize/deserialize/detect + BLOB_V2_VERSION                                      | VERIFIED | All 4 symbols present; 10 tests pass; exact hex matches TypeScript vector                                                                                           |
| `apps/desktop/src-tauri/src/crypto/mod.rs`                    | `pub mod vault_blob`                                                                     | VERIFIED | Line 15: `pub mod vault_blob`                                                                                                                                       |
| `apps/desktop/src-tauri/src/commands/vault.rs`                | Handles null DB keys via IPFS v2 blob                                                    | VERIFIED | Uses `vault_blob::detect_blob_version` and `vault_blob::deserialize_vault_blob_v2` for migrated user path                                                           |
| `apps/desktop/src-tauri/src/fuse/mod.rs`                      | `encrypt_root_metadata_to_v2_blob` + root folder publish                                 | VERIFIED | Function at line 235; called at root folder publish sites; `serialize_vault_blob_v2` invoked                                                                        |
| `apps/web/src/hooks/useAuth.ts`                               | PATH A + PATH B + migration trigger                                                      | VERIFIED | Imports `detectBlobVersion`, `deserializeVaultBlobV2`, `serializeVaultBlobV2`, `vaultControllerMigrateVault`; `existingVault.migratedAt` branch at line 111         |
| `apps/web/public/recovery.html`                               | Inline v2 parsing + IPFS-direct UI                                                       | VERIFIED | `BLOB_V2_VERSION = 0x02` (3 occurrences), `detectBlobVersion`, `deserializeVaultBlobV2` inline; IPFS-direct recovery panel with private key input and gateway input |

### Key Link Verification

| From                                           | To                                                | Via                                                                           | Status | Details                                                                                                                      |
| ---------------------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `packages/core/src/vault/blob.ts`              | `packages/core/src/vault/types.ts`                | `VaultBlobV2` type import                                                     | WIRED  | Line 16: `import type { VaultBlobV2 } from './types'`                                                                        |
| `packages/core/src/vault/index.ts`             | `packages/core/src/vault/blob.ts`                 | re-export blob functions                                                      | WIRED  | Lines 9-14: `export { serializeVaultBlobV2, deserializeVaultBlobV2, detectBlobVersion, BLOB_V2_VERSION } from './blob'`      |
| `apps/api/src/vault/vault.controller.ts`       | `apps/api/src/vault/vault.service.ts`             | `migrateVault` method call                                                    | WIRED  | Line 64: `return this.vaultService.migrateVault(req.user.id)`                                                                |
| `apps/api/src/vault/vault.service.ts`          | `apps/api/src/vault/entities/vault.entity.ts`     | TypeORM repository update                                                     | WIRED  | `vaultRepository.update(...)` with `migratedAt: new Date(), encryptedRootFolderKey: null, encryptedRootIpnsPrivateKey: null` |
| `apps/desktop/src-tauri/src/fuse/mod.rs`       | `apps/desktop/src-tauri/src/crypto/vault_blob.rs` | `serialize_vault_blob_v2` in root publish                                     | WIRED  | `crate::crypto::vault_blob::serialize_vault_blob_v2` at 2 call sites                                                         |
| `apps/desktop/src-tauri/src/commands/vault.rs` | `apps/desktop/src-tauri/src/crypto/vault_blob.rs` | `detect_blob_version` for IPFS parsing                                        | WIRED  | `crypto::vault_blob::detect_blob_version` + `crypto::vault_blob::deserialize_vault_blob_v2`                                  |
| `apps/web/src/hooks/useAuth.ts`                | `@cipherbox/core`                                 | `detectBlobVersion`, `deserializeVaultBlobV2`, `serializeVaultBlobV2` imports | WIRED  | Lines 17-20: all three functions imported and used in PATH A and PATH B                                                      |
| `apps/web/src/hooks/useAuth.ts`                | `/vault/migrate` API                              | `vaultControllerMigrateVault` after successful IPNS publish                   | WIRED  | Line 35 import; line 209 call inside migration IIFE, gated on `publishResult.success`                                        |
| `apps/web/src/services/folder.service.ts`      | `@cipherbox/core`                                 | `detectBlobVersion` + `deserializeVaultBlobV2` in `fetchAndDecryptMetadata`   | WIRED  | Lines 17-18 import; lines 968-969 used in `fetchAndDecryptMetadata` for transparent v1/v2 handling                           |

### Requirements Coverage

| Requirement | Source Plan  | Description                                                                        | Status    | Evidence                                                                                                                                                                                          |
| ----------- | ------------ | ---------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | --------- | --------------------------------- |
| VAULT-01    | Plan 01      | rootFolderKey embedded in IPFS vault blob v2 format (ECIES-wrapped in blob header) | SATISFIED | `blob.ts` binary format: `0x02                                                                                                                                                                    | uint16_BE(key_len) | ECIES_key | AES_GCM_metadata`; all tests pass |
| VAULT-02    | Plans 02, 04 | Client reads rootFolderKey from IPFS blob on login, falls back to DB vaults table  | SATISFIED | `useAuth.ts` PATH A reads from IPFS; catch block falls back to DB if `encryptedRootFolderKey` is non-null; throws only if both are unavailable                                                    |
| VAULT-03    | Plans 02, 04 | Lazy migration writes vault blob v2 on next folder metadata publish                | SATISFIED | `useAuth.ts` PATH B: non-migrated users trigger fire-and-forget migration on login; writes v2 blob, publishes IPNS, calls `POST /vault/migrate`                                                   |
| VAULT-04    | Plans 02, 04 | encryptedRootIpnsPrivateKey column deprecated from vaults table (HKDF-derivable)   | SATISFIED | API column is nullable; `InitVaultDto.encryptedRootIpnsPrivateKey` is optional; web client omits field on new vault init; API client type has `encryptedRootIpnsPrivateKey?: string`              |
| VAULT-05    | Plan 04      | Recovery tool updated to parse vault blob v2 format                                | SATISFIED | `recovery.html` contains inline `BLOB_V2_VERSION`, `detectBlobVersion`, `deserializeVaultBlobV2`; IPFS-direct recovery UI with private key and gateway inputs; null key export handled gracefully |
| VAULT-06    | Plan 03      | Desktop app (Rust) parses vault blob v2 format                                     | SATISFIED | `vault_blob.rs` byte-identical to TypeScript (cross-platform test vector); `fuse/decrypt.rs` transparently handles v2; root folder publishes produce v2 blobs                                     |

**Note on REQUIREMENTS.md data inconsistency:** The requirement checklist (lines 19-24) shows all 6 as `[x]` completed, but the status table (lines 103-108) shows VAULT-05 as "Pending". This is a stale status in the table row — the code implements VAULT-05 fully (confirmed above). The checklist is correct.

### Anti-Patterns Found

| File                                      | Line          | Pattern                                                                                                                   | Severity | Impact                                                                                                                                                                                                                                                                                                     |
| ----------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/api/src/vault/vault.controller.ts`  | 128-133       | `getVault` re-implements 404 check that `findVault` already handles separately                                            | Info     | No functional impact; minor redundancy                                                                                                                                                                                                                                                                     |
| `apps/desktop/src-tauri/src/api/types.rs` | 94-96         | `InitVaultRequest.encrypted_root_ipns_private_key: String` (non-optional) — desktop new vault init still sends this field | Info     | API accepts it (column nullable); functional but inconsistent with VAULT-04 goal. The web client correctly omits this field. The desktop will ECIES-wrap and send the IPNS key, which the API stores then ignores for migrated flows. No security impact since column is nullable and NULLed on migration. |
| `apps/web/src/hooks/useAuth.ts`           | 137, 157, 160 | `as unknown as string` casts for `encryptedRootFolderKey` and `encryptedRootIpnsPrivateKey`                               | Warning  | Required because orval generates `{ [key: string]: unknown }                                                                                                                                                                                                                                               | null`for nullable string fields instead of`string | null`. Web build passes (0 TypeScript errors). Runtime behavior is correct since the actual JSON value is a string. This is a known orval quirk with nullable string types and does not affect correctness. |

All anti-patterns are informational. None block the phase goal.

## Gaps

### GAP-01: Remove dead migration code — v2 blob is canonical (no non-migrated users exist)

**Status:** failed
**Severity:** medium
**Rationale:** The staging database was nuked during Phase 19.2 (pebbleds datastore migration), and the only user account has already been migrated to v2. There are zero non-migrated vaults in any environment. The migration code paths (PATH B lazy migration, `POST /vault/migrate` endpoint, nullable DB crypto columns, `as unknown as string` type casts, DB fallback in PATH A) are dead code that adds complexity, test burden, and security surface area for a scenario that will never occur.

**What to remove:**

- `useAuth.ts` PATH B (DB decrypt + lazy migration IIFE) and DB fallback in PATH A catch
- `POST /vault/migrate` endpoint and `migrateVault()` service method
- `encryptedRootFolderKey` and `encryptedRootIpnsPrivateKey` DB columns (drop, not just nullable)
- `migratedAt` column (all users are migrated — column becomes meaningless)
- Crypto field handling in `InitVaultDto`, `VaultResponseDto`, `VaultExportDto`
- Desktop `InitVaultRequest` crypto fields and ECIES wrapping for DB storage
- Recovery tool export-file path handling of null crypto fields
- `decryptVaultKeys` import in useAuth.ts, `serializeVaultBlobV2` import (client no longer writes v2 blobs — only reads)
- All migration-related tests in `vault.service.spec.ts`
- `as unknown as string` casts (orval workaround for fields that no longer exist)

**What to keep:**

- v2 blob format module (`blob.ts`, `vault_blob.rs`) — canonical format
- v2 blob reading in login flow (PATH A without fallback)
- v2 blob writing in desktop FUSE publish and new vault init
- `fetchAndDecryptMetadata` v2 blob detection (folder sync)
- Recovery tool IPFS-direct path (v2 blob read)
- Cross-platform test vectors

### Human Verification Required

#### 1. Web Login Lazy Migration End-to-End

**Test:** Log in to the web app with an account that has NOT yet been migrated (check DB: `migrated_at IS NULL`). Open browser console.
**Expected:** Console shows `[Auth] Vault successfully migrated to v2 blob format`. After a few seconds, check DB: `migrated_at` is now set, `encrypted_root_folder_key` is NULL, `encrypted_root_ipns_private_key` is NULL. Log out and log back in — console should NOT show the migration message; vault should load from IPFS v2 blob instead.
**Why human:** Live API + IPFS node required. The migration is an async fire-and-forget IIFE inside the login flow — cannot be verified programmatically without a running environment.

#### 2. Recovery Tool IPFS-Direct Path

**Test:** Open `apps/web/public/recovery.html` in a browser. Select "From IPFS (v2 blob, key only)". Enter the hex private key of a migrated vault. Click Recover.
**Expected:** The tool derives the IPNS name from the key, resolves it via the IPFS gateway, fetches the v2 blob, parses the header, ECIES-unwraps the rootFolderKey, and lists folder contents. No CipherBox API dependency.
**Why human:** Requires a live IPFS gateway, a real migrated vault, and browser interaction. The IPNS DHT propagation for gateway resolution is an infrastructure concern that cannot be verified statically.

### Summary

Phase 20 achieves its goal. All six requirements (VAULT-01 through VAULT-06) are implemented and verified in the actual codebase. The server now stores zero crypto material for migrated users — both `encryptedRootFolderKey` and `encryptedRootIpnsPrivateKey` are NULLed after migration. The rootFolderKey lives exclusively in the ECIES-wrapped header of the IPFS vault blob v2 format.

Key technical accomplishments verified:

- TypeScript and Rust produce byte-identical output for the same inputs (cross-platform test vectors confirmed)
- The web login flow correctly branches on `migratedAt` for PATH A (read from IPFS) vs PATH B (read from DB + migrate)
- Migration is non-blocking — failures are caught and retried on next login
- The recovery tool is fully standalone with no CipherBox API dependency for v2 blobs
- All existing folder operations continue working (non-root folders use v1 JSON format unchanged)

Two items require human verification: the web login lazy migration flow and the recovery tool IPFS-direct path. These are behavioral confirmations in a live environment — the code supporting them is fully present and wired.

---

_Verified: 2026-03-24T01:48:50Z_
_Verifier: Claude (gsd-verifier)_

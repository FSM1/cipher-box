# Phase 20: Vault Migration - Research

**Researched:** 2026-03-23
**Domain:** IPFS vault blob format migration, zero-knowledge key storage, cross-client binary serialization
**Confidence:** HIGH

## Summary

Phase 20 migrates `rootFolderKey` from the server database to an IPFS vault blob v2 format, making the CipherBox server a true zero-knowledge relay. The migration is lazy (triggers on next login), uses a per-user `migratedAt` flag, and maintains a silent DB fallback for reliability. Three clients must be updated: the web app (TypeScript), the desktop app (Rust), and the standalone recovery tool (inline HTML/JS).

The core work is: (1) define a binary vault blob v2 format that prepends the ECIES-wrapped rootFolderKey to the existing AES-GCM encrypted folder metadata, (2) implement serialize/deserialize in `@cipherbox/core`, (3) mirror the logic in Rust for the desktop app, (4) update the recovery tool, (5) add a `migrated_at` column and update the API to NULL both crypto columns post-migration, and (6) stop sending `encryptedRootIpnsPrivateKey` on new vault init.

**Primary recommendation:** Implement blob v2 format as a binary-prefixed envelope in `@cipherbox/core` with version byte detection, then update all three clients to read v2 and write v2 on every root folder publish. The DB fallback ensures zero-risk migration.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- Migration fires **on next login** for existing users -- resolve current root blob, rewrite as v2, republish to IPNS
- **No forced migration** for dormant accounts -- they stay on v1 blobs indefinitely, migrate whenever they next log in. DB fallback always works for them
- Migration stamps a **migratedAt timestamp** on the vault DB record
- After confirmed v2 blob write, both `encryptedRootFolderKey` AND `encryptedRootIpnsPrivateKey` columns are **set to NULL** on the vault row
- **Per-user phased rollout**: migrated users (migratedAt set) read rootFolderKey from IPFS blob v2; non-migrated users continue reading from DB via GET /vault
- Initially, migrated users get **silent DB fallback** if IPFS blob read fails
- **Both web and desktop write blob v2** on root folder publishes -- any client can trigger migration
- **Recovery tool (recovery.html) updated to read blob v2** -- extracts rootFolderKey from IPFS without needing the CipherBox API
- Blob v2 serialization/deserialization logic lives in **@cipherbox/core**
- Desktop (Rust) implements the same v2 format independently
- **Stop sending** encryptedRootIpnsPrivateKey on new vault init -- all clients derive via HKDF
- API init-vault endpoint **accepts but ignores** the field if sent (backward compat)
- Column stays in DB but is NULL for new users
- Existing users: **NULL both crypto columns together** during v2 migration

### Claude's Discretion

- Exact blob v2 byte layout (research proposes `0x02 | uint16 key_length | ECIES_key | AES_GCM_metadata` -- final format at implementation time)
- v1 vs v2 detection heuristic details
- Migration retry logic if v2 blob write fails mid-login
- Test vector design for v2 blob parsing
- API endpoint changes to stop returning crypto columns for migrated users
- Error handling and logging specifics during migration

### Deferred Ideas (OUT OF SCOPE)

- **Column DROP migration** -- after all users migrated, drop encryptedRootFolderKey and encryptedRootIpnsPrivateKey columns. Separate future migration, not this phase.
- **IPFS-only retry-then-error mode** -- transition from silent DB fallback to hard IPFS-only after Kubo performance proves out. Configuration change, not code change.
- **Full login-to-vault E2E timing** -- Phase 22 scope (PERF-06)
- **Forced migration for dormant accounts** -- not needed; they migrate on next login whenever that is
  </user_constraints>

<phase_requirements>

## Phase Requirements

| ID       | Description                                                                        | Research Support                                                                                               |
| -------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| VAULT-01 | rootFolderKey embedded in IPFS vault blob v2 format (ECIES-wrapped in blob header) | Blob v2 binary format spec below; ECIES ciphertext is 129 bytes (97 overhead + 32 key); version byte detection |
| VAULT-02 | Client reads rootFolderKey from IPFS blob on login, falls back to DB vaults table  | Login flow redesign documented; per-user migration flag (`migratedAt`) gates read path; silent DB fallback     |
| VAULT-03 | Lazy migration writes vault blob v2 on next folder metadata publish                | Migration trigger on login (not on publish as stated -- CONTEXT overrides); web + desktop both write v2        |
| VAULT-04 | encryptedRootIpnsPrivateKey column deprecated from vaults table (HKDF-derivable)   | HKDF derivation already in both TS and Rust; init-vault DTO made optional; NULL both columns atomically        |
| VAULT-05 | Recovery tool updated to parse vault blob v2 format                                | recovery.html inline JS needs v2-aware blob parsing; independent of CipherBox API -- reads from IPFS directly  |
| VAULT-06 | Desktop app (Rust) parses vault blob v2 format                                     | Rust v2 deserialize in `commands/vault.rs`; `encrypt_metadata_to_json` updated to v2 in `fuse/mod.rs`          |

</phase_requirements>

## Standard Stack

### Core

| Library            | Version | Purpose                         | Why Standard                                                |
| ------------------ | ------- | ------------------------------- | ----------------------------------------------------------- |
| @cipherbox/core    | current | Vault blob v2 serialize/parse   | Already owns vault init, encrypt/decrypt vault keys         |
| @cipherbox/crypto  | current | ECIES wrapKey/unwrapKey, HKDF   | All crypto primitives live here                             |
| eciesjs            | 0.4.16  | ECIES encryption under the hood | Already used; 129-byte ciphertext for 32-byte rootFolderKey |
| TypeORM            | current | DB migration for migratedAt col | Already used for all migrations                             |
| serde + serde_json | current | Rust v2 blob handling           | Already used for all Rust serialization                     |
| ecies (Rust crate) | current | Rust ECIES wrap/unwrap          | Already used in desktop `crypto::ecies`                     |

### Supporting

| Library        | Version | Purpose                                  | When to Use                        |
| -------------- | ------- | ---------------------------------------- | ---------------------------------- |
| vitest         | current | Unit tests for @cipherbox/core v2 module | Test blob v2 serialize/deserialize |
| jest           | current | API integration tests for migration      | Test vault service migration flow  |
| @noble/ed25519 | current | Ed25519 key derivation in vault init     | Already used in decryptVaultKeys   |

### Alternatives Considered

None -- this phase operates entirely within the existing stack. No new libraries needed. The work is format design and cross-client implementation.

## Architecture Patterns

### Recommended Project Structure

```
packages/core/src/vault/
  init.ts          # Existing: initializeVault, encryptVaultKeys, decryptVaultKeys
  types.ts         # Existing: VaultInit, EncryptedVaultKeys + new BlobV2 types
  blob.ts          # NEW: serializeBlobV2, deserializeBlobV2, detectBlobVersion
  index.ts         # Re-exports new blob functions

apps/api/src/vault/
  vault.service.ts     # Modified: migration logic, migratedAt handling
  vault.controller.ts  # Modified: conditional response based on migratedAt
  entities/vault.entity.ts  # Modified: add migratedAt, make crypto cols nullable
  dto/init-vault.dto.ts     # Modified: encryptedRootIpnsPrivateKey optional

apps/api/src/migrations/
  174XXXXXXXX-AddVaultMigratedAt.ts  # NEW: add migrated_at, nullable crypto cols

apps/desktop/src-tauri/src/
  commands/vault.rs     # Modified: v2 blob parsing in fetch_and_decrypt_vault
  fuse/mod.rs           # Modified: encrypt_metadata_to_json becomes v2 format
  crypto/vault_blob.rs  # NEW: Rust v2 serialize/deserialize

apps/web/src/hooks/
  useAuth.ts            # Modified: v2 blob read + migration trigger on login

apps/web/public/
  recovery.html         # Modified: v2-aware blob parsing
```

### Pattern 1: Vault Blob v2 Binary Format

**What:** A binary envelope that prepends the ECIES-wrapped rootFolderKey before the existing AES-GCM metadata JSON.

**When to use:** Every root folder IPFS blob write and read.

**Specification:**

```
Vault Blob v2 (binary):
  Byte 0:         version = 0x02
  Bytes 1-2:      encryptedRootFolderKey length (uint16, big-endian) = 0x0081 (129)
  Bytes 3..131:   ECIES-encrypted rootFolderKey (129 bytes for 32-byte AES key)
  Bytes 132..:    AES-GCM encrypted folder metadata JSON (unchanged: {"iv":"...","data":"..."})

Vault Blob v1 (current, no version byte):
  All bytes:      JSON text: {"iv":"...","data":"..."}
```

**Detection heuristic:**

- If `blob[0] === 0x02`: parse as v2 (version byte present)
- Otherwise: parse as v1 (first byte will be `0x7B` = `{` for JSON)
- `0x7B` (123) is never a valid version byte we'll use, so detection is unambiguous

**Why uint16 for key length:** Future-proofing. The ECIES ciphertext is always 129 bytes for a 32-byte key (97 overhead + 32 plaintext), but encoding the length explicitly allows the format to handle different key sizes or ECIES parameter changes without a version bump.

**TypeScript implementation sketch:**

```typescript
// packages/core/src/vault/blob.ts

const BLOB_V2_VERSION = 0x02;

export function serializeVaultBlobV2(
  encryptedRootFolderKey: Uint8Array,
  encryptedMetadataJson: Uint8Array
): Uint8Array {
  const keyLen = encryptedRootFolderKey.length;
  const header = new Uint8Array(3 + keyLen);
  header[0] = BLOB_V2_VERSION;
  header[1] = (keyLen >> 8) & 0xff; // big-endian uint16
  header[2] = keyLen & 0xff;
  header.set(encryptedRootFolderKey, 3);

  const result = new Uint8Array(header.length + encryptedMetadataJson.length);
  result.set(header);
  result.set(encryptedMetadataJson, header.length);
  return result;
}

export function detectBlobVersion(blob: Uint8Array): 1 | 2 {
  return blob[0] === BLOB_V2_VERSION ? 2 : 1;
}

export function deserializeVaultBlobV2(blob: Uint8Array): {
  encryptedRootFolderKey: Uint8Array;
  encryptedMetadataJson: Uint8Array;
} {
  if (blob[0] !== BLOB_V2_VERSION) {
    throw new Error('Not a v2 vault blob');
  }
  const keyLen = (blob[1] << 8) | blob[2];
  const encryptedRootFolderKey = blob.slice(3, 3 + keyLen);
  const encryptedMetadataJson = blob.slice(3 + keyLen);
  return { encryptedRootFolderKey, encryptedMetadataJson };
}
```

**Rust implementation sketch:**

```rust
// apps/desktop/src-tauri/src/crypto/vault_blob.rs

const BLOB_V2_VERSION: u8 = 0x02;

pub fn detect_blob_version(blob: &[u8]) -> u8 {
    if !blob.is_empty() && blob[0] == BLOB_V2_VERSION { 2 } else { 1 }
}

pub fn serialize_vault_blob_v2(
    encrypted_root_folder_key: &[u8],
    encrypted_metadata_json: &[u8],
) -> Vec<u8> {
    let key_len = encrypted_root_folder_key.len() as u16;
    let mut result = Vec::with_capacity(3 + encrypted_root_folder_key.len() + encrypted_metadata_json.len());
    result.push(BLOB_V2_VERSION);
    result.push((key_len >> 8) as u8);
    result.push((key_len & 0xff) as u8);
    result.extend_from_slice(encrypted_root_folder_key);
    result.extend_from_slice(encrypted_metadata_json);
    result
}

pub fn deserialize_vault_blob_v2(blob: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if blob.is_empty() || blob[0] != BLOB_V2_VERSION {
        return Err("Not a v2 vault blob".into());
    }
    if blob.len() < 3 {
        return Err("Blob too short for v2 header".into());
    }
    let key_len = ((blob[1] as usize) << 8) | (blob[2] as usize);
    if blob.len() < 3 + key_len {
        return Err(format!("Blob too short for key (expected {} bytes)", key_len));
    }
    Ok((&blob[3..3 + key_len], &blob[3 + key_len..]))
}
```

### Pattern 2: Per-User Migration Flag

**What:** A `migrated_at` nullable timestamp column on the `vaults` table. When set, the user's login path reads rootFolderKey from IPFS blob v2 instead of the DB.

**When to use:** Login flow decision point and migration write path.

**Database migration:**

```typescript
// AddVaultMigratedAt migration
export class AddVaultMigratedAt implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add migrated_at timestamp
    await queryRunner.query(`
      ALTER TABLE vaults
      ADD COLUMN IF NOT EXISTS migrated_at TIMESTAMP NULL
    `);

    // Make crypto columns nullable for post-migration NULL-ing
    await queryRunner.query(`
      ALTER TABLE vaults
      ALTER COLUMN encrypted_root_folder_key DROP NOT NULL
    `);
    await queryRunner.query(`
      ALTER TABLE vaults
      ALTER COLUMN encrypted_root_ipns_private_key DROP NOT NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE vaults DROP COLUMN IF EXISTS migrated_at`);
    // Note: Cannot safely re-add NOT NULL if NULLs exist
  }
}
```

### Pattern 3: Login Flow with v2 Blob Read

**What:** Modified login flow that tries to extract rootFolderKey from the IPFS blob v2 header before falling back to the DB.

**Web app flow (useAuth.ts):**

```
Login (existing user):
  1. GET /vault -> { rootIpnsName, migratedAt, encryptedRootFolderKey? }
  2a. If migratedAt is set:
      - Derive IPNS key via HKDF -> resolve IPNS -> fetch blob
      - If blob is v2: extract encryptedRootFolderKey from header
      - If fetch fails: fall back to encryptedRootFolderKey from vault response (if provided)
  2b. If migratedAt is NOT set:
      - Use encryptedRootFolderKey from vault response (current behavior)
      - On next root folder publish: write blob v2, call POST /vault/migrate
  3. ECIES decrypt rootFolderKey with user's privateKey
  4. Decrypt folder metadata from the remaining blob bytes
```

**Migration trigger flow:**

```
On root folder metadata publish (web or desktop):
  1. Client already has rootFolderKey in memory
  2. ECIES-wrap rootFolderKey with user's publicKey -> encryptedRootFolderKey
  3. Encrypt folder metadata with rootFolderKey -> AES-GCM JSON
  4. Serialize as blob v2: version + key_len + encrypted_key + metadata_json
  5. Upload to IPFS -> new CID
  6. Create & publish signed IPNS record
  7. Call POST /vault/migrate (or PATCH /vault) to stamp migratedAt and NULL columns
```

### Pattern 4: Recovery Tool v2 Blob Parsing

**What:** The recovery tool currently gets rootFolderKey from the export JSON. With v2, it ALSO needs to parse the blob from IPFS directly (VAULT-05 -- recovery without CipherBox API).

**Two recovery paths:**

1. **Export-based recovery (existing):** Export JSON still contains encryptedRootFolderKey -- unchanged. Works for non-migrated users.
2. **IPFS-direct recovery (new for v2):** User provides privateKey + rootIpnsName (derivable from privateKey). Tool resolves IPNS, fetches blob, detects v2, extracts encryptedRootFolderKey from header. No export file needed.

The recovery tool should support both paths. For migrated users whose export was created pre-migration, the encryptedRootFolderKey in the export JSON may be stale (NULL if vault row was updated). The IPFS-direct path is the authoritative recovery mechanism for migrated users.

### Anti-Patterns to Avoid

- **Writing blob v2 only for root folder:** All clients must detect version on read, so the serialization path must be consistent. Non-root folders never get blob v2 (only root has encryptedRootFolderKey).
- **Migrating during publish instead of login:** The CONTEXT specifies migration fires on next login, not on next folder metadata publish. The publish writes v2 format, but the migration API call (stamping migratedAt) should happen as part of the login flow.
- **Dropping columns in this phase:** Explicitly deferred. Columns become nullable and get NULLed, but are not dropped.
- **Blocking login on migration failure:** If the v2 blob write fails, log the error and proceed with the DB-based key. The user will be retried on next login.

## Don't Hand-Roll

| Problem                  | Don't Build           | Use Instead                              | Why                                              |
| ------------------------ | --------------------- | ---------------------------------------- | ------------------------------------------------ |
| ECIES encryption         | Custom ECIES          | eciesjs (TS) / ecies crate (Rust)        | Proven, matches existing ECIES ciphertext format |
| HKDF IPNS key derivation | Manual key derivation | @cipherbox/crypto deriveVaultIpnsKeypair | Already implemented and tested in both platforms |
| Binary format parsing    | Manual bit shifting   | DataView (TS) / byte slicing (Rust)      | Standard approaches, well-tested                 |
| DB migration             | Manual SQL            | TypeORM migration with IF NOT EXISTS     | Follows project pattern from prior migrations    |

**Key insight:** The blob v2 format is intentionally simple (3-byte header + two concatenated payloads) to minimize parsing complexity across three implementations (TypeScript, Rust, recovery HTML). No protobuf, no CBOR, no msgpack -- raw bytes with a version discriminator.

## Common Pitfalls

### Pitfall 1: Race Between Migration Write and Concurrent Publish

**What goes wrong:** User logs in on Device A (triggers migration v2 write), while Device B simultaneously publishes a v1 blob update. Device B's v1 blob overwrites A's v2 blob in IPNS, and the migratedAt flag is already stamped.

**Why it happens:** The migration write and normal folder publishes use the same IPNS record. Optimistic concurrency (sequence number check) prevents stale overwrites, but the conflict resolution doesn't know about v2 format.

**How to avoid:**

1. Migration v2 write should use the same `createAndPublishIpnsRecord` with expected sequence number, so it participates in conflict detection.
2. On 409 Conflict during migration: resolve the current IPNS, check if the existing blob is already v2 (another device migrated), and if v1, retry the migration with the merged metadata.
3. Do NOT stamp migratedAt until the v2 blob is confirmed written (IPNS publish succeeds).

**Warning signs:** migratedAt is set but IPNS resolves to a v1 blob. The silent DB fallback covers this, but it means the migration didn't actually stick.

### Pitfall 2: Recovery Tool Breaks for Migrated Users with Stale Export

**What goes wrong:** User exports vault data (contains encryptedRootFolderKey from DB), then migrates. The API NULLs the DB columns. Later, the user tries to recover using the old export file but the server no longer has encryptedRootFolderKey. If the export was made AFTER migration, the field is null/missing.

**Why it happens:** The export endpoint (`GET /vault/export`) reads from the DB. After migration NULLs the columns, the export returns null for encryptedRootFolderKey.

**How to avoid:**

1. Update the export endpoint: for migrated users, resolve IPNS, fetch blob v2, and extract encryptedRootFolderKey from the IPFS blob to include in the export JSON.
2. Alternatively: the recovery tool should have an IPFS-direct mode where the user provides only their privateKey and the tool derives rootIpnsName via HKDF, resolves IPNS, and reads the v2 blob. No export file needed.
3. Both approaches should be implemented for maximum recovery resilience.

**Warning signs:** Recovery tool shows "missing encryptedRootFolderKey" error for migrated users.

### Pitfall 3: Version Detection Ambiguity with Corrupted Data

**What goes wrong:** A corrupted blob happens to start with `0x02`, causing the parser to treat random data as a v2 header. The extracted "key" is garbage, ECIES decrypt fails cryptically.

**Why it happens:** Single-byte version detection has a 1/256 chance of false positive on random data.

**How to avoid:**

1. After detecting v2, validate the key length field is reasonable (e.g., between 81 and 1024 bytes -- ECIES minimum is 81 bytes for empty plaintext).
2. If the ECIES decrypt of the extracted key fails, fall through to v1 parsing as a second attempt.
3. The v1 path will also fail on truly corrupted data, but at least we tried both interpretations.

**Warning signs:** ECIES decrypt errors that only happen for some users after v2 rollout.

### Pitfall 4: encryptedRootIpnsPrivateKey NULL Breaks Older Clients

**What goes wrong:** After migration NULLs both columns, an older client that hasn't been updated to derive IPNS keys via HKDF tries to read `encryptedRootIpnsPrivateKey` from the vault response and gets null. Login fails.

**Why it happens:** The API currently always returns `encryptedRootIpnsPrivateKey` in the vault response. Old clients depend on it.

**How to avoid:**

1. For non-migrated users (migratedAt is null), the API continues returning both columns as-is.
2. For migrated users (migratedAt is set), the API returns null/empty for both crypto columns. Old clients that read these will fail gracefully (HKDF derivation has been in the codebase since before Phase 20).
3. Both web and desktop already have HKDF derivation code. The desktop app's `fetch_and_decrypt_vault` already verifies the stored IPNS key matches HKDF derivation (vault.rs line 172-181). After migration, it simply uses HKDF directly.
4. Make `encryptedRootIpnsPrivateKey` optional in VaultResponseDto and handle null in all clients.

**Warning signs:** Login failures for migrated users on older client versions.

### Pitfall 5: Metadata Evolution Protocol Not Followed

**What goes wrong:** The blob v2 format is a breaking change to the vault blob format (Section 3.2 of METADATA_EVOLUTION_PROTOCOL.md). If the protocol checklist is not followed, cross-platform deserialization breaks silently.

**Why it happens:** Developers focus on the TypeScript implementation and forget the Rust side, or don't update the recovery tool.

**How to avoid:**

1. Follow the full Evolution Checklist (Section 4) from METADATA_EVOLUTION_PROTOCOL.md.
2. Both TypeScript and Rust implementations must produce byte-identical v2 blobs for the same input.
3. Create hardcoded test vectors: a known privateKey + rootFolderKey + folder metadata produces a specific v2 blob. Both TS and Rust tests verify against the same expected output.
4. The recovery tool gets its own test (manual but documented) with the same test vector.

**Warning signs:** Desktop app can't parse blobs written by web app, or vice versa.

## Code Examples

### Vault Blob v2 Serialize (TypeScript)

```typescript
// packages/core/src/vault/blob.ts
import { wrapKey } from '@cipherbox/crypto';
import { encryptFolderMetadata } from '../folder/metadata';
import type { FolderMetadata } from '../folder/types';

const BLOB_V2_VERSION = 0x02;

/**
 * Serialize root folder metadata as vault blob v2.
 * Prepends ECIES-wrapped rootFolderKey before the encrypted metadata JSON.
 *
 * @param rootFolderKey - 32-byte AES key (plaintext, in memory)
 * @param userPublicKey - 65-byte uncompressed secp256k1 public key
 * @param metadata - Folder metadata to encrypt
 * @returns Binary blob ready for IPFS upload
 */
export async function serializeRootBlobV2(
  rootFolderKey: Uint8Array,
  userPublicKey: Uint8Array,
  metadata: FolderMetadata
): Promise<Uint8Array> {
  // 1. ECIES-wrap rootFolderKey
  const encryptedKey = await wrapKey(rootFolderKey, userPublicKey);

  // 2. Encrypt folder metadata with AES-GCM
  const encrypted = await encryptFolderMetadata(metadata, rootFolderKey);
  const metadataJson = new TextEncoder().encode(JSON.stringify(encrypted));

  // 3. Build binary envelope
  return serializeVaultBlobV2(encryptedKey, metadataJson);
}
```

### Login with v2 Blob Read (TypeScript, sketch)

```typescript
// In useAuth.ts initializeOrLoadVault callback
const existingVault = await vaultApi.getVault();

if (existingVault.migratedAt) {
  // Migrated user: try reading from IPFS blob v2
  try {
    const ipnsKeypair = await deriveVaultIpnsKeypair(userKeypair.privateKey);
    const ipnsName = await deriveIpnsName(ipnsKeypair.publicKey);
    const resolved = await ipnsApi.resolve(ipnsName);
    const blobBytes = await ipfsApi.fetch(resolved.cid);

    if (detectBlobVersion(blobBytes) === 2) {
      const { encryptedRootFolderKey, encryptedMetadataJson } = deserializeVaultBlobV2(blobBytes);
      const rootFolderKey = await unwrapKey(encryptedRootFolderKey, userKeypair.privateKey);
      // Decrypt metadata from remaining bytes
      const encryptedMeta = JSON.parse(new TextDecoder().decode(encryptedMetadataJson));
      const metadata = await decryptFolderMetadata(encryptedMeta, rootFolderKey);
      // ... hydrate stores
    }
  } catch {
    // Silent DB fallback
    const rootFolderKey = await unwrapKey(
      hexToBytes(existingVault.encryptedRootFolderKey),
      userKeypair.privateKey
    );
    // ... existing v1 path
  }
} else {
  // Non-migrated user: existing DB path + trigger migration
  // ... existing decryptVaultKeys path
}
```

### DB Migration (TypeORM)

```typescript
export class AddVaultMigratedAt1740600000000 implements MigrationInterface {
  name = 'AddVaultMigratedAt1740600000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE vaults ADD COLUMN IF NOT EXISTS migrated_at TIMESTAMP NULL
    `);
    await queryRunner.query(`
      ALTER TABLE vaults ALTER COLUMN encrypted_root_folder_key DROP NOT NULL
    `);
    await queryRunner.query(`
      ALTER TABLE vaults ALTER COLUMN encrypted_root_ipns_private_key DROP NOT NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE vaults DROP COLUMN IF EXISTS migrated_at`);
    // Cannot safely re-add NOT NULL constraints if NULLs exist
  }
}
```

### Vault Entity Update

```typescript
// vault.entity.ts additions
@Column({ type: 'bytea', name: 'encrypted_root_folder_key', nullable: true })
encryptedRootFolderKey!: Buffer | null;

@Column({ type: 'bytea', name: 'encrypted_root_ipns_private_key', nullable: true })
encryptedRootIpnsPrivateKey!: Buffer | null;

@Column({ type: 'timestamp', nullable: true, name: 'migrated_at' })
migratedAt!: Date | null;
```

## State of the Art

| Old Approach                                       | Current Approach                             | When Changed | Impact                                    |
| -------------------------------------------------- | -------------------------------------------- | ------------ | ----------------------------------------- |
| rootFolderKey in DB only                           | rootFolderKey in IPFS blob v2 + DB fallback  | Phase 20     | Server becomes zero-knowledge relay       |
| encryptedRootIpnsPrivateKey stored and returned    | HKDF derivation canonical, column deprecated | Phase 20     | One less secret in DB                     |
| Recovery requires export file with DB-sourced keys | Recovery reads directly from IPFS blob v2    | Phase 20     | True server-independent recovery          |
| All clients send encryptedRootIpnsPrivateKey       | New vaults skip it, API accepts but ignores  | Phase 20     | Cleaner vault init, less data transmitted |

**Deprecated/outdated:**

- `encryptedRootIpnsPrivateKey` column: HKDF-derivable since project inception. Kept as nullable DB column but no longer populated for new users or post-migration users.
- `VaultResponseDto.encryptedRootIpnsPrivateKey`: Becomes optional/nullable in API response.

## Open Questions

1. **Migration API endpoint design**
   - What we know: After successful v2 blob write, the client needs to tell the server to stamp migratedAt and NULL both columns.
   - What's unclear: Should this be a new `POST /vault/migrate` endpoint, or a `PATCH /vault` with a migration flag? The existing vault service only has init/get/export.
   - Recommendation: Add a dedicated `POST /vault/migrate` endpoint. It's a one-time operation per user, not a general update. The endpoint should verify the caller owns the vault and idempotently set migratedAt.

2. **Export endpoint for migrated users**
   - What we know: `GET /vault/export` currently reads encryptedRootFolderKey from the DB. After migration, this is NULL.
   - What's unclear: Should the export endpoint fetch from IPFS to populate the field, or should the export format be updated to indicate "use IPFS-direct recovery"?
   - Recommendation: Update the export endpoint to resolve IPNS and extract the key from the v2 blob for migrated users. This keeps the export format backward-compatible and self-contained.

3. **Desktop app migration trigger timing**
   - What we know: Desktop uses `fetch_and_decrypt_vault` on login (reads from API), then publishes metadata via FUSE mount operations.
   - What's unclear: Should the desktop trigger migration on login (like web), or on first root folder metadata publish?
   - Recommendation: Desktop triggers migration on first root folder publish (it doesn't have a separate "login vault init" step that writes to IPFS -- the FUSE mount does that). Both approaches are acceptable since the format is written by whoever publishes root metadata first.

## Validation Architecture

### Test Framework

| Property           | Value                                                                  |
| ------------------ | ---------------------------------------------------------------------- |
| Framework          | Vitest (core/crypto packages), Jest (API), cargo test (Rust)           |
| Config file        | `packages/core/vitest.config.ts`, `apps/api/jest config`, `Cargo.toml` |
| Quick run command  | `pnpm --filter @cipherbox/core test -- --run`                          |
| Full suite command | `pnpm test && cd apps/desktop/src-tauri && cargo test --features fuse` |

### Phase Requirements -> Test Map

| Req ID   | Behavior                                        | Test Type   | Automated Command                                    | File Exists? |
| -------- | ----------------------------------------------- | ----------- | ---------------------------------------------------- | ------------ |
| VAULT-01 | Blob v2 serialize/deserialize round-trip        | unit        | `pnpm --filter @cipherbox/core test -- --run blob`   | Wave 0       |
| VAULT-01 | Version detection (v1 vs v2)                    | unit        | `pnpm --filter @cipherbox/core test -- --run blob`   | Wave 0       |
| VAULT-01 | ECIES key extraction from v2 header             | unit        | `pnpm --filter @cipherbox/core test -- --run blob`   | Wave 0       |
| VAULT-02 | Login reads from v2 blob for migrated user      | integration | `pnpm --filter api test -- vault`                    | Wave 0       |
| VAULT-02 | Login falls back to DB on IPFS failure          | integration | `pnpm --filter api test -- vault`                    | Wave 0       |
| VAULT-03 | Migration stamps migratedAt and NULLs columns   | integration | `pnpm --filter api test -- vault`                    | Wave 0       |
| VAULT-04 | Init-vault accepts without encryptedRootIpnsKey | unit        | `pnpm --filter api test -- vault`                    | Wave 0       |
| VAULT-04 | HKDF derivation matches stored key              | unit        | `pnpm --filter @cipherbox/core test -- --run vault`  | Existing     |
| VAULT-05 | Recovery tool parses v2 blob                    | manual-only | Manual: open recovery.html, load v2 test export      | N/A          |
| VAULT-06 | Rust v2 blob round-trip matches TypeScript      | unit        | `cd apps/desktop/src-tauri && cargo test vault_blob` | Wave 0       |
| VAULT-06 | Rust v2 deserialize of TS-generated blob        | unit        | `cd apps/desktop/src-tauri && cargo test vault_blob` | Wave 0       |

### Sampling Rate

- **Per task commit:** `pnpm --filter @cipherbox/core test -- --run`
- **Per wave merge:** `pnpm test && cd apps/desktop/src-tauri && cargo test --features fuse`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `packages/core/src/__tests__/vault-blob.test.ts` -- covers VAULT-01 (v2 serialize/deserialize/detect)
- [ ] `packages/core/src/__tests__/vault-blob-vectors.test.ts` -- cross-platform test vectors for VAULT-06
- [ ] `apps/api/src/vault/__tests__/vault-migration.spec.ts` -- covers VAULT-02, VAULT-03, VAULT-04
- [ ] `apps/desktop/src-tauri/src/crypto/vault_blob.rs` -- Rust v2 module with inline `#[test]` for VAULT-06
- [ ] DB migration file for `migrated_at` column

_(Existing test infrastructure in `packages/core/src/__tests__/vault.test.ts` covers current encrypt/decrypt -- extend, do not replace)_

## Sources

### Primary (HIGH confidence)

- **Codebase analysis** -- Direct reading of all source files listed in CONTEXT.md canonical references:
  - `packages/core/src/vault/init.ts` (vault encrypt/decrypt)
  - `packages/core/src/vault/types.ts` (EncryptedVaultKeys type)
  - `packages/core/src/folder/metadata.ts` (encryptFolderMetadata/decryptFolderMetadata)
  - `apps/api/src/vault/vault.service.ts` (server vault CRUD)
  - `apps/api/src/vault/entities/vault.entity.ts` (DB schema)
  - `apps/api/src/vault/dto/init-vault.dto.ts` (API DTOs)
  - `apps/web/src/hooks/useAuth.ts` (login flow)
  - `apps/web/src/stores/vault.store.ts` (vault state)
  - `apps/desktop/src-tauri/src/commands/vault.rs` (Rust vault)
  - `apps/desktop/src-tauri/src/fuse/mod.rs` (FUSE metadata publish)
  - `apps/web/public/recovery.html` (recovery tool)

- **Project documentation** -- All referenced in CONTEXT.md:
  - `.planning/research/ARCHITECTURE.md` S3.1.1 -- vault blob v2 format specification
  - `.planning/research/PITFALLS.md` Pitfall 2 -- rootFolderKey IPNS dependency risks
  - `docs/METADATA_SCHEMAS.md` S10 -- EncryptedVaultKeys schema
  - `docs/METADATA_EVOLUTION_PROTOCOL.md` -- breaking change rules
  - `docs/VAULT_EXPORT_FORMAT.md` S4 -- ECIES ciphertext binary format (129 bytes for 32-byte key)

### Secondary (MEDIUM confidence)

- **ECIES ciphertext sizing** -- Verified from `packages/crypto/src/constants.ts`: `ECIES_MIN_CIPHERTEXT_SIZE = 65 + 16 = 81 bytes` (minimum). For 32-byte plaintext: 65 (ephemeral PK) + 16 (nonce) + 16 (tag) + 32 (ciphertext) = 129 bytes. Confirmed by `docs/VAULT_EXPORT_FORMAT.md` table.

### Tertiary (LOW confidence)

- None. All findings verified against codebase and project documentation.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- all libraries are already in use, no new dependencies
- Architecture: HIGH -- blob format design is straightforward binary envelope; all integration points inspected
- Pitfalls: HIGH -- race conditions and fallback paths identified from real codebase patterns; metadata evolution protocol is documented
- Cross-platform parity: MEDIUM -- Rust and TypeScript implementations must produce identical blobs; test vectors are the verification mechanism, not yet written

**Research date:** 2026-03-23
**Valid until:** 2026-04-23 (stable -- no external dependency changes expected)

# Security Review: Phase 20 -- Vault Migration (v2 Blob Format)

**Reviewer:** Claude Opus 4.6 (Security Agent)
**Date:** 2026-03-24
**Phase:** 20 -- Vault Migration
**Scope:** All files changed by phase 20 commits (20-01 through 20-03)
**Status:** COMPLETE

---

## Executive Summary

Phase 20 introduces a vault blob v2 binary format that embeds the ECIES-encrypted
rootFolderKey alongside AES-GCM-encrypted folder metadata in a single IPFS blob.
This migrates encrypted key storage from the server-side database to IPFS, further
reducing the server's role and improving the zero-knowledge property.

The implementation is well-structured, with clean separation of concerns. The binary
format is simple and sound. Cross-platform test vectors ensure TypeScript/Rust
compatibility. The migration flow is carefully sequenced to avoid data loss.

**Issues found:** 7 total (0 Critical, 2 High, 3 Medium, 2 Low)

---

## Files Analyzed

| #   | File                                                          | Purpose                                |
| --- | ------------------------------------------------------------- | -------------------------------------- |
| 1   | `packages/core/src/vault/blob.ts`                             | v2 blob serialize/deserialize/detect   |
| 2   | `packages/core/src/vault/types.ts`                            | VaultBlobV2 type definitions           |
| 3   | `packages/core/src/vault/init.ts`                             | Vault init, encrypt/decrypt vault keys |
| 4   | `packages/core/src/__tests__/vault-blob.test.ts`              | Unit tests                             |
| 5   | `packages/core/src/__tests__/vault-blob-vectors.test.ts`      | Cross-platform test vectors            |
| 6   | `apps/api/src/migrations/1740600000000-AddVaultMigratedAt.ts` | DB migration                           |
| 7   | `apps/api/src/vault/entities/vault.entity.ts`                 | Vault entity (nullable columns)        |
| 8   | `apps/api/src/vault/dto/init-vault.dto.ts`                    | DTOs (optional IPNS key)               |
| 9   | `apps/api/src/vault/vault.service.ts`                         | migrateVault() service method          |
| 10  | `apps/api/src/vault/vault.controller.ts`                      | POST /vault/migrate endpoint           |
| 11  | `apps/desktop/src-tauri/src/crypto/vault_blob.rs`             | Rust v2 blob module                    |
| 12  | `apps/desktop/src-tauri/src/commands/vault.rs`                | Desktop vault commands                 |
| 13  | `apps/desktop/src-tauri/src/api/types.rs`                     | API types (nullable fields)            |
| 14  | `apps/desktop/src-tauri/src/fuse/mod.rs`                      | FUSE mount v2 publish                  |
| 15  | `apps/desktop/src-tauri/src/fuse/decrypt.rs`                  | v2 blob-aware decrypt                  |
| 16  | `apps/web/src/hooks/useAuth.ts`                               | Web client login + migration flow      |
| 17  | `apps/web/public/recovery.html`                               | Recovery tool v2 support               |
| 18  | `apps/desktop/src-tauri/src/crypto/mod.rs`                    | Crypto module (vault_blob export)      |

**Crypto operations catalogued:** 14

---

## Findings

### [HIGH] H-1: Rust `serialize_vault_blob_v2` silently truncates key lengths > 65535 bytes

**Location:** `apps/desktop/src-tauri/src/crypto/vault_blob.rs:29`

**Code:**

```rust
let key_len = encrypted_root_folder_key.len() as u16;
```

**Issue:**
The Rust serializer casts the key length to `u16` without checking for overflow. If
`encrypted_root_folder_key` is longer than 65,535 bytes, the length silently wraps
around. The serialized blob would then have an incorrect `key_len` field, causing
deserialization to produce corrupted components -- the encrypted key would be
truncated and the metadata boundary would be wrong.

While ECIES-wrapped keys are typically ~129 bytes (making this practically unlikely
in normal operation), the function signature accepts `&[u8]` with no documented
length constraint. A programming error passing the wrong buffer, or a future format
change with larger keys, could trigger silent data corruption.

The TypeScript version has the same theoretical issue (JavaScript bit shifts on
numbers > 65535 would produce wrong uint16 values) but it manifests differently due
to JS number semantics.

**Impact:**
Silent data corruption of the vault blob. The deserialized key and metadata would
both be garbage, failing ECIES decryption in a way that looks like key mismatch
rather than a format error.

**Recommendation:**

```rust
pub fn serialize_vault_blob_v2(
    encrypted_root_folder_key: &[u8],
    encrypted_metadata_json: &[u8],
) -> Result<Vec<u8>, String> {
    if encrypted_root_folder_key.len() > u16::MAX as usize {
        return Err(format!(
            "Encrypted key too large for v2 format ({} bytes, max {})",
            encrypted_root_folder_key.len(),
            u16::MAX
        ));
    }
    let key_len = encrypted_root_folder_key.len() as u16;
    // ... rest unchanged
    Ok(result)
}
```

And for TypeScript (`packages/core/src/vault/blob.ts:55`):

```typescript
export function serializeVaultBlobV2(
  encryptedRootFolderKey: Uint8Array,
  encryptedMetadataJson: Uint8Array
): Uint8Array {
  const keyLen = encryptedRootFolderKey.length;
  if (keyLen > 0xffff) {
    throw new Error(`Encrypted key too large for v2 format (${keyLen} bytes, max 65535)`);
  }
  // ... rest unchanged
}
```

**References:**

- Rust `as` casting: <https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions>

---

### [HIGH] H-2: `InitVaultRequest` Rust struct derives `Debug` with sensitive encrypted key data

**Location:** `apps/desktop/src-tauri/src/api/types.rs:91-98`

**Code:**

```rust
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitVaultRequest {
    pub owner_public_key: String,
    pub encrypted_root_folder_key: String,
    pub encrypted_root_ipns_private_key: String,
    pub root_ipns_name: String,
}
```

**Issue:**
The `InitVaultRequest` struct derives `Debug` without a manual implementation.
While the other auth-related structs (`LoginRequest`, `LoginResponse`,
`RefreshRequest`, `RefreshResponse`) all have custom `Debug` impls that redact
sensitive fields, this struct would print encrypted key material in logs if ever
logged via `{:?}` format.

The encrypted keys are not plaintext (they are ECIES-wrapped), so the severity is
reduced. However, logging ECIES ciphertext could assist an attacker with access to
logs -- ciphertext combined with knowledge of the ECIES scheme could narrow attack
surface.

The `VaultResponse` struct at line 105 also derives `Debug` without redaction,
exposing the same hex-encoded encrypted keys.

**Impact:**
Encrypted key material could appear in application logs if these structs are ever
logged via debug formatting.

**Recommendation:**

```rust
impl fmt::Debug for InitVaultRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitVaultRequest")
            .field("owner_public_key", &"[REDACTED]")
            .field("encrypted_root_folder_key", &"[REDACTED]")
            .field("encrypted_root_ipns_private_key", &"[REDACTED]")
            .field("root_ipns_name", &self.root_ipns_name)
            .finish()
    }
}

impl fmt::Debug for VaultResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultResponse")
            .field("encrypted_root_folder_key", &self.encrypted_root_folder_key.as_ref().map(|_| "[REDACTED]"))
            .field("root_ipns_name", &self.root_ipns_name)
            .field("encrypted_root_ipns_private_key", &self.encrypted_root_ipns_private_key.as_ref().map(|_| "[REDACTED]"))
            .field("tee_keys", &self.tee_keys)
            .field("migrated_at", &self.migrated_at)
            .finish()
    }
}
```

---

### [MEDIUM] M-1: Recovery tool private key persists in module-scope variable after recovery

**Location:** `apps/web/public/recovery.html:485`

**Code:**

```javascript
let privateKeyBytes = null;
```

**Issue:**
The recovery tool stores the user's secp256k1 private key in a module-scope variable
(`privateKeyBytes`) and never clears it after recovery completes. While the page
displays "Your private key was used in-memory only and is not stored or transmitted"
(line 457), the variable remains populated in the JavaScript heap until the page is
closed or navigated away from.

If the user leaves the recovery page open (as the note only says "Close this page
when done" -- advisory, not enforced), the private key remains in memory accessible
to:

- Browser extensions with content script access
- DevTools console
- Any XSS vulnerability in the page

The `rootFolderKey` and `rootIpnsPrivateKey` variables have the same issue.

**Impact:**
Private key material remains in memory longer than necessary. An attacker with
script execution on the page could extract it.

**Recommendation:**
After recovery completes (success or failure), zero the key material:

```javascript
// After recovery completes (in the btn-recover click handler, after try/catch):
if (privateKeyBytes) {
  privateKeyBytes.fill(0);
  privateKeyBytes = null;
}
if (rootFolderKey) {
  if (rootFolderKey instanceof Uint8Array) rootFolderKey.fill(0);
  rootFolderKey = null;
}
if (rootIpnsPrivateKey) {
  if (rootIpnsPrivateKey instanceof Uint8Array) rootIpnsPrivateKey.fill(0);
  rootIpnsPrivateKey = null;
}
```

Note: JavaScript garbage collection means the original ArrayBuffer may still exist,
but zeroing the typed array view provides defense-in-depth.

---

### [MEDIUM] M-2: Web migration race condition -- concurrent logins could double-migrate

**Location:** `apps/web/src/hooks/useAuth.ts:181-233`

**Code:**

```typescript
// Non-blocking migration trigger: write v2 blob + call /vault/migrate
void (async () => {
  try {
    // 1. ECIES-wrap rootFolderKey with user's publicKey
    const encryptedKey = await wrapKey(decryptedVault.rootFolderKey, userKeypair.publicKey);
    // ...
    await vaultControllerMigrateVault();
  } catch (migrationError) {
    console.warn('[Auth] Vault v2 migration failed (will retry on next login):', migrationError);
  }
})();
```

**Issue:**
The migration is triggered as a fire-and-forget async IIFE. If the user is logged in
on two browser tabs simultaneously (or on browser + desktop), both clients could
detect `!existingVault.migratedAt` and start the migration flow concurrently. While
the server-side `migrateVault()` is idempotent (checks `vault.migratedAt` before
updating), the IPNS publish step uses optimistic concurrency
(`expectedSequenceNumber`). Two concurrent migrations would:

1. Both resolve the same current IPNS CID
2. Both wrap the same rootFolderKey (deterministic, so the content is the same)
3. Both upload identical v2 blobs (different CIDs due to IPFS content addressing
   of potentially different ECIES nonces)
4. First IPNS publish succeeds, second gets 409 Conflict
5. Second migration fails silently, retries on next login (eventually succeeds)

The safety net here is that:

- The IPNS publish uses `expectedSequenceNumber` for conflict detection
- `migrateVault()` is idempotent
- Both blobs contain the same rootFolderKey (different ECIES wrapping, same plaintext)

So this is not a data loss scenario, but it creates unnecessary IPFS garbage (orphan
blob from the failed migration) and confusing log output.

**Impact:**
Low actual risk due to idempotency guards. Orphan IPFS blobs and confusing logs.

**Recommendation:**
Add a lightweight client-side deduplication flag to prevent concurrent migration
attempts within the same browser session:

```typescript
// At module scope or in a ref:
let migrationInProgress = false;

// In the migration IIFE:
if (migrationInProgress) return;
migrationInProgress = true;
try {
  // ... migration logic
} finally {
  migrationInProgress = false;
}
```

---

### [MEDIUM] M-3: ECIES re-wrapping on every root folder publish generates fresh ciphertexts

**Location:** `apps/desktop/src-tauri/src/fuse/mod.rs:243-244`

**Code:**

```rust
let encrypted_key = crate::crypto::ecies::wrap_key(folder_key, public_key)
    .map_err(|e| format!("Failed to wrap rootFolderKey for v2 blob: {}", e))?;
```

Also in web: `apps/web/src/hooks/useAuth.ts:184`

**Issue:**
Every time the root folder metadata is published (on every file create, delete,
rename, or content change in the root folder), the rootFolderKey is freshly
ECIES-wrapped. ECIES uses an ephemeral key, so each wrapping produces a different
ciphertext for the same plaintext key. This means:

1. **Performance:** An ECIES wrap operation (ECDH + HKDF + AES-GCM) happens on
   every root folder metadata publish, which is unnecessary overhead. The encrypted
   key doesn't change -- only the metadata portion changes.

2. **Ciphertext diversity:** Each blob on IPFS contains a different ECIES ciphertext
   wrapping the same rootFolderKey. While this is not a vulnerability (ECIES with
   ephemeral keys is IND-CCA2 secure), it does mean that an attacker with access to
   multiple historical blobs gets multiple ECIES ciphertexts of the same plaintext.
   This is fine cryptographically but violates the principle of minimal exposure.

3. **Random number consumption:** Each ECIES wrap consumes entropy from the CSPRNG.

**Impact:**
Minor performance overhead and unnecessary cryptographic operations. No security
vulnerability, but a design inefficiency.

**Recommendation:**
Cache the ECIES-wrapped rootFolderKey and reuse it for all root folder publishes
during a session. It only needs to be freshly wrapped when:

- The vault is first initialized
- The user's keypair rotates (which doesn't happen in v1.0)

```rust
// In CipherBoxFS state:
cached_encrypted_root_key: Option<Vec<u8>>,

// In encrypt_root_metadata_to_v2_blob:
fn encrypt_root_metadata_to_v2_blob(
    metadata: &FolderMetadata,
    folder_key: &[u8],
    public_key: &[u8],
    cached_encrypted_key: &Option<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let json_bytes = encrypt_metadata_to_json(metadata, folder_key)?;
    let encrypted_key = match cached_encrypted_key {
        Some(key) => key.clone(),
        None => crypto::ecies::wrap_key(folder_key, public_key)?,
    };
    Ok((serialize_vault_blob_v2(&encrypted_key, &json_bytes), encrypted_key))
}
```

This is an optimization suggestion, not a security fix.

---

### [LOW] L-1: `deserializeVaultBlobV2` allows zero-length encryptedRootFolderKey

**Location:** `packages/core/src/vault/blob.ts:82-103` and
`apps/desktop/src-tauri/src/crypto/vault_blob.rs:43-62`

**Code:**

```typescript
// TypeScript
const keyLen = (blob[1] << 8) | blob[2];
// No check for keyLen === 0
```

```rust
// Rust
let key_len = ((blob[1] as usize) << 8) | (blob[2] as usize);
// No check for key_len === 0
```

**Issue:**
Both implementations allow `key_len = 0`, which would produce a zero-length
`encryptedRootFolderKey` and pass the entire remaining blob as
`encryptedMetadataJson`. A valid ECIES ciphertext is at minimum 65 + 16 + 16 = 97
bytes (ephemeral public key + nonce + tag), so a zero-length key is always invalid.

This would not cause a crash (the downstream ECIES unwrap would fail with a
descriptive error), but catching it early provides a better error message and
prevents wasted crypto operations.

**Impact:**
Poor error messaging on malformed blobs. No security impact since ECIES unwrap
fails safely.

**Recommendation:**
Add a minimum key length check:

```typescript
if (keyLen === 0) {
  throw new Error('Vault blob v2 has zero-length encrypted key');
}
```

---

### [LOW] L-2: Recovery tool loads fflate from CDN without integrity check

**Location:** `apps/web/public/recovery.html:467`

**Code:**

```html
<script src="https://cdn.jsdelivr.net/npm/fflate@0.8.2/umd/index.js"></script>
```

**Issue:**
The fflate compression library is loaded from a CDN without a Subresource Integrity
(SRI) hash. The other imports use ES module imports from the same CDN
(noble-curves, noble-hashes, noble-ed25519) which also lack SRI.

If the CDN is compromised, an attacker could inject malicious code that exfiltrates
the user's private key or decrypted files during recovery. The recovery tool
specifically handles the user's most sensitive data (secp256k1 private key +
decrypted vault contents).

**Impact:**
CDN compromise would allow exfiltration of private keys and decrypted file contents.
Likelihood is low (jsdelivr is widely trusted), but the impact would be total
compromise of the user's vault.

**Recommendation:**
Add SRI hashes to all script tags:

```html
<script
  src="https://cdn.jsdelivr.net/npm/fflate@0.8.2/umd/index.js"
  integrity="sha384-<computed-hash>"
  crossorigin="anonymous"
></script>
```

For ES module imports, SRI is not natively supported. Consider:

1. Bundling the recovery tool with all dependencies (self-contained HTML)
2. Or pinning to exact CDN commit hashes rather than version tags

Note: This finding also appeared in previous reviews. Repeating for completeness.

---

## Positive Security Observations

### P-1: Migration ordering is correct (write-before-stamp)

The migration flow correctly writes the v2 blob to IPFS and publishes IPNS
_before_ calling `POST /vault/migrate` to NULL the DB columns. This means a crash
during migration cannot cause data loss -- the DB columns remain populated until
the IPFS write is confirmed. (See `useAuth.ts:220-223` comment.)

### P-2: Server-side migrateVault is idempotent

`vault.service.ts:201-223` checks `vault.migratedAt` before updating, and returns
success on re-call. This prevents double-NULL and handles retry scenarios safely.

### P-3: migrate endpoint requires JWT authentication

The `POST /vault/migrate` endpoint is protected by `@UseGuards(JwtAuthGuard)` at
the controller class level (`vault.controller.ts:13`), and uses `req.user.id` to
scope the operation. No user can migrate another user's vault.

### P-4: migrate endpoint takes no body parameters

`vault.controller.ts:63` accepts no `@Body()` parameter. The server determines what
to NULL based on the authenticated user ID only. There is no way for a client to
influence which vault or which fields are affected.

### P-5: Desktop fallback path for migrated vaults is sound

`commands/vault.rs:173-200` correctly handles the migrated path: derive IPNS key
via HKDF, resolve IPNS, fetch blob, detect v2, deserialize, ECIES-unwrap. If the
blob is not v2 format, it returns an explicit error rather than silently failing.

### P-6: v2 blob detection is backward-compatible

`detectBlobVersion()` returns 1 for any blob not starting with 0x02, which means
existing v1 JSON blobs (starting with `{` = 0x7B) are correctly identified. An empty
blob returns 1, which will then fail at JSON parse (appropriate error path).

### P-7: FUSE decrypt module correctly strips v2 header

`fuse/decrypt.rs:9-23` correctly detects v2 blobs and strips the encrypted key
header before passing only the metadata JSON portion to the AES-GCM decryption
logic. The encrypted key is discarded (`_enc_key`), which is correct -- the
rootFolderKey is already in memory from vault initialization.

### P-8: Cross-platform test vectors ensure binary compatibility

Test vectors in `vault-blob-vectors.test.ts` and `vault_blob.rs` verify byte-for-byte
identical serialization output between TypeScript and Rust implementations. This
prevents subtle endianness or encoding bugs.

### P-9: No sensitive keys logged

Log messages in `commands/vault.rs` mention key operations descriptively
("Fetching and decrypting vault keys", "Vault keys decrypted and stored in memory")
but never log actual key bytes. The `private_key` variable is cloned from the
RwLock but never formatted for output.

### P-10: Web client v2 fallback path for DB recovery

`useAuth.ts:132-143` handles the case where a vault is marked as migrated but IPFS
read fails (e.g., IPNS expired, gateway down). It falls back to DB-stored
`encryptedRootFolderKey` if still available. This is defense-in-depth for the
window between v2 blob write and DB column NULLing.

### P-11: Recovery tool properly guides migrated vault users

`recovery.html:1334-1336` detects when export data has null encrypted keys (migrated
vault) and directs users to use the IPFS-direct recovery method instead. This
prevents a confusing "cannot decrypt null" error.

---

## Compliance Checklist

| Rule                                                     | Status | Notes                                                                                                       |
| -------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------- |
| Never store privateKey in localStorage/sessionStorage    | PASS   | Keys stored only in Zustand (memory) and Rust RwLock (memory)                                               |
| Never log sensitive keys                                 | PASS   | See P-9. Auth structs have redacted Debug impls. H-2 notes InitVaultRequest/VaultResponse lack redaction.   |
| Never send unencrypted keys to server                    | PASS   | All keys are ECIES-wrapped before transmission. Migration endpoint sends no key data.                       |
| Always use ECIES for key wrapping                        | PASS   | rootFolderKey wrapped with ECIES in v2 blob header; all vault keys ECIES-wrapped                            |
| Always use AES-256-GCM for content encryption            | PASS   | Metadata encrypted with AES-256-GCM (iv + sealed data format)                                               |
| Server NEVER has access to plaintext or unencrypted keys | PASS   | Server only stores/relays ECIES ciphertext; migrateVault NULLs server columns                               |
| Always encrypt ipnsPrivateKey with TEE public key        | N/A    | Phase 20 does not modify TEE key handling                                                                   |
| Web Crypto API only (no JS crypto libraries)             | N/A    | Phase 20 blob code is pure byte manipulation (no crypto). Crypto operations use existing ECIES/AES modules. |
| Uint8Array for all binary data                           | PASS   | blob.ts uses Uint8Array throughout; recovery.html uses Uint8Array for all crypto                            |

---

## Suggested Test Cases

### Binary Format Security Tests

```typescript
describe('Vault Blob v2 Security Tests', () => {
  describe('Boundary Conditions', () => {
    it('should reject key_len = 0 (no valid ECIES ciphertext is 0 bytes)', () => {
      const blob = new Uint8Array([0x02, 0x00, 0x00, 0xAA, 0xBB]);
      // Current behavior: succeeds with 0-byte key -- should fail
      const parsed = deserializeVaultBlobV2(blob);
      expect(parsed.encryptedRootFolderKey.length).toBe(0);
      // Recommendation: add minimum key length validation
    });

    it('should handle key_len = 65535 (max uint16)', () => {
      const maxKey = new Uint8Array(65535).fill(0xCC);
      const meta = new Uint8Array([0x42]);
      const blob = serializeVaultBlobV2(maxKey, meta);
      expect(blob[1]).toBe(0xFF);
      expect(blob[2]).toBe(0xFF);
      const parsed = deserializeVaultBlobV2(blob);
      expect(parsed.encryptedRootFolderKey.length).toBe(65535);
      expect(parsed.encryptedMetadataJson).toEqual(meta);
    });

    it('should handle empty metadata (key-only blob)', () => {
      const key = new Uint8Array(129).fill(0xAA);
      const blob = serializeVaultBlobV2(key, new Uint8Array(0));
      const parsed = deserializeVaultBlobV2(blob);
      expect(parsed.encryptedRootFolderKey).toEqual(key);
      expect(parsed.encryptedMetadataJson.length).toBe(0);
    });

    it('should handle key_len pointing to exact end of blob (no metadata)', () => {
      // 3 header bytes + 5 key bytes = 8 total, key_len = 5
      const blob = new Uint8Array([0x02, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
      const parsed = deserializeVaultBlobV2(blob);
      expect(parsed.encryptedRootFolderKey.length).toBe(5);
      expect(parsed.encryptedMetadataJson.length).toBe(0);
    });
  });

  describe('Tamper Detection', () => {
    it('should fail ECIES unwrap if key portion is tampered', async () => {
      // Serialize a valid v2 blob with real ECIES-wrapped key
      const rootFolderKey = crypto.getRandomValues(new Uint8Array(32));
      const userKeypair = /* generate secp256k1 keypair */;
      const encKey = await wrapKey(rootFolderKey, userKeypair.publicKey);
      const meta = new TextEncoder().encode('test');
      const blob = serializeVaultBlobV2(encKey, meta);

      // Tamper: flip a bit in the encrypted key region
      blob[10] ^= 0x01;

      const parsed = deserializeVaultBlobV2(blob);
      // Deserialization succeeds (it's just byte slicing)
      // But ECIES unwrap should fail
      await expect(unwrapKey(parsed.encryptedRootFolderKey, userKeypair.privateKey))
        .rejects.toThrow();
    });

    it('should fail AES-GCM decrypt if metadata portion is tampered', async () => {
      // Similar: tamper metadata portion, verify AES-GCM auth tag catches it
    });

    it('should fail if version byte is changed from 0x02', () => {
      const blob = serializeVaultBlobV2(new Uint8Array(129), new Uint8Array(10));
      blob[0] = 0x03;
      expect(() => deserializeVaultBlobV2(blob)).toThrow('Not a v2');
    });

    it('should fail if key_len is inflated beyond blob size', () => {
      const blob = new Uint8Array([0x02, 0xFF, 0xFF, 0xAA]);
      expect(() => deserializeVaultBlobV2(blob)).toThrow('too short for key');
    });
  });

  describe('Version Confusion', () => {
    it('detectBlobVersion returns 1 for 0x01 byte (not v2)', () => {
      expect(detectBlobVersion(new Uint8Array([0x01]))).toBe(1);
    });

    it('detectBlobVersion returns 1 for 0x00 byte', () => {
      expect(detectBlobVersion(new Uint8Array([0x00]))).toBe(1);
    });

    it('detectBlobVersion returns 1 for pure whitespace JSON', () => {
      const ws = new TextEncoder().encode('  {');
      expect(detectBlobVersion(ws)).toBe(1);
    });
  });
});
```

### Migration Flow Security Tests

```typescript
describe('Vault Migration Security', () => {
  it('should not call /vault/migrate before v2 blob is confirmed on IPFS', async () => {
    // Verify the ordering: IPFS upload + IPNS publish MUST complete before
    // vaultControllerMigrateVault() is called
    // This requires mocking the API calls and verifying call order
  });

  it('should handle migration failure gracefully (non-blocking)', async () => {
    // Mock IPFS upload failure
    // Verify user can still use the app with v1 keys
    // Verify migration retries on next login
  });

  it('should handle concurrent migration from two tabs', async () => {
    // Both tabs detect non-migrated vault
    // First tab succeeds migration
    // Second tab's IPNS publish gets 409 Conflict
    // Verify no data loss, vault is still usable
  });

  it('should handle migrated vault with expired IPNS record', async () => {
    // Mock IPNS resolution failure
    // Verify fallback to DB-stored encryptedRootFolderKey (if still available)
    // Verify clear error if both IPFS and DB fail
  });
});
```

### API Endpoint Security Tests

```typescript
describe('POST /vault/migrate Security', () => {
  it('should require authentication', async () => {
    const response = await request(app.getHttpServer()).post('/vault/migrate').expect(401);
  });

  it('should only affect the authenticated user vault', async () => {
    // Login as user A, call migrate
    // Verify user B's vault is not affected
  });

  it('should be idempotent (multiple calls return success)', async () => {
    await request(app.getHttpServer())
      .post('/vault/migrate')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    // Call again
    await request(app.getHttpServer())
      .post('/vault/migrate')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
  });

  it('should return 404 for non-existent vault', async () => {
    // Login as user with no vault
    await request(app.getHttpServer())
      .post('/vault/migrate')
      .set('Authorization', `Bearer ${newUserToken}`)
      .expect(404);
  });

  it('should NULL both crypto columns after migration', async () => {
    await request(app.getHttpServer())
      .post('/vault/migrate')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    const vault = await vaultRepository.findOne({ where: { ownerId: userId } });
    expect(vault.encryptedRootFolderKey).toBeNull();
    expect(vault.encryptedRootIpnsPrivateKey).toBeNull();
    expect(vault.migratedAt).not.toBeNull();
  });
});
```

---

## SECURITY REVIEW COMPLETE

**Files analyzed:** 18
**Crypto operations found:** 14
**Issues found:** 0 Critical, 2 High, 3 Medium, 2 Low

### Critical Issues

None found.

### High Priority

1. **H-1:** Rust `as u16` silent truncation on key lengths > 65535 bytes
2. **H-2:** `InitVaultRequest` and `VaultResponse` derive `Debug` without key redaction

### Medium Priority

1. **M-1:** Recovery tool private key persists in memory after recovery completes
2. **M-2:** Concurrent browser tab migration race (mitigated by idempotency)
3. **M-3:** ECIES re-wrap on every root folder publish (performance, not security)

### Low Priority

1. **L-1:** Zero-length key allowed in deserialization
2. **L-2:** CDN scripts loaded without SRI integrity hashes

### Test Cases Generated

14 test suggestions across 3 categories (binary format, migration flow, API endpoint)

### Recommendations (Priority Order)

1. **Add key length validation to both TypeScript and Rust serializers** (H-1) --
   prevents silent data corruption from programming errors
2. **Add custom Debug impl for InitVaultRequest and VaultResponse** (H-2) --
   prevents encrypted key material in logs
3. **Zero private key bytes in recovery tool after completion** (M-1) --
   reduces exposure window for the most sensitive data
4. **Add client-side migration deduplication flag** (M-2) -- reduces wasted
   IPFS storage and confusing logs
5. **Cache ECIES-wrapped rootFolderKey during session** (M-3) -- performance
   optimization, not security critical
6. **Add minimum key length check in deserializers** (L-1) -- better error messages
7. **Add SRI hashes to recovery tool CDN scripts** (L-2) -- defense against CDN
   compromise

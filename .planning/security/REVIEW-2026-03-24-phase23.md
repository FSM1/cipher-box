# Security Review Report

**Date:** 2026-03-24
**Scope:** Phase 23 -- Rust SDK Extraction (5 crates + desktop thin shell)
**Reviewer:** Claude (security:review command)
**Branch:** `feat/phase-23-rust-sdk-extraction`

## Executive Summary

Phase 23 extracted cryptographic and domain logic from the desktop app into 5 independent crates. The extraction is architecturally sound and follows the project's zero-knowledge security model correctly. The cryptographic primitives use reputable, well-maintained Rust crates with proper parameterization. Key material is wrapped in `Zeroizing<Vec<u8>>` throughout and cleared on logout/unmount. **No critical vulnerabilities were found.** Two high-priority issues and several medium/low recommendations are documented below.

**Risk Level:** MEDIUM (two high-priority issues related to AES-CTR integrity and `generate_ed25519_keypair` zeroization; no exploitable critical flaws)

## Files Reviewed

| Crate                         | Files     | Crypto Operations                                                                                                              | Risk Level |
| ----------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `crates/crypto/src/`          | 9 files   | AES-GCM encrypt/decrypt, AES-CTR encrypt/decrypt/range, ECIES wrap/unwrap, HKDF derive, Ed25519 sign/verify, IV/key generation | HIGH       |
| `crates/core/src/`            | 9 files   | Folder/file metadata encrypt/decrypt, vault blob v2 parse, IPNS record create/marshal, bin metadata ECIES encrypt/decrypt      | HIGH       |
| `crates/api-client/src/`      | 7 files   | Token handling, HTTP auth, request/response types                                                                              | MEDIUM     |
| `crates/fuse/src/`            | 12+ files | File content decrypt, metadata decrypt, key unwrap in inode population, temp file handling                                     | HIGH       |
| `crates/sdk/src/`             | 7 files   | Key state management, sync daemon, write queue, device registry                                                                | MEDIUM     |
| `apps/desktop/src-tauri/src/` | 11+ files | Auth flow, keychain, vault init/decrypt, key derivation                                                                        | MEDIUM     |

Total: ~55 files analyzed, ~30 distinct crypto operations identified

## Findings

### Critical Issues

None found.

### High Priority

#### [HIGH-1] AES-CTR provides no authentication -- integrity relies entirely on IPFS CID

**Location:** `crates/crypto/src/aes_ctr.rs:10-11`

**Code:**

```rust
//! SECURITY NOTE: AES-CTR does NOT provide authentication (unlike GCM).
//! Integrity is provided by IPFS content addressing.
```

**Issue:**
AES-CTR mode is used for streaming media files to enable random-access decryption. Unlike AES-GCM, CTR mode provides no authentication tag. The code comment states that "integrity is provided by IPFS content addressing" (CID is a hash of the ciphertext). This is a valid design if and only if the CID is verified before decryption. However, the FUSE layer fetches content by CID and decrypts it without explicitly verifying the CID matches the fetched bytes.

If an attacker controls the IPFS gateway or the CipherBox API relay and serves different bytes for a requested CID, AES-CTR would happily decrypt them, producing corrupted plaintext without any error. With AES-GCM, this would fail authentication.

In practice, the CipherBox API + IPFS gateway should verify CIDs, but this is a trust boundary violation: the API is in the "untrusted server" threat model category.

**Impact:**
An attacker who compromises the API/IPFS relay can serve tampered ciphertext for CTR-mode files. Since CTR XORs a keystream, bit-flipping attacks on the ciphertext produce predictable bit-flips in the plaintext. This is exploitable if the file format is known (e.g., modifying a specific byte in a video header).

**Recommendation:**

1. Add a client-side CID verification step: after fetching bytes from IPFS, compute the CID locally and compare before decrypting. This is straightforward since CIDs are content hashes.
2. Alternatively, consider using an HMAC alongside CTR mode (encrypt-then-MAC) and storing the MAC in the file metadata. This provides authentication without sacrificing random-access capability.
3. Document the threat model assumption more explicitly: "IPFS CID verification at the gateway is the authentication mechanism for CTR-mode files."

**References:**

- NIST SP 800-38A (CTR mode -- no integrity)
- CipherBox TECHNICAL_ARCHITECTURE.md security model

---

#### [HIGH-2] `generate_ed25519_keypair` returns private key in non-zeroizing `Vec<u8>`

**Location:** `crates/crypto/src/ed25519.rs:24-32`

**Code:**

```rust
pub fn generate_ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    (
        verifying_key.to_bytes().to_vec(),
        signing_key.to_bytes().to_vec(),  // <-- plain Vec<u8>, not Zeroizing
    )
}
```

**Issue:**
The function returns the private key as a plain `Vec<u8>`, not wrapped in `Zeroizing<Vec<u8>>`. When callers drop the returned value, the private key bytes remain in memory until the allocator reuses the page. Contrast with `sign_ed25519` (line 42-46) and `get_public_key` (line 81-85) which properly zeroize intermediate `key_bytes`.

This function is called from `crates/fuse/src/write_ops.rs:433` for generating per-folder IPNS keypairs during `mkdir`, and `crates/fuse/src/write_ops.rs:172` for per-file IPNS keypairs during `create`. At both call sites, the returned private key is eventually stored in a `Zeroizing<Vec<u8>>` wrapper, but there is a window between the function return and the wrapping where the original `Vec<u8>` could be leaked (e.g., if an error occurs between the two).

**Impact:**
Key material may persist in freed memory. While not directly exploitable without memory-read access, it weakens defense-in-depth against memory forensics and use-after-free bugs.

**Recommendation:**

```rust
pub fn generate_ed25519_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    (
        verifying_key.to_bytes().to_vec(),
        Zeroizing::new(signing_key.to_bytes().to_vec()),
    )
}
```

Update call sites in `write_ops.rs` accordingly (they already wrap in `Zeroizing`, so the change is straightforward).

---

### Medium Priority

#### [MEDIUM-1] `SigningKey` object not zeroized after use in `sign_ed25519`

**Location:** `crates/crypto/src/ed25519.rs:45-48`

**Code:**

```rust
let signing_key = SigningKey::from_bytes(&key_bytes);
key_bytes.zeroize();
let signature = signing_key.sign(message);
// signing_key is dropped here without explicit zeroization
```

**Issue:**
While `key_bytes` is properly zeroized, the `SigningKey` struct itself contains a copy of the key material internally. `ed25519_dalek::SigningKey` does implement `Zeroize` (via `Drop`), but this depends on the `zeroize` feature being enabled for `ed25519-dalek`. The workspace `Cargo.toml` specifies `ed25519-dalek = { version = "2", features = ["rand_core"] }` -- the `zeroize` feature is NOT explicitly enabled.

**Impact:**
If `ed25519-dalek`'s `zeroize` feature is not active, `SigningKey::drop()` does not zero its internal key bytes. The 32-byte private key would persist in freed memory.

**Recommendation:**
Add the `zeroize` feature to the `ed25519-dalek` dependency:

```toml
ed25519-dalek = { version = "2", features = ["rand_core", "zeroize"] }
```

Verify with: `cargo tree -i zeroize -e features | grep ed25519`

---

#### [MEDIUM-2] Temp file plaintext may survive on disk despite zero-overwrite

**Location:** `crates/fuse/src/file_handle.rs:193-216`

**Code:**

```rust
pub fn cleanup(&self) {
    if let Some(ref temp_path) = self.temp_path {
        if temp_path.exists() {
            // Overwrite with zeros before deletion
            if let Ok(size) = fs::metadata(temp_path).map(|m| m.len()) {
                if size > 0 {
                    if let Ok(mut file) = fs::OpenOptions::new().write(true).open(temp_path) {
                        let zeros = vec![0u8; std::cmp::min(size as usize, 64 * 1024)];
                        // ... write zeros ...
                        let _ = file.sync_all();
                    }
                }
            }
            if let Err(e) = fs::remove_file(temp_path) { /* ... */ }
        }
    }
}
```

**Issue:**
The zero-overwrite is a good defense-in-depth measure, but it has limitations:

1. **SSD wear leveling** means the original data may persist on different physical sectors even after overwrite.
2. **APFS copy-on-write** (macOS default) may keep the original content in a snapshot or the old block, with the zero-overwrite going to a new block.
3. The `sync_all()` error is silently ignored -- if sync fails, the zeros may only be in the page cache.
4. If the process crashes between writing plaintext and calling `cleanup()`, temp files persist. The `Drop` impl calls `cleanup()`, but `Drop` is not guaranteed to run in all crash scenarios (SIGKILL, OOM killer).

**Impact:**
Plaintext file content may persist in temp files on disk after intended cleanup, especially on modern filesystems with copy-on-write semantics.

**Recommendation:**

1. Consider using `mmap` with `MAP_PRIVATE | MAP_ANONYMOUS` (memory-only, no disk backing) for write buffers, eliminating disk persistence entirely for files under a size threshold (e.g., 256 MiB).
2. For larger files, use encrypted temp files -- encrypt with a random ephemeral key before writing to the temp file, decrypt on read-back.
3. Document the limitation: "Temp file cleanup provides best-effort zeroization but cannot guarantee physical erasure on COW filesystems."
4. Consider a startup cleanup routine that removes any stale `cb-write-*` files from the temp directory (partially implemented for mount cleanup).

---

#### [MEDIUM-3] `decrypt_folder_metadata` logs decryption context on failure

**Location:** `crates/core/src/folder.rs:120-121`

**Code:**

```rust
let value: serde_json::Value =
    serde_json::from_slice(&json).map_err(|e| {
        log::error!("JSON parse failed: {}", e);
        json.zeroize();
        FolderError::DeserializationFailed
    })?;
```

**Issue:**
When JSON parsing fails after successful AES-GCM decryption, the error message from `serde_json` may include a snippet of the decrypted JSON, which contains plaintext folder/file names and encrypted key material. The `log::error!` call outputs this to the system log.

**Impact:**
Folder names and structure could leak to system logs. While not critical (the metadata is encrypted at rest), it violates the principle of not logging decrypted content.

**Recommendation:**

```rust
log::error!("Folder metadata JSON parse failed (invalid structure)");
```

Remove the serde error message from the log output, or sanitize it to omit the JSON content.

---

#### [MEDIUM-4] No HTTPS enforcement in `ApiClient`

**Location:** `crates/api-client/src/client.rs:25-36`

**Code:**

```rust
pub fn new(base_url: &str) -> Self {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to initialize HTTP client");
    Self {
        client,
        base_url: base_url.trim_end_matches('/').to_string(),
        // ...
    }
}
```

**Issue:**
The `ApiClient` accepts any base URL without validating that it uses HTTPS. In development, `http://localhost:3000` is expected, but in production/staging there is no programmatic guard against misconfiguration. Bearer tokens and encrypted key material would be sent over plaintext HTTP.

**Impact:**
If misconfigured to use HTTP in a non-local environment, access tokens and ECIES-wrapped key material could be intercepted by network observers.

**Recommendation:**
Add a validation check in release builds:

```rust
#[cfg(not(debug_assertions))]
{
    if !base_url.starts_with("https://") {
        panic!("CipherBox API URL must use HTTPS in release builds");
    }
}
```

---

### Low Priority / Recommendations

#### [LOW-1] `ecies` crate version 0.2 -- consider updating

**Location:** Root `Cargo.toml:17`

**Code:**

```toml
ecies = { version = "0.2", default-features = false, features = ["pure"] }
```

**Issue:**
The `ecies` crate at v0.2 is maintained and compatible with the `eciesjs` npm package (same author). However, v0.2 was published in 2023 and the crate has had updates since. The `pure` feature flag avoids linking to OpenSSL, which is correct for this project.

**Recommendation:**
Periodically check for updates. The current version is functional and the library is reputable (used by multiple blockchain projects).

---

#### [LOW-2] Bin metadata decryption does not zeroize on failure

**Location:** `crates/core/src/bin.rs:96-108`

**Code:**

```rust
pub fn decrypt_bin_metadata(
    ciphertext: &[u8],
    user_private_key: &[u8],
) -> Result<RecycleBinMetadata, BinError> {
    let plaintext = cipherbox_crypto::ecies::unwrap_key(ciphertext, user_private_key)?;
    let metadata: RecycleBinMetadata = serde_json::from_slice(&plaintext)?;
    // plaintext is dropped without zeroization
    if metadata.version != "v1" { /* ... */ }
    Ok(metadata)
}
```

**Issue:**
The decrypted plaintext `Vec<u8>` is not zeroized before being dropped. While the content is JSON-serialized metadata (not raw key material), it contains folder/file names and other user data.

**Recommendation:**

```rust
let plaintext = cipherbox_crypto::ecies::unwrap_key(ciphertext, user_private_key)?;
let result = serde_json::from_slice(&plaintext);
let mut plaintext = plaintext; // make mutable for zeroize
plaintext.zeroize();
let metadata: RecycleBinMetadata = result.map_err(|_| BinError::DeserializationFailed)?;
```

---

#### [LOW-3] `ipns_name.rs:104` uses `unwrap()` on `try_into()`

**Location:** `crates/crypto/src/ipns_name.rs:104` (also `aes_ctr.rs:104`)

**Code:**

```rust
let base_counter = u64::from_be_bytes(iv[8..16].try_into().unwrap());
```

**Issue:**
While this `unwrap()` is technically safe (a slice of exactly 8 bytes from a 16-byte array will always convert), panics in crypto code are undesirable. In `ipns_name.rs:113`, `String::from_utf8(result).unwrap_or_default()` is correctly handled with `unwrap_or_default()`.

**Recommendation:**
Replace with:

```rust
let base_counter = u64::from_be_bytes(
    iv[8..16].try_into().map_err(|_| CryptoError::InvalidIvSize { expected: 16, actual: iv.len() })?
);
```

---

#### [LOW-4] Registry `register_device` has a copy-paste bug in app_version update

**Location:** `crates/sdk/src/registry.rs:102`

**Code:**

```rust
existing.app_version = device_info.device_id.clone(); // Preserve original pattern
```

**Issue:**
When updating an existing device entry, the code sets `app_version` to `device_info.device_id` (the device ID) instead of `device_info.app_version`. This is a logic bug, not a security issue per se, but the incorrect field value could cause confusion in the device registry display.

**Recommendation:**

```rust
existing.app_version = device_info.app_version.clone();
```

---

#### [LOW-5] `get_dev_key` Tauri command exposes dev key to webview

**Location:** `apps/desktop/src-tauri/src/commands/debug.rs:20-25`

**Code:**

```rust
#[tauri::command]
pub async fn get_dev_key(state: State<'_, AppState>) -> Result<Option<String>, String> {
    log::info!("get_dev_key invoked by webview");
    let key = state.dev_key.read().await.clone();
    log::info!("get_dev_key returning: has_key={}", key.is_some());
    Ok(key)
}
```

**Issue:**
The `get_dev_key` command returns the hex-encoded private key to the webview. This is gated behind `#[cfg(debug_assertions)]` which prevents it from compiling in release builds. The security gate is correct, but the implementation could be tighter -- it sends the actual key value rather than just a boolean flag.

**Recommendation:**
The current implementation is acceptable since it's debug-only and the webview needs the key for test-login flow. However, add a comment explaining why the full key is returned:

```rust
// Returns the full hex key because the webview needs it for the
// POST /auth/test-login request. This command is debug-only.
```

---

## Detailed Analysis

### 1. crates/crypto -- Cryptographic Primitives

**AES-256-GCM (`aes.rs`):**

- Correct 12-byte nonce, 16-byte tag, 32-byte key sizes
- `seal_aes_gcm` generates fresh random IV via `OsRng` -- no nonce reuse risk
- `unseal_aes_gcm` validates minimum size before parsing
- Uses `aes-gcm` v0.10 (RustCrypto, well-audited)
- IV is prepended to ciphertext matching Web Crypto API format
- Grade: **PASS**

**AES-256-CTR (`aes_ctr.rs`):**

- Correct 16-byte IV, 32-byte key
- Uses `ctr` v0.9 with `Ctr64BE` matching Web Crypto's `length: 64`
- Range decryption correctly computes block-aligned offsets
- `wrapping_add` on counter correctly handles overflow
- **No authentication** -- see HIGH-1
- Grade: **PASS with caveat** (integrity depends on external CID verification)

**ECIES (`ecies.rs`):**

- Validates public key size (65 bytes) and 0x04 prefix
- Validates private key size (32 bytes)
- Validates minimum ciphertext size
- Delegates to `ecies` crate (compatible with `eciesjs` npm package)
- Error messages are generic, no oracle
- Grade: **PASS**

**HKDF (`hkdf.rs`):**

- Uses HKDF-SHA256 with domain-separated info strings
- Salt is constant `"CipherBox-v1"` -- acceptable for deterministic derivation
- Output key material is zeroized via `Zeroizing::new()`
- Intermediate `okm` array is zeroized after use
- Per-file IPNS derivation includes file ID for domain separation with minimum length validation
- Grade: **PASS**

**Ed25519 (`ed25519.rs`):**

- Uses `ed25519-dalek` v2 with `OsRng` for key generation
- `sign_ed25519` properly zeroizes intermediate `key_bytes`
- `verify_ed25519` returns `bool`, no timing-dependent exceptions
- **`generate_ed25519_keypair` does not wrap return in `Zeroizing`** -- see HIGH-2
- Grade: **PASS with caveat**

**Utilities (`utils.rs`):**

- Uses `OsRng` for all random generation (CSPRNG)
- `clear_bytes` delegates to `zeroize`
- UUID v4 generation correctly sets version and variant bits
- Grade: **PASS**

**Error Types (`error.rs`):**

- Generic error messages with no sensitive data
- No distinction between "wrong key" and "corrupted data" in AES errors (correct -- prevents oracle)
- Grade: **PASS**

### 2. crates/core -- Domain Types

**Vault Blob v2 (`vault_blob.rs`):**

- Validates minimum header size (3 bytes)
- Validates key length > 0 and <= u16::MAX
- Validates blob has enough bytes for declared key length
- Zero-copy parsing via borrowed slice
- Comprehensive test suite including cross-platform test vectors
- Grade: **PASS**

**Folder Metadata (`folder.rs`):**

- JSON serialized then AES-256-GCM sealed -- proper encrypt-then-authenticate
- Plaintext JSON is zeroized after encryption
- Decrypted JSON is zeroized after deserialization (including on error paths)
- Version check rejects non-"v2" metadata
- Grade: **PASS**

**IPNS Records (`ipns.rs`):**

- V1 and V2 signatures both computed (backward compatibility)
- CBOR field order matches TypeScript `ipns` package
- Protobuf encoding is hand-rolled but follows spec
- No timing-sensitive operations
- Grade: **PASS**

**Bin Metadata (`bin.rs`):**

- ECIES encryption/decryption for the whole blob
- Version validation on decrypt
- **Plaintext not zeroized on decrypt** -- see LOW-2
- Grade: **PASS with minor issue**

### 3. crates/api-client -- HTTP Client

**Token Handling:**

- `LoginRequest`, `LoginResponse`, `RefreshRequest`, `RefreshResponse` all have custom `Debug` impls that redact tokens and keys
- `InitVaultRequest` redacts `owner_public_key`
- Access token stored in `Arc<RwLock<Option<String>>>` -- not persisted to disk
- Grade: **PASS**

**Request Construction:**

- Bearer auth correctly uses `bearer_auth()` (sets `Authorization: Bearer` header)
- No key material in URL query params (IPNS name is not sensitive)
- `X-Client-Type: desktop` header enables body-based refresh token delivery
- **No HTTPS enforcement** -- see MEDIUM-4
- Grade: **PASS with caveat**

### 4. crates/fuse -- FUSE Filesystem

**Key Storage in CipherBoxFS:**

- `private_key: Zeroizing<Vec<u8>>` -- properly wrapped
- `public_key: Zeroizing<Vec<u8>>` -- properly wrapped
- `root_folder_key: Zeroizing<Vec<u8>>` -- properly wrapped
- Grade: **PASS**

**File Content Decrypt (`operations.rs`):**

- File key unwrapped via ECIES with private key
- Unwrapped key stored in `Zeroizing::new()`
- Key array is validated to be 32 bytes
- Both GCM and CTR modes supported with correct IV sizes
- Grade: **PASS**

**Temp File Handling (`file_handle.rs`):**

- Temp files created with `0o600` permissions (owner-only)
- `Drop` impl zeroizes `cached_content` and calls `cleanup()`
- `cleanup()` overwrites with zeros before deletion
- **COW filesystem limitations** -- see MEDIUM-2
- Grade: **PASS with caveat**

**Content Cache (`cache.rs`):**

- `CachedContent::drop()` calls `data.zeroize()` -- defense-in-depth
- `ContentCache::clear()` drops all entries (triggering zeroize)
- `handle_destroy()` zeroizes all caches and pending content
- Grade: **PASS**

**Inode Table (`inode.rs`):**

- Folder keys stored as `Zeroizing<Vec<u8>>`
- IPNS private keys stored as `Option<Zeroizing<Vec<u8>>>`
- ECIES unwrap of folder keys and IPNS keys during `populate_folder`
- Grade: **PASS**

### 5. crates/sdk -- Stateful SDK

**Key State (`state.rs`):**

- All sensitive fields use `RwLock<Option<Vec<u8>>>` with `zeroize()` in `clear()`
- `clear()` zeroizes private_key, public_key, root_folder_key, root_ipns_private_key
- API access token cleared via `clear_access_token()`
- Grade: **PASS**

**Sync Daemon (`sync.rs`):**

- `sanitize_error()` strips filesystem paths and long hex tokens from error messages
- No key material logged
- Only IPNS names and CIDs appear in logs (not sensitive)
- Grade: **PASS**

**Write Queue (`queue.rs`):**

- `QueuedWrite` stores already-encrypted content (`encrypted_content`) -- plaintext never enters the queue
- The `encrypted_file_key` in the queue is the ECIES-wrapped key (not the raw key)
- Grade: **PASS**

**Device Registry (`registry.rs`):**

- Registry is ECIES-encrypted with user's public key
- HKDF-derived IPNS keypair for registry namespace
- Zeroizing wrapper used for derived private keys
- **Copy-paste bug** in `app_version` update -- see LOW-4
- Grade: **PASS with minor issue**

### 6. Desktop Thin Shell

**Auth Flow (`commands/auth.rs`):**

- Private key received as hex string, converted to bytes, wrapped in `Zeroizing`
- `clear_keys()` delegates to `KeyState::clear()` + zeroizes dev_key
- Refresh token stored in macOS Keychain (not disk)
- JWT extracted without verification (acceptable -- server already verified)
- Grade: **PASS**

**Vault Operations (`commands/vault.rs`):**

- Root folder key generated via `generate_random_bytes(32)` (CSPRNG)
- ECIES wrapping with user's public key before v2 blob creation
- IPNS records created with proper sequence numbers
- Conflict on sequence-0 publish correctly aborts initialization
- Grade: **PASS**

**Keychain (`keychain.rs`):**

- Uses `keyring` crate with platform-native backend
- Delete-before-set pattern for macOS Keychain compatibility
- Idempotent delete (ignores NoEntry)
- No key material logged
- Grade: **PASS**

## Test Cases

### crates/crypto -- Suggested Security Tests

```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    // --- AES-GCM ---

    #[test]
    fn aes_gcm_rejects_wrong_key() {
        let key1 = utils::generate_file_key();
        let key2 = utils::generate_file_key();
        let plaintext = b"secret data";
        let sealed = aes::seal_aes_gcm(plaintext, &key1).unwrap();
        assert!(aes::unseal_aes_gcm(&sealed, &key2).is_err());
    }

    #[test]
    fn aes_gcm_rejects_tampered_ciphertext() {
        let key = utils::generate_file_key();
        let plaintext = b"secret data";
        let mut sealed = aes::seal_aes_gcm(plaintext, &key).unwrap();
        // Flip a bit in the ciphertext (after IV)
        sealed[15] ^= 0x01;
        assert!(aes::unseal_aes_gcm(&sealed, &key).is_err());
    }

    #[test]
    fn aes_gcm_rejects_tampered_iv() {
        let key = utils::generate_file_key();
        let plaintext = b"secret data";
        let mut sealed = aes::seal_aes_gcm(plaintext, &key).unwrap();
        // Flip a bit in the IV
        sealed[0] ^= 0x01;
        assert!(aes::unseal_aes_gcm(&sealed, &key).is_err());
    }

    #[test]
    fn aes_gcm_rejects_truncated_sealed() {
        let key = utils::generate_file_key();
        let plaintext = b"secret data";
        let sealed = aes::seal_aes_gcm(plaintext, &key).unwrap();
        // Truncate to less than IV + tag
        assert!(aes::unseal_aes_gcm(&sealed[..27], &key).is_err());
    }

    #[test]
    fn aes_gcm_handles_empty_plaintext() {
        let key = utils::generate_file_key();
        let sealed = aes::seal_aes_gcm(b"", &key).unwrap();
        let decrypted = aes::unseal_aes_gcm(&sealed, &key).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn aes_gcm_nonce_uniqueness() {
        let key = utils::generate_file_key();
        let sealed1 = aes::seal_aes_gcm(b"data", &key).unwrap();
        let sealed2 = aes::seal_aes_gcm(b"data", &key).unwrap();
        // IVs should differ (first 12 bytes)
        assert_ne!(&sealed1[..12], &sealed2[..12]);
        // Ciphertext should differ (same plaintext, different IV)
        assert_ne!(sealed1, sealed2);
    }

    // --- AES-CTR ---

    #[test]
    fn aes_ctr_roundtrip() {
        let key = utils::generate_file_key();
        let iv = [0u8; 16]; // fixed for test
        let plaintext = b"streaming media content";
        let ciphertext = aes_ctr::encrypt_aes_ctr(plaintext, &key, &iv).unwrap();
        let decrypted = aes_ctr::decrypt_aes_ctr(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_ctr_range_decrypt_matches_full_decrypt() {
        let key = utils::generate_file_key();
        let iv = [0u8; 16];
        let plaintext = vec![42u8; 1024]; // 1KB
        let ciphertext = aes_ctr::encrypt_aes_ctr(&plaintext, &key, &iv).unwrap();

        // Decrypt range [100, 200]
        let range_result = aes_ctr::decrypt_aes_ctr_range(
            &ciphertext, &key, &iv, 100, 200,
        ).unwrap();
        assert_eq!(range_result, &plaintext[100..=200]);
    }

    #[test]
    fn aes_ctr_range_invalid_range() {
        let key = utils::generate_file_key();
        let iv = [0u8; 16];
        let ciphertext = vec![0u8; 100];
        assert!(aes_ctr::decrypt_aes_ctr_range(&ciphertext, &key, &iv, 50, 10).is_err());
    }

    #[test]
    fn aes_ctr_wrong_key_produces_wrong_plaintext() {
        let key1 = utils::generate_file_key();
        let key2 = utils::generate_file_key();
        let iv = [0u8; 16];
        let plaintext = b"secret";
        let ciphertext = aes_ctr::encrypt_aes_ctr(plaintext, &key1, &iv).unwrap();
        let wrong_decrypt = aes_ctr::decrypt_aes_ctr(&ciphertext, &key2, &iv).unwrap();
        // CTR mode: wrong key produces garbage, no error (no auth tag)
        assert_ne!(wrong_decrypt.as_slice(), plaintext);
    }

    // --- ECIES ---

    #[test]
    fn ecies_roundtrip() {
        let sk = ecies::SecretKey::random(&mut rand::rngs::OsRng);
        let pk = ecies::PublicKey::from_secret_key(&sk);
        let data = b"root folder key material";
        let wrapped = ecies::wrap_key(data, &pk.serialize()).unwrap();
        let unwrapped = ecies::unwrap_key(&wrapped, &sk.serialize()).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn ecies_rejects_wrong_private_key() {
        let sk1 = ecies::SecretKey::random(&mut rand::rngs::OsRng);
        let sk2 = ecies::SecretKey::random(&mut rand::rngs::OsRng);
        let pk1 = ecies::PublicKey::from_secret_key(&sk1);
        let wrapped = ecies::wrap_key(b"data", &pk1.serialize()).unwrap();
        assert!(ecies::unwrap_key(&wrapped, &sk2.serialize()).is_err());
    }

    #[test]
    fn ecies_rejects_invalid_public_key_size() {
        assert!(ecies::wrap_key(b"data", &[0u8; 33]).is_err());
    }

    #[test]
    fn ecies_rejects_compressed_public_key() {
        let mut pk = [0u8; 65];
        pk[0] = 0x02; // compressed prefix
        assert!(ecies::wrap_key(b"data", &pk).is_err());
    }

    #[test]
    fn ecies_rejects_short_ciphertext() {
        let sk = ecies::SecretKey::random(&mut rand::rngs::OsRng);
        assert!(ecies::unwrap_key(&[0u8; 10], &sk.serialize()).is_err());
    }

    // --- HKDF ---

    #[test]
    fn hkdf_deterministic_derivation() {
        let key = [42u8; 32];
        let (priv1, pub1, name1) = hkdf::derive_vault_ipns_keypair(&key).unwrap();
        let (priv2, pub2, name2) = hkdf::derive_vault_ipns_keypair(&key).unwrap();
        assert_eq!(priv1.as_slice(), priv2.as_slice());
        assert_eq!(pub1, pub2);
        assert_eq!(name1, name2);
    }

    #[test]
    fn hkdf_domain_separation() {
        let key = [42u8; 32];
        let (_, _, vault_name) = hkdf::derive_vault_ipns_keypair(&key).unwrap();
        let (_, _, vault_key_name) = hkdf::derive_vault_key_ipns_keypair(&key).unwrap();
        let (_, _, registry_name) = hkdf::derive_registry_ipns_keypair(&key).unwrap();
        let (_, _, bin_name) = hkdf::derive_bin_ipns_keypair(&key).unwrap();
        // All four IPNS names must be different (domain separation)
        let names = vec![&vault_name, &vault_key_name, &registry_name, &bin_name];
        let unique: std::collections::HashSet<&&String> = names.iter().collect();
        assert_eq!(unique.len(), 4, "HKDF domain separation failed");
    }

    #[test]
    fn hkdf_per_file_different_files_different_keys() {
        let key = [42u8; 32];
        let (_, _, name1) = hkdf::derive_file_ipns_keypair(&key, "file-id-0001").unwrap();
        let (_, _, name2) = hkdf::derive_file_ipns_keypair(&key, "file-id-0002").unwrap();
        assert_ne!(name1, name2);
    }

    #[test]
    fn hkdf_rejects_short_file_id() {
        let key = [42u8; 32];
        assert!(hkdf::derive_file_ipns_keypair(&key, "short").is_err());
    }

    // --- Ed25519 ---

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let (pub_key, priv_key) = ed25519::generate_ed25519_keypair();
        let message = b"test message";
        let signature = ed25519::sign_ed25519(message, &priv_key).unwrap();
        assert!(ed25519::verify_ed25519(message, &signature, &pub_key));
    }

    #[test]
    fn ed25519_rejects_tampered_message() {
        let (pub_key, priv_key) = ed25519::generate_ed25519_keypair();
        let signature = ed25519::sign_ed25519(b"original", &priv_key).unwrap();
        assert!(!ed25519::verify_ed25519(b"tampered", &signature, &pub_key));
    }

    #[test]
    fn ed25519_rejects_wrong_public_key() {
        let (_, priv_key) = ed25519::generate_ed25519_keypair();
        let (other_pub, _) = ed25519::generate_ed25519_keypair();
        let signature = ed25519::sign_ed25519(b"message", &priv_key).unwrap();
        assert!(!ed25519::verify_ed25519(b"message", &signature, &other_pub));
    }

    #[test]
    fn ed25519_verify_rejects_invalid_sizes() {
        assert!(!ed25519::verify_ed25519(b"msg", &[0u8; 63], &[0u8; 32])); // short sig
        assert!(!ed25519::verify_ed25519(b"msg", &[0u8; 64], &[0u8; 31])); // short key
    }

    // --- Random Generation ---

    #[test]
    fn generate_iv_is_12_bytes() {
        let iv = utils::generate_iv();
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn generate_file_key_is_32_bytes() {
        let key = utils::generate_file_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn generate_random_bytes_produces_unique_output() {
        let a = utils::generate_random_bytes(32);
        let b = utils::generate_random_bytes(32);
        assert_ne!(a, b); // probability of collision: 2^-256
    }
}
```

### crates/core -- Suggested Security Tests

```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn vault_blob_v2_rejects_empty_blob() {
        assert!(vault_blob::deserialize_vault_blob_v2(&[]).is_err());
    }

    #[test]
    fn vault_blob_v2_rejects_truncated_payload() {
        // Header claims 100 bytes but blob only has 10
        let mut blob = vec![0x02, 0x00, 0x64]; // version=2, length=100
        blob.extend_from_slice(&[0u8; 10]);
        assert!(vault_blob::deserialize_vault_blob_v2(&blob).is_err());
    }

    #[test]
    fn vault_blob_v2_ignores_trailing_bytes() {
        let key = vec![0xAA; 32];
        let mut blob = vault_blob::serialize_vault_blob_v2(&key).unwrap();
        blob.extend_from_slice(&[0xFF; 100]); // trailing garbage
        let parsed = vault_blob::deserialize_vault_blob_v2(&blob).unwrap();
        assert_eq!(parsed, &key[..]);
    }

    #[test]
    fn folder_metadata_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let metadata = folder::FolderMetadata {
            version: "v2".to_string(),
            children: vec![],
        };
        let sealed = folder::encrypt_folder_metadata(&metadata, &key1).unwrap();
        assert!(folder::decrypt_folder_metadata(&sealed, &key2).is_err());
    }

    #[test]
    fn folder_metadata_tampered_ciphertext_fails() {
        let key = [1u8; 32];
        let metadata = folder::FolderMetadata {
            version: "v2".to_string(),
            children: vec![],
        };
        let mut sealed = folder::encrypt_folder_metadata(&metadata, &key).unwrap();
        sealed[20] ^= 0xFF;
        assert!(folder::decrypt_folder_metadata(&sealed, &key).is_err());
    }

    #[test]
    fn folder_metadata_rejects_v1_version() {
        let key = [1u8; 32];
        // Manually create a valid AES-GCM sealed blob with version "v1"
        let json = b"{\"version\":\"v1\",\"children\":[]}";
        let sealed = cipherbox_crypto::aes::seal_aes_gcm(json, &key).unwrap();
        assert!(folder::decrypt_folder_metadata(&sealed, &key).is_err());
    }
}
```

## Compliance Checklist

| Rule                                                     | Status      | Notes                                                                                  |
| -------------------------------------------------------- | ----------- | -------------------------------------------------------------------------------------- |
| Never store privateKey in localStorage/sessionStorage    | PASS        | Keys are in-memory (`RwLock<Option<Vec<u8>>>`) or Keychain only                        |
| Never log sensitive keys                                 | PASS        | All log statements checked; tokens redacted in Debug impls                             |
| Never send unencrypted keys to server                    | PASS        | Only ECIES-wrapped keys sent; rootFolderKey in v2 blob is ECIES-encrypted              |
| Always use ECIES for key wrapping                        | PASS        | folder keys, IPNS keys, file keys all ECIES-wrapped                                    |
| Always use AES-256-GCM for content encryption            | PARTIAL     | GCM for standard files, CTR for streaming media (documented, with CID-based integrity) |
| Server never has access to plaintext or unencrypted keys | PASS        | All encryption is client-side; server sees only ciphertext                             |
| Always encrypt ipnsPrivateKey with TEE public key        | PASS        | `encrypted_ipns_for_tee` in mkdir uses ECIES with TEE key                              |
| TEE decrypts IPNS keys in hardware only                  | N/A         | TEE is server-side, not in scope for this review                                       |
| Zeroize key material after use                           | MOSTLY PASS | `Zeroizing` used throughout; see HIGH-2 and MEDIUM-1 for gaps                          |

## Recommendations Summary

| Priority | Issue                                        | Action                                          | Effort  |
| -------- | -------------------------------------------- | ----------------------------------------------- | ------- |
| HIGH     | AES-CTR no authentication                    | Add client-side CID verification before decrypt | Medium  |
| HIGH     | `generate_ed25519_keypair` returns plain Vec | Wrap return in `Zeroizing`                      | Low     |
| MEDIUM   | `ed25519-dalek` missing `zeroize` feature    | Add `zeroize` to features list in Cargo.toml    | Trivial |
| MEDIUM   | Temp file plaintext on COW filesystems       | Consider in-memory or encrypted temp buffers    | High    |
| MEDIUM   | Decryption error log may contain plaintext   | Sanitize log messages in folder.rs              | Low     |
| MEDIUM   | No HTTPS enforcement in ApiClient            | Add release-build validation                    | Low     |
| LOW      | Bin metadata plaintext not zeroized          | Add `zeroize()` before drop                     | Low     |
| LOW      | `unwrap()` in crypto code                    | Replace with error propagation                  | Low     |
| LOW      | Registry app_version copy-paste bug          | Fix field assignment                            | Trivial |
| LOW      | `get_dev_key` sends key to webview           | Add documentation comment                       | Trivial |

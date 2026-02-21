# Security Review: Random File IPNS Keys

**Date:** 2026-02-21
**Branch:** `feat/random-file-ipns-keys`
**Reviewer:** Claude Opus 4.6 (security agent)
**Files analyzed:** 16
**Crypto operations found:** 12
**Issues found:** 1 Critical, 2 High, 2 Medium, 3 Low, 2 Informational
**Resolution:** All Critical, High, and Medium issues fixed in commit `d70d9f7`

---

## Executive Summary

This PR switches file IPNS keypairs from deterministic HKDF derivation to randomly generated Ed25519 keys, stored via ECIES wrapping in the parent folder's encrypted metadata. The core cryptographic design is sound: random keygen uses proper CSPRNG sources, ECIES wrapping is correctly applied (wrap with public key, unwrap with private key), and the HKDF fallback provides safe backward compatibility.

One critical issue was found and fixed: the Rust desktop client had no HKDF fallback for legacy files. Two high-priority issues (key memory clearing and redundant ECIES re-wrapping) were also fixed. LOW-01 (TEE enrollment for desktop files) was logged as a GSD todo for follow-up.

---

## Findings

### [CRITICAL-01] Desktop Rust: No HKDF Fallback for Legacy File IPNS Updates

**Status: FIXED** (commit `d70d9f7`)

**Location:** `apps/desktop/src-tauri/src/fuse/inode.rs:388-445`

**Issue:**
When `file_ipns_private_key` is `None` (which it will be for all legacy files where `ipnsPrivateKeyEncrypted` was absent in the FilePointer), the desktop client **silently skipped** publishing the per-file IPNS record. The web app has a proper HKDF fallback in `getFileIpnsPrivateKey()` (`apps/web/src/services/file-metadata.service.ts:64-74`), but the Rust FUSE code had no equivalent. This means:

1. Any file created before this migration that is edited via the desktop app would not have its per-file IPNS metadata updated.
2. The file content CID would be uploaded to IPFS but the IPNS pointer would remain stale.
3. Other devices would see the old file content, causing silent data divergence.

**Impact:**
Silent data loss/divergence for legacy files edited from the desktop app.

**Resolution:**
Added HKDF fallback in `populate_folder()`. When ECIES decryption fails or `ipnsPrivateKeyEncrypted` is absent, the code now calls `crypto::hkdf::derive_file_ipns_keypair()` with the user's private key and the file's ID. The derived key is stored in the inode's `file_ipns_private_key` field, ensuring legacy files can still publish IPNS updates.

---

### [HIGH-01] IPNS Private Key Not Cleared After ECIES Wrapping (TypeScript)

**Status: FIXED** (commit `d70d9f7`)

**Location:** `apps/web/src/services/file-metadata.service.ts:162`

**Issue:**
The generated `ipnsKeypair.privateKey` (a 32-byte Ed25519 seed) was never cleared from memory after it was used. The function returns `ipnsPrivateKeyEncrypted` (the wrapped version) but the plaintext private key remained in the `ipnsKeypair` object until garbage collected.

**Impact:**
The Ed25519 private key material persisted in JavaScript heap memory longer than necessary.

**Resolution:**
Added `ipnsKeypair.privateKey.fill(0)` after all uses (ECIES wrapping, IPNS record signing, TEE enrollment) are complete, just before the function returns.

---

### [HIGH-02] Rust Desktop: Re-wrapping ECIES on Every Metadata Publish

**Status: FIXED** (commit `d70d9f7`)

**Location:** `apps/desktop/src-tauri/src/fuse/mod.rs:497-511`

**Issue:**
Every time `build_folder_metadata()` was called (on every folder metadata publish), the file IPNS private key was **re-wrapped** with a fresh ECIES ephemeral key. ECIES produces different ciphertext each time due to ephemeral key generation, causing:

1. The `ipnsPrivateKeyEncrypted` value to change on every publish, even when the underlying key hadn't changed.
2. Unnecessary IPFS content churn (new CID for identical logical content).
3. Wasted storage quota and unnecessary ECIES computation.

**Resolution:**
Added `file_ipns_key_encrypted_hex: Option<String>` field to `InodeKind::File` to cache the ECIES-wrapped hex. In `populate_folder()`, the original hex from the FilePointer is preserved in the cache. In `create()`, the key is ECIES-wrapped eagerly and cached. `build_folder_metadata()` now reads the cached hex first, only falling back to re-wrapping if the cache is empty.

---

### [MEDIUM-01] Missing Minimum Length Validation on `ipnsPrivateKeyEncrypted` Field

**Status: FIXED** (commit `d70d9f7`)

**Location:** `packages/crypto/src/folder/metadata.ts:74-85`

**Issue:**
The validation only checked that the field was a string, not that it had a minimum plausible length. An empty string `""` or very short string would pass validation but fail at ECIES unwrap time with an unhelpful error.

**Resolution:**
Added minimum length check of 64 hex characters. An ECIES-wrapped 32-byte key produces ciphertext of at least 81 bytes (162 hex chars), but 64 is used as a conservative lower bound. Tests updated to cover both the short-string rejection and the non-string rejection cases.

---

### [MEDIUM-02] Stale Comment in Rust InodeKind::File

**Status: FIXED** (commit `d70d9f7`)

**Location:** `apps/desktop/src-tauri/src/fuse/inode.rs:86-90`

**Issue:**
The doc comment said "derived via HKDF from user privateKey + fileId" but after this PR, new files use randomly generated keypairs. The comment was misleading.

**Resolution:**
Updated doc comment to accurately describe both paths: "For new files: generated randomly, ECIES-wrapped in FilePointer. For legacy files: derived via HKDF from user privateKey + fileId."

---

### [LOW-01] No TEE Enrollment for Desktop-Created Files

**Status: TODO logged** (commit `8a7890b`)

**Location:** `apps/desktop/src-tauri/src/fuse/operations.rs:969-996`

**Issue:**
When a file is created via the desktop FUSE filesystem, the random Ed25519 IPNS keypair is generated and stored in the inode, but it is never encrypted with the TEE public key and sent to the backend for IPNS republishing enrollment. Compare with the web app's `createFileMetadata()` (lines 150-159) which explicitly wraps the IPNS key with `teeKeys.currentPublicKey`.

**Impact:**
Files created from the desktop app will not have their IPNS records republished by the TEE after the IPNS record lifetime expires, unless the user re-publishes from the web app.

**Resolution:**
Logged as GSD todo: `.planning/todos/pending/2026-02-21-desktop-tee-enrollment-for-new-files.md`

---

### [LOW-02] Web App Does Not Perform Lazy Migration of Legacy FilePointers

Status: Deferred

**Location:** `apps/web/src/services/file-metadata.service.ts:64-74`

**Issue:**
The HKDF-derived key is used for the current operation but the FilePointer is not updated with the wrapped key. This means legacy files will use HKDF derivation indefinitely, preventing the eventual removal of the HKDF code path.

**Impact:**
The migration from HKDF to random keys will never complete organically. HKDF code paths must be maintained indefinitely unless a separate migration sweep is performed.

**Recommendation:**
After deriving the IPNS key via HKDF, wrap it with the user's public key and update the FilePointer in the parent folder's metadata. This requires passing `userPublicKey` and triggering folder metadata re-publish, better suited for a follow-up PR.

---

### [LOW-03] Redundant `.to_vec()` on Ed25519 Private Key in Rust `create()`

Status: Partially addressed

**Location:** `apps/desktop/src-tauri/src/fuse/operations.rs:972,996`

**Issue:**
`file_ipns_private_key` is already a `Vec<u8>` from line 972. On line 996, `.to_vec()` was called again, creating an unnecessary copy. The original `Vec<u8>` is then dropped without zeroization.

**Resolution:**
The redundant `.to_vec()` was removed in the security fix commit. The key is now moved directly into `Zeroizing::new()`. However, the initial `signing_key.to_bytes().to_vec()` still creates an intermediate non-zeroized `Vec<u8>` before being wrapped in `Zeroizing`. This is acceptable given that the `SigningKey` itself implements `Zeroize` on drop.

---

### [INFO-01] Entropy Sources Are Cryptographically Sound

**TypeScript (`packages/crypto/src/ed25519/keygen.ts:31`):**
Uses `@noble/ed25519`'s `randomPrivateKey()` which calls `crypto.getRandomValues()` (WebCrypto CSPRNG). Correct entropy source for browser environments.

**Rust (`apps/desktop/src-tauri/src/fuse/operations.rs:970`):**
Uses `OsRng` from the `rand` crate, which reads from the OS-level CSPRNG (`/dev/urandom` on macOS/Linux). Correct entropy source for native applications.

Both implementations produce 32-byte Ed25519 seeds with sufficient entropy (256 bits). No issues found.

---

### [INFO-02] ECIES Wrapping Direction Is Correct

Throughout the codebase, the ECIES key wrapping follows the correct direction:

- **Wrap (encrypt):** `wrapKey(plaintext, recipientPublicKey)` -- uses the user's secp256k1 _public_ key
- **Unwrap (decrypt):** `unwrapKey(ciphertext, privateKey)` -- uses the user's secp256k1 _private_ key

Verified in:

- `apps/web/src/services/file-metadata.service.ts:114` -- wraps with `params.userPublicKey`
- `apps/web/src/services/file-metadata.service.ts:69` -- unwraps with `userPrivateKey`
- `apps/desktop/src-tauri/src/fuse/mod.rs:499` -- wraps with `self.public_key`
- `apps/desktop/src-tauri/src/fuse/inode.rs:392` -- unwraps with `private_key`

The `createFileMetadata` function signature correctly accepts `userPublicKey` (not `userPrivateKey`), which was a change from the old HKDF pattern. No key confusion found.

---

## Positive Observations

1. **Double encryption at rest:** The ECIES-wrapped IPNS private key is stored inside AES-256-GCM encrypted FolderMetadata. An attacker would need to compromise both the folder key and the ECIES wrapping to extract the file IPNS signing key. Good defense in depth.

2. **Zeroizing in Rust:** The `file_ipns_private_key` field in `InodeKind::File` uses `Zeroizing<Vec<u8>>`, ensuring automatic memory cleanup on drop. The `signing_key` from `ed25519_dalek` also implements `Zeroize`.

3. **Generic error messages:** Both TypeScript and Rust ECIES implementations use generic error messages ("Key wrapping failed", "Key unwrapping failed") to prevent oracle attacks.

4. **Validation on deserialization:** The `validateFolderMetadata()` function rejects non-string and too-short values for `ipnsPrivateKeyEncrypted`, preventing type confusion and early-fail on corrupt data.

5. **Backward compatibility:** The `ipnsPrivateKeyEncrypted` field is correctly `Optional<String>` in Rust and `string | undefined` in TypeScript, allowing clean dual-read migration.

6. **Test coverage:** The new `generateFileIpnsKeypair` tests verify both structural correctness (key sizes, IPNS name format) and randomness (two calls produce different results). Validation tests cover string type, minimum length, and legacy (absent) cases.

---

## Attack Scenario Analysis

### Downgrade Attack: Forcing HKDF Derivation

**Scenario:** An attacker with write access to encrypted folder metadata strips `ipnsPrivateKeyEncrypted` from a FilePointer, forcing clients to fall back to HKDF derivation.

**Assessment:** Not exploitable. The attacker would need the AES-256 folder key to modify the encrypted metadata, and if they have that key, they already have full read/write access to the folder contents. The AES-GCM authentication tag prevents modification without the key.

### Key Substitution: Replacing the Wrapped IPNS Key

**Scenario:** An attacker replaces `ipnsPrivateKeyEncrypted` with a key wrapped to their own public key, so they can sign IPNS records for the file.

**Assessment:** Not exploitable for the same reason as above -- the metadata is AES-GCM encrypted. Additionally, the wrapping is done with the _victim's_ public key, so the attacker cannot unwrap the real key even if they inject their own wrapped key.

### IPNS Record Replay

**Scenario:** An attacker captures a signed IPNS record and replays it later to point the file's IPNS name back to old content.

**Assessment:** Mitigated by IPNS sequence numbers. Records with lower sequence numbers are rejected by IPNS validators. The monotonically increasing sequence number (managed by `PublishCoordinator` in Rust and `resolveIpnsRecord` in TypeScript) prevents replay.

### Server-Side Key Extraction

**Scenario:** A compromised server attempts to extract IPNS private keys from the data it stores.

**Assessment:** Not exploitable. The IPNS private key is ECIES-wrapped inside AES-GCM encrypted metadata. The server has access to neither the folder key (AES-GCM) nor the user's private key (ECIES). The TEE receives a _separate_ ECIES wrapping with the TEE public key, and the TEE is assumed trusted (hardware isolation).

---

## Summary Table

| ID          | Severity | Title                                                    | File                                  | Status              |
| ----------- | -------- | -------------------------------------------------------- | ------------------------------------- | ------------------- |
| CRITICAL-01 | Critical | No HKDF fallback for legacy files in Rust desktop        | `inode.rs`                            | **FIXED** `d70d9f7` |
| HIGH-01     | High     | IPNS private key not cleared after ECIES wrapping        | `file-metadata.service.ts`            | **FIXED** `d70d9f7` |
| HIGH-02     | High     | Re-wrapping ECIES on every metadata publish              | `mod.rs`, `inode.rs`, `operations.rs` | **FIXED** `d70d9f7` |
| MEDIUM-01   | Medium   | Missing minimum length validation on encrypted key field | `metadata.ts`                         | **FIXED** `d70d9f7` |
| MEDIUM-02   | Medium   | Stale doc comment on file_ipns_private_key               | `inode.rs`                            | **FIXED** `d70d9f7` |
| LOW-01      | Low      | No TEE enrollment for desktop-created files              | `operations.rs`                       | **TODO** `8a7890b`  |
| LOW-02      | Low      | No lazy migration of legacy FilePointers                 | `file-metadata.service.ts`            | Deferred            |
| LOW-03      | Low      | Redundant .to_vec() leaks unzeroized key copy            | `operations.rs`                       | Partially fixed     |
| INFO-01     | Info     | Entropy sources are cryptographically sound              | Multiple                              | No action needed    |
| INFO-02     | Info     | ECIES wrapping direction is correct                      | Multiple                              | No action needed    |

---

## Remaining Open Items

| Priority | Item                                     | Action          |
| -------- | ---------------------------------------- | --------------- |
| Low      | TEE enrollment for desktop-created files | GSD todo logged |
| Low      | Lazy migration of legacy FilePointers    | Follow-up PR    |

---

_Generated by security:review command_
_This review is automated guidance, not a substitute for professional security audit_

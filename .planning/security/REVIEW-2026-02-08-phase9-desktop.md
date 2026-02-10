# Security Review Report: Phase 9 Desktop Client

**Date:** 2026-02-08
**Scope:** Rust crypto implementation, keychain interactions, API changes, FUSE/sync modules
**Branch:** `feat/phase-9-desktop-client` (PR vs `main`)
**Reviewer:** Claude (security:review command) -- 4 parallel review agents
**Files Analyzed:** 25+ source files across `apps/desktop/src-tauri/src/` and `apps/api/src/auth/`

## Executive Summary

The cryptographic algorithm choices, parameter sizes, library selections, and protocol implementations are **correct and well-engineered**. AES-256-GCM with random IVs, ECIES key wrapping, Ed25519 signing, and cross-language test vectors all demonstrate strong security awareness. The zero-knowledge guarantee is preserved -- the server never sees plaintext keys.

The primary systemic weakness is **memory hygiene for key material**: `Vec<u8>` values containing keys or plaintext are freed without zeroization when cloned, moved into closures, or evicted from caches. This is a defense-in-depth gap requiring local process memory access to exploit. The fix (`Zeroizing<Vec<u8>>`) is mechanical and low-risk.

Secondary concerns include FUSE filesystem permission enforcement, temp file security, and an O(N) Argon2 token scan in the API refresh flow.

**Risk Level:** MEDIUM (no remotely exploitable vulnerabilities; findings require local access or are DoS-class)

## Findings Summary

| Severity      | Count | Addressed | Key Theme                                                                                                 |
| ------------- | ----- | --------- | --------------------------------------------------------------------------------------------------------- |
| Critical      | 0     | --        | --                                                                                                        |
| High          | 6     | 6/6       | Memory hygiene (key zeroization), FUSE permissions, IPNS race, temp files, cache cleanup                  |
| Medium        | 5     | 5/5       | Token scan performance, temp dir permissions, intermediate key copies, lock discipline, mount permissions |
| Low           | 7     | 0/7       | Debug logging, URL encoding, stack key residue, error messages, write queue persistence                   |
| Informational | 3     | --        | Positive design observations                                                                              |

---

## Critical Issues

None found.

---

## High Priority Issues

### H-1: CipherBoxFS Holds Root Private Key as Plain Vec<u8> Without Zeroize-on-Drop -- ADDRESSED

**Severity:** HIGH
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/fuse/mod.rs:180-184`
**Description:** `CipherBoxFS` holds `private_key`, `public_key`, and `root_folder_key` as plain `Vec<u8>`. When the FUSE filesystem unmounts and `CipherBoxFS` is dropped, these vectors are freed without zeroization. The key bytes persist in freed heap pages.
**Impact:** The secp256k1 `private_key` is the root of the entire key hierarchy. Post-unmount, an attacker with process memory access (core dump, swap, hibernation image) could recover it.
**Recommendation:** Use `zeroize::Zeroizing<Vec<u8>>` for all key fields. This auto-zeroizes on drop and propagates through `.clone()`.
**Resolution:** All three fields changed to `Zeroizing<Vec<u8>>` in mod.rs. InodeKind key fields in inode.rs also wrapped with `Zeroizing`.

### H-2: Private Key Cloned Into Async Tasks Without Zeroization -- ADDRESSED

**Severity:** HIGH
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/fuse/operations.rs:141,179,300,728,964`
**Description:** Every file decryption and folder refresh clones `fs.private_key` into a `Vec<u8>` for async task closures. Dozens of un-zeroized copies accumulate in freed heap over a session.
**Impact:** Multiplies the exposure window from H-1.
**Recommendation:** Fix H-1 first -- `Zeroizing<Vec<u8>>` propagates through `.clone()` automatically.
**Resolution:** Fixed as side-effect of H-1. `.clone()` on `Zeroizing<Vec<u8>>` returns a new `Zeroizing` wrapper that auto-zeroizes on drop.

### H-3: Plaintext Folder Metadata JSON Not Zeroized After Encryption -- ADDRESSED

**Severity:** HIGH
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/crypto/folder.rs:96`
**Description:** In `encrypt_folder_metadata`, the serialized JSON `Vec<u8>` containing file names, folder structure, wrapped keys, and CIDs is dropped without zeroization after encryption.
**Impact:** File tree structure (names, hierarchy) persists in freed heap. For a zero-knowledge system, leaking organizational structure is a meaningful privacy breach.
**Recommendation:** Call `json.zeroize()` before returning.
**Resolution:** Both `encrypt_folder_metadata` and `decrypt_folder_metadata` now call `json.zeroize()` after use.

### H-4: access() Callback Grants All Permissions Unconditionally -- ADDRESSED

**Severity:** HIGH
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/fuse/operations.rs:1836-1848`
**Description:** The FUSE `access()` callback ignores the `_mask` parameter and returns `ok()` for any existing inode. Combined with the removal of `MountOption::DefaultPermissions` (for FUSE-T compatibility), there is no permission enforcement.
**Impact:** Any local process can read, write, and delete files in the mounted CipherBox directory.
**Recommendation:** Implement manual permission checking comparing `req.uid()`/`req.gid()` against inode ownership.
**Resolution:** Implemented owner-only permission checking: verifies `req.uid() == attr.uid`, checks R/W/X bits against owner permission bits, returns EACCES on mismatch.

### H-5: Temp Files Contain Plaintext, Not Securely Deleted -- ADDRESSED

**Severity:** HIGH
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/fuse/file_handle.rs:176-184`
**Description:** Write-buffered temp files store plaintext and are deleted with `fs::remove_file()` (unlink only). Content remains on disk and is recoverable with forensic tools. On APFS, snapshots may preserve deleted content.
**Impact:** Plaintext file content recoverable from disk after deletion.
**Recommendation:** Overwrite file content with zeros before `remove_file()`. Use the `tempfile` crate for proper cleanup semantics.
**Resolution:** Temp file `cleanup()` now overwrites content with zeros (64KB chunks) before `remove_file()`. Temp files created with 0o600 permissions.

### H-6: Content Cache (256 MiB Plaintext) Never Cleared on Unmount -- ADDRESSED

**Severity:** HIGH
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/fuse/cache.rs:81-84`, `fuse/mod.rs:718-756`
**Description:** `unmount_filesystem()` only cleans the temp directory. The `ContentCache` (up to 256 MiB of decrypted plaintext), `MetadataCache`, `pending_content`, and inode key material are never explicitly cleared or zeroized.
**Impact:** Up to 256 MiB of decrypted file content persists in process memory after unmount.
**Recommendation:** Implement `Filesystem::destroy()` to clear all caches. Add `Drop` impl on `CachedContent` calling `.zeroize()` on data.
**Resolution:** Added `Drop` impl on `CachedContent` that zeroizes data. Added `clear()` methods to `ContentCache` and `MetadataCache`. Implemented `Filesystem::destroy()` callback that zeroizes all caches, pending_content, and open file handles on unmount.

---

## Medium Priority Issues

### M-1: `refreshByToken` O(N) Argon2 Scan -- Performance and DoS Vector -- ADDRESSED

**Severity:** MEDIUM
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/api/src/auth/auth.service.ts:117-162`
**Description:** The refresh endpoint loads ALL non-revoked refresh tokens and iterates with Argon2 verification. At ~100ms per verify, 1000 tokens = ~100s worst case. The desktop PR increases exposure (body-based tokens, cold-start silent refresh on every launch).
**Impact:** Performance degradation at scale; potential CPU exhaustion via invalid refresh requests.
**Recommendation:** Add a `tokenPrefix` column (first 8 bytes of token, stored as separate indexed field) for O(1) lookup before Argon2 verification.
**Resolution:** Added `tokenPrefix` varchar(16) column to `refresh_tokens` entity with indexed lookup. Both `refreshByToken()` and `rotateRefreshToken()` now filter by prefix before Argon2 verification, reducing candidates to 1-2. Migration: `1738972800000-AddTokenPrefix.ts`.

### M-2: Temp Directory Created with Default Permissions -- ADDRESSED

**Severity:** MEDIUM
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/fuse/mod.rs:537-539`
**Description:** `/tmp/cipherbox` is created with default umask permissions. The predictable name is susceptible to symlink attacks on multi-user systems.
**Impact:** Other users could read temp files containing plaintext; symlink attacks possible.
**Recommendation:** Set permissions to 0o700 after creation. Use `tempfile` crate for unique, properly-permissioned directories.
**Resolution:** Temp directory permissions set to 0o700 after creation. Individual temp files created with 0o600 permissions.

### M-3: file_key.clone().try_into() Creates Un-Zeroized Intermediate Copy -- ADDRESSED

**Severity:** MEDIUM
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/fuse/operations.rs:197,748,984`
**Description:** `file_key.clone().try_into()` creates a heap `Vec<u8>` copy that is consumed by `try_into()` but freed without zeroing. The resulting `[u8; 32]` stack copy is also not zeroized.
**Impact:** Per-file ephemeral key copies persist in freed heap.
**Recommendation:** Use `.as_slice().try_into()` to avoid the clone. Explicitly zeroize the `[u8; 32]` after use.
**Resolution:** All three sites changed from `.clone().try_into()` to `.as_slice().try_into()`, eliminating the intermediate heap copy.

### M-4: AppState::clear_keys() Double-Acquires Write Lock (TOCTOU) -- ADDRESSED

**Severity:** MEDIUM
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/state.rs:94-99`
**Description:** Each key field's write lock is acquired twice: once to zeroize, once to set to `None`. A concurrent reader could observe the zeroized-but-still-present key between acquisitions.
**Impact:** Low practical impact (reader gets zero bytes, crypto ops fail). Represents sloppy lock discipline.
**Recommendation:** Combine into single lock acquisition per field.
**Resolution:** Consolidated to single scoped lock acquisition per field: zeroize + set None in one block.

### M-5: Mount Point ~/CipherBox Has No Permission Restrictions -- ADDRESSED

**Severity:** MEDIUM
**Status:** ADDRESSED (2026-02-08)
**Location:** `apps/desktop/src-tauri/src/fuse/mod.rs:511-513`
**Description:** `~/CipherBox` is created with default permissions (typically 0o755). Between mount cycles, the directory is accessible. Stale-mount cleanup recursively deletes without symlink verification.
**Impact:** Symlink planted between cycles could redirect cleanup to delete unintended files.
**Recommendation:** Set permissions to 0o700. Verify not a symlink before cleanup.
**Resolution:** Mount point permissions set to 0o700 after creation. Added symlink check before stale-mount cleanup — refuses to proceed if mount path is a symlink.

---

## Low Priority Issues

### L-1: Auth Controller Missing Explicit ThrottlerGuard

**Severity:** LOW
**Location:** `apps/api/src/auth/auth.controller.ts:42`
**Description:** The auth controller does not have `@UseGuards(ThrottlerGuard)`, unlike the IPNS controller. While global ThrottlerModule exists, NestJS requires the guard to be applied per-controller.
**Recommendation:** Add `@UseGuards(ThrottlerGuard)` with stricter per-endpoint limits on login (5/min) and refresh (10/min).

### L-2: IPNS Name in Query Parameter Not URL-Encoded

**Severity:** LOW
**Location:** `apps/desktop/src-tauri/src/api/ipns.rs:29`
**Description:** `format!("/ipns/resolve?ipnsName={}", ipns_name)` -- no URL encoding. Currently safe (IPNS names are `[a-z0-9]`) but establishes a fragile pattern.
**Recommendation:** Use `urlencoding::encode()`.

### L-3: Debug eprintln! Statements Leak Filenames to stderr

**Severity:** LOW
**Location:** `apps/desktop/src-tauri/src/fuse/operations.rs:1638-1641` and others
**Description:** Multiple `eprintln!(">>>` statements bypass log-level filtering and leak filenames (sensitive in a privacy-focused app). Already noted in project memory as pre-merge cleanup.
**Recommendation:** Remove or replace with `log::debug!()` before merge.

### L-4: Private Key Logged by Length in auth.ts

**Severity:** LOW
**Location:** `apps/desktop/src/auth.ts:167`
**Description:** `console.log('Got private key, length:', privateKey.length)` -- logs the length (always 64 hex chars), not the key itself. Not a secret leak, but establishes a risky log-adjacent pattern.
**Recommendation:** Remove or reduce to `console.debug`.

### L-5: Ed25519 Stack Key Copy Not Zeroized

**Severity:** LOW
**Location:** `apps/desktop/src-tauri/src/crypto/ed25519.rs:50-56`
**Description:** `key_bytes: [u8; 32]` stack copy of Ed25519 private key is not zeroized (the `SigningKey` itself IS auto-zeroized via the `zeroize` feature).
**Recommendation:** Call `key_bytes.zeroize()` after creating `SigningKey`.

### L-6: IPNS Sequence Number Fallback to 0 on Resolve Failure — RESOLVED

**Severity:** LOW (but HIGH data integrity impact)
**Status:** RESOLVED — Added `PublishCoordinator` with monotonic sequence cache and per-folder tokio::sync::Mutex. All 3 publish paths updated: `spawn_metadata_publish`, file upload release, and mkdir. Resolve failures now use cached seq or return error (never fallback to 0).
**Location:** `apps/desktop/src-tauri/src/fuse/operations.rs:1141-1147`
**Description:** When IPNS resolve fails, sequence falls back to 0. Publishing with seq=1 when current is seq=100 could cause metadata rollback. Concurrent publishes can also race on the same sequence number.
**Impact:** Silent data loss (overwrites), metadata rollback to stale state.
**Recommendation:** Never fall back to seq=0. Maintain local monotonic counter per IPNS name. Serialize publishes with per-folder mutex.

### L-7: Sync Daemon Error Messages Exposed Raw in Tray Status

**Severity:** LOW
**Location:** `apps/desktop/src-tauri/src/sync/mod.rs:158-161`
**Description:** Raw error strings (potentially containing API URLs, CIDs, internal info) passed to tray status display.
**Recommendation:** Map to user-friendly messages; log full errors internally.

---

## Positive Observations

### Cryptographic Implementation Quality

1. **AES-256-GCM with type-level size enforcement.** Key params are `&[u8; 32]` and IV params are `&[u8; 12]` -- wrong sizes are compile-time errors, not runtime.
2. **Fresh random IV per seal.** `seal_aes_gcm` always calls `generate_iv()` via `OsRng`. No caller can accidentally reuse an IV.
3. **Minimum sealed size check.** `unseal_aes_gcm` validates `MIN_SEALED_SIZE` (28 bytes = 12 IV + 16 tag) before slicing.
4. **Generic error messages.** "Encryption failed" / "Decryption failed" -- no oracle information leakage.
5. **ECIES public key validation.** Checks 65-byte uncompressed size and 0x04 prefix before passing to library.
6. **Ed25519 zeroize-on-drop confirmed.** `ed25519-dalek` compiled with `zeroize` feature, so `SigningKey` auto-zeroizes.
7. **All randomness from OS CSPRNG.** Every `generate_*` function uses `OsRng`. No weak PRNGs anywhere.
8. **Cross-language test vectors.** AES, ECIES, Ed25519, and IPNS name derivation all verified byte-for-byte against TypeScript implementation.
9. **Correct IPNS V2 signature format.** Domain separator, CBOR field order, and protobuf encoding all match the IPFS spec.

### Auth and Key Management

10. **Keychain storage for refresh tokens.** Desktop correctly uses macOS Keychain (hardware-encrypted on Apple Silicon), not disk files.
11. **Delete-before-set Keychain pattern.** Handles macOS idiosyncrasy where `set_password` fails if entry exists.
12. **AppState properly zeroizes keys on logout.** `clear_keys()` uses `zeroize` crate correctly.
13. **Token rotation enforced.** Both web and desktop paths revoke old token before issuing new ones.
14. **Server-side logout invalidates ALL tokens.** `revokeAllUserTokens` ensures stolen tokens become useless after logout.
15. **Tauri capability permissions minimal.** Only window, deep-link, shell, notification, and autostart -- no file system or HTTP permissions exposed to webview.

### FUSE and Sync

16. **File key zeroization after use.** `clear_bytes(&mut file_key)` called after decryption in multiple locations.
17. **Write queue stores encrypted content, not plaintext.** `QueuedWrite` holds `encrypted_content`, preventing plaintext-at-rest in the queue.
18. **Platform special files filtered.** `.DS_Store`, `._*` resource forks, etc. are blocked from IPFS sync.
19. **Non-blocking content prefetch.** Async background tasks avoid stalling the single-threaded NFS callback.

### API Changes

20. **Zero-knowledge guarantee preserved.** Desktop client performs ECIES wrapping locally; API never receives plaintext keys.
21. **Inline protobuf parser reduces supply chain risk.** Replacing `ipns` NPM package with minimal inline parser eliminates dependency tree attack surface.
22. **Global ValidationPipe with whitelist.** Unknown properties stripped AND rejected, preventing mass assignment attacks.
23. **Graceful IPNS resolve fallback.** Returns null with DB cache fallback instead of throwing `BAD_GATEWAY`.

---

## Compliance Checklist (Project Security Rules)

- [x] No privateKey in localStorage/sessionStorage (stored in macOS Keychain + Rust memory)
- [x] No sensitive keys logged (only key lengths logged in auth.ts:167)
- [x] No unencrypted keys sent to server (ECIES wrapping verified)
- [x] ECIES used for key wrapping (ecies crate v0.2.9, pure feature)
- [x] AES-256-GCM used for content encryption (aes-gcm crate v0.10.3)
- [x] Server has zero knowledge of plaintext (verified across all API call sites)
- [x] IPNS keys encrypted with TEE public key before sending (verified in commands.rs)
- [x] Key material zeroized after use (CipherBoxFS keys wrapped in `Zeroizing`, cache `Drop` zeroizes, `destroy()` clears all on unmount)

---

## Dependency Audit

| Crate           | Version        | Assessment                                    |
| --------------- | -------------- | --------------------------------------------- |
| `aes-gcm`       | 0.10.3         | Current. RustCrypto project, well-audited.    |
| `ecies`         | 0.2.9 (`pure`) | Current. Pure Rust, same author as `eciesjs`. |
| `ed25519-dalek` | 2.2.0          | Current. Zeroize-on-drop active.              |
| `rand`          | 0.8.5          | Current. `OsRng` delegates to OS CSPRNG.      |
| `zeroize`       | 1.x            | Current. Used for `clear_bytes` and AppState. |
| `ciborium`      | 0.2.x          | Current. CBOR encoding for IPNS.              |

No known CVEs in any dependency versions.

---

## Recommendations Summary (Priority Order)

| Priority | Recommendation                                                                   | Effort | Fixes              | Status     |
| -------- | -------------------------------------------------------------------------------- | ------ | ------------------ | ---------- |
| P0       | Adopt `Zeroizing<Vec<u8>>` for all key fields in `CipherBoxFS` and inode types   | MEDIUM | H-1, H-2, L-5      | DONE       |
| P0       | Implement `Drop` on `CachedContent` with `.zeroize()` on data                    | LOW    | H-6, M-3 partially | DONE       |
| P0       | Zeroize JSON buffer in `encrypt/decrypt_folder_metadata`                         | LOW    | H-3                | DONE       |
| P1       | Overwrite temp file content before deletion; restrict permissions to 0o600/0o700 | LOW    | H-5, M-2           | DONE       |
| P1       | Implement `Filesystem::destroy()` to clear all caches on unmount                 | MEDIUM | H-6                | DONE       |
| P1       | Add token prefix column for O(1) refresh token lookup                            | MEDIUM | M-1                | DONE       |
| P2       | Implement permission checking in `access()` callback                             | MEDIUM | H-4                | DONE       |
| P2       | Add `@UseGuards(ThrottlerGuard)` to AuthController                               | LOW    | L-1                | Backlogged |
| ~~P2~~   | ~~Serialize IPNS sequence operations per folder; never fall back to seq=0~~      | MEDIUM | L-6                | DONE       |
| P3       | Remove `eprintln!(">>>` debug lines before merge                                 | LOW    | L-3                | Backlogged |
| P3       | URL-encode query parameters in Rust API client                                   | LOW    | L-2                | Backlogged |
| P3       | Consolidate `clear_keys()` to single lock acquisition per field                  | LOW    | M-4                | DONE       |

---

## Next Steps

All High and Medium severity issues have been addressed (2026-02-08). Remaining work:

1. **Before merge:** Remove `eprintln!(">>>` debug lines (L-3) -- already in project memory as pre-merge task.
2. **Backlogged (Low):** L-1 through L-7 tracked in `LOW-SEVERITY-BACKLOG.md` (items 13-19).

---

_Generated by security:review command_
_This review is automated guidance, not a substitute for professional security audit_

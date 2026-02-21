# CipherBox Metadata Schema Reference

**Version:** 1.0
**Last Updated:** 2026-02-21
**Status:** Stable

## Table of Contents

1. [Overview](#1-overview)
2. [Encryption Hierarchy](#2-encryption-hierarchy)
3. [Wire Format](#3-wire-format)
4. [FolderMetadata (v2)](#4-foldermetadata-v2)
5. [FolderChild (Union)](#5-folderchild-union)
6. [FolderEntry](#6-folderentry)
7. [FilePointer](#7-filepointer)
8. [FileMetadata (v1)](#8-filemetadata-v1)
9. [VersionEntry](#9-versionentry)
10. [EncryptedVaultKeys](#10-encryptedvaultkeys)
11. [DeviceRegistry (v1)](#11-deviceregistry-v1)
12. [DeviceEntry](#12-deviceentry)
13. [Cross-Implementation Parity](#13-cross-implementation-parity)
14. [IPNS Key Derivation Summary](#14-ipns-key-derivation-summary)

---

## 1. Overview

CipherBox stores all metadata encrypted client-side using AES-256-GCM or ECIES before persisting to IPFS or the server database. The server is zero-knowledge -- it never sees plaintext metadata or unencrypted keys.

Metadata exists in two implementations that must produce byte-identical JSON (camelCase field names):

- **TypeScript** -- `packages/crypto/src/` (web app, shared crypto library)
- **Rust** -- `apps/desktop/src-tauri/src/crypto/` (desktop app, uses `serde(rename_all = "camelCase")`)

This document defines the canonical schema for every metadata object in the system. For rules governing how these schemas evolve over time, see [METADATA_EVOLUTION_PROTOCOL.md](METADATA_EVOLUTION_PROTOCOL.md).

---

## 2. Encryption Hierarchy

Each metadata type uses a specific encryption scheme and storage location.

| Metadata Type      | Encrypted By                 | Algorithm                  | Storage   | IPNS Addressing           |
| ------------------ | ---------------------------- | -------------------------- | --------- | ------------------------- |
| FolderMetadata     | Folder's own `folderKey`     | AES-256-GCM                | IPFS blob | Folder's IPNS name        |
| FileMetadata       | Parent folder's `folderKey`  | AES-256-GCM                | IPFS blob | File's own IPNS name      |
| EncryptedVaultKeys | User's secp256k1 `publicKey` | ECIES                      | Server DB | N/A                       |
| DeviceRegistry     | User's secp256k1 `publicKey` | ECIES                      | IPFS blob | Registry's IPNS name      |
| File content       | Per-file random `fileKey`    | AES-256-GCM or AES-256-CTR | IPFS blob | N/A (CID in FileMetadata) |

**Key principle:** Access to a folder's `folderKey` grants access to all children (subfolders via ECIES-wrapped keys, files via the parent's `folderKey` encrypting their metadata).

---

## 3. Wire Format

Folder metadata and file metadata share the same encrypted envelope format for IPFS storage.

```json
{
  "iv": "<hex-encoded 12-byte IV>",
  "data": "<base64-encoded AES-GCM ciphertext + 16-byte tag>"
}
```

| Field  | Type   | Encoding | Description                                                     |
| ------ | ------ | -------- | --------------------------------------------------------------- |
| `iv`   | string | hex      | 12-byte AES-256-GCM initialization vector (24 hex characters)   |
| `data` | string | base64   | AES-256-GCM ciphertext with appended 16-byte authentication tag |

**Source files:**

- TS folder: `packages/crypto/src/folder/types.ts:53-58` (`EncryptedFolderMetadata`)
- TS file: `packages/crypto/src/file/types.ts:75-80` (`EncryptedFileMetadata`)
- Rust: inline struct in `apps/desktop/src-tauri/src/fuse/operations.rs` (defined locally)

**Encoding note:** The `iv` field is hex-encoded. The `data` field uses standard base64 (not base64url, not hex). Mixing up encodings causes decryption failures.

---

## 4. FolderMetadata (v2)

The top-level metadata object for each folder. Contains an array of children (subfolders and file pointers).

**Current version:** `v2`

| Field      | Type            | Required | Description                                   |
| ---------- | --------------- | -------- | --------------------------------------------- |
| `version`  | `'v2'`          | Yes      | Schema version (literal string `"v2"`)        |
| `children` | `FolderChild[]` | Yes      | Array of FolderEntry and FilePointer children |

**Encryption:** AES-256-GCM with this folder's 32-byte `folderKey`.

**Storage:** IPFS (as JSON envelope `{iv, data}`), addressed via the folder's IPNS name.

**Source files:**

- TS types: `packages/crypto/src/folder/types.ts:15-20`
- TS validator: `packages/crypto/src/folder/metadata.ts:32-78`
- Rust: `apps/desktop/src-tauri/src/crypto/folder.rs:78-84`

**Version history:**

| Version | Phase   | Change                                                                                                   |
| ------- | ------- | -------------------------------------------------------------------------------------------------------- |
| v1      | Initial | Children contained inline `FileEntry` with `cid`, `fileKeyEncrypted`, `fileIv`, `size`, `encryptionMode` |
| v2      | 12.6    | Children use `FilePointer` (slim IPNS reference). Per-file metadata moved to dedicated IPNS records      |

v1 was completely removed in Phase 11.2. The validator rejects v1 data with a `CryptoError`. This was a clean-break migration (pre-production vault wipe).

---

## 5. FolderChild (Union)

Discriminated union type for children within a folder.

| Discriminant     | Type          | Description                              |
| ---------------- | ------------- | ---------------------------------------- |
| `type: 'folder'` | `FolderEntry` | Subfolder with ECIES-wrapped keys        |
| `type: 'file'`   | `FilePointer` | Slim reference to a per-file IPNS record |

**Source files:**

- TS: `packages/crypto/src/folder/types.ts:25`
- Rust: `apps/desktop/src-tauri/src/crypto/folder.rs:66-73` (serde internally tagged enum with `#[serde(tag = "type", rename_all = "lowercase")]`)

---

## 6. FolderEntry

A subfolder child within folder metadata. Contains ECIES-wrapped keys for accessing the subfolder's own metadata.

| Field                     | Type   | Encoding  | Required | Description                                                         |
| ------------------------- | ------ | --------- | -------- | ------------------------------------------------------------------- |
| `type`                    | string | --        | Yes      | Always `"folder"`                                                   |
| `id`                      | string | UUID      | Yes      | Unique identifier for this subfolder                                |
| `name`                    | string | --        | Yes      | Folder name (plaintext; entire metadata blob is encrypted)          |
| `ipnsName`                | string | base32/36 | Yes      | IPNS name for resolving this subfolder's metadata                   |
| `ipnsPrivateKeyEncrypted` | string | hex       | Yes      | ECIES-wrapped 64-byte Ed25519 IPNS key (161 bytes, 322 hex chars)   |
| `folderKeyEncrypted`      | string | hex       | Yes      | ECIES-wrapped 32-byte AES-256 folder key (129 bytes, 258 hex chars) |
| `createdAt`               | number | --        | Yes      | Unix timestamp in milliseconds                                      |
| `modifiedAt`              | number | --        | Yes      | Unix timestamp in milliseconds                                      |

**Not independently encrypted** -- lives inside the parent `FolderMetadata` blob.

**ECIES wrapping:** Both `folderKeyEncrypted` and `ipnsPrivateKeyEncrypted` are encrypted to the vault owner's secp256k1 `publicKey`. See [VAULT_EXPORT_FORMAT.md](VAULT_EXPORT_FORMAT.md) Section 4 for the ECIES ciphertext binary format.

**Subfolder IPNS keys:** Randomly generated Ed25519 keypairs (not HKDF-derived). This is different from root vault and per-file IPNS keys which are deterministically derived.

**Source files:**

- TS: `packages/crypto/src/folder/types.ts:31-47`
- Rust: `apps/desktop/src-tauri/src/crypto/folder.rs:28-45`

**Version history:** Unchanged since initial design.

---

## 7. FilePointer

A slim file reference within v2 folder metadata. Points to a file's own IPNS record instead of embedding file data inline.

| Field              | Type   | Encoding | Required | Description                                                    |
| ------------------ | ------ | -------- | -------- | -------------------------------------------------------------- |
| `type`             | string | --       | Yes      | Always `"file"`                                                |
| `id`               | string | UUID     | Yes      | Unique file identifier (used in HKDF derivation for file IPNS) |
| `name`             | string | --       | Yes      | File name (plaintext; entire metadata blob is encrypted)       |
| `fileMetaIpnsName` | string | base36   | Yes      | IPNS name of the file's own metadata record                    |
| `createdAt`        | number | --       | Yes      | Unix timestamp in milliseconds                                 |
| `modifiedAt`       | number | --       | Yes      | Unix timestamp in milliseconds                                 |

**Not independently encrypted** -- lives inside the parent `FolderMetadata` blob.

**Key distinction from v1 FileEntry:** FilePointer does not contain `cid`, `fileKeyEncrypted`, `fileIv`, `encryptionMode`, or `size`. All file crypto material is in the per-file `FileMetadata` record, enabling file content updates without touching folder metadata.

**Source files:**

- TS: `packages/crypto/src/file/types.ts:57-69`
- Rust: `apps/desktop/src-tauri/src/crypto/folder.rs:50-63`

**Version history:** Added in Phase 12.6 (replaced inline `FileEntry` in v2 folders).

---

## 8. FileMetadata (v1)

Per-file metadata stored in a file's own IPNS record. Contains all crypto material needed to decrypt the file content.

**Current version:** `v1`

| Field              | Type               | Encoding | Required | Default | Description                                            |
| ------------------ | ------------------ | -------- | -------- | ------- | ------------------------------------------------------ |
| `version`          | `'v1'`             | --       | Yes      | --      | Schema version (literal string `"v1"`)                 |
| `cid`              | string             | CIDv1    | Yes      | --      | IPFS content identifier of the encrypted file          |
| `fileKeyEncrypted` | string             | hex      | Yes      | --      | ECIES-wrapped 32-byte AES-256 file key (258 hex chars) |
| `fileIv`           | string             | hex      | Yes      | --      | 12-byte IV used for file encryption (24 hex chars)     |
| `size`             | number             | --       | Yes      | --      | Original unencrypted file size in bytes                |
| `mimeType`         | string             | --       | Yes      | --      | MIME type of the original file                         |
| `encryptionMode`   | `'GCM'` \| `'CTR'` | --       | No       | `'GCM'` | Encryption algorithm used for file content             |
| `createdAt`        | number             | --       | Yes      | --      | Unix timestamp in milliseconds                         |
| `modifiedAt`       | number             | --       | Yes      | --      | Unix timestamp in milliseconds                         |
| `versions`         | `VersionEntry[]`   | --       | No       | omitted | Past versions of this file (newest first)              |

**Encryption:** AES-256-GCM with the parent folder's `folderKey` (not the file's own key). This means anyone who can read the folder can also read file metadata and decrypt the file.

**Storage:** IPFS (as JSON envelope `{iv, data}`), addressed via the file's own IPNS name. The IPNS name is deterministically derived from the user's `privateKey` + `fileId` via HKDF (see [Section 14](#14-ipns-key-derivation-summary)).

**Source files:**

- TS types: `packages/crypto/src/file/types.ts:30-51`
- TS validator: `packages/crypto/src/file/metadata.ts:93-188`
- Rust: `apps/desktop/src-tauri/src/crypto/folder.rs:166-192`

**Version history:**

| Version               | Phase     | Change                                                                 | Version Bumped? |
| --------------------- | --------- | ---------------------------------------------------------------------- | --------------- |
| v1 (initial)          | 12.6      | Initial per-file IPNS schema                                           | --              |
| v1 + `encryptionMode` | 12.6/12.1 | Optional field added, defaults to `'GCM'`. Supports AES-CTR streaming. | No              |
| v1 + `versions`       | 13        | Optional `VersionEntry[]` array. Omitted when empty.                   | No              |

Both additions were additive optional fields with sensible defaults -- the version field was not bumped. This informal pattern is formalized in [METADATA_EVOLUTION_PROTOCOL.md](METADATA_EVOLUTION_PROTOCOL.md).

**Rust serde annotations for optional fields:**

```rust
#[serde(default = "default_encryption_mode")]  // defaults to "GCM"
pub encryption_mode: String,

#[serde(skip_serializing_if = "Option::is_none")]
#[serde(default)]
pub versions: Option<Vec<VersionEntry>>,
```

---

## 9. VersionEntry

A single past version of a file. Embedded in the `versions` array of `FileMetadata`. Each entry contains the full crypto context needed to independently decrypt that version's content.

| Field              | Type               | Encoding | Required | Description                                                        |
| ------------------ | ------------------ | -------- | -------- | ------------------------------------------------------------------ |
| `cid`              | string             | CIDv1    | Yes      | IPFS content identifier of the encrypted file for this version     |
| `fileKeyEncrypted` | string             | hex      | Yes      | ECIES-wrapped 32-byte AES-256 key for this version (258 hex chars) |
| `fileIv`           | string             | hex      | Yes      | 12-byte IV used for this version's encryption (24 hex chars)       |
| `size`             | number             | --       | Yes      | Original unencrypted file size in bytes                            |
| `timestamp`        | number             | --       | Yes      | When this version was created (Unix ms)                            |
| `encryptionMode`   | `'GCM'` \| `'CTR'` | --       | Yes      | Encryption mode used for this version                              |

**Not independently encrypted** -- embedded in the parent `FileMetadata` blob.

**Key difference from FileMetadata:** `encryptionMode` is **required** (not optional) because past versions always record the explicit encryption mode used at the time of creation.

**Constraints:**

- Maximum 10 versions per file
- 15-minute cooldown between version creation

**Source files:**

- TS types: `packages/crypto/src/file/types.ts:10-23`
- TS validator: `packages/crypto/src/file/metadata.ts:32-87`
- Rust: `apps/desktop/src-tauri/src/crypto/folder.rs:145-160`

**Version history:** Added in Phase 13 (File Versioning).

---

## 10. EncryptedVaultKeys

Root-level keys for the user's vault, encrypted with ECIES for server-side storage.

| Field                     | Type         | Encoding | Required | Description                                                |
| ------------------------- | ------------ | -------- | -------- | ---------------------------------------------------------- |
| `encryptedRootFolderKey`  | `Uint8Array` | raw      | Yes      | ECIES-wrapped 32-byte AES-256 root folder key (129 bytes)  |
| `encryptedIpnsPrivateKey` | `Uint8Array` | raw      | Yes      | ECIES-wrapped 64-byte Ed25519 IPNS private key (161 bytes) |

**Encryption:** ECIES with the user's secp256k1 `publicKey`.

**Storage:** Server database (API `users` table). Transmitted as raw `Uint8Array` in TypeScript, not hex-encoded strings.

**Source files:**

- TS: `packages/crypto/src/vault/types.ts:32-37`

**No Rust equivalent.** The desktop app retrieves vault keys from the API response and decrypts them using the webview's TypeScript crypto.

**Version history:**

| Change                      | Phase  | Description                                                                                                                                                                                |
| --------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `rootIpnsPublicKey` removed | 12.3.1 | Was previously stored alongside private key. Removed because it is derivable from the private key via deterministic Ed25519 derivation. Eliminates redundancy and potential inconsistency. |

**No version field.** Changes to this structure should be paired with a new vault export format version (see [VAULT_EXPORT_FORMAT.md](VAULT_EXPORT_FORMAT.md)).

---

## 11. DeviceRegistry (v1)

The encrypted device registry tracking all authenticated devices for a user.

**Current version:** `v1`

| Field            | Type            | Required | Description                                               |
| ---------------- | --------------- | -------- | --------------------------------------------------------- |
| `version`        | `'v1'`          | Yes      | Schema version (literal string `"v1"`)                    |
| `sequenceNumber` | number          | Yes      | Monotonically increasing counter for IPNS ordering        |
| `devices`        | `DeviceEntry[]` | Yes      | Array of all device entries (including revoked for audit) |

**Encryption:** ECIES with the user's secp256k1 `publicKey`. The entire registry is encrypted as a single blob (not AES-GCM like folder/file metadata).

**Storage:** IPFS (raw ECIES ciphertext blob, not the `{iv, data}` JSON envelope), addressed via the device registry IPNS name (HKDF-derived).

**`sequenceNumber` usage:** Each update increments the sequence number. Used by the IPNS publisher to set the record's sequence field, ensuring newer records supersede older ones across the DHT.

**Validator constraints:**

- `sequenceNumber` must be a non-negative integer
- `devices` must be an array (may be empty)
- Generic error messages (`'Invalid registry format'`) to avoid leaking schema details to attackers

**Source files:**

- TS types: `packages/crypto/src/registry/types.ts:54-61`
- TS validator: `packages/crypto/src/registry/schema.ts:26-58`

**No Rust equivalent.** The desktop app uses the webview's TypeScript crypto for device registry operations.

**Version history:** Added in Phase 12.2 (Encrypted Device Registry).

---

## 12. DeviceEntry

An individual device record within the `DeviceRegistry`. Tracks authentication status, platform information, and revocation state.

| Field         | Type                                             | Encoding | Required | Description                                                |
| ------------- | ------------------------------------------------ | -------- | -------- | ---------------------------------------------------------- |
| `deviceId`    | string                                           | hex      | Yes      | SHA-256 hash of device's Ed25519 public key (64 hex chars) |
| `publicKey`   | string                                           | hex      | Yes      | Device's Ed25519 public key, uncompressed (130 hex chars)  |
| `name`        | string                                           | --       | Yes      | Human-readable device name (max 200 chars)                 |
| `platform`    | `'web'` \| `'macos'` \| `'linux'` \| `'windows'` | --       | Yes      | Platform identifier                                        |
| `appVersion`  | string                                           | --       | Yes      | Application version string (max 50 chars)                  |
| `deviceModel` | string                                           | --       | Yes      | Device model or OS version (max 200 chars)                 |
| `ipHash`      | string                                           | hex      | Yes      | SHA-256 hash of IP address at registration (64 hex chars)  |
| `status`      | `'pending'` \| `'authorized'` \| `'revoked'`     | --       | Yes      | Authorization status                                       |
| `createdAt`   | number                                           | --       | Yes      | When device was first registered (Unix ms)                 |
| `lastSeenAt`  | number                                           | --       | Yes      | Last time device synced with registry (Unix ms)            |
| `revokedAt`   | number \| null                                   | --       | Yes      | When device was revoked (Unix ms), `null` if not revoked   |
| `revokedBy`   | string \| null                                   | --       | Yes      | Device ID of the revoking device, `null` if not revoked    |

**Not independently encrypted** -- embedded in the parent `DeviceRegistry` blob.

**Validator constraints:**

- `deviceId`: exactly 64 hex characters (SHA-256 output)
- `publicKey`: exactly 130 hex characters (uncompressed secp256k1 point: `04` prefix + 64 bytes)
- `ipHash`: exactly 64 hex characters (SHA-256 output)
- `name`: max 200 characters
- `appVersion`: max 50 characters
- `deviceModel`: max 200 characters
- `platform`: must be one of the four valid values
- `status`: must be one of the three valid values
- `revokedAt` and `revokedBy`: must both be null or both be non-null

**Source files:**

- TS types: `packages/crypto/src/registry/types.ts:21-46`
- TS validator: `packages/crypto/src/registry/schema.ts:63-136`

**Version history:** Added in Phase 12.2 (Encrypted Device Registry).

---

## 13. Cross-Implementation Parity

TypeScript and Rust implementations must produce identical JSON for the same logical data.

| Schema             | TypeScript          | Rust                                   | Notes           |
| ------------------ | ------------------- | -------------------------------------- | --------------- |
| FolderMetadata     | `folder/types.ts`   | `crypto/folder.rs`                     | Both platforms  |
| FolderChild        | `folder/types.ts`   | `crypto/folder.rs` (serde tagged enum) | Both platforms  |
| FolderEntry        | `folder/types.ts`   | `crypto/folder.rs`                     | Both platforms  |
| FilePointer        | `file/types.ts`     | `crypto/folder.rs`                     | Both platforms  |
| FileMetadata       | `file/types.ts`     | `crypto/folder.rs`                     | Both platforms  |
| VersionEntry       | `file/types.ts`     | `crypto/folder.rs`                     | Both platforms  |
| EncryptedVaultKeys | `vault/types.ts`    | --                                     | TypeScript only |
| DeviceRegistry     | `registry/types.ts` | --                                     | TypeScript only |
| DeviceEntry        | `registry/types.ts` | --                                     | TypeScript only |

**Rust serialization strategy:** All Rust structs use `#[serde(rename_all = "camelCase")]` to produce camelCase JSON field names matching the TypeScript convention. The `FolderChild` enum uses `#[serde(tag = "type", rename_all = "lowercase")]` for internally tagged union serialization.

**Types without Rust implementations** (EncryptedVaultKeys, DeviceRegistry, DeviceEntry) are handled entirely by the TypeScript crypto library running in the desktop app's webview. The Rust backend does not need to serialize or deserialize these types directly.

---

## 14. IPNS Key Derivation Summary

CipherBox uses HKDF-SHA256 to derive deterministic Ed25519 IPNS keypairs from the user's secp256k1 private key. All derivations share the same salt but use different HKDF info strings for domain separation.

| Purpose              | Salt           | HKDF Info                           | Source File                                   |
| -------------------- | -------------- | ----------------------------------- | --------------------------------------------- |
| Root vault IPNS      | `CipherBox-v1` | `cipherbox-vault-ipns-v1`           | `packages/crypto/src/vault/derive-ipns.ts`    |
| Device registry IPNS | `CipherBox-v1` | `cipherbox-device-registry-ipns-v1` | `packages/crypto/src/registry/derive-ipns.ts` |
| Per-file IPNS        | `CipherBox-v1` | `cipherbox-file-ipns-v1:{fileId}`   | `packages/crypto/src/file/derive-ipns.ts`     |

**Derivation path:**

```text
secp256k1 privateKey (32 bytes)
  -> HKDF-SHA256(salt, info) -> 32-byte Ed25519 seed
  -> Ed25519 keypair (@noble/ed25519)
  -> IPNS name (CIDv1 with libp2p-key codec + identity multihash)
```

**Subfolder IPNS keys:** Subfolders use randomly generated Ed25519 keypairs, not HKDF-derived. The keypair is ECIES-wrapped with the vault owner's public key and stored in the parent folder's `FolderEntry.ipnsPrivateKeyEncrypted` field.

**Per-file IPNS validation:** The `fileId` used in the HKDF info string must be at least 10 characters (enforced by the derivation function). This ensures UUID-length identifiers and prevents accidental short strings in the derivation material.

---

_Document version: 1.0_
_Last updated: 2026-02-21_
_See also: [METADATA_EVOLUTION_PROTOCOL.md](METADATA_EVOLUTION_PROTOCOL.md) for schema change rules_
_See also: [VAULT_EXPORT_FORMAT.md](VAULT_EXPORT_FORMAT.md) for recovery and crypto format details_

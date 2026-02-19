# CipherBox Vault Export Format Specification

**Version:** 1.0
**Last Updated:** 2026-02-17
**Status:** Stable

## Table of Contents

1. [Overview](#1-overview)
2. [Export JSON Format](#2-export-json-format)
3. [Cryptographic Algorithms](#3-cryptographic-algorithms)
4. [ECIES Ciphertext Binary Format](#4-ecies-ciphertext-binary-format)
5. [Encrypted Folder Metadata Format](#5-encrypted-folder-metadata-format)
6. [Recovery Procedure](#6-recovery-procedure)
7. [Test Vectors](#7-test-vectors)
8. [Security Considerations](#8-security-considerations)
9. [Compatibility Notes](#9-compatibility-notes)

---

## 1. Overview

CipherBox is a zero-knowledge encrypted cloud storage system. All files and metadata are encrypted client-side before being stored on IPFS. The server never has access to plaintext data or unencrypted keys.

The **vault export** enables users to recover all their files independently of CipherBox infrastructure. The export contains the minimum data needed for recovery:

- The root IPNS name (pointer to the encrypted folder hierarchy)
- Two ECIES-encrypted root keys (root folder key and root IPNS private key)

From these three values, combined with the user's secp256k1 private key, the entire folder hierarchy and all files can be recovered using only public IPFS gateways. No CipherBox servers, accounts, or APIs are required.

### Architecture Context

CipherBox stores files on IPFS (content-addressed, immutable) and organizes them into folders using IPNS (mutable name system). Each folder has:

- An **IPNS name** that resolves to the current CID of its encrypted metadata
- A **folder key** (AES-256) for encrypting/decrypting the folder's metadata
- An **IPNS private key** (Ed25519) for signing IPNS record updates

The root folder's IPNS name and keys are stored in the user's vault on the CipherBox server, encrypted with the user's secp256k1 public key using ECIES. Subfolder keys are stored within each parent folder's encrypted metadata, also ECIES-encrypted.

This design means the vault export only needs the root-level data. Recovery traverses the IPNS hierarchy to discover and decrypt all subfolders and files.

---

## 2. Export JSON Format

The vault export is a JSON file with the following schema:

| Field                         | Type           | Encoding      | Size (decoded) | Required | Description                                           |
| ----------------------------- | -------------- | ------------- | -------------- | -------- | ----------------------------------------------------- |
| `format`                      | string         | -             | -              | Yes      | Always `"cipherbox-vault-export"`                     |
| `version`                     | string         | -             | -              | Yes      | Always `"1.0"`                                        |
| `exportedAt`                  | string         | ISO 8601      | -              | Yes      | UTC timestamp of export creation                      |
| `rootIpnsName`                | string         | base32/base36 | -              | Yes      | libp2p-key multihash identifying the root folder      |
| `encryptedRootFolderKey`      | string         | hex           | 129 bytes      | Yes      | ECIES-encrypted 32-byte AES-256 root folder key       |
| `encryptedRootIpnsPrivateKey` | string         | hex           | 161 bytes      | Yes      | ECIES-encrypted 64-byte Ed25519 root IPNS private key |
| `derivationInfo`              | object \| null | -             | -              | No       | Hints about private key derivation method             |

### derivationInfo Object

When present, `derivationInfo` contains hints about how the user's secp256k1 private key was derived, to assist recovery tools in prompting correctly:

| Field               | Type           | Description                                                                                       |
| ------------------- | -------------- | ------------------------------------------------------------------------------------------------- |
| `method`            | string         | `"web3auth"` (social login, key managed by Web3Auth MPC) or `"external-wallet"` (EIP-712 derived) |
| `derivationVersion` | number \| null | `null` for social logins, `1`+ for external wallet key derivation versions                        |

### Example Export JSON

```json
{
  "format": "cipherbox-vault-export",
  "version": "1.0",
  "exportedAt": "2026-02-11T12:00:00.000Z",
  "rootIpnsName": "k51qzi5uqu5dg05y48rp46k4yq2tse4ufqfhn6w4i6js3t456ss9dkk",
  "encryptedRootFolderKey": "04a1b2c3d4e5f6...hex...258 hex characters total",
  "encryptedRootIpnsPrivateKey": "04d5e6f7a8b9c0...hex...322 hex characters total",
  "derivationInfo": {
    "method": "web3auth",
    "derivationVersion": null
  }
}
```

### Field Details

**`rootIpnsName`:** A libp2p-key multihash in either base32 (`k51...`) or base36 format, derived from the Ed25519 public key of the root folder's IPNS keypair. This name is resolvable via any IPFS gateway or delegated routing API.

**`encryptedRootFolderKey`:** The root folder's 32-byte AES-256-GCM symmetric key, encrypted to the user's secp256k1 public key using ECIES. After ECIES decryption, this key is used to decrypt the root folder's metadata stored on IPFS.

**`encryptedRootIpnsPrivateKey`:** The root folder's Ed25519 private key in 64-byte libp2p format (`seed(32) || publicKey(32)`), encrypted to the user's secp256k1 public key using ECIES. The first 32 bytes are the Ed25519 seed; the last 32 bytes are the corresponding Ed25519 public key.

---

## 3. Cryptographic Algorithms

### 3.1 ECIES (secp256k1) -- Key Wrapping

ECIES (Elliptic Curve Integrated Encryption Scheme) is used to wrap symmetric keys to a recipient's secp256k1 public key. CipherBox uses the `eciesjs` library (version 0.4.16) with its default configuration.

| Parameter                | Value                                                        |
| ------------------------ | ------------------------------------------------------------ |
| Library                  | eciesjs v0.4.16                                              |
| Elliptic curve           | secp256k1                                                    |
| Public key format        | Uncompressed, 65 bytes (0x04 prefix + 32-byte x + 32-byte y) |
| Private key format       | Raw 32-byte scalar                                           |
| Ephemeral key format     | Uncompressed, 65 bytes                                       |
| Inner cipher             | AES-256-GCM                                                  |
| Inner nonce size         | **16 bytes** (NOT the standard 12 bytes)                     |
| Inner tag size           | 16 bytes (128-bit authentication tag)                        |
| Key derivation           | HKDF-SHA256                                                  |
| HKDF IKM                 | `concat(ephemeralPublicKey, sharedPoint)`                    |
| HKDF salt                | `undefined` (empty/no salt)                                  |
| HKDF info                | `undefined` (empty/no info)                                  |
| HKDF output length       | 32 bytes (256 bits)                                          |
| ECDH shared point format | Uncompressed, 65 bytes                                       |

**IMPORTANT:** The 16-byte AES-GCM nonce is non-standard. Most AES-GCM implementations default to 12 bytes. This is an intentional choice by eciesjs for increased collision resistance. Recovery tools must use 16-byte nonces for the ECIES inner cipher.

**ECDH Key Agreement:**

```text
sharedPoint = ECDH(recipientPrivateKey, ephemeralPublicKey)
```

The ECDH shared secret is computed using the recipient's private key and the ephemeral public key from the ECIES ciphertext. The shared point is in uncompressed format (65 bytes).

Note: eciesjs internally compresses the ephemeral public key before passing it to `getSharedSecret()` (`pk.toBytes(true)`), then the result is returned in uncompressed format. When reimplementing, pass the compressed form of the ephemeral public key to the ECDH function and request uncompressed output:

```text
ephemeralPKCompressed = compress(ephemeralPublicKey)  // 33 bytes
sharedPoint = getSharedSecret(privateKey, ephemeralPKCompressed, false)  // uncompressed output
```

**Key Derivation:**

```text
ikm = concat(ephemeralPublicKey, sharedPoint)   // 65 + 65 = 130 bytes
sharedKey = HKDF-SHA256(ikm, salt=undefined, info=undefined, length=32)
```

The IKM (input key material) is the concatenation of the uncompressed ephemeral public key (65 bytes) and the uncompressed ECDH shared point (65 bytes), totaling 130 bytes. The HKDF salt and info parameters are both `undefined` (treated as empty by the implementation).

### 3.2 AES-256-GCM -- Folder Metadata and File Content

AES-256-GCM is used for two purposes: encrypting folder metadata and encrypting file content.

| Parameter    | Value                        |
| ------------ | ---------------------------- |
| Algorithm    | AES-256-GCM (Web Crypto API) |
| Key size     | 32 bytes (256 bits)          |
| IV size      | 12 bytes (96 bits)           |
| Tag size     | 16 bytes (128 bits)          |
| Tag position | Appended to ciphertext       |

The authentication tag is appended to the ciphertext by Web Crypto API. The ciphertext output is `encrypted_data || tag` where `tag` is 16 bytes.

**Folder metadata encryption:** The folder key (32-byte AES key) encrypts the JSON-serialized folder metadata with a random 12-byte IV. The IV and ciphertext are stored separately (see [Section 5](#5-encrypted-folder-metadata-format)).

**File content encryption:** Each file has its own random 32-byte file key and 12-byte IV. The encrypted file is stored as a single binary blob on IPFS (ciphertext with appended tag).

### 3.3 Ed25519 -- IPNS Signing

Ed25519 is used for IPNS record signing. Keys are stored in libp2p format.

| Parameter          | Value                                                   |
| ------------------ | ------------------------------------------------------- |
| Algorithm          | Ed25519                                                 |
| Private key format | 64 bytes: `seed(32) \|\| publicKey(32)` (libp2p format) |
| Public key format  | 32 bytes                                                |
| Signature format   | 64 bytes                                                |
| IPNS compatibility | V1 + V2 compatible signatures                           |

The 64-byte libp2p format stores the 32-byte Ed25519 private key seed concatenated with the 32-byte public key. For IPNS name derivation, the public key (last 32 bytes) is used. For recovery, only the IPNS name is needed to resolve records (no signing required).

---

## 4. ECIES Ciphertext Binary Format

ECIES ciphertext produced by eciesjs v0.4.16 has the following binary layout:

```text
+------------------+------------------+------------------+------------------+
|   Ephemeral PK   |      Nonce       |       Tag        |    Ciphertext    |
|    (65 bytes)     |   (16 bytes)     |   (16 bytes)     |    (N bytes)     |
+------------------+------------------+------------------+------------------+
```

| Offset | Size | Field                | Description                                           |
| ------ | ---- | -------------------- | ----------------------------------------------------- |
| 0      | 65   | Ephemeral Public Key | Uncompressed secp256k1 point (0x04 \|\| x \|\| y)     |
| 65     | 16   | Nonce                | AES-256-GCM nonce (16 bytes, NOT 12)                  |
| 81     | 16   | Authentication Tag   | AES-256-GCM authentication tag                        |
| 97     | N    | Ciphertext           | AES-256-GCM encrypted data (same length as plaintext) |

**Total size:** 97 + plaintext_length bytes

### Expected Sizes for CipherBox Fields

| Field                               | Plaintext Size | ECIES Ciphertext Size | Hex-Encoded Size |
| ----------------------------------- | -------------- | --------------------- | ---------------- |
| `encryptedRootFolderKey`            | 32 bytes       | 129 bytes             | 258 characters   |
| `encryptedRootIpnsPrivateKey`       | 64 bytes       | 161 bytes             | 322 characters   |
| Subfolder `folderKeyEncrypted`      | 32 bytes       | 129 bytes             | 258 characters   |
| Subfolder `ipnsPrivateKeyEncrypted` | 64 bytes       | 161 bytes             | 322 characters   |
| File `fileKeyEncrypted`             | 32 bytes       | 129 bytes             | 258 characters   |

### Decryption Pseudocode

```text
function ecies_decrypt(private_key, ciphertext):
    // 1. Parse ciphertext
    ephemeral_pk      = ciphertext[0:65]          // uncompressed secp256k1 point
    nonce             = ciphertext[65:81]          // 16-byte AES-GCM nonce
    tag               = ciphertext[81:97]          // 16-byte AES-GCM auth tag
    encrypted_data    = ciphertext[97:]            // N bytes

    // 2. ECDH key agreement
    ephemeral_pk_compressed = compress(ephemeral_pk)     // 33 bytes
    shared_point = ecdh(private_key, ephemeral_pk_compressed, uncompressed=true)  // 65 bytes

    // 3. HKDF key derivation
    ikm = concat(ephemeral_pk, shared_point)             // 65 + 65 = 130 bytes
    shared_key = hkdf_sha256(ikm, salt=empty, info=empty, length=32)

    // 4. AES-256-GCM decryption
    //    Note: tag must be appended to ciphertext for most APIs
    aes_input = concat(encrypted_data, tag)
    plaintext = aes_256_gcm_decrypt(shared_key, nonce, aes_input)

    return plaintext
```

---

## 5. Encrypted Folder Metadata Format

Folder metadata is stored on IPFS as a JSON object with the following structure:

### Encrypted Envelope

```json
{
  "iv": "<hex-encoded 12-byte IV>",
  "data": "<base64-encoded AES-GCM ciphertext>"
}
```

| Field  | Encoding | Description                                                     |
| ------ | -------- | --------------------------------------------------------------- |
| `iv`   | hex      | 12-byte (24 hex characters) AES-256-GCM initialization vector   |
| `data` | base64   | AES-256-GCM ciphertext with appended 16-byte authentication tag |

**Encoding note:** The `iv` field uses hex encoding. The `data` field uses standard base64 encoding (NOT base64url, NOT hex). This is an important distinction -- mixing up encodings will cause decryption failures.

### Decrypted Metadata Schema

After decrypting the `data` field with the folder's AES-256 key and the `iv`, the plaintext is a UTF-8 JSON string with the following structure:

```json
{
  "version": "v1",
  "children": [ ... ]
}
```

| Field      | Type   | Description                                                                  |
| ---------- | ------ | ---------------------------------------------------------------------------- |
| `version`  | string | Schema version: `"v1"` (inline file data) or `"v2"` (per-file IPNS pointers) |
| `children` | array  | Array of folder and file child entries                                       |

### Folder Child Entry

```json
{
  "type": "folder",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Documents",
  "ipnsName": "k51qzi5uqu5dg...",
  "ipnsPrivateKeyEncrypted": "04abcdef...hex...",
  "folderKeyEncrypted": "04abcdef...hex...",
  "createdAt": 1705268100000,
  "modifiedAt": 1705268100000
}
```

| Field                     | Type   | Encoding  | Description                                                            |
| ------------------------- | ------ | --------- | ---------------------------------------------------------------------- |
| `type`                    | string | -         | Always `"folder"`                                                      |
| `id`                      | string | UUID      | Unique identifier for this folder                                      |
| `name`                    | string | -         | Folder name (plaintext, since entire metadata blob is encrypted)       |
| `ipnsName`                | string | base32/36 | IPNS name for resolving this subfolder's metadata                      |
| `ipnsPrivateKeyEncrypted` | string | hex       | ECIES-encrypted 64-byte Ed25519 IPNS key (161 bytes / 322 hex chars)   |
| `folderKeyEncrypted`      | string | hex       | ECIES-encrypted 32-byte AES-256 folder key (129 bytes / 258 hex chars) |
| `createdAt`               | number | -         | Unix timestamp in milliseconds                                         |
| `modifiedAt`              | number | -         | Unix timestamp in milliseconds                                         |

### File Child Entry

```json
{
  "type": "file",
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "name": "photo.jpg",
  "cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
  "fileKeyEncrypted": "04abcdef...hex...",
  "fileIv": "aabbccdd11223344eeff5566",
  "encryptionMode": "GCM",
  "size": 2048576,
  "createdAt": 1705268100000,
  "modifiedAt": 1705268100000
}
```

| Field              | Type   | Encoding | Description                                                          |
| ------------------ | ------ | -------- | -------------------------------------------------------------------- |
| `type`             | string | -        | Always `"file"`                                                      |
| `id`               | string | UUID     | Unique identifier for this file                                      |
| `name`             | string | -        | File name (plaintext, since entire metadata blob is encrypted)       |
| `cid`              | string | CIDv1    | IPFS content identifier of the encrypted file                        |
| `fileKeyEncrypted` | string | hex      | ECIES-encrypted 32-byte AES-256 file key (129 bytes / 258 hex chars) |
| `fileIv`           | string | hex      | 12-byte IV used for file encryption (24 hex characters)              |
| `encryptionMode`   | string | -        | Always `"GCM"` for format version 1.0                                |
| `size`             | number | -        | Original unencrypted file size in bytes                              |
| `createdAt`        | number | -        | Unix timestamp in milliseconds                                       |
| `modifiedAt`       | number | -        | Unix timestamp in milliseconds                                       |

### v2 Folder Metadata Schema

Version `"v2"` folder metadata uses per-file IPNS records instead of embedding file data inline. The folder metadata contains slim `FilePointer` references that point to each file's own IPNS record.

```json
{
  "version": "v2",
  "children": [
    {
      "type": "folder",
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Documents",
      "ipnsName": "k51qzi5uqu5dg...",
      "ipnsPrivateKeyEncrypted": "04abcdef...hex...",
      "folderKeyEncrypted": "04abcdef...hex...",
      "createdAt": 1705268100000,
      "modifiedAt": 1705268100000
    },
    {
      "type": "file",
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "photo.jpg",
      "fileMetaIpnsName": "k51qzi5uqu5dj...",
      "createdAt": 1705268100000,
      "modifiedAt": 1705268100000
    }
  ]
}
```

**Folder entries** (`FolderEntry`) are identical between v1 and v2.

**File entries** in v2 use the `FilePointer` format:

| Field              | Type   | Encoding | Description                                                    |
| ------------------ | ------ | -------- | -------------------------------------------------------------- |
| `type`             | string | -        | Always `"file"`                                                |
| `id`               | string | UUID     | Unique file identifier (used in HKDF derivation)               |
| `name`             | string | -        | File name (plaintext, since entire metadata blob is encrypted) |
| `fileMetaIpnsName` | string | base36   | IPNS name of the file's own metadata record                    |
| `createdAt`        | number | -        | Unix timestamp in milliseconds                                 |
| `modifiedAt`       | number | -        | Unix timestamp in milliseconds                                 |

Note: v2 `FilePointer` does **not** contain `cid`, `fileKeyEncrypted`, `fileIv`, `encryptionMode`, or `size`. These are stored in the per-file metadata record.

### Per-File Metadata Schema (FileMetadata)

Each file's metadata is stored as its own IPNS record, encrypted with the parent folder's `folderKey` (AES-256-GCM, same encryption as folder metadata). The encrypted envelope uses the same format as folder metadata: `{ "iv": "hex", "data": "base64" }`.

After decryption, the plaintext is a UTF-8 JSON string:

```json
{
  "version": "v1",
  "cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
  "fileKeyEncrypted": "04abcdef...hex...",
  "fileIv": "aabbccdd11223344eeff5566",
  "size": 2048576,
  "mimeType": "image/jpeg",
  "encryptionMode": "GCM",
  "createdAt": 1705268100000,
  "modifiedAt": 1705268100000
}
```

| Field              | Type   | Encoding | Description                                                          |
| ------------------ | ------ | -------- | -------------------------------------------------------------------- |
| `version`          | string | -        | Always `"v1"` for the file metadata schema                           |
| `cid`              | string | CIDv1    | IPFS content identifier of the encrypted file                        |
| `fileKeyEncrypted` | string | hex      | ECIES-encrypted 32-byte AES-256 file key (129 bytes / 258 hex chars) |
| `fileIv`           | string | hex      | 12-byte IV used for file encryption (24 hex characters)              |
| `size`             | number | -        | Original unencrypted file size in bytes                              |
| `mimeType`         | string | -        | MIME type of the original file (e.g., `"image/jpeg"`)                |
| `encryptionMode`   | string | -        | `"GCM"` (default) or `"CTR"` for streaming encryption                |
| `createdAt`        | number | -        | Unix timestamp in milliseconds                                       |
| `modifiedAt`       | number | -        | Unix timestamp in milliseconds                                       |

**Encryption:** The `FileMetadata` JSON is encrypted with the parent folder's `folderKey` using AES-256-GCM, exactly like folder metadata. This means anyone who can read the folder can also read the file metadata (and thus decrypt the file).

**IPNS addressing:** Each file has its own IPNS record derived deterministically from the user's secp256k1 `privateKey` and the file's `id` using HKDF.

### HKDF File IPNS Key Derivation

The per-file IPNS keypair is derived deterministically, enabling recovery from the user's private key and the file's UUID alone.

```text
Derivation path:
  secp256k1 privateKey (32 bytes)
    -> HKDF-SHA256(salt, info)
    -> 32-byte Ed25519 seed
    -> Ed25519 keypair
    -> IPNS name (k51...)
```

| Parameter     | Value                                                       |
| ------------- | ----------------------------------------------------------- |
| Algorithm     | HKDF-SHA256 (Web Crypto API)                                |
| Input key     | User's 32-byte secp256k1 private key                        |
| Salt          | `CipherBox-v1` (UTF-8 encoded, 12 bytes)                    |
| Info          | `cipherbox-file-ipns-v1:<fileId>` (UTF-8 encoded)           |
| Output length | 32 bytes (Ed25519 seed)                                     |
| Ed25519       | Seed -> public key via `@noble/ed25519` `getPublicKeyAsync` |
| IPNS name     | CIDv1 with libp2p-key codec (0x72) + identity multihash     |

**Domain separation:** The `fileId` (UUID from the `FilePointer`) in the HKDF info string ensures each file gets a unique IPNS keypair. This uses the same salt (`CipherBox-v1`) as vault and device registry IPNS derivation, with a different info prefix (`cipherbox-file-ipns-v1:` vs `cipherbox-vault-ipns-v1` and `cipherbox-device-registry-ipns-v1`).

**IPNS record lifecycle:** File IPNS records have a 24-hour TTL and are republished by the TEE every 6 hours. If the TEE has been down and records have expired, the file content is still on IPFS but the CID is not discoverable via IPNS.

---

## 6. Recovery Procedure

This section describes how to recover all files from a vault export. The procedure requires:

1. The vault export JSON file
2. The user's 32-byte secp256k1 private key

### Step 1: Parse and Validate Export

```text
export = parse_json(file_contents)

assert export.format == "cipherbox-vault-export"
assert export.version == "1.0"
assert export.rootIpnsName is not empty
assert export.encryptedRootFolderKey is not empty
assert export.encryptedRootIpnsPrivateKey is not empty
```

### Step 2: Accept Private Key

The user's secp256k1 private key is 32 bytes. It may be provided as:

- 64-character hex string (with or without `0x` prefix)
- Base64-encoded string (~44 characters)

```text
private_key = parse_key_input(user_input)   // 32 bytes
assert length(private_key) == 32
```

### Step 3: Decrypt Root Keys

Use ECIES decryption (see [Section 3.1](#31-ecies-secp256k1----key-wrapping) and [Section 4](#4-ecies-ciphertext-binary-format)):

```text
root_folder_key = ecies_decrypt(private_key, hex_to_bytes(export.encryptedRootFolderKey))
// root_folder_key is 32 bytes (AES-256 key)

root_ipns_private_key = ecies_decrypt(private_key, hex_to_bytes(export.encryptedRootIpnsPrivateKey))
// root_ipns_private_key is 64 bytes (Ed25519 libp2p format: seed || public_key)
```

### Step 4: Resolve Root IPNS Name

Resolve the root IPNS name to get the CID of the root folder's encrypted metadata.

**Method A: Delegated Routing API** (recommended)

```text
GET https://delegated-ipfs.dev/routing/v1/ipns/{rootIpnsName}
Accept: application/vnd.ipfs.ipns-record

// Response is a binary IPNS record (protobuf-encoded)
// Parse protobuf field 2 (Value) to extract the IPFS path: "/ipfs/{CID}"
```

Method B -- Kubo-compatible Gateway API:

```text
POST https://ipfs.io/api/v0/name/resolve?arg={rootIpnsName}

// Response: { "Path": "/ipfs/{CID}" }
```

Method C -- Any IPFS gateway that supports IPNS resolution can be used. The CID extracted from the response points to the encrypted folder metadata on IPFS.

### Step 5: Fetch and Decrypt Root Metadata

```text
// Fetch encrypted metadata from IPFS
encrypted_metadata_bytes = http_get("https://ipfs.io/ipfs/{CID}")

// Parse as JSON
encrypted_metadata = parse_json(encrypted_metadata_bytes)
// encrypted_metadata = { "iv": "hex...", "data": "base64..." }

// Decrypt
iv = hex_to_bytes(encrypted_metadata.iv)                  // 12 bytes
ciphertext = base64_to_bytes(encrypted_metadata.data)     // includes 16-byte auth tag
plaintext = aes_256_gcm_decrypt(root_folder_key, iv, ciphertext)

// Parse decrypted metadata
metadata = parse_json(plaintext)
// metadata = { "version": "v1" | "v2", "children": [...] }
// Check metadata.version to determine child processing strategy
```

### Step 6: Recursively Process Children

For each child in `metadata.children`:

**If child is a folder:**

```text
// 1. ECIES-decrypt the subfolder's keys
subfolder_key = ecies_decrypt(private_key, hex_to_bytes(child.folderKeyEncrypted))
// subfolder_key is 32 bytes

// 2. IPNS private key can be decrypted but is not needed for recovery
//    (only needed for publishing, not reading)
// subfolder_ipns_key = ecies_decrypt(private_key, hex_to_bytes(child.ipnsPrivateKeyEncrypted))

// 3. Resolve subfolder IPNS name -> CID
subfolder_cid = resolve_ipns(child.ipnsName)

// 4. Fetch and decrypt subfolder metadata (same as Step 5)
// 5. Recursively process subfolder's children (this step)
```

**If child is a file (v1 -- inline file data):**

```text
// v1 folder metadata: file data embedded directly in the child entry
// 1. ECIES-decrypt the file key
file_key = ecies_decrypt(private_key, hex_to_bytes(child.fileKeyEncrypted))
// file_key is 32 bytes

// 2. Fetch encrypted file from IPFS
encrypted_file = http_get("https://ipfs.io/ipfs/{child.cid}")

// 3. Decrypt file content
iv = hex_to_bytes(child.fileIv)    // 12 bytes
decrypted_file = aes_256_gcm_decrypt(file_key, iv, encrypted_file)

// 4. Save decrypted_file with name child.name
//    Preserve folder path from recursive traversal
```

**If child is a file (v2 -- FilePointer with per-file IPNS):**

```text
// v2 folder metadata: child has fileMetaIpnsName instead of inline cid/key/iv
// 1. Resolve file IPNS name -> file metadata CID
file_meta_cid = resolve_ipns(child.fileMetaIpnsName)

// 2. Fetch and decrypt file metadata (same format as folder metadata)
encrypted_file_meta = fetch_from_ipfs(file_meta_cid)
file_meta = aes_256_gcm_decrypt(folder_key, encrypted_file_meta)
// file_meta = { "version": "v1", "cid": "...", "fileKeyEncrypted": "...",
//               "fileIv": "...", "size": N, "mimeType": "...", ... }

// 3. ECIES-decrypt the file key from file metadata
file_key = ecies_decrypt(private_key, hex_to_bytes(file_meta.fileKeyEncrypted))

// 4. Fetch encrypted file from IPFS
encrypted_file = fetch_from_ipfs(file_meta.cid)

// 5. Decrypt file content
iv = hex_to_bytes(file_meta.fileIv)
decrypted_file = aes_256_gcm_decrypt(file_key, iv, encrypted_file)

// 6. Save decrypted_file with name child.name
//    If IPNS resolution fails (expired record), log warning and continue
```

**Note:** In v2, if the file IPNS record has expired (e.g., TEE was down for >24 hours), the file content CID is not discoverable. The file is still on IPFS but cannot be located without the CID from another source. Recovery tools should warn about these failures but continue recovering other files.

### Step 7: Assemble Output

Collect all decrypted files with their full paths (folder hierarchy preserved) and either:

- Save individual files to a directory structure
- Create a zip archive with the folder hierarchy

### Complete Recovery Pseudocode

```text
function recover_vault(export_json, private_key):
    export = parse_and_validate(export_json)

    root_folder_key = ecies_decrypt(private_key, hex_to_bytes(export.encryptedRootFolderKey))
    root_ipns_key = ecies_decrypt(private_key, hex_to_bytes(export.encryptedRootIpnsPrivateKey))

    files = []
    recover_folder(export.rootIpnsName, root_folder_key, private_key, "", files)
    return files

function recover_folder(ipns_name, folder_key, private_key, path, files):
    cid = resolve_ipns(ipns_name)
    encrypted_meta = fetch_from_ipfs(cid)
    metadata = decrypt_folder_metadata(encrypted_meta, folder_key)
    is_v2 = (metadata.version == "v2")

    for child in metadata.children:
        if child.type == "folder":
            sub_key = ecies_decrypt(private_key, hex_to_bytes(child.folderKeyEncrypted))
            sub_path = path + "/" + child.name if path else child.name
            recover_folder(child.ipnsName, sub_key, private_key, sub_path, files)

        else if child.type == "file" and is_v2 and child.fileMetaIpnsName:
            // v2 FilePointer: resolve per-file IPNS record
            try:
                file_meta_cid = resolve_ipns(child.fileMetaIpnsName)
                enc_file_meta = fetch_from_ipfs(file_meta_cid)
                file_meta = decrypt_file_metadata(enc_file_meta, folder_key)
                file_key = ecies_decrypt(private_key, hex_to_bytes(file_meta.fileKeyEncrypted))
                encrypted_file = fetch_from_ipfs(file_meta.cid)
                iv = hex_to_bytes(file_meta.fileIv)
                decrypted = aes_256_gcm_decrypt(file_key, iv, encrypted_file)
                file_path = path + "/" + child.name if path else child.name
                files.append({ path: file_path, data: decrypted })
            catch ipns_error:
                warn("File IPNS expired: " + child.name)
                continue  // don't block other files

        else if child.type == "file":
            // v1 inline file entry
            file_key = ecies_decrypt(private_key, hex_to_bytes(child.fileKeyEncrypted))
            encrypted_file = fetch_from_ipfs(child.cid)
            iv = hex_to_bytes(child.fileIv)
            decrypted = aes_256_gcm_decrypt(file_key, iv, encrypted_file)
            file_path = path + "/" + child.name if path else child.name
            files.append({ path: file_path, data: decrypted })
```

---

## 7. Test Vectors

The following test vectors are generated using `@cipherbox/crypto` (the same library CipherBox uses in production) and can be independently verified.

### 7.1 ECIES Test Vector

```text
Private Key (hex):
  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

Public Key (uncompressed, hex):
  (derived from private key via secp256k1)

Plaintext (32-byte folder key, hex):
  aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd

Encrypted (hex):
  (produced by eciesjs@0.4.16 encrypt)
  Length: 258 hex characters (129 bytes)
```

> **Note:** ECIES encryption is non-deterministic (uses a random ephemeral key per encryption). The encrypted output will differ on each run. To verify: decrypt the test vector's encrypted output with the private key and confirm the result matches the plaintext.

### 7.2 AES-256-GCM Folder Metadata Test Vector

```text
Folder Key (hex):
  (32 random bytes)

IV (hex):
  (12 random bytes)

Plaintext JSON:
  {"version":"v1","children":[{"type":"file","id":"test-file-001","name":"hello.txt","cid":"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi","fileKeyEncrypted":"(hex)","fileIv":"(hex)","encryptionMode":"GCM","size":13,"createdAt":1705268100000,"modifiedAt":1705268100000}]}

Encrypted output:
  iv: (24 hex chars)
  data: (base64 string)
```

> **Note:** Concrete values for this test vector are generated by running `scripts/generate-test-vectors.ts`. See that script for reproducible output.

### 7.3 Sample Export JSON

```json
{
  "format": "cipherbox-vault-export",
  "version": "1.0",
  "exportedAt": "2026-02-11T00:00:00.000Z",
  "rootIpnsName": "k51qzi5uqu5dg05y48rp46k4yq2tse4ufqfhn6w4i6js3t456ss9dkk",
  "encryptedRootFolderKey": "(258 hex characters)",
  "encryptedRootIpnsPrivateKey": "(322 hex characters)",
  "derivationInfo": {
    "method": "web3auth",
    "derivationVersion": null
  }
}
```

> **Note:** The `rootIpnsName` in the sample is illustrative. In a real export, this would be a valid libp2p-key multihash derived from the root folder's Ed25519 public key.

---

## 8. Security Considerations

### 8.1 Export File Alone Is Insufficient

The vault export file does **not** contain the user's private key. Without the private key, the ECIES-encrypted root keys cannot be decrypted, and no files can be recovered. The export is safe to store in locations with moderate trust (cloud storage, email attachment) as long as the private key is stored separately and securely.

### 8.2 Private Key Never in Export

The export deliberately excludes the user's secp256k1 private key. This separation ensures that compromise of the export file alone does not compromise the vault.

### 8.3 ECIES IND-CCA2 Security

ECIES with HKDF-SHA256 and AES-256-GCM provides IND-CCA2 (indistinguishability under adaptive chosen-ciphertext attack) security. This means:

- An attacker cannot learn the plaintext from the ciphertext without the private key
- An attacker cannot forge valid ciphertexts
- Each encryption produces different output (fresh ephemeral key)

### 8.4 Memory Handling in Recovery Tools

Recovery tools should clear sensitive key material from memory after use:

- The private key bytes
- The decrypted root folder key
- The decrypted root IPNS private key
- Individual file keys after decrypting each file

In JavaScript: overwrite `Uint8Array` contents with zeros using `array.fill(0)`.

### 8.5 AES-GCM IV Uniqueness

Each AES-256-GCM encryption in CipherBox uses a randomly generated IV. The IV does not need to be secret but must never be reused with the same key. For recovery (decryption only), this is not a concern -- IVs are stored alongside their ciphertexts.

### 8.6 Transport Security

The vault export download should occur over HTTPS. The recovery tool itself can run locally (saved HTML file) without network access during the key decryption phase. Network access is only needed for IPNS resolution and IPFS content fetching, which retrieve only encrypted data.

---

## 9. Compatibility Notes

### 9.1 Format Versioning

The `version` field in the export JSON indicates the export format version. Version `"1.0"` corresponds to:

- eciesjs v0.4.16 ECIES binary format
- AES-256-GCM with 12-byte IV for folder metadata and file content
- Ed25519 IPNS keys in 64-byte libp2p format
- Folder metadata schema version `"v1"` or `"v2"`

The vault export JSON structure itself does **not** change between v1 and v2 folder metadata (still export version `"1.0"`). The recovery procedure detects v2 vaults by checking `FolderMetadata.version === 'v2'` after decrypting each folder's metadata.

If the ECIES binary format changes (e.g., eciesjs library upgrade changes nonce size or byte layout), the export version field would increment. Recovery tools should check the version field and reject unsupported versions with a clear error message.

### 9.2 ECIES Library Compatibility

The ECIES format is specific to eciesjs v0.4.16 defaults:

- 16-byte AES-GCM nonce (non-standard)
- Uncompressed ephemeral public key
- HKDF-SHA256 with no salt and no info
- Authentication tag stored separately (nonce || tag || ciphertext), not appended to ciphertext

Other ECIES implementations (e.g., Go's ecies package, Python's eciespy) use different formats and are **not compatible**. A recovery tool in another language must reimplement the exact eciesjs algorithm using the underlying primitives (secp256k1 ECDH, HKDF-SHA256, AES-256-GCM with 16-byte nonce).

### 9.3 IPNS Record Format

IPNS records use Ed25519 V1+V2 compatible signatures. Records are protobuf-encoded with the following relevant fields:

- Field 2 (Value): The IPFS path (e.g., `/ipfs/bafybeig...`)
- Field 3 (SignatureV1): Legacy signature
- Field 6 (Data): CBOR-encoded data containing TTL, Value, Sequence, Validity, ValidityType

For recovery, only the Value field is needed to extract the CID. The delegated routing API returns the record in binary protobuf format.

### 9.4 IPFS Gateway Compatibility

Any IPFS gateway can serve the encrypted content. The recovery tool should support configurable gateway URLs. Well-known public gateways:

| Gateway            | Type              | URL Pattern                                     |
| ------------------ | ----------------- | ----------------------------------------------- |
| delegated-ipfs.dev | Delegated routing | `GET /routing/v1/ipns/{name}`                   |
| ipfs.io            | Full gateway      | `GET /ipfs/{cid}`, `POST /api/v0/name/resolve`  |
| dweb.link          | Full gateway      | `GET /ipfs/{cid}`                               |
| Any Kubo node      | Local/self-hosted | `POST /api/v0/name/resolve`, `POST /api/v0/cat` |

---

_Specification version: 1.0_
_Document generated: 2026-02-11_
_Reference implementation: `apps/web/public/recovery.html`_
_Crypto library: `packages/crypto/` using eciesjs@0.4.16_

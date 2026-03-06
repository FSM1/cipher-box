# Architecture

CipherBox implements layered, zero-knowledge encryption where **all user data is encrypted client-side before leaving the device**. The server and storage layer never see plaintext — not file contents, not file names, not folder names, not timestamps, not plaintext file sizes (encrypted blob sizes are visible for storage accounting).

## System Overview

```text
User Device (Web/Desktop)
        ↓ Auth (4 methods)
CipherBox Backend (JWT)
        ↓
Web3Auth Network (Key Derivation)
        ↓ ECDSA Private Key (RAM only!)
User Device ← Vault Data ← PostgreSQL
        ↓ Encrypted Keys
IPFS (Kubo) ← Encrypted Files
        ↑
TEE (Phala; Nitro fallback planned) ← IPNS Republish (every 6h)
```

**Key Properties:**

- Same user identity → same keypair → same vault (auth methods share a vault when they resolve to the same CipherBox `userId`; see [Authentication Architecture](AUTHENTICATION_ARCHITECTURE.md))
- TEE republishes IPNS records even when all devices are offline

## Key Derivation

Two paths produce the same `VaultKey` (a secp256k1 keypair):

```text
┌─────────────────────────────────────────────────────────────────────┐
│                       KEY DERIVATION                                │
├─────────────────────────┬───────────────────────────────────────────┤
│  Web3Auth (Social Login)│  Web3Auth (External Wallet via SIWE)     │
│                         │                                           │
│  Google/Email/etc.      │  1. Wallet signs SIWE (EIP-4361) message │
│        ↓                │  2. Backend verifies SIWE, issues JWT    │
│  Web3Auth Network       │  3. Web3Auth Core Kit validates JWT      │
│        ↓                │  4. Web3Auth Network                     │
│  secp256k1 keypair      │        ↓                                  │
│  (deterministic)        │  secp256k1 keypair (deterministic)       │
│                         │                                           │
│                         │                                           │
├─────────────────────────┴───────────────────────────────────────────┤
│                              ↓                                      │
│                   VaultKey (secp256k1)                               │
│          ┌─────────────────────────────────────┐                    │
│          │ Private Key: 32 bytes (RAM only!)   │                    │
│          │ Public Key:  65 bytes (uncompressed) │                   │
│          └─────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Encryption Hierarchy

Keys below the VaultKey are either **randomly generated** or **HKDF-derived**, then **ECIES-wrapped** with the user's public key. IPNS keypairs (vault, device-registry, per-file) are derived deterministically via HKDF-SHA256 from the user's private key (see [Cryptographic Primitives](#cryptographic-primitives)). Content encryption keys (rootFolderKey, per-folder keys, per-file keys) are randomly generated. Compromising one file key reveals nothing about other file keys.

```text
    VaultKey (secp256k1 keypair)
    │
    │  ECIES-unwrap
    ├──────────────────────────────────────────┐
    │                                          │
    ▼                                          ▼
 rootFolderKey (random 32B)          rootIpnsPrivateKey (Ed25519, HKDF-derived)
    │                                          │
    │  AES-256-GCM decrypt                     │  Signs IPNS records
    ▼                                          ▼
 Root Folder Metadata (encrypted JSON)     IPNS publish/resolve
    │
    │  Contains per-child entries:
    │
    ├── File Pointer Entries ────────────────────────────────────────────┐
    │     name (encrypted)           ◄── only visible after              │
    │     timestamps (encrypted)         decrypting metadata             │
    │     fileMetaIpnsName (k51...)  ─────────────────────────────────────┤
    │          │                                                        │
    │          ▼                                                        │
    │     File Metadata (per-file IPNS record, encrypted JSON)          │
    │         fileKeyEncrypted ─ ECIES-unwrap ──► fileKey (32B)         │
    │         fileIv (12B)                             │                │
    │         cid (IPFS ref)          AES-256-GCM decrypt               │
    │                                                    ▼              │
    │                                             File Contents          │
    │                                                                   │
    ├── Subfolder Entries ──────────────────────────────────────────────┤
    │     name (encrypted)        ◄── only visible after                │
    │     timestamps (encrypted)      decrypting metadata               │
    │     folderKeyEncrypted ── ECIES-unwrap ──► folderKey              │
    │     ipnsPrivateKeyEncrypted ─ ECIES-unwrap ► ipnsKey              │
    │     ipnsName (k51...)                                             │
    │          │                                                        │
    │          ▼                                                        │
    │     Subfolder Metadata (same structure, recursive)                │
    └───────────────────────────────────────────────────────────────────┘
```

## Visibility Model

```text
┌─────────────────────────────────────────────────────────────────┐
│                    FULLY ENCRYPTED                               │
│   (requires user's private key + folder key to access)          │
│                                                                  │
│   ✓ File contents              ✓ File names                     │
│   ✓ Folder names               ✓ Folder structure / child list  │
│   ✓ File sizes                 ✓ Creation timestamps            │
│   ✓ Modification timestamps    ✓ All encryption keys            │
│   ✓ IPNS private keys          ✓ File-to-folder relationships   │
├─────────────────────────────────────────────────────────────────┤
│                    VISIBLE (Plaintext)                           │
│   (required for IPFS/IPNS protocol operation)                   │
│                                                                  │
│   • IPFS CIDs (content-addressed hashes, no semantic meaning)  │
│   • IPNS names (k51... public identifiers for folders)         │
│   • Encrypted blob sizes (approximate original sizes)          │
│   • Encryption IVs (required for decryption, not secret)       │
│   • User's secp256k1 public key                                │
├─────────────────────────────────────────────────────────────────┤
│                    NEVER STORED (RAM Only)                       │
│                                                                  │
│   • User's private key          • Decrypted file names          │
│   • Decrypted folder metadata   • Decrypted file contents       │
│   • Plaintext file/folder keys  • Wallet signatures             │
└─────────────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

| Purpose                             | Algorithm                  | Parameters                               |
| :---------------------------------- | :------------------------- | :--------------------------------------- |
| File & metadata encryption          | AES-256-GCM                | 256-bit key, 96-bit IV, 128-bit auth tag |
| Key wrapping                        | ECIES (secp256k1)          | Ephemeral keypair + AES-GCM              |
| Deterministic key derivation (IPNS) | HKDF-SHA256                | 32-byte output, context-specific salt    |
| IPNS record signing                 | Ed25519                    | 32-byte seed, 64-byte signatures         |
| Random generation                   | `crypto.getRandomValues()` | CSPRNG (Web Crypto API)                  |

## Data Flows

### File Upload

```text
  ┌──────────────────────────────────────────────────────────────┐
  │                    FILE UPLOAD FLOW                           │
  │                                                              │
  │  1. User selects "document.pdf"                              │
  │         │                                                    │
  │         ▼                                                    │
  │  2. Generate random fileKey (32 bytes)                       │
  │     Generate random IV (12 bytes)                            │
  │         │                                                    │
  │         ▼                                                    │
  │  3. AES-256-GCM encrypt(plaintext, fileKey, IV)              │
  │     → ciphertext ‖ auth_tag (16 bytes)                       │
  │         │                                                    │
  │         ▼                                                    │
  │  4. ECIES wrap(fileKey, userPublicKey)                        │
  │     → ephemeral_pubkey ‖ wrapped_key ‖ tag                   │
  │         │                                                    │
  │         ▼                                                    │
  │  5. Clear plaintext fileKey from memory                      │
  │         │                                                    │
  │         ▼                                                    │
  │  6. Upload encrypted blob → IPFS (Kubo) → returns CID     │
  │         │                                                    │
  │         ▼                                                    │
  │  7. Create per-file FileMetadata entry (own IPNS record):    │
  │       { cid, fileKeyEncrypted, fileIv, size, ... }           │
  │         │                                                    │
  │         ▼                                                    │
  │  8. Add FilePointer to folder metadata children:             │
  │       { type: "file", nameEncrypted, nameIv,                 │
  │         fileMetaIpnsName, ipnsPrivateKeyEncrypted? }         │
  │         │                                                    │
  │         ▼                                                    │
  │  9. Re-encrypt folder metadata with folderKey (AES-256-GCM)  │
  │         │                                                    │
  │         ▼                                                    │
  │ 10. Upload encrypted metadata → IPFS → new CID              │
  │         │                                                    │
  │         ▼                                                    │
  │ 11. Publish IPNS record: /ipns/k51... → /ipfs/<new CID>     │
  │     (signed with folder's Ed25519 private key)               │
  └──────────────────────────────────────────────────────────────┘
```

## Defense in Depth

Each file key is protected by multiple nested layers. An attacker must break through all layers to access any file content:

```text
   File Content
     └─ encrypted with ──► fileKey (random, unique per file)
         └─ ECIES-wrapped with ──► User's Public Key
             └─ stored inside ──► Folder Metadata
                 └─ encrypted with ──► folderKey (random, unique per folder)
                     └─ ECIES-wrapped with ──► User's Public Key
                         └─ stored on ──► Server (zero-knowledge)
```

## Threat Model

With full access to IPFS and the CipherBox server but without the user's private key:

```text
  IPFS (public network):

    /ipfs/bafybei3a7x...   ← encrypted blob (file? folder? unknown)
    /ipfs/bafybei9f2k...   ← encrypted blob (file? folder? unknown)
    /ipfs/bafybeiqw8m...   ← encrypted blob (file? folder? unknown)

  Without the user's private key:
    ✗ Cannot read file contents
    ✗ Cannot read file or folder names
    ✗ Cannot determine folder structure
    ✗ Cannot read timestamps or file sizes
    ✗ Cannot determine which blobs are files vs. folders
    ✓ Can see encrypted blob sizes (approximates original size)
    ✓ Can see IPNS update frequency (usage pattern)
```

## Key Design Decisions

### 1. Web3Auth for Key Derivation

```text
Any auth method → CipherBox backend resolves userId → Web3Auth → Same ECDSA keypair
```

### 2. Layered Encryption

```text
File (AES-256-GCM) → Metadata (AES-256-GCM) → Keys (ECIES)
```

### 3. Per-Folder IPNS

```text
Root IPNS → Folder1 IPNS → Folder2 IPNS (modular sharing-ready)
```

### 4. IPNS Polling Sync

```text
30s polling, no push infrastructure (MVP simple)
```

### 5. Zero-Knowledge Keys

```text
Server holds: Encrypted root key only
Client holds: Private key (RAM only)
```

### 6. TEE-Based IPNS Republishing

```text
IPNS records expire after ~24h → backend scheduler triggers republish every 6h
Client encrypts ipnsPrivateKey with TEE public key (ECIES)
TEE decrypts in hardware, signs, zeroes key immediately
Providers: Phala Cloud (current) / AWS Nitro (planned fallback)
```

## User Journey Example

```text
1. Signup (Google) → Web3Auth derives KeyA
2. Upload file → Encrypt → IPFS CID → IPNS publish
3. Phone login (Email) → Web3Auth derives KeyA (same!)
4. Phone polls IPNS → Sees file → Downloads & decrypts
5. Export vault → JSON with CIDs + encrypted root key
6. CipherBox gone? → Use export + private key → Full recovery
```

## Further Reading

- [Frozen Specifications](../00-Preliminary-R&D/Documentation/) — PRD, Technical Architecture, API Specification, Data Flows, Client Specification
- [Authentication Architecture](AUTHENTICATION_ARCHITECTURE.md) — detailed auth flow documentation
- [Metadata Schemas](METADATA_SCHEMAS.md) — all metadata object schemas with field tables
- [Vault Export Format](VAULT_EXPORT_FORMAT.md) — export/recovery data format

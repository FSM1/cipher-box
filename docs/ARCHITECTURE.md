<!-- generated-by: gsd-doc-writer -->

# Architecture

CipherBox implements layered, zero-knowledge encryption where **all user data is encrypted
client-side before leaving the device**. The server and storage layer never see plaintext —
not file contents, not file names, not folder names, not timestamps, not plaintext file sizes
(encrypted blob sizes are visible for storage accounting).

## System Overview

```text
User Device (Web / Desktop)
        |
        | Web3Auth key derivation (secp256k1)
        v
CipherBox API  (NestJS, JWT auth)
        |                           |
        v                           v
PostgreSQL                       Kubo (IPFS)
(users, vaults,                  (encrypted blobs
 IPNS schedules,                  pinned by CID)
 device approvals,                     |
 share metadata)                       v
        |                       IPNS (folder metadata,
        |                        per-file metadata,
        |                        device registry)
        v
TEE Worker (Phala Cloud CVM)
  IPNS republish every 6 hours
  even when all devices are offline
```

**Key properties:**

- All encryption and decryption is performed on the client. The server is zero-knowledge.
- The same Web3Auth-derived keypair is always produced for a given identity, so the same vault
  is accessible from any device.
- The TEE republishes IPNS records on a fixed schedule so vault metadata remains resolvable
  even when all user devices are offline.

## Component Map

```text
apps/
  api          NestJS backend — auth, vault registry, IPFS relay,
                 IPNS relay, TEE coordination, sharing, device approval
  web          React + Vite browser client — full vault UI,
                 Zustand stores, Web Crypto worker
  desktop      Tauri + Rust — macOS/Linux FUSE mount, Windows WinFsp
                 (feature-gated in crates/fuse), native keychain, system tray
  tee-worker   Express HTTP service — runs in Phala Cloud CVM,
                 IPNS key decryption and batch signing

packages/
  crypto       Pure crypto primitives: AES-256-GCM/CTR, ECIES,
                 Ed25519, HKDF-SHA256, key generation utilities
  core         Domain types and metadata: folder/file/bin metadata
                 encrypt/decrypt, vault init, IPNS record construction,
                 device registry, BYO-IPFS config
  sdk-core     Stateless operations: upload, download, IPFS/IPNS calls,
                 folder CRUD, pinning providers (Kubo, PSA, Pinata, dual)
  sdk          Stateful CipherBoxClient with Zustand-compatible events,
                 folder state cache, share and bin operations
  api-client   Generated OpenAPI client (@cipherbox/api-client)

crates/
  crypto       Rust crypto mirrors (used by desktop Tauri backend)
  core         Rust domain mirrors
  fuse         FUSE filesystem crate; depends on fuser 0.16 (vendored patched source at apps/desktop/src-tauri/vendor/fuser/)
  sdk          Rust SDK for desktop native operations
  api-client   Rust API client
```

## Key Derivation

Two paths produce the same VaultKey (a secp256k1 keypair):

```text
┌─────────────────────────────────┬──────────────────────────────────────────────┐
│  Web3Auth (Social Login)        │  Web3Auth (External Wallet via SIWE)         │
│                                 │                                              │
│  Google / Email / Passkey       │  1. Wallet signs EIP-4361 SIWE message       │
│           |                     │  2. CipherBox backend verifies SIWE,         │
│           v                     │     issues JWT                               │
│  Web3Auth Network               │  3. Web3Auth Core Kit validates JWT          │
│  (threshold key derivation)     │  4. Web3Auth Network                         │
│           |                     │           |                                  │
│           v                     │           v                                  │
│  secp256k1 keypair              │  secp256k1 keypair (deterministic)           │
│  (deterministic)                │                                              │
└─────────────────────────────────┴──────────────────────────────────────────────┘
                                  |
                                  v
                     VaultKey (secp256k1)
              ┌───────────────────────────────────┐
              │  privateKey: 32 bytes (RAM only!)  │
              │  publicKey:  65 bytes (0x04 prefix)│
              └───────────────────────────────────┘
```

The VaultKey `publicKey` is stored as the user's primary identifier in the `users` table.
The `privateKey` never leaves RAM and is never sent to the server. See
[Authentication Architecture](AUTHENTICATION_ARCHITECTURE.md) for full auth flow detail.

## Encryption Hierarchy

Content encryption keys (`rootFolderKey`, per-folder `folderKey`, per-file `fileKey`) are
randomly generated. IPNS keypairs are deterministically derived via HKDF-SHA256 from the
user's `privateKey`. All keys that must be stored are ECIES-wrapped with the user's
`publicKey`. Compromising one `fileKey` reveals nothing about sibling keys.

```text
VaultKey (secp256k1)
    |
    |  ECIES-unwrap (client only)
    |
    +----> rootFolderKey (random 32B, AES-256-GCM)
    |          |
    |          v
    |      Root Folder Metadata (encrypted JSON)
    |          |
    |          +----> FilePointer entries
    |          |          nameEncrypted, timestamps (encrypted)
    |          |          fileMetaIpnsName  --> per-file IPNS record
    |          |                                    fileKey (ECIES-wrapped)
    |          |                                    cid (IPFS blob ref)
    |          |
    |          +----> Subfolder entries
    |                     nameEncrypted, timestamps (encrypted)
    |                     folderKey (ECIES-wrapped)
    |                     encryptedIpnsPrivateKey (ECIES-wrapped)
    |                     ipnsName (k51..., public)
    |
    +----> rootIpnsKeypair (Ed25519, HKDF-derived)
               |
               v
           Signs root folder IPNS records
```

The `encryptedIpnsPrivateKey` for each folder is stored in both the folder's parent metadata
(for client-side re-publish) and in `ipns_republish_schedule` (so the TEE can republish
on schedule without decrypting folder contents).

## Visibility Model

```text
┌──────────────────────────────────────────────────────────────┐
│                    FULLY ENCRYPTED                            │
│  (requires privateKey + folderKey to access)                 │
│                                                              │
│  File contents          File names                           │
│  Folder names           Folder structure / child list        │
│  File sizes             Creation and modification timestamps │
│  All encryption keys    IPNS private keys                    │
│  File-to-folder relationships                                │
├──────────────────────────────────────────────────────────────┤
│                    VISIBLE (plaintext)                        │
│  (required for IPFS/IPNS protocol operation)                 │
│                                                              │
│  IPFS CIDs (content-addressed hashes, no semantic meaning)  │
│  IPNS names (k51... public identifiers)                      │
│  Encrypted blob sizes (approximate original sizes)          │
│  Encryption IVs (required for decryption, not secret)       │
│  User's secp256k1 publicKey                                  │
├──────────────────────────────────────────────────────────────┤
│                    NEVER STORED (RAM only)                    │
│                                                              │
│  privateKey              Decrypted file names                │
│  Decrypted folder metadata  Decrypted file contents          │
│  Plaintext file/folder keys  Wallet signatures               │
└──────────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

| Purpose                           | Algorithm                  | Parameters                               |
| :-------------------------------- | :------------------------- | :--------------------------------------- |
| File and metadata encryption      | AES-256-GCM                | 256-bit key, 96-bit IV, 128-bit auth tag |
| Random-access media decryption    | AES-256-CTR                | 256-bit key, 128-bit IV, 64-bit nonce    |
| Key wrapping                      | ECIES (secp256k1)          | Ephemeral keypair + AES-GCM              |
| Deterministic IPNS key derivation | HKDF-SHA256                | 32-byte output, context-specific salt    |
| IPNS record signing               | Ed25519                    | 32-byte seed, 64-byte signatures         |
| Random generation                 | `crypto.getRandomValues()` | CSPRNG (Web Crypto API)                  |

All browser-side crypto uses the Web Crypto API or audited libraries (`@noble/*`, `eciesjs`).
Desktop Rust mirrors use `aes-gcm`, `ecies`, and `ed25519-dalek`. Error messages are kept generic to prevent
oracle attacks. See `packages/crypto/src/` for the canonical implementations.

## Data Flows

### File Upload

```text
1. Generate random fileKey (32 bytes) and IV (12 bytes)
2. AES-256-GCM encrypt(plaintext, fileKey, IV) → ciphertext || auth_tag
3. ECIES wrap(fileKey, publicKey) → encryptedFileKey
4. Clear plaintext fileKey from memory
5. Upload ciphertext to IPFS via CipherBox API relay → returns CID
6. Create per-file FileMetadata: { cid, encryptedFileKey, fileIv, size, ... }
7. Publish FileMetadata as a new IPNS record (per-file ipnsName)
8. Add FilePointer to parent folder metadata children:
     { type: "file", nameEncrypted, nameIv, fileMetaIpnsName }
9. Re-encrypt folder metadata with folderKey (AES-256-GCM)
10. Upload encrypted metadata to IPFS → new CID
11. Publish IPNS record: /ipns/k51... → /ipfs/<newCID>
    signed with folder's Ed25519 ipnsPrivateKey
```

### File Download

```text
1. Resolve IPNS record for the target folder → CID
2. Fetch encrypted folder metadata blob from IPFS
3. Decrypt folder metadata with folderKey (AES-256-GCM)
4. Locate the target FilePointer; resolve its fileMetaIpnsName → CID
5. Fetch encrypted FileMetadata blob from IPFS
6. Decrypt FileMetadata; extract encryptedFileKey and cid
7. ECIES unwrap(encryptedFileKey, privateKey) → fileKey
8. Fetch encrypted file blob from IPFS using cid
9. AES-256-GCM decrypt(ciphertext, fileKey, fileIv) → plaintext
10. Clear fileKey from memory
```

### TEE IPNS Republish (every 6 hours)

```text
CipherBox API (RepublishService)
    |
    | Reads ipns_republish_schedule rows where next_republish_at <= now
    |   Each row contains:
    |     ipnsName, encryptedIpnsPrivateKey, keyEpoch, latestCid, sequenceNumber
    |
    v
TEE Worker (POST /republish)
    |
    | For each entry:
    |   1. Decrypt encryptedIpnsPrivateKey with epoch-derived TEE key (RAM only)
    |   2. Build IPNS record pointing to latestCid
    |   3. Sign with decrypted Ed25519 ipnsPrivateKey
    |   4. Discard ipnsPrivateKey immediately
    |   5. If keyEpoch < currentEpoch, re-encrypt with currentEpoch TEE key
    |      → returns upgradedEncryptedKey and upgradedKeyEpoch
    |
    v
CipherBox API
    | Receives signed IPNS records
    | Publishes each via Kubo delegated routing
    | Updates schedule rows: next_republish_at += 6h
    | Persists any upgraded key epochs to ipns_republish_schedule
```

The TEE worker runs as an isolated Express service inside a Phala Cloud CVM. It never
writes to a database; all state flows through the API. In staging the TEE runs in Docker
simulator mode. See [tee-worker/src/index.ts](../apps/tee-worker/src/index.ts) for the
route listing.

### TEE Key Rotation and keyEpoch Grace Period

The TEE derives its per-epoch secp256k1 keypair from a root secret inside the CVM. When a
new `teePublicKey` is registered (epoch N+1), the previous epoch (N) enters a 4-week grace
period. During this period the API accepts `encryptedIpnsPrivateKey` values encrypted with
either epoch. At each republish cycle the TEE automatically re-encrypts epoch-N keys to
epoch-(N+1) (the `upgradedEncryptedKey` field). After the grace period ends, the previous
epoch key is deprecated.

Key epoch state is tracked in the `tee_key_state` table (columns `current_epoch`,
`previous_epoch`, `grace_period_ends_at`). See `apps/api/src/tee/tee-key-state.entity.ts`.

## API Modules (apps/api)

The NestJS backend is decomposed into focused modules. Each module owns its database entities
via TypeORM repositories. Redis (BullMQ) backs the republish and migration job queues.

| Module            | Purpose                                                                  |
| :---------------- | :----------------------------------------------------------------------- |
| `auth`            | Web3Auth JWT login, SIWE wallet auth, refresh tokens, account linking    |
| `vault`           | Vault init, encrypted key blobs, storage quota, config endpoint          |
| `ipfs`            | IPFS blob relay (upload / fetch / unpin) via Kubo HTTP API               |
| `ipns`            | IPNS publish / resolve relay, folder IPNS registration                   |
| `tee`             | TEE key state, TEE worker HTTP proxy, key rotation                       |
| `republish`       | BullMQ-backed 6-hour IPNS republish scheduler                            |
| `device-approval` | Cross-device new-device approval flow (IPNS-based registry)              |
| `shares`          | Share creation, invite links, share key distribution                     |
| `migration`       | BullMQ-backed CID migration between pinning providers                    |
| `health`          | Health check endpoint                                                    |
| `metrics`         | Prometheus metrics registry (`prom-client`) and HTTP metrics interceptor |

## Client Applications

### Web App (apps/web)

React + Vite SPA. State is managed with Zustand stores:

| Store                   | Responsibility                                           |
| :---------------------- | :------------------------------------------------------- |
| `vault.store`           | Root vault key material (RAM only), vault init state     |
| `folder.store`          | Folder tree, current path, folder children               |
| `upload.store`          | Upload queue, progress tracking                          |
| `download.store`        | Download queue, progress tracking                        |
| `sync.store`            | IPNS poll status (30-second interval), conflict tracking |
| `share.store`           | Active shares, invite state                              |
| `bin.store`             | Recycle bin metadata                                     |
| `device-registry.store` | Known devices, device approval state                     |
| `auth.store`            | Auth session, Web3Auth instance                          |
| `quota.store`           | Storage quota used / available                           |
| `vault-settings.store`  | BYO-IPFS pinning config, recycle bin settings            |

Encryption is offloaded to a `encrypt.worker.ts` Web Worker to keep the main thread
responsive. Decryption of streamed media uses `decrypt-sw.ts` (a Service Worker) for
AES-256-CTR random-access range decryption.

### Desktop App (apps/desktop)

Tauri v2 shell wrapping the same React web frontend. The Rust native backend handles:

- **FUSE virtual filesystem** — mounts the encrypted vault at `~/CipherBox`. On macOS
  uses FUSE-T's SMB backend (avoids a macOS Sequoia NFS write bug). A vendored fuser 0.16
  with a patched `channel.rs` handles FUSE-T's Unix socket framing.
- **Native keychain** — device ID and session tokens stored in macOS Keychain (release
  builds) or ephemeral memory (debug builds, avoids signature prompts on each rebuild).
- **Device registry** — registers the device in the encrypted IPNS-based device registry
  on first login; delegates crypto to the Rust `sdk` and `core` crates.
- **Debounced publish** — file mutations coalesce with a 1.5s debounce / 10s safety valve
  before triggering IPNS metadata re-publish.

FUSE callbacks run single-threaded. Network I/O is prohibited in FUSE callbacks (except
`release()` which spawns a background Tokio task). See the `apps/desktop` `CLAUDE.md` for
FUSE architecture details.

## Sharing Model

File and folder sharing is client-side key distribution. The owner wraps the target
`folderKey` (or `fileKey`) with the recipient's `publicKey` using ECIES and stores the
result as a `ShareKey` in the `shares` table. The recipient fetches the `ShareKey`, unwraps
it with their own `privateKey`, and then has direct access to the shared content.

The server stores only the ECIES-wrapped `ShareKey` ciphertext — it cannot access the
plaintext key. Invite links are one-time tokens that deliver the wrapped key to a recipient
who registers their `publicKey`.

Share key types (`file`, `folder`, `file-ipns`, `folder-ipns`) control whether the
recipient can read only or also write (subfolder IPNS key required for write).

## BYO-IPFS Pinning

Users can configure their own IPFS pinning backend instead of (or in addition to) the
default CipherBox Kubo node. Supported pinning modes:

- `cipherbox` — default; all pins managed by CipherBox's Kubo node.
- `external` — all pins sent to a user-configured endpoint (PSA-compatible, Kubo HTTP API,
  or Pinata).
- `dual` — pins sent to both CipherBox and the external provider simultaneously.

The `ByoIpfsConfig` is stored encrypted in the user's vault settings IPNS record and never
sent to the server in plaintext. The `sdk-core` `pinning/` module implements
`KuboProvider`, `PsaProvider`, `PinataProvider`, and `DualPinProvider`.

## Database Schema (PostgreSQL)

Managed via TypeORM migrations. See [DATABASE_EVOLUTION_PROTOCOL.md](DATABASE_EVOLUTION_PROTOCOL.md)
for migration discipline rules.

| Table                     | Purpose                                                                            |
| :------------------------ | :--------------------------------------------------------------------------------- |
| `users`                   | One row per identity; unique `publicKey` column (UUID primary key)                 |
| `auth_methods`            | Linked auth providers per user (Web3Auth, SIWE wallet)                             |
| `refresh_tokens`          | HTTP-only cookie refresh token store (7-day TTL)                                   |
| `vaults`                  | Encrypted vault key blobs and root IPNS name per user                              |
| `pinned_cids`             | CIDs pinned by the user for quota tracking                                         |
| `folder_ipns`             | IPNS name → owner mapping, used for access control                                 |
| `ipns_republish_schedule` | Per-folder republish entries: encryptedIpnsPrivateKey, keyEpoch, next_republish_at |
| `tee_key_state`           | Singleton row: current and previous TEE key epochs + grace period                  |
| `tee_key_rotation_log`    | Audit log of epoch rotations                                                       |
| `device_approvals`        | Cross-device approval requests                                                     |
| `shares`                  | Share records: sharer, recipient, target IPNS name                                 |
| `share_keys`              | ECIES-wrapped key material per share entry                                         |
| `share_invites`           | One-time invite tokens for share delivery                                          |
| `pin_migrations`          | BullMQ-backed CID migration job state                                              |

## Further Reading

Detailed specifications are maintained in separate documents:

- [AUTHENTICATION_ARCHITECTURE.md](AUTHENTICATION_ARCHITECTURE.md) — Web3Auth flows,
  SIWE wallet auth, JWT / refresh token lifecycle, multi-auth method linking
- [FILESYSTEM_SPECIFICATION.md](FILESYSTEM_SPECIFICATION.md) — encrypted filesystem design,
  IPNS metadata structure, FUSE mount behavior
- [METADATA_SCHEMAS.md](METADATA_SCHEMAS.md) — all metadata object schemas with field
  types and encryption status
- [METADATA_EVOLUTION_PROTOCOL.md](METADATA_EVOLUTION_PROTOCOL.md) — versioning rules for
  evolving metadata schemas without breaking existing vaults
- [DATABASE_EVOLUTION_PROTOCOL.md](DATABASE_EVOLUTION_PROTOCOL.md) — TypeORM migration
  discipline, naming conventions, do-and-don't rules
- [CAPACITY.md](CAPACITY.md) — storage limits, quota accounting, capacity planning
- [VAULT_EXPORT_FORMAT.md](VAULT_EXPORT_FORMAT.md) — vault export/import format spec
- [../README.md](../README.md) — local dev setup: the one recipe that boots the stack

# CipherBox Metadata Schema Reference

**Version:** 2.0
**Last Updated:** 2026-06-28
**Status:** Active (node/v3)

## Table of Contents

1. [Overview](#1-overview)
2. [Encryption Hierarchy](#2-encryption-hierarchy)
3. [Node (node/v3)](#3-node-nodev3)
4. [SealedChildRef and ResolvedChild](#4-sealedchildref)
5. [PublishedNode](#5-publishednode)
6. [NodeContent](#6-nodecontent)
7. [VersionEntry](#7-versionentry)
8. [NodeWriteBody and WriteChildRef](#8-nodewritebody-and-writechildref)
9. [VaultKeyBlob (v3)](#9-vaultkeyblob-v3)
10. [Invariants](#10-invariants)
11. [EncryptedVaultKeys (Removed)](#11-encryptedvaultkeys-removed)
12. [DeviceRegistry (v1/v2)](#12-deviceregistry-v1v2)
13. [DeviceEntry](#13-deviceentry)
14. [Cross-Implementation Parity](#14-cross-implementation-parity)
15. [IPNS Key Derivation Summary](#15-ipns-key-derivation-summary)

---

## 1. Overview

CipherBox stores all metadata encrypted client-side before persisting to IPFS or the server
database. The server is zero-knowledge -- it never sees plaintext metadata or unencrypted keys.

Phase 62 introduced the unified **node/v3** schema replacing the legacy per-kind types
(`FolderMetadata`, `FileMetadata`, `FilePointer`, `FolderEntry`). All metadata trees are
modelled as a discriminated `Node` union keyed on `kind` (`folder`, `file`, `root`). The
node/v3 schema is the sole current metadata model; the legacy schemas are retired.

Metadata exists in two implementations that must produce byte-identical JSON (camelCase field
names):

- **TypeScript** -- `packages/core/src/node/` (web app, shared crypto library)
- **Rust** -- `crates/core/src/` (desktop app; Phase 69 consumer of the frozen wire format)

This document defines the canonical schema for every metadata object in the system. For rules
governing how schemas evolve over time, see
[METADATA_EVOLUTION_PROTOCOL.md](METADATA_EVOLUTION_PROTOCOL.md).

> **Deferred:** Navigation walk, read-key rotation, and write-revocation FLOW behavior are not
> documented here. Those behaviors depend on phases 63-69 and will be documented in their owning
> phases. This document covers only the static node/v3 schema.

---

## 2. Encryption Hierarchy

Each metadata type uses a specific encryption scheme and storage location.

| Metadata Type                  | Encrypted By                    | Algorithm                  | Storage                    | IPNS Addressing          |
| ------------------------------ | ------------------------------- | -------------------------- | -------------------------- | ------------------------ |
| Node read-body (any kind)      | Node's `readKey` (32-byte AES)  | AES-256-GCM + AAD          | IPFS blob                  | Node's IPNS k51 name     |
| Node write-body (any kind)     | Node's `writeKey` (32-byte AES) | AES-256-GCM + AAD          | IPFS blob                  | Same IPNS record         |
| NodeContent (file kind)        | File node's `readKey`           | AES-256-GCM + AAD          | Inside `readSealed`        | N/A (embedded)           |
| `SealedChildRef.readKeySealed` | Parent node's `readKey`         | AES-256-GCM + AAD          | Inside parent `readSealed` | N/A                      |
| VaultKeyBlob (v3)              | User's secp256k1 `publicKey`    | ECIES (two root keys)      | IPFS blob                  | Vault key IPNS (HKDF)    |
| DeviceRegistry                 | User's secp256k1 `publicKey`    | ECIES                      | IPFS blob                  | Registry IPNS (HKDF)     |
| File content                   | Per-file random `fileKey`       | AES-256-GCM or AES-256-CTR | IPFS blob                  | N/A (CID in NodeContent) |

**Key principle:** Access to a node's `readKey` grants access to that node's read-body and to
each `SealedChildRef.readKeySealed` sealed under it, enabling read traversal of the subtree.

### AAD-bound seal primitive

Node body sealing uses AES-256-GCM with Additional Authenticated Data (AAD) that binds each
sealed blob to the identity of the node it belongs to (node ID, kind, key generation, and role).
This prevents replay or transplant of a blob under a different node identity without a
cryptographic authentication failure.

See [ADR 0003](adr/0003-aad-bound-node-seal-encoding.md) for the authoritative freeze: the
exact 45-byte AAD byte-encoding table, kind-byte and role-byte assignments, AEAD parameters
(`AES-256-GCM`, 12-byte IV, 16-byte tag), and the standing rule that every new role byte must
extend the cross-language Known-Answer Test.

The role bytes reserved by this implementation are:

| Value  | Role           | Usage                                 |
| ------ | -------------- | ------------------------------------- |
| `0x01` | body           | `readSealed` and `writeSealed` bodies |
| `0x02` | child-readkey  | `SealedChildRef.readKeySealed`        |
| `0x03` | content        | `NodeContent` self-seal (file nodes)  |
| `0x04` | child-writekey | `WriteChildRef.writeKeySealed`        |

---

## 3. Node (node/v3)

The unified in-memory Node shape (decrypted plaintext). This is the type that lives inside
the sealed read-body (and write-body). The `schema: 'node/v3'` discriminator is the version
handle for this schema.

**TypeScript source:** `packages/core/src/node/types.ts`

| Field        | Type                           | Required         | Description                                                                              |
| ------------ | ------------------------------ | ---------------- | ---------------------------------------------------------------------------------------- |
| `schema`     | `'node/v3'`                    | Yes              | Schema discriminator -- always the literal string `"node/v3"`                            |
| `kind`       | `'folder' \| 'file' \| 'root'` | Yes              | Node kind discriminator                                                                  |
| `id`         | string (UUID)                  | Yes              | Hyphenated RFC-4122 UUID                                                                 |
| `generation` | number                         | Yes              | Per-node read-key rotation clock; range `[0, 2^32-1]` (see [Invariants](#10-invariants)) |
| `createdAt`  | number                         | Yes              | Unix timestamp in milliseconds                                                           |
| `modifiedAt` | number                         | Yes              | Unix timestamp in milliseconds                                                           |
| `children`   | `SealedChildRef[]`             | folder/root only | Sealed references to child nodes                                                         |
| `content`    | `NodeContent`                  | file only        | File content descriptor (self-sealed under the file node's own `readKey`)                |
| `writeBody`  | `NodeWriteBody`                | No               | IPNS signing material and write chain; absent on read-only nodes                         |

### JSON body encoding

The read-body and write-body are independently JSON-encoded and then sealed. The read-body
JSON uses a fixed field order (`schema`, `kind`, `id`, `generation`, kind-specific
`children`/`content`, `createdAt`, `modifiedAt`) for wire-format determinism (D-04).
`writeBody` does not appear in the read-body JSON -- it is encoded and sealed separately via
`encodeWriteBody`.

Encoding rules for the read-body JSON:

- `SealedChildRef.versionFloor` bigint is serialized as a decimal string (`"0"`, `"1"`, etc.),
  because `bigint` is not JSON-serializable.
- `NodeContent.fileKey` and every `VersionEntry.fileKey` are base64-encoded (raw 32-byte
  Uint8Array -- see [Invariants](#10-invariants) for the type-change context).
- `NodeWriteBody.ipnsPrivateKey` is base64-encoded in the write-body JSON.

**Source files:**

- TS types: `packages/core/src/node/types.ts`
- TS encoder: `packages/core/src/node/encode.ts` (`encodeReadBody`, `encodeWriteBody`, `serializeContentForWire`)
- TS decoder: `packages/core/src/node/decode.ts` (`decodeReadBody`, `decodeWriteBody`, `validateNode`, `deserializeContentFromWire`)
- TS seal: `packages/core/src/node/seal.ts` (`sealNode`, `unsealNode`)
- Golden vectors: `tests/vectors/node-codec.json` (body-byte and full-seal cross-language vectors)

**Version history:**

| Change                        | Phase | Description                                                                                                  |
| ----------------------------- | ----- | ------------------------------------------------------------------------------------------------------------ |
| `node/v3` introduced          | 62    | Unified Node replaces FolderMetadata, FileMetadata, FilePointer, FolderEntry                                 |
| `NodeWriteBody.recipientPins` | 80    | Additive optional recipient-pubkey pin list (D-03b); omitted when empty, `schema` unchanged, tolerant decode |

---

## 4. SealedChildRef

A sealed reference to a child node, stored inside the parent's read-body `children` array. The
field set is FROZEN to exactly five fields -- no write field, and no size/date display field
(NODE-03, design §2.6). An interim revision (commit `ba3e0229a`, Phase 68.1) added optional
`size`/`modifiedAt` display mirrors directly to this type; these were reverted in Phase 68.2
(D-08) in favor of `ResolvedChild` (below), which resolves each child's own `Node` once per
folder-load instead of maintaining a second, independently-stale mirror inside the sealed parent
read-body.

| Field           | Type   | Encoding              | Description                                                                                         |
| --------------- | ------ | --------------------- | --------------------------------------------------------------------------------------------------- |
| `name`          | string | --                    | Display name of the child (plaintext within the sealed parent read-body)                            |
| `ipnsName`      | string | k51 base32            | IPNS k51 name of the child node                                                                     |
| `generation`    | number | --                    | Staleness witness for the child's read-key epoch (see [Invariants](#10-invariants))                 |
| `versionFloor`  | bigint | decimal string (wire) | Owner-vouched IPNS sequence-number floor, bound at (re)share                                        |
| `readKeySealed` | string | base64                | AES-256-GCM seal of the child's `readKey` under the parent `readKey`; AAD role `0x02` child-readkey |

**Encryption:** `readKeySealed` is sealed by `sealChildReadKey` (role `0x02`). The entire
`SealedChildRef` object lives inside the parent's sealed read-body -- it is not independently
encrypted.

**Wire format:** `versionFloor` is serialized as a decimal string on the JSON wire because
`bigint` is not JSON-serializable. The decoder reconstructs it via `BigInt(String(raw.versionFloor))`.

**Source files:** `packages/core/src/node/types.ts`, `packages/core/src/node/seal.ts`
(`sealChildReadKey`, `unsealChildReadKey`)

### ResolvedChild (SDK-resolved display projection)

`ResolvedChild` is the canonical carrier for a folder child's display metadata (kind, size,
last-modified time). It is NOT a wire/encrypted schema -- it is an in-memory TypeScript type
(`packages/sdk/src/folder-listing.ts`) that the SDK assembles once per folder-load by resolving
each `SealedChildRef`'s own child `Node` through the gated read path
(`RotationHighWater.enforceResolved`, ROT-07). `apps/web` renders exclusively from
`ResolvedChild` -- it never reads a size/date display field off `SealedChildRef` (SDK-READ-02,
D-08).

| Field        | Type               | Description                                                                                         |
| ------------ | ------------------ | --------------------------------------------------------------------------------------------------- |
| `ipnsName`   | string             | IPNS k51 name of the child node (matches `SealedChildRef.ipnsName`)                                 |
| `name`       | string             | Display name of the child (matches `SealedChildRef.name`)                                           |
| `kind`       | `NodeKind`         | `'file' \| 'folder' \| 'root'`, read from the child's own resolved `Node.kind`                      |
| `size`       | number? (optional) | Plaintext byte size (`NodeContent.size`); populated for file children only, `undefined` for folders |
| `modifiedAt` | number             | The child's own `Node.modifiedAt` (Unix ms) -- authoritative, not a mirror                          |
| `sequence`   | number             | The child's own current IPNS sequence number at resolve time                                        |

**Authoritative, not cached long-term:** unlike the retired `SealedChildRef` mirror,
`ResolvedChild.size`/`modifiedAt` are read directly from the child's own `Node` at resolve time
(via the same gated resolve used for every other read), so they cannot go stale independently of
the child's actual content -- resolving again always reflects the child's current state. The SDK
caches `ResolvedChild[]` per folder keyed by the folder's own IPNS sequence number
(`CipherBoxClient`'s `listingCache`), invalidating whenever the folder's sequence advances.

**Source files:** `packages/sdk/src/folder-listing.ts` (`ResolvedChild`, `resolveChildren`),
`packages/sdk/src/client.ts` (`listFolder`, `listSharedFolder`, `ensureFolderLoaded`)

---

## 5. PublishedNode

The on-wire published node as stored in IPFS and addressed via IPNS. The plaintext envelope
wraps two sealed bodies. The plaintext fields are also AAD inputs -- they are tamper-evident
via the IPNS signature chain.

| Field         | Type                           | Required | Description                                                                                  |
| ------------- | ------------------------------ | -------- | -------------------------------------------------------------------------------------------- |
| `schema`      | `'node/v3'`                    | Yes      | Schema discriminator                                                                         |
| `kind`        | `'folder' \| 'file' \| 'root'` | Yes      | Node kind (plaintext; used in AAD)                                                           |
| `id`          | string (UUID)                  | Yes      | Hyphenated UUID (plaintext; used in AAD)                                                     |
| `generation`  | number                         | Yes      | Read-key epoch (plaintext; used in AAD; lets honest readers detect staleness)                |
| `aeadVersion` | `1`                            | Yes      | AEAD primitive version tag (always `1` for this implementation)                              |
| `readSealed`  | string                         | Yes      | Base64 of `IV \|\| AES-256-GCM ciphertext+tag` for the read-body                             |
| `writeSealed` | string                         | No       | Base64 of `IV \|\| AES-256-GCM ciphertext+tag` for the write-body; absent on read-only nodes |

### Sealed body wire format

Each sealed body is:

```text
base64( IV [12 bytes] | AES-256-GCM ciphertext | GCM tag [16 bytes] )
```

The AAD for both `readSealed` and `writeSealed` is `buildNodeAad(id, kind, generation, role=0x01)`
(45 bytes; see [ADR 0003](adr/0003-aad-bound-node-seal-encoding.md)). `readSealed` is sealed
under `readKey`; `writeSealed` is sealed under `writeKey`.

**Storage:** The `PublishedNode` JSON is uploaded to IPFS (the CID is the IPNS value) and
addressed via the node's IPNS k51 name.

**Source files:**

- TS types: `packages/core/src/node/types.ts`
- TS seal: `packages/core/src/node/seal.ts` (`sealNode`, `unsealNode`)
- Cross-language vectors: `tests/vectors/node-codec.json` (FULL-SEAL vectors with fixed IV;
  Phase 69 Rust `#[test]` will assert the same bytes against these vectors)

---

## 6. NodeContent

File content descriptor for a `file`-kind node. Sealed separately under the file node's own
`readKey` (role `0x03` content) by `sealContent`. The sealed blob (`base64(IV||ct+tag)`) is
embedded as the `readSealed` field of the file node's `PublishedNode` envelope.

| Field            | Type                    | Encoding      | Description                                                                   |
| ---------------- | ----------------------- | ------------- | ----------------------------------------------------------------------------- |
| `cid`            | string                  | CIDv1         | IPFS content identifier of the encrypted file                                 |
| `fileIv`         | string                  | base64        | 12-byte IV used for file content encryption (base64 of the raw IV)            |
| `size`           | number                  | --            | Original unencrypted file size in bytes                                       |
| `mimeType`       | string                  | --            | MIME type of the original file                                                |
| `encryptionMode` | `'GCM' \| 'CTR'`        | --            | **Mandatory** -- `'CTR'` supports large-file range reads                      |
| `fileKey`        | `Uint8Array` (32 bytes) | base64 (wire) | Raw AES-256 key; **semantic type change** -- see [Invariants](#10-invariants) |
| `versions`       | `VersionEntry[]`        | --            | Past versions of this file (newest first)                                     |

**Wire encoding:** `fileKey` is base64-encoded on the JSON wire (raw 32-byte Uint8Array via
chunked helper for large-blob safety, SECURITY MEDIUM-08). Each `VersionEntry.fileKey` is
likewise base64-encoded.

**Source files:**

- TS types: `packages/core/src/node/types.ts`
- TS encoder/decoder: `packages/core/src/node/encode.ts` (`serializeContentForWire`),
  `packages/core/src/node/decode.ts` (`deserializeContentFromWire`)
- TS seal: `packages/core/src/node/seal.ts` (`sealContent`, `unsealContent`)

---

## 7. VersionEntry

A single past version of a file node's content. Embedded in the `NodeContent.versions` array
inside the sealed content body. Each entry contains the full crypto context needed to
independently decrypt that version.

| Field            | Type                    | Encoding      | Description                                                                   |
| ---------------- | ----------------------- | ------------- | ----------------------------------------------------------------------------- |
| `versionId`      | string                  | UUID          | Unique identifier for this version                                            |
| `cid`            | string                  | CIDv1         | IPFS content identifier of the encrypted file for this version                |
| `fileIv`         | string                  | base64        | 12-byte IV for this version's file content (base64 of the raw IV)             |
| `size`           | number                  | --            | Original unencrypted file size for this version                               |
| `createdAt`      | number                  | --            | When this version was created (Unix ms)                                       |
| `encryptionMode` | `'GCM' \| 'CTR'`        | --            | **Mandatory** -- encryption mode used for this version                        |
| `fileKey`        | `Uint8Array` (32 bytes) | base64 (wire) | Raw AES-256 key; **semantic type change** -- see [Invariants](#10-invariants) |

**Not independently encrypted** -- embedded in the parent `NodeContent` sealed body.

**Key difference from NodeContent:** `encryptionMode` is required (not defaulted) because past
versions must always record the explicit mode used at the time of creation.

**Source files:** `packages/core/src/node/types.ts`

---

## 8. NodeWriteBody and WriteChildRef

The write-body carries IPNS signing material and the write chain to child nodes. It is sealed
separately from the read-body under the node's `writeKey` (role `0x01` body). It is absent on
read-only nodes (when only `readKey` is held).

### NodeWriteBody

| Field            | Type              | Encoding            | Description                                                                                                                                        |
| ---------------- | ----------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ipnsPrivateKey` | `Uint8Array`      | base64 (wire)       | Raw Ed25519 signing seed for this node's IPNS record                                                                                               |
| `writeChildren`  | `WriteChildRef[]` | --                  | Write-chain references to child nodes                                                                                                              |
| `recipientPins`  | `string[]`        | base64 array (wire) | Optional. Recipient-pubkey pins bound at share/re-mint (D-03b); each entry a raw compressed secp256k1 public key. Omitted from the wire when empty |

**`recipientPins` (additive, optional):** Introduced for the D-03 re-mint recipient-identity
check. It is an additive optional field per
[METADATA_EVOLUTION_PROTOCOL §3.1](METADATA_EVOLUTION_PROTOCOL.md#31-additive-non-breaking-changes) —
the `schema` discriminator is NOT bumped. Both codecs OMIT the field from the wire when the list
is empty (TS conditional spread; Rust `#[serde(skip_serializing_if = "Vec::is_empty")]`), which
preserves the frozen empty-pin golden vector (`seal_vectors[0]`) byte-for-byte. Decoders tolerate
an absent field (TS: field stays absent; Rust: `#[serde(default)]` yields an empty `Vec`) and never
fail-closed on it — `NodeWriteBody` intentionally carries NO `deny_unknown_fields`. A non-empty-pin
golden vector (`seal_vectors[1]`) locks the pinned wire path across Rust and TypeScript.

**Folder/root only (file-share carve-out, D-03g):** `recipientPins` is meaningful only for
**folder and root** nodes. A shared **file** is a leaf whose `NodeWriteBody` (when present) never
carries pins — pin issuance (`addRecipientPubkeyPin`) is folder-only, since a file leaf is not a
tracked folder-tree entry. Consequently the D-03d/D-03e re-mint pin enforcement
(`re_mint_grants_rooted_at` / `reMintGrantsRootedAt`) **exempts file-rooted grants** from the
"pin absent → hard fail-closed" rule: a file grant is re-minted without a pin check (otherwise a
scope-exit rotation of any folder that merely contains a separately-shared file would fail-closed
and abort). Folder/root grants remain fully fail-closed. File-share recipient-substitution
protection is a known, tracked limitation (`recipient-pin-lifecycle-hardening` todo §5).

### WriteChildRef

| Field            | Type            | Description                                                                                             |
| ---------------- | --------------- | ------------------------------------------------------------------------------------------------------- |
| `childId`        | string (UUID)   | Hyphenated UUID of the child node                                                                       |
| `writeKeySealed` | string (base64) | AES-256-GCM seal of the child's `writeKey` under this node's `writeKey`; AAD role `0x04` child-writekey |

**Separation invariant:** `writeKeySealed` appears ONLY in `WriteChildRef` (write-body). It
NEVER appears in `SealedChildRef` (read-body). This separation ensures a read-only holder of
`readKey` gains no write access (NODE-03, design §2.2).

**Wire encoding:** `ipnsPrivateKey` Uint8Array is base64-encoded in the write-body JSON. The
write-body JSON is then sealed by `sealNode` under `writeKey` with AAD role `0x01`.

**Source files:** `packages/core/src/node/types.ts`, `packages/core/src/node/seal.ts`

---

## 9. VaultKeyBlob (v3)

Binary envelope storing two ECIES-encrypted root keys on IPFS. Written once during vault
initialization and read on every login. Version `0x03` replaces the single-key `v2` envelope
retired in Phase 62 (greenfield hard-cut; staging vault wiped).

### Binary format

```text
0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)
```

| Offset      | Size       | Field                   | Description                                                               |
| ----------- | ---------- | ----------------------- | ------------------------------------------------------------------------- |
| 0           | 1          | Version                 | `0x03` -- v3 blob identifier                                              |
| 1           | 2          | `readLen`               | Big-endian uint16: byte length of `encryptedRootReadKey` (typically 129)  |
| 3           | `readLen`  | `encryptedRootReadKey`  | ECIES-wrapped 32-byte AES-256 root read key                               |
| 3+readLen   | 2          | `writeLen`              | Big-endian uint16: byte length of `encryptedRootWriteKey` (typically 129) |
| 3+readLen+2 | `writeLen` | `encryptedRootWriteKey` | ECIES-wrapped 32-byte AES-256 root write key                              |

**Encryption:** Both keys are ECIES-wrapped with the user's secp256k1 `publicKey`.

**Storage:** IPFS blob, addressed via vault key IPNS name (HKDF-derived with
`cipherbox-vault-key-ipns-v1`). The blob content and CID are immutable after vault init; the
IPNS record is periodically republished by the TEE without changing the blob.

**Key independence:** `rootReadKey` and `rootWriteKey` are independently generated via
`generateFileKey()`. Neither is derived from the other or from the Ed25519 IPNS keypair.

**Source files:**

- TS: `packages/core/src/vault/blob.ts` (`serializeVaultBlobV3`, `deserializeVaultBlobV3`,
  `BLOB_V3_VERSION`)
- TS types: `packages/core/src/vault/types.ts` (`VaultInit.rootReadKey`,
  `VaultInit.rootWriteKey`, `EncryptedVaultKeys.encryptedRootReadKey`,
  `EncryptedVaultKeys.encryptedRootWriteKey`)
- Cross-language vectors: `tests/vectors/vault-v3-blob.json`

**Version history:**

| Change                    | Phase | Description                                                                        |
| ------------------------- | ----- | ---------------------------------------------------------------------------------- |
| v3 introduced; v2 retired | 62    | Two-key envelope; greenfield hard-cut                                              |
| v2 format                 | 20    | Binary envelope replaced server-side `EncryptedVaultKeys`. Single `rootFolderKey`. |

---

## 10. Invariants

Two invariants are required by SC#6 of the v2.0 ROADMAP. Every implementation that reads or
writes node/v3 data must uphold them.

### generation-as-convergence-witness

`generation` is a per-node read-key rotation clock, represented as a `number` (u32-safe,
range `[0, 2^32-1]`).

**Authoritative source:** The authoritative `generation` value for a node is the one on the
**child's own `PublishedNode` envelope** -- the `generation` field in the plaintext
`PublishedNode` JSON at the node's own IPNS k51 address. This value is also embedded in the
AAD of both sealed bodies, making tampering a cryptographic authentication failure.

**Staleness witnesses** (mirrors only -- never authoritative):

- `SealedChildRef.generation` -- a mirror written by the parent when it last sealed the child's
  `readKey`. It is a convergence hint that lets the parent detect when its sealed reference is
  stale (e.g., after a read-key rotation). It is NOT an independent source of the child's
  generation.
- `shares.rootGeneration` -- a similar staleness mirror in share rows. The same rule applies:
  it is a witness, never the authoritative value.

**Distinction from the other per-node counters** (see the project CONTEXT.md Counters table
for full definitions):

| Counter          | Type                | Scope            | Role                                            |
| ---------------- | ------------------- | ---------------- | ----------------------------------------------- |
| `generation`     | `number` (u32-safe) | Per-node         | Read-key rotation clock; AAD-bound              |
| `keyEpoch`       | number              | TEE / grant rows | TEE public-key rotation epoch                   |
| `sequenceNumber` | `bigint`            | Per-IPNS record  | IPNS record ordering (monotonically increasing) |

These three counters serve different purposes and must not be conflated.

**Validation:** `decodeReadBody` and `validateNode` enforce `generation` in `[0, 0xffffffff]`
fail-closed (D-08), mirroring the guard in `buildNodeAad`.

### fileKey semantic type change

In the legacy model (`FileMetadata.fileKeyEncrypted`, `VersionEntry.fileKeyEncrypted`), the
file encryption key was an ECIES-wrapped hex string stored in the parent folder's metadata.

In node/v3, the file encryption key (`NodeContent.fileKey`, `VersionEntry.fileKey`) is a
**raw 32-byte `Uint8Array`** stored **inside the sealed read-body**. The outer AES-256-GCM
sealed body (role `0x01` or `0x03`) provides confidentiality and integrity; ECIES wrapping
is not used for the file key inside node metadata.

This is a **semantic type change**, not a rename:

| Aspect          | Legacy (`fileKeyEncrypted`)                     | node/v3 (`fileKey`)                      |
| --------------- | ----------------------------------------------- | ---------------------------------------- |
| Type            | string                                          | `Uint8Array` (raw 32 bytes)              |
| Encoding        | ECIES-wrapped hex (258 hex chars)               | base64 on JSON wire (inside sealed body) |
| Confidentiality | ECIES wrapping                                  | AES-256-GCM sealed body                  |
| Where stored    | Inside parent FolderMetadata (plaintext object) | Inside child's own sealed read-body      |

The change applies to `NodeContent.fileKey` and every `VersionEntry.fileKey`. The decoder
(`deserializeContentFromWire`) asserts `instanceof Uint8Array && length === 32` on decode.

---

## 11. EncryptedVaultKeys (Removed)

> **Removed in Phase 20.** The server no longer stores any crypto material. Root keys are
> stored exclusively in the [VaultKeyBlob (v3)](#9-vaultkeyblob-v3) on IPFS. The IPNS
> private key is HKDF-derived client-side and never transmitted to the server.
>
> The `encrypted_root_folder_key`, `encrypted_root_ipns_private_key`, and `migrated_at`
> database columns have been dropped. The API vault DTO only contains `ownerPublicKey`
> and `rootIpnsName`.

---

## 12. DeviceRegistry (v1/v2)

The encrypted device registry tracking all authenticated devices for a user.

**Current version:** `v1` | `v2`

| Field            | Type            | Required | Description                                                   |
| ---------------- | --------------- | -------- | ------------------------------------------------------------- |
| `version`        | `'v1' \| 'v2'`  | Yes      | Schema version (`'v1'` accepted for read, migrated to `'v2'`) |
| `sequenceNumber` | number          | Yes      | Monotonically increasing counter for IPNS ordering            |
| `devices`        | `DeviceEntry[]` | Yes      | Array of all device entries (including revoked for audit)     |

**Encryption:** ECIES with the user's secp256k1 `publicKey`. The entire registry is encrypted
as a single blob (not AES-GCM like node metadata).

**Storage:** IPFS (raw ECIES ciphertext blob, not the `{iv, data}` JSON envelope), addressed
via the device registry IPNS name (HKDF-derived).

**`sequenceNumber` usage:** Each update increments the sequence number. Used by the IPNS
publisher to set the record's sequence field, ensuring newer records supersede older ones
across the DHT.

**Validator constraints:**

- `sequenceNumber` must be a non-negative integer
- `devices` must be an array (may be empty)
- v1 registries: ipHash may be empty (migrated to zero placeholder on read)
- v2 registries: ipHash must be valid 64-char hex (strict validation)
- Generic error messages (`'Invalid registry format'`) to avoid leaking schema details

**Source files:**

- TS types: `packages/core/src/registry/types.ts`
- TS validator: `packages/core/src/registry/schema.ts`

**No Rust equivalent.** The desktop app uses the webview's TypeScript crypto for device
registry operations.

### Version History

| Version | Changes                                                                                                                         | Phase      |
| ------- | ------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| v1      | Initial schema                                                                                                                  | Phase 12.4 |
| v2      | ipHash validation relaxed for migration (accept empty string from v1, fill zero placeholder). Lenient v1 read, strict v2 write. | Phase 24   |

---

## 13. DeviceEntry

An individual device record within the `DeviceRegistry`. Tracks authentication status,
platform information, and revocation state.

| Field         | Type                                       | Encoding | Required | Description                                                |
| ------------- | ------------------------------------------ | -------- | -------- | ---------------------------------------------------------- |
| `deviceId`    | string                                     | hex      | Yes      | SHA-256 hash of device's Ed25519 public key (64 hex chars) |
| `publicKey`   | string                                     | hex      | Yes      | Device's Ed25519 public key (64 hex chars)                 |
| `name`        | string                                     | --       | Yes      | Human-readable device name (max 200 chars)                 |
| `platform`    | `'web' \| 'macos' \| 'linux' \| 'windows'` | --       | Yes      | Platform identifier                                        |
| `appVersion`  | string                                     | --       | Yes      | Application version string (max 50 chars)                  |
| `deviceModel` | string                                     | --       | Yes      | Device model or OS version (max 200 chars)                 |
| `ipHash`      | string                                     | hex      | Yes      | SHA-256 hash of IP address at registration (64 hex chars)  |
| `status`      | `'pending' \| 'authorized' \| 'revoked'`   | --       | Yes      | Authorization status                                       |
| `createdAt`   | number                                     | --       | Yes      | When device was first registered (Unix ms)                 |
| `lastSeenAt`  | number                                     | --       | Yes      | Last time device synced with registry (Unix ms)            |
| `revokedAt`   | number \| null                             | --       | Yes      | When device was revoked (Unix ms), `null` if not revoked   |
| `revokedBy`   | string \| null                             | --       | Yes      | Device ID of the revoking device, `null` if not revoked    |

**Not independently encrypted** -- embedded in the parent `DeviceRegistry` blob.

**Validator constraints:**

- `deviceId`: exactly 64 hex characters (SHA-256 output)
- `publicKey`: exactly 64 hex characters (32-byte Ed25519 public key)
- `ipHash`: exactly 64 hex characters (SHA-256 output)
- `name`: max 200 characters
- `appVersion`: max 50 characters
- `deviceModel`: max 200 characters
- `platform`: must be one of the four valid values
- `status`: must be one of the three valid values
- `revokedAt` and `revokedBy`: must both be null or both be non-null

**Source files:**

- TS types: `packages/core/src/registry/types.ts:21-46`
- TS validator: `packages/core/src/registry/schema.ts:63-136`

**Version history:** Added in Phase 12.2 (Encrypted Device Registry).

---

## 14. Cross-Implementation Parity

TypeScript and Rust implementations must produce identical JSON for the same logical data.

| Schema            | TypeScript          | Rust                                       | Notes                                                                 |
| ----------------- | ------------------- | ------------------------------------------ | --------------------------------------------------------------------- |
| Node (node/v3)    | `node/types.ts`     | `crates/core/src/` (Phase 69)              | Phase-69 Rust twin; frozen vectors in `tests/vectors/node-codec.json` |
| SealedChildRef    | `node/types.ts`     | `crates/core/src/` (Phase 69)              | Embedded in Node read-body                                            |
| PublishedNode     | `node/types.ts`     | `crates/core/src/` (Phase 69)              | On-wire IPFS/IPNS object                                              |
| NodeContent       | `node/types.ts`     | `crates/core/src/` (Phase 69)              | Embedded in file node `readSealed`                                    |
| VersionEntry      | `node/types.ts`     | `crates/core/src/` (Phase 69)              | Embedded in NodeContent                                               |
| VaultKeyBlob (v3) | `vault/blob.ts`     | `crates/core/src/vault_blob.rs` (Phase 69) | Binary format; vectors in `tests/vectors/vault-v3-blob.json`          |
| DeviceRegistry    | `registry/types.ts` | --                                         | TypeScript only                                                       |
| DeviceEntry       | `registry/types.ts` | --                                         | TypeScript only                                                       |

**Rust serialization strategy:** All Rust structs use `#[serde(rename_all = "camelCase")]` to
produce camelCase JSON field names matching the TypeScript convention.

**Phase 69 consumer:** The Rust `Node` enum and FUSE/WinFsp symmetric unwrap are deferred to
Phase 69. The TypeScript codec in Phase 62 freezes the wire format; Phase 69 will assert the
same golden bytes from `tests/vectors/node-codec.json` in `crates/crypto/tests/cross_language.rs`.

---

## 15. IPNS Key Derivation Summary

CipherBox uses two strategies for Ed25519 IPNS keypairs.

### HKDF-derived (deterministic)

Used for the root vault, vault key blob, and device registry where discoverability from the
private key alone is required.

| Purpose              | Salt           | HKDF Info                           | Stores                         | Source File                                 |
| -------------------- | -------------- | ----------------------------------- | ------------------------------ | ------------------------------------------- |
| Root node IPNS       | `CipherBox-v1` | `cipherbox-vault-ipns-v1`           | Root `PublishedNode` (node/v3) | `packages/crypto/src/vault/derive-ipns.ts`  |
| Vault key blob IPNS  | `CipherBox-v1` | `cipherbox-vault-key-ipns-v1`       | VaultKeyBlob (v3)              | `packages/crypto/src/vault/derive-ipns.ts`  |
| Device registry IPNS | `CipherBox-v1` | `cipherbox-device-registry-ipns-v1` | ECIES-encrypted registry       | `packages/core/src/registry/derive-ipns.ts` |

**Root node vs vault key blob:** These are two separate IPNS names derived from the same
private key with different HKDF info strings. The root node IPNS stores the root
`PublishedNode` (updated on every node operation). The vault key blob IPNS stores the
ECIES-wrapped root keys (written once at vault init, read on every login). This separation
prevents node publishes from overwriting the key blob.

**Derivation path:**

```text
secp256k1 privateKey (32 bytes)
  -> HKDF-SHA256(salt, info) -> 32-byte Ed25519 seed
  -> Ed25519 keypair (@noble/ed25519)
  -> IPNS name (CIDv1 with libp2p-key codec + identity multihash)
```

### Random Ed25519 keypairs

Used for all non-root nodes (subfolders, files). The Ed25519 private key (signing seed) is
stored in the sealed `NodeWriteBody.ipnsPrivateKey` under the node's `writeKey`. Only a
holder of the node's `writeKey` can read and use it for IPNS publishing.

| Purpose           | Storage Location                                          | Access                   |
| ----------------- | --------------------------------------------------------- | ------------------------ |
| Any non-root node | `NodeWriteBody.ipnsPrivateKey` (inside sealed write-body) | Requires node `writeKey` |

---

_Document version: 2.0_
_Last updated: 2026-06-28_
_See also: [METADATA_EVOLUTION_PROTOCOL.md](METADATA_EVOLUTION_PROTOCOL.md) for schema change rules_
_See also: [VAULT_EXPORT_FORMAT.md](VAULT_EXPORT_FORMAT.md) for recovery and crypto format details_
_See also: [ADR 0003](adr/0003-aad-bound-node-seal-encoding.md) for the frozen AAD/role byte encoding_

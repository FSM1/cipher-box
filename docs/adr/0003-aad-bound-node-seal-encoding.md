---
status: accepted
date: 2026-06-28
---

# AAD-bound node-seal encoding (AES-256-GCM with frozen AAD layout)

Phase 61 introduces `sealAesGcmAad`/`unsealAesGcmAad` and `buildNodeAad` as additive
primitives alongside the existing `sealAesGcm`/`unsealAesGcm` functions. The AAD is
constructed from a frozen byte layout that binds each sealed blob to the identity of the
node it belongs to, preventing replay or transplant of a blob under a different node
identity without cryptographic authentication failure.

This ADR is the authoritative freeze of that byte layout, the AEAD parameters, and the
cross-language test discipline. Any future change to the layout requires bumping the
domain separator (see Standing Rules below) rather than silent drift.

## AAD byte encoding

The `buildNodeAad` function produces a 45-byte AAD from the following fixed-layout
concatenation:

| Offset | Length | Field        | Encoding                                             |
| ------ | ------ | ------------ | ---------------------------------------------------- |
| 0      | 22     | domain       | UTF-8 bytes of `"cipherbox/node-seal/v1"`            |
| 22     | 1      | null sep     | `0x00` — separator between domain and binary fields  |
| 23     | 16     | `nodeId`     | Raw RFC-4122 UUID bytes (field order, NOT UTF-8 hex) |
| 39     | 1      | `kind`       | 1-byte node kind (see Kind Bytes table below)        |
| 40     | 4      | `generation` | Key generation as big-endian unsigned 32-bit integer |
| 44     | 1      | `role`       | 1-byte role byte (see Role Bytes table below)        |

Total: **45 bytes**.

The null separator at byte 22 ensures that domain-string variants of different length
cannot collide with each other (e.g., `"cipherbox/node-seal/v10"` and
`"cipherbox/node-seal/v1"` followed by `0` would otherwise be ambiguous if the
separator were absent).

### Kind bytes

| Value  | Meaning |
| ------ | ------- |
| `0x01` | folder  |
| `0x02` | file    |
| `0x03` | root    |

### Role bytes

| Value  | Meaning        |
| ------ | -------------- |
| `0x01` | body           |
| `0x02` | child-readkey  |
| `0x03` | content        |
| `0x04` | child-writekey |

## AEAD parameters

| Parameter     | Value                                                 |
| ------------- | ----------------------------------------------------- |
| Algorithm     | AES-256-GCM                                           |
| Key size      | 32 bytes                                              |
| IV size       | 12 bytes, fresh random per seal operation             |
| Auth tag size | 16 bytes (appended to ciphertext by both runtimes)    |
| AAD           | 45-byte output of `buildNodeAad` (see encoding above) |
| Sealed blob   | `[IV (12 bytes)][ciphertext + GCM tag (16 bytes)]`    |

Each call to `sealAesGcmAad` mints a fresh random 12-byte IV. Caller-supplied IVs are
not accepted by the high-level seal API. The sealed blob layout `[IV][ct+tag]` is
identical to the existing `sealAesGcm`/`seal_aes_gcm` non-AAD functions — the AAD
variants are strictly additive.

## Implementations

- TypeScript: `packages/crypto/src/aes/seal.ts` — `buildNodeAad`, `sealAesGcmAad`,
  `unsealAesGcmAad`
- Rust: `crates/crypto/src/aes.rs` — `build_node_aad`, `seal_aes_gcm_aad`,
  `unseal_aes_gcm_aad`
- KAT fixture: `tests/vectors/crypto/node-aad.json` — asserted by both
  `packages/crypto/__tests__/build-node-aad.test.ts` and
  `crates/crypto/tests/cross_language.rs`

## Standing rules

**Every new role byte must extend the cross-language KAT.**
Adding a role byte without a corresponding KAT vector is forbidden. The KAT is the
merge gate that proves byte-identical AAD construction across TypeScript and Rust.

**Any byte-layout change bumps the domain separator.**
If the 45-byte layout changes for any reason (field reorder, new field, width change),
the domain string must be updated from `"cipherbox/node-seal/v1"` to
`"cipherbox/node-seal/v2"` (or later). A blob sealed under `v1` will fail to unseal
under `v2` and vice versa — this is intentional and prevents silent format drift.

**`buildNodeAad` is fail-closed.**
Invalid inputs (`kind` outside `{0x01, 0x02, 0x03}`, `role` outside
`{0x01, 0x02, 0x03, 0x04}`, malformed UUID, generation outside `[0, 2^32-1]`) throw
immediately with a `CryptoError` / `Err`. A wrong-length AAD must never be silently
produced.

## Scope

This ADR covers the encryption and encoding layer only. The unified Node schema
(`FolderMetadata`/`FileMetadata`/`FilePointer` → `Node`) and its documentation are
deferred to phase 62.

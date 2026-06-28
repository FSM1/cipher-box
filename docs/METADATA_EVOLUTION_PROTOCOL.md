# CipherBox Metadata Schema Evolution Protocol

**Version:** 1.0
**Last Updated:** 2026-02-21
**Status:** Active

## Table of Contents

1. [Purpose](#1-purpose)
2. [Guiding Principles](#2-guiding-principles)
3. [Change Classification](#3-change-classification)
4. [Evolution Checklist](#4-evolution-checklist)
5. [Version Field Convention](#5-version-field-convention)
6. [Testing Requirements](#6-testing-requirements)
7. [Recovery Tool Compatibility Matrix](#7-recovery-tool-compatibility-matrix)
8. [References](#8-references)

---

## 1. Purpose

CipherBox metadata is encrypted client-side and stored on IPFS. Once written, records may persist indefinitely -- IPFS content is immutable and old CIDs remain valid even after IPNS updates. This has three consequences:

1. **Old records are permanent.** A new client version must be able to read metadata written by any prior version.
2. **Clients of different versions coexist.** A user may have the desktop app on v1.3 and the web app on v1.4. Both must read and write metadata the other can understand.
3. **Two implementations must agree.** The TypeScript crypto library (`packages/crypto/`) and the Rust desktop implementation (`crates/core/src/`) must produce byte-identical JSON for the same logical data.

This protocol establishes formal rules for evolving metadata schemas. It replaces the informal pattern of adding optional fields without documentation that was used through Phase 13.

---

## 2. Guiding Principles

1. **Backward compatibility is mandatory.** New clients must read old data. Old clients must not crash on new data (graceful degradation via ignoring unknown fields).

2. **Forward compatibility via optional fields.** Unknown JSON fields are ignored by both `JSON.parse()` and serde (CipherBox uses manual validators, not strict schema validation). This is safe only if new fields are optional.

3. **Version bumps are breaking changes.** Incrementing the `version` field (e.g., `'v1'` to `'v2'`) signals that old clients cannot fully understand the data. This is a last resort.

4. **Both platforms move together.** A schema change is not complete until both TypeScript and Rust implementations are updated. A partially-shipped change creates cross-device data corruption risk.

5. **Validators are the source of truth.** If the validator does not check a field, that field does not exist from a compatibility perspective. Type definitions document intent; validators enforce it.

---

## 3. Change Classification

### 3.1 Additive (Non-Breaking) Changes

Adding a new optional field with a sensible default. The metadata version field is NOT bumped.

**Examples of additive changes:**

- Adding a new optional field to an existing object
- Adding a new enum variant to a string union field (only if consumers ignore unknown variants)
- Adding new properties to an existing nested object field

**Rules for additive changes:**

- The field MUST be optional in TypeScript (`field?: Type`)
- The field MUST have `#[serde(default)]` in Rust (or `#[serde(default = "default_fn")]` if the default is not the zero value)
- The field MUST have `#[serde(skip_serializing_if = "Option::is_none")]` in Rust (or `skip_serializing_if = "Vec::is_empty"` for arrays)
- The validator MUST accept data without the new field
- The validator MUST NOT reject unknown fields (already true -- CipherBox uses manual validation, not strict schema validation)
- The default value MUST preserve existing behavior. If there is no default that preserves existing behavior, this is a breaking change.
- The version field is NOT bumped

**Historical examples:**

| Field                         | Schema       | Phase     | Default               | Rationale                                                      |
| ----------------------------- | ------------ | --------- | --------------------- | -------------------------------------------------------------- |
| `FileMetadata.encryptionMode` | FileMetadata | 12.6/12.1 | `'GCM'`               | All pre-CTR files used GCM; default preserves behavior         |
| `FileMetadata.versions`       | FileMetadata | 13        | `undefined` (omitted) | No versions existed before Phase 13; omission means no history |

### 3.2 Breaking Changes (Version Bump Required)

Changes that alter the meaning or structure of existing data. The metadata version field MUST be bumped.

**What counts as a breaking change:**

- Removing a field
- Changing a field's type (e.g., `string` to `number`)
- Making an optional field required
- Changing the semantics of an existing field (same type, different meaning)
- Restructuring a nested object or array format
- Changing a default value (this is a breaking change in disguise -- see Section 3.3)

**Rules for breaking changes:**

- The version field MUST be bumped (e.g., `'v1'` to `'v2'`)
- Choose one migration strategy:
  - **Migration path:** Write a converter that upgrades old format to new format. Preferred for data at rest.
  - **Dual support:** Read both versions, write only new version. Temporary measure -- converge within 2 releases.
  - **Clean break:** Reject old format entirely. Only valid when ALL existing data can be wiped (e.g., pre-production).
- Both TypeScript and Rust validators must be updated simultaneously
- The recovery tool (`apps/web/public/recovery.html`) must handle both old and new versions unless a clean break was chosen

**Historical example:**

| Change   | Schema         | Phase     | Strategy    | Details                                                                                                                              |
| -------- | -------------- | --------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| v1 to v2 | FolderMetadata | 12.6/11.2 | Clean break | Changed file children from inline FileEntry to slim FilePointer. Pre-production vault wipe. v1 later removed entirely in Phase 11.2. |

### 3.3 Dangerous Gray Areas

These changes look safe but can cause subtle failures. Treat them with extra scrutiny.

**Changing default values:** If `encryptionMode` default changed from `'GCM'` to `'CTR'`, old files without the field would be decrypted with the wrong algorithm. Changing defaults is a breaking change.

**Widening a string union type:** Adding `'CTR'` to the `encryptionMode` union is safe only if old clients handle unknown modes gracefully. In practice, they do not -- an unknown mode passed to Web Crypto API causes a hard failure. New enum variants MUST be paired with the optional-field pattern (old clients never see the new value because the field is absent from old data).

**Reordering array elements:** The `versions` array order (newest-first) is semantic. All version display code assumes index 0 is newest. Changing to oldest-first would silently break version numbering UI without any deserialization error.

**Renaming a field:** Even if the type and semantics are identical, a rename is a breaking change. The old field name will be missing from the JSON, causing validator failures. Use serde aliases (`#[serde(alias = "oldName")]`) if a rename is absolutely necessary, and only as a dual-support transition.

---

## 4. Evolution Checklist

Complete this checklist for every metadata schema change. This is the most important section of this document -- it is what developers use during implementation.

### 4.1 Before Implementation

- [ ] Classify the change: Additive (Section 3.1) or Breaking (Section 3.2)?
- [ ] If additive: What is the default value? Does it preserve existing behavior for all existing data?
- [ ] If breaking: What migration strategy? (migration path / dual support / clean break)
- [ ] Document the planned change in `docs/METADATA_SCHEMAS.md` version history section for the affected schema
- [ ] Check: Does the recovery tool (`apps/web/public/recovery.html`) need updating?
- [ ] Check: Does the vault export format (`docs/VAULT_EXPORT_FORMAT.md`) need updating?

### 4.2 TypeScript Implementation

- [ ] Update type definition in `packages/core/src/{domain}/types.ts`
- [ ] If optional: use `field?: Type` syntax
- [ ] Update validator in `packages/core/src/{domain}/metadata.ts` or `schema.ts`
- [ ] If optional: validator accepts `undefined`/missing field
- [ ] If optional: validator applies default value when constructing the return object
- [ ] If breaking: validator checks `version` field and branches accordingly
- [ ] Add or update unit tests in `packages/crypto/` for the new or changed field

### 4.3 Rust Implementation

- [ ] Update struct in `crates/core/src/folder.rs` (or relevant file)
- [ ] If optional: use `Option<T>` with `#[serde(default)]` and `#[serde(skip_serializing_if = "Option::is_none")]`
- [ ] If new enum variant: ensure `#[serde(rename_all = "...")]` handles casing correctly
- [ ] Verify JSON round-trip: serialize then deserialize produces identical output
- [ ] Add or update cargo tests

### 4.4 Cross-Platform Verification

- [ ] Generate test JSON from TypeScript, deserialize in Rust (or vice versa)
- [ ] Verify old-format JSON (without new field) deserializes correctly in both implementations
- [ ] Verify new-format JSON (with new field) serializes identically in both implementations
- [ ] Run: `pnpm test` (TypeScript) and `cargo test -p cipherbox-core` (Rust)

### 4.5 Downstream Updates

- [ ] Recovery tool (`apps/web/public/recovery.html`): handles new field or version
- [ ] Vault export format (`docs/VAULT_EXPORT_FORMAT.md`): update if export-related schemas changed
- [ ] API client regeneration: run `pnpm api:generate` if API DTOs changed
- [ ] `docs/METADATA_SCHEMAS.md`: add entry to version history for the affected schema

---

## 5. Version Field Convention

The node/v3 schema (Phase 62) uses a `schema` discriminator field instead of a numeric `version`
field. The table below covers both the current node/v3 types and the surviving non-node schemas.

| Schema          | Current Version      | Version Lever          | Evolves Via                            |
| --------------- | -------------------- | ---------------------- | -------------------------------------- |
| Node (any kind) | `schema: 'node/v3'`  | `schema` field literal | Bump schema string (e.g., `'node/v4'`) |
| SealedChildRef  | --                   | Parent Node            | Evolves through parent Node schema     |
| PublishedNode   | --                   | Parent Node            | Evolves through parent Node schema     |
| NodeContent     | --                   | Parent Node            | Evolves through parent Node schema     |
| VersionEntry    | --                   | Parent Node            | Evolves through parent Node schema     |
| NodeWriteBody   | --                   | Parent Node            | Evolves through parent Node schema     |
| WriteChildRef   | --                   | Parent Node            | Evolves through parent Node `schema`   |
| VaultKeyBlob    | `0x03` (binary byte) | Version byte           | New version byte (0x04, etc.)          |
| DeviceRegistry  | `v1` / `v2`          | `version` string field | Own version field                      |
| DeviceEntry     | --                   | Parent DeviceRegistry  | Evolves through parent                 |

**Objects without independent version levers** (SealedChildRef, NodeContent, VersionEntry, etc.)
evolve only through the parent Node's `schema` discriminator. For example, adding a field to
`NodeContent` requires bumping `schema` from `'node/v3'` to `'node/v4'` unless the new field is
optional with a sensible default.

**Legacy schemas retired:** `FolderMetadata`, `FileMetadata`, `FilePointer`, `FolderEntry`,
`EncryptedVaultKeys`, and VaultKeyBlob v2 are retired in Phase 62 (greenfield hard-cut; no
migration path). The node/v3 `Node` / `SealedChildRef` / `PublishedNode` / `NodeContent` /
`VersionEntry` types replace them.

### node/v3 schema discriminator lever

The Node schema uses `schema: 'node/v3'` as its version handle. This is validated by
`validateNode` on decode -- a mismatch throws a `CryptoError` immediately. Any breaking change
to the Node JSON body structure (field rename, type change, field removal) must bump the schema
string to `'node/v4'` (and so on).

Because the schema string is embedded in the read-body (inside the AES-256-GCM sealed body),
a bump is also a key-epoch change in practice: the existing sealed bodies must be re-sealed
under the new schema version. This makes schema changes expensive by design -- the cost
discourages gratuitous changes.

For additive changes (new optional field, new kind), the schema string may remain `'node/v3'`
provided the decoder accepts missing fields with sensible defaults and the cross-language
validators are updated simultaneously.

### node/v3 cross-language vector lockstep discipline

The frozen wire format for node/v3 is asserted by the golden vectors in
`tests/vectors/node-codec.json` (body-byte PRIMARY LOCK vectors + full-seal FULL-SEAL vectors
committed in Phase 62 Plan 02). The Phase 69 Rust `Node` implementation must assert the
**same bytes** from the same fixture file:

- **PRIMARY LOCK:** `expected_read_body_hex` -- the UTF-8 hex of `JSON.stringify(encodeReadBody(node))`.
  IV-independent. Asserts the JSON body encoding is byte-identical across TypeScript and Rust.
- **FULL-SEAL LOCK:** `expected_published_node.readSealed` / `.writeSealed` -- a deterministic
  `base64(fixedIV || encryptAesGcmAad(bodyBytes, key, fixedIV, aad))`. Asserts the full
  AES-256-GCM seal (including AAD assembly) is byte-identical across runtimes.

**Lockstep rule:** Every new role byte added to the AAD (see
[ADR 0003](adr/0003-aad-bound-node-seal-encoding.md)) must extend both `tests/vectors/crypto/node-aad.json`
(AAD-only KAT) and `tests/vectors/node-codec.json` (full-seal vector using that role) before
merging. Extending one without the other is forbidden.

### AAD domain-separator version lever

The AAD-bound node-seal primitive (Phase 61) uses the domain string `"cipherbox/node-seal/v1"` as
a version lever embedded in the 45-byte AAD (see [ADR 0003](adr/0003-aad-bound-node-seal-encoding.md)
for the full encoding). Any change to the AAD byte layout -- field reorder, new field, or width
change -- must bump this string to `"cipherbox/node-seal/v2"` (and so on). A blob sealed under `v1`
will fail to unseal under `v2` by design, making format changes explicit rather than silent drift.

---

## 6. Testing Requirements

### 6.1 Backward Compatibility Test Pattern

For every schema change, add a test with a hardcoded JSON string representing the OLD format (before the change). Verify the new validator/deserializer accepts it and produces correct output.

**TypeScript example:**

```typescript
// Test: FileMetadata without versions field (pre-Phase 13 format)
it('accepts old format without versions field', () => {
  const oldFormatJson = JSON.parse(
    '{"version":"v1","cid":"bafybeig...","fileKeyEncrypted":"04ab...",' +
      '"fileIv":"aabbccdd11223344eeff5566","size":1024,"mimeType":"text/plain",' +
      '"createdAt":1705268100000,"modifiedAt":1705268100000}'
  );
  const result = validateFileMetadata(oldFormatJson);
  expect(result.versions).toBeUndefined();
  expect(result.encryptionMode).toBe('GCM'); // default applied
});
```

**Rust example:**

```rust
#[test]
fn accepts_old_format_without_versions() {
    let old_json = r#"{
        "version": "v1", "cid": "bafybeig...", "fileKeyEncrypted": "04ab...",
        "fileIv": "aabbccdd11223344eeff5566", "size": 1024,
        "mimeType": "text/plain", "encryptionMode": "GCM",
        "createdAt": 1705268100000, "modifiedAt": 1705268100000
    }"#;
    let meta: FileMetadata = serde_json::from_str(old_json).unwrap();
    assert!(meta.versions.is_none());
    assert_eq!(meta.encryption_mode, "GCM");
}
```

### 6.2 Cross-Platform Round-Trip Test

Produce a JSON string from TypeScript, feed it to the Rust deserializer (via a hardcoded string in a cargo test or a generated fixture file). Verify all fields parse correctly and no data is lost.

The reverse direction (Rust-produced JSON verified in TypeScript) is equally valuable, particularly for fields where serde and manual TypeScript serialization might diverge (e.g., `skip_serializing_if` behavior for empty arrays vs `undefined`).

### 6.3 Unknown Field Resilience Test

Add a JSON string with an extra field that does not exist in the current schema. Verify both TypeScript and Rust deserializers accept the data without error and ignore the unknown field. This confirms forward compatibility.

### 6.4 Cross-language KAT discipline for the AAD-bound seal and Node codec

The TypeScript and Rust implementations of `buildNodeAad`/`build_node_aad` and
`sealAesGcmAad`/`seal_aes_gcm_aad` must remain byte-identical. This is asserted by
the cross-language Known-Answer Test (KAT) in `tests/vectors/crypto/node-aad.json`,
which is loaded and verified by both `packages/crypto/src/__tests__/build-node-aad.test.ts`
and `crates/crypto/tests/cross_language.rs`.

The KAT is a merge gate: no PR that introduces a new role byte or changes the AAD byte
layout may merge until the KAT vector for that change is committed and passes on both
sides. See [ADR 0003](adr/0003-aad-bound-node-seal-encoding.md) for the standing rule.

For the Node codec specifically, `tests/vectors/node-codec.json` (Phase 62) provides:

- **Body-byte (PRIMARY LOCK)** vectors for all three node kinds (folder, file/GCM, file/CTR, root)
  asserting that `encodeReadBody` produces the same bytes in TypeScript and Rust.
- **Full-seal (FULL-SEAL)** vectors with a fixed IV asserting that `sealNode` produces the
  same `readSealed`/`writeSealed` base64 values in TypeScript and Rust.

The Phase 69 Rust `Node` implementation must load and assert these same vectors in
`crates/crypto/tests/cross_language.rs`. Any change to the Node body encoding must update
`tests/vectors/node-codec.json` before merging. See Section 5 for the lockstep rule.

---

## 7. Recovery Tool Compatibility Matrix

The recovery tool (`apps/web/public/recovery.html`) is a standalone HTML file that operates independently of the CipherBox web app. It has its own inline implementations of crypto operations and metadata parsing.

**When the recovery tool MUST be updated:**

- Any change that affects how files are discovered (IPNS resolution, folder traversal, child type detection)
- Any change that affects how files are decrypted (encryption algorithm, key format, IV format)
- Any breaking change (version bump) to FolderMetadata, FileMetadata, or EncryptedVaultKeys
- Adding a new encryption mode (the recovery tool must know how to decrypt it)

**When the recovery tool does NOT need updating:**

- Additive metadata fields that do not affect crypto operations (e.g., a hypothetical `tags` field on FilePointer)
- Changes to DeviceRegistry or DeviceEntry (the recovery tool does not use device data)
- UI-only changes or validator tightening that does not reject valid data

**Current recovery tool capabilities:**

- Reads FolderMetadata v2 (v1 also supported as legacy)
- Reads FileMetadata v1 (with optional `encryptionMode` and `versions` fields)
- Decrypts AES-256-GCM and AES-256-CTR content
- Resolves IPNS names via delegated routing API
- Traverses folder hierarchy recursively
- Handles per-file IPNS (v2 FilePointer) and inline file data (v1 FileEntry)

---

## 8. References

- **Metadata Schema Reference:** [docs/METADATA_SCHEMAS.md](METADATA_SCHEMAS.md) -- field tables, encryption, storage, and source file cross-references for all 10 metadata objects
- **Vault Export Format:** [docs/VAULT_EXPORT_FORMAT.md](VAULT_EXPORT_FORMAT.md) -- recovery procedure and ECIES ciphertext format
- **Technical Architecture:** [docs/ARCHITECTURE.md](ARCHITECTURE.md) -- encryption hierarchy and key management design

---

_Protocol version: 1.0_
_Last updated: 2026-02-21_
_Applies to: All metadata objects in `packages/core/src/` and `crates/core/src/`_

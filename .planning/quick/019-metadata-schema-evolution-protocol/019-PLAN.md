---
phase: quick-019
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - docs/METADATA_SCHEMAS.md
  - docs/METADATA_EVOLUTION_PROTOCOL.md
autonomous: true

must_haves:
  truths:
    - 'Every metadata object in the system is documented with field types, encryption, storage, and source file references'
    - 'A formal evolution protocol exists with clear rules for additive vs breaking changes'
    - 'Future tickets that touch metadata can reference these docs for backward compatibility rules'
  artifacts:
    - path: 'docs/METADATA_SCHEMAS.md'
      provides: 'Complete metadata schema reference'
      contains: 'FolderMetadata'
    - path: 'docs/METADATA_EVOLUTION_PROTOCOL.md'
      provides: 'Schema evolution rules and checklist'
      contains: 'Breaking Change'
  key_links:
    - from: 'docs/METADATA_EVOLUTION_PROTOCOL.md'
      to: 'docs/METADATA_SCHEMAS.md'
      via: 'cross-reference'
      pattern: 'METADATA_SCHEMAS.md'
---

<objective>
Create formal documentation for all CipherBox metadata schemas and a schema evolution protocol.

Purpose: CipherBox has 10 metadata objects across TypeScript and Rust with no formal evolution rules. Fields have been added informally (optional fields, serde defaults) without version bumps. This documentation establishes the ground truth and future rules before Phase 14 (Sharing) adds shared folder metadata.

Output: Two docs/ files (METADATA_SCHEMAS.md, METADATA_EVOLUTION_PROTOCOL.md) plus a Claude memory reference.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/STATE.md

Source files for all metadata types:
@packages/crypto/src/folder/types.ts
@packages/crypto/src/file/types.ts
@packages/crypto/src/vault/types.ts
@packages/crypto/src/registry/types.ts
@packages/crypto/src/folder/metadata.ts
@packages/crypto/src/file/metadata.ts
@packages/crypto/src/registry/schema.ts
@apps/desktop/src-tauri/src/crypto/folder.rs

Existing docs for style reference:
@docs/VAULT_EXPORT_FORMAT.md
</context>

<tasks>

<task type="auto">
  <name>Task 1: Create METADATA_SCHEMAS.md -- Complete metadata reference</name>
  <files>docs/METADATA_SCHEMAS.md</files>
  <action>
Create `docs/METADATA_SCHEMAS.md` documenting all 10 metadata objects. Follow the style and formatting conventions of `docs/VAULT_EXPORT_FORMAT.md` (tables, code blocks, clear field descriptions).

Structure:

<!-- outline -->

# CipherBox Metadata Schema Reference

**Version:** 1.0
**Last Updated:** 2026-02-21
**Status:** Stable

## Table of Contents

(numbered sections)

## 1. Overview

- CipherBox stores all metadata encrypted client-side
- Metadata exists in TypeScript (packages/crypto/) and Rust (apps/desktop/src-tauri/src/crypto/)
- Both implementations must produce byte-identical JSON (camelCase field names)

## 2. Encryption Hierarchy

Diagram/table showing:

- FolderMetadata: AES-256-GCM with folderKey -> IPFS (via IPNS)
- FileMetadata: AES-256-GCM with parent's folderKey -> IPFS (per-file IPNS)
- EncryptedVaultKeys: ECIES with user's secp256k1 publicKey -> Server DB
- DeviceRegistry: ECIES with user's secp256k1 publicKey -> IPFS (via IPNS)

## 3. Wire Format

Document the EncryptedFolderMetadata / EncryptedFileMetadata envelope:
{ iv: string (hex, 24 chars = 12 bytes), data: string (base64, AES-GCM ciphertext + 16-byte tag) }
Note: Both folder and file metadata use the same envelope format.

## 4. FolderMetadata (v2)

- Current version: v2
- Type definition (TypeScript syntax)
- Field table with: Field | Type | Required | Encoding | Description
- Encryption: AES-256-GCM with this folder's folderKey
- Storage: IPFS, addressed via folder's IPNS name
- Source files:
  - TS types: packages/crypto/src/folder/types.ts:15-20
  - TS validator: packages/crypto/src/folder/metadata.ts:32-78
  - Rust: apps/desktop/src-tauri/src/crypto/folder.rs:78-84
- Version history:
  - v1 (initial): children contained inline FileEntry with cid/fileKeyEncrypted/fileIv/size/encryptionMode
  - v2 (Phase 12.6): children use FilePointer (slim IPNS reference). v1 completely removed in Phase 11.2.

## 5. FolderChild (union)

- Discriminated union on `type` field: 'folder' | 'file'
- TS: FolderEntry | FilePointer
- Rust: serde tagged enum FolderChild { Folder(FolderEntry), File(FilePointer) }
- Source: folder/types.ts:25, folder.rs:66-73

## 6. FolderEntry

- Full field table
- Note: ipnsPrivateKeyEncrypted and folderKeyEncrypted are ECIES-wrapped with parent folder owner's publicKey
- Source: folder/types.ts:31-47, folder.rs:28-45
- No version history (unchanged since initial design)

## 7. FilePointer

- Full field table
- Note: Slim reference -- no crypto material. All file data is in the per-file IPNS record.
- Source: file/types.ts:57-69, folder.rs:50-63
- Added in Phase 12.6 (replaced inline FileEntry)

## 8. FileMetadata (v1)

- Current version: v1
- Full field table
- Note encryptionMode is optional (defaults to 'GCM') -- added in Phase 12.6 for CTR support
- Note versions is optional (omitted when empty) -- added in Phase 13
- Encryption: AES-256-GCM with PARENT folder's folderKey (NOT the file's own key)
- Storage: IPFS, addressed via file's own IPNS name (derived via HKDF from user privateKey + fileId)
- Source files:
  - TS types: packages/crypto/src/file/types.ts:30-51
  - TS validator: packages/crypto/src/file/metadata.ts:93-188
  - Rust: apps/desktop/src-tauri/src/crypto/folder.rs:166-192
- Version history:
  - v1 (Phase 12.6): Initial per-file IPNS schema
  - v1 + encryptionMode (Phase 12.6/12.1): Optional field, defaults to 'GCM'. NOT a version bump.
  - v1 + versions (Phase 13): Optional VersionEntry array. NOT a version bump.
  - NOTE: Version was NOT bumped for either addition. This is the motivation for the evolution protocol.

## 9. VersionEntry

- Full field table
- Note: encryptionMode is REQUIRED (not optional like in FileMetadata) because past versions always record explicit mode
- Source: file/types.ts:10-23, folder.rs:145-160
- TS validator: file/metadata.ts:32-87
- Added in Phase 13

## 10. EncryptedVaultKeys

- Full field table (2 fields: encryptedRootFolderKey, encryptedIpnsPrivateKey)
- Note: Uint8Array in TS (not hex strings like other encrypted fields)
- Encryption: ECIES with user's secp256k1 publicKey
- Storage: Server database (users table)
- Source: packages/crypto/src/vault/types.ts:32-37
- No Rust equivalent (desktop gets vault keys from API response)
- Version history: rootIpnsPublicKey removed in Phase 12.3.1 (derivable from private key)

## 11. DeviceRegistry (v1)

- Current version: v1
- Full field table
- sequenceNumber: monotonically increasing, used for IPNS sequence ordering
- Encryption: ECIES with user's secp256k1 publicKey (entire registry as one blob)
- Storage: IPFS, addressed via device registry IPNS name (derived via HKDF)
- Source:
  - TS types: packages/crypto/src/registry/types.ts:54-61
  - TS validator: packages/crypto/src/registry/schema.ts:26-58
- No Rust equivalent (desktop uses TS types via API)
- Added in Phase 12.2

## 12. DeviceEntry

- Full field table (12 fields)
- Note validation constraints: deviceId = 64 hex chars (SHA-256), publicKey = 130 hex chars (uncompressed secp256k1), ipHash = 64 hex chars
- Note max lengths: name 200, appVersion 50, deviceModel 200
- Source: registry/types.ts:21-46, validator: registry/schema.ts:63-136
- Added in Phase 12.2

## 13. Cross-Implementation Parity

Table comparing TS vs Rust for each type:
| Schema | TypeScript | Rust | Notes |

- FolderMetadata: both
- FolderEntry: both
- FilePointer: both
- FolderChild: both
- FileMetadata: both
- VersionEntry: both
- EncryptedVaultKeys: TS only
- DeviceRegistry: TS only
- DeviceEntry: TS only

## 14. IPNS Key Derivation Summary

Table of all HKDF-derived IPNS keys:
| Purpose | Salt | Info | Source |
| Vault root IPNS | CipherBox-v1 | cipherbox-vault-ipns-v1 | vault crypto |
| Device registry IPNS | CipherBox-v1 | cipherbox-device-registry-ipns-v1 | registry crypto |
| Per-file IPNS | CipherBox-v1 | cipherbox-file-ipns-v1:{fileId} | file crypto |
Note: Folder IPNS keys are randomly generated (not derived) and stored ECIES-wrapped in parent folder metadata.

Do NOT copy-paste type definitions verbatim. Summarize them in field tables (like VAULT_EXPORT_FORMAT.md does). Cross-reference source file paths with line numbers.
</action>
<verify>
File exists at docs/METADATA_SCHEMAS.md. Manual review: all 10 metadata objects documented, each has field table + encryption + storage + source refs + version history where applicable.
</verify>
<done>Complete metadata reference covering all 10 objects with field tables, encryption details, storage locations, source file cross-references, and version history.</done>
</task>

<task type="auto">
  <name>Task 2: Create METADATA_EVOLUTION_PROTOCOL.md -- Formal evolution rules</name>
  <files>docs/METADATA_EVOLUTION_PROTOCOL.md</files>
  <action>
Create `docs/METADATA_EVOLUTION_PROTOCOL.md` with formal rules for evolving metadata schemas. This is the key deliverable -- it prevents ad-hoc field additions without considering cross-platform compatibility.

Structure:

<!-- outline -->

# CipherBox Metadata Schema Evolution Protocol

**Version:** 1.0
**Last Updated:** 2026-02-21
**Status:** Active

## 1. Purpose

Why this protocol exists: metadata is encrypted and stored on IPFS. Once written, old records may persist indefinitely. Clients of different versions must coexist. Desktop (Rust) and web (TypeScript) must agree on schemas.

## 2. Guiding Principles

1. **Backward compatibility is mandatory.** New clients must read old data. Old clients must not crash on new data (graceful degradation).
2. **Forward compatibility via optional fields.** Unknown fields are ignored (JSON.parse/serde default behavior).
3. **Version bumps are breaking changes.** Incrementing the version field signals old clients cannot fully understand the data. This is a last resort.
4. **Both platforms move together.** A schema change is not complete until both TS and Rust implementations are updated.
5. **Validators are the source of truth.** If the validator doesn't check it, the field doesn't exist from a compatibility perspective.

## 3. Change Classification

### 3.1 Additive (Non-Breaking) Changes

- Adding a NEW optional field with a sensible default
- Adding a new enum variant to a string union field (if consumers ignore unknown variants)
- Adding new properties to an existing object field

Rules:

- Field MUST be optional in TypeScript (`field?: Type`)
- Field MUST have `#[serde(default)]` in Rust
- Field MUST have `#[serde(skip_serializing_if = "Option::is_none")]` in Rust (or equivalent for Vec with is_empty)
- Validator MUST accept data without the new field
- Validator MUST NOT reject unknown fields (already true -- we use manual validation, not strict schema validation)
- Default value MUST preserve existing behavior (e.g., encryptionMode defaults to 'GCM' because all pre-CTR files were GCM)
- Version field is NOT bumped

Examples from history:

- FileMetadata.encryptionMode (Phase 12.6): optional, defaults to 'GCM'
- FileMetadata.versions (Phase 13): optional, omitted when empty

### 3.2 Breaking Changes (Version Bump Required)

- Removing a field
- Changing a field's type
- Making an optional field required
- Changing the semantics of an existing field
- Restructuring the children array format

Rules:

- Version field MUST be bumped (e.g., 'v1' -> 'v2')
- Old version support: decide one of:
  a) Migration path: write converter that upgrades old format to new (preferred for data at rest)
  b) Dual support: read both versions, write only new (temporary -- converge within 2 releases)
  c) Clean break: reject old format entirely (only when ALL data can be wiped, e.g., pre-production)
- Both TS and Rust validators must be updated simultaneously
- Recovery tool (recovery.html) must handle both old and new versions unless clean break

Examples from history:

- FolderMetadata v1 -> v2 (Phase 12.6): Changed file children from inline FileEntry to slim FilePointer. Clean break chosen (pre-production, vault wipe). v1 later removed entirely (Phase 11.2).

### 3.3 Dangerous Gray Areas

- Changing default values: This is a breaking change in disguise. If encryptionMode default changed from 'GCM' to 'CTR', old files would be decrypted with wrong mode.
- Widening a union type: Adding 'CTR' to encryptionMode union is safe only if old clients handle unknown modes gracefully (they don't -- they'd pass unknown mode to Web Crypto API and fail). MUST be paired with the optional-field pattern.
- Reordering array elements: versions array order (newest-first) is semantic. Changing to oldest-first would break all version display code.

## 4. Evolution Checklist

For EVERY metadata schema change, complete this checklist:

### 4.1 Before Implementation

- [ ] Classify change: Additive or Breaking?
- [ ] If additive: What is the default value? Does it preserve existing behavior?
- [ ] If breaking: What version bump strategy? (migration / dual / clean break)
- [ ] Document the change in METADATA_SCHEMAS.md version history section
- [ ] Check: Does the recovery tool (recovery.html) need updating?

### 4.2 TypeScript Implementation

- [ ] Update type definition in packages/crypto/src/{domain}/types.ts
- [ ] If optional: use `field?: Type` syntax
- [ ] Update validator in packages/crypto/src/{domain}/metadata.ts or schema.ts
- [ ] If optional: validator accepts undefined/missing field
- [ ] If optional: validator applies default when constructing return object
- [ ] If breaking: validator checks version field and branches
- [ ] Add/update unit tests in packages/crypto for the new/changed field

### 4.3 Rust Implementation

- [ ] Update struct in apps/desktop/src-tauri/src/crypto/folder.rs (or relevant file)
- [ ] If optional: use `Option<T>` with `#[serde(default)]` and `#[serde(skip_serializing_if = "Option::is_none")]`
- [ ] If new enum variant: ensure `#[serde(rename_all = "...")]` handles casing
- [ ] Verify JSON round-trip: serialize -> deserialize produces identical output
- [ ] Add/update cargo tests

### 4.4 Cross-Platform Verification

- [ ] Generate test JSON from TypeScript, deserialize in Rust (or vice versa)
- [ ] Verify old-format JSON (without new field) deserializes correctly in both
- [ ] Verify new-format JSON (with new field) serializes identically in both
- [ ] Run: `pnpm test` (TS) + `cargo test --features fuse` (Rust)

### 4.5 Downstream Updates

- [ ] Recovery tool (recovery.html): handles new field/version
- [ ] Vault export format (docs/VAULT_EXPORT_FORMAT.md): update if export format changes
- [ ] API client regeneration: `pnpm api:generate` if API DTOs changed
- [ ] METADATA_SCHEMAS.md: add entry to version history for affected schema

## 5. Version Field Convention

All versioned metadata objects use a string version field: 'v1', 'v2', etc.

| Schema | Current Version | Has Version Field |
| FolderMetadata | v2 | Yes |
| FileMetadata | v1 | Yes |
| DeviceRegistry | v1 | Yes |
| EncryptedVaultKeys | (none) | No |
| FolderEntry | (none) | No |
| FilePointer | (none) | No |
| VersionEntry | (none) | No |
| DeviceEntry | (none) | No |

Objects without version fields (FolderEntry, FilePointer, VersionEntry, DeviceEntry) evolve only via their parent's version. For example, changing FilePointer fields requires bumping FolderMetadata version.

EncryptedVaultKeys has no version field. Changes to its structure should be paired with a new vault export format version.

## 6. Testing Requirements

### 6.1 Backward Compatibility Test Pattern

For every schema change, add a test with a hardcoded JSON string representing the OLD format (before the change). Verify the new validator/deserializer accepts it and produces correct output.

```typescript
// Example: FileMetadata without versions field (pre-Phase 13)
const oldFormatJson =
  '{"version":"v1","cid":"bafy...","fileKeyEncrypted":"04...","fileIv":"aabb...","size":1024,"mimeType":"text/plain","createdAt":1705268100000,"modifiedAt":1705268100000}';
const result = validateFileMetadata(JSON.parse(oldFormatJson));
expect(result.versions).toBeUndefined();
expect(result.encryptionMode).toBe('GCM'); // default applied
```

### 6.2 Cross-Platform Round-Trip Test

Produce JSON from TypeScript, feed to Rust deserializer (via file or inline string in cargo test). Verify all fields parse correctly.

## 7. Recovery Tool Compatibility Matrix

The recovery tool (apps/web/public/recovery.html) is a standalone HTML file that must work independently. It has its own inline implementations of crypto operations.

When updating schemas:

- The recovery tool MUST be updated for any change that affects how files are discovered or decrypted
- Additive metadata fields that don't affect crypto operations (e.g., a hypothetical `tags` field) do NOT require recovery tool updates
- Breaking changes (version bumps) ALWAYS require recovery tool updates

## 8. References

- Metadata Schema Reference: docs/METADATA_SCHEMAS.md
- Vault Export Format: docs/VAULT_EXPORT_FORMAT.md
- Technical Architecture: 00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md
- Data Flows: 00-Preliminary-R&D/Documentation/DATA_FLOWS.md

Write clean, specific prose. Do NOT use vague language. Every rule must be actionable. The checklist in Section 4 is the most important part -- it's what developers will actually use.
</action>
<verify>
File exists at docs/METADATA_EVOLUTION_PROTOCOL.md. Manual review: contains change classification (additive vs breaking), checklist covering TS/Rust/recovery/tests, version field convention table, and backward compatibility test pattern.
</verify>
<done>Formal evolution protocol with classification rules, dual-platform checklist, version convention, testing requirements, and recovery tool compatibility matrix.</done>
</task>

<task type="auto">
  <name>Task 3: Update Claude memory with metadata documentation reference</name>
  <files></files>
  <action>
Add the following entry to the MEMORY.md file (under a new "## Metadata Schema Documentation" heading, placed after the "## Patterns and Lessons" section):

```markdown
## Metadata Schema Documentation

- **Schema reference:** `docs/METADATA_SCHEMAS.md` -- documents all 10 metadata objects (FolderMetadata, FileMetadata, DeviceRegistry, etc.) with field tables, encryption, storage, source file cross-references
- **Evolution protocol:** `docs/METADATA_EVOLUTION_PROTOCOL.md` -- formal rules for evolving metadata schemas (additive vs breaking changes, version bump rules, dual-platform checklist)
- **ALWAYS consult these docs** before any ticket that adds/removes/changes fields on metadata objects
- Evolution checklist (Section 4 of protocol) must be completed for every schema change
- Key rule: optional fields with sensible defaults = no version bump; removing/changing fields = version bump required
```

This ensures future Claude sessions are aware of these docs when working on metadata-related tickets.

NOTE: The MEMORY.md file is at `/Users/michael/.claude/projects/-Users-michael-Code-cipher-box/memory/MEMORY.md`. Read it first, then append the new section.
</action>
<verify>
MEMORY.md contains the new "Metadata Schema Documentation" section with references to both docs.
</verify>
<done>Claude memory updated with metadata documentation references for future ticket awareness.</done>
</task>

</tasks>

<verification>
1. `docs/METADATA_SCHEMAS.md` exists and documents all 10 metadata objects
2. `docs/METADATA_EVOLUTION_PROTOCOL.md` exists with formal evolution rules
3. Both files follow the style conventions of existing `docs/VAULT_EXPORT_FORMAT.md`
4. Claude MEMORY.md references both new documents
5. No source code was modified (documentation only)
</verification>

<success_criteria>

- All 10 metadata objects documented with field tables, encryption keys, storage locations, and source file references
- Evolution protocol contains actionable classification rules and a checklist covering both TypeScript and Rust
- Version history for each schema captures when fields were added and whether version was bumped
- Claude memory references these docs for future metadata-related tickets
  </success_criteria>

<output>
After completion, create `.planning/quick/019-metadata-schema-evolution-protocol/019-SUMMARY.md`
</output>

---
phase: 62-unified-node-codec-core-keystone
plan: "04"
subsystem: docs
tags: [docs, node-v3, metadata-schemas, invariants, sc6]
status: complete

dependency_graph:
  requires: ["62-01", "62-02", "62-03"]
  provides:
    - docs/METADATA_SCHEMAS.md (node/v3 full static schema + two SC#6 invariants)
    - docs/METADATA_EVOLUTION_PROTOCOL.md (node/v3 lever + vector lockstep discipline)
    - docs/FILESYSTEM_SPECIFICATION.md (node/v3 storage description)
  affects:
    - Phase 69 Rust implementers (full schema + frozen vector discipline documented)

tech_stack:
  added: []
  patterns:
    - generation-as-convergence-witness invariant documented (SC#6 invariant 1)
    - fileKey-inside-sealed-read-body semantic type change documented (SC#6 invariant 2)
    - node/v3 schema discriminator as version lever (replaces numeric version field)
    - Cross-language vector lockstep discipline for node-codec.json (Phase-69 Rust gate)

key_files:
  created: []
  modified:
    - docs/METADATA_SCHEMAS.md
    - docs/METADATA_EVOLUTION_PROTOCOL.md
    - docs/FILESYSTEM_SPECIFICATION.md

decisions:
  - "Legacy schema sections (FolderMetadata/FileMetadata/FilePointer/FolderEntry/VaultKeyBlob v2) replaced, not retained — presented only in version-history tables and the EncryptedVaultKeys (Removed) historical note"
  - "ADR 0003 cited for AAD/role byte encoding, not restated in METADATA_SCHEMAS.md"
  - "Flow docs (navigation/rotation/write-revocation) explicitly deferred to phases 63-69 with a callout block in the Overview"
  - "DeviceRegistry and DeviceEntry sections retained unchanged — still active schemas"

metrics:
  duration: "14 minutes"
  completed: "2026-06-28"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 3
---

# Phase 62 Plan 04: Metadata Schema Documentation (D-07) Summary

Rewrote METADATA_SCHEMAS.md for the full static node/v3 schema and both SC#6 invariants, and
updated METADATA_EVOLUTION_PROTOCOL.md and FILESYSTEM_SPECIFICATION.md pointer docs.

## What Was Built

### Task 1: METADATA_SCHEMAS.md rewrite

Complete rewrite replacing 15 sections describing legacy types with 15 sections for node/v3:

- Sections 3-9 document the full static schema: `Node` (discriminated by kind, JSON body
  encoding rules, fixed field order, versionFloor as decimal string), `SealedChildRef` (exact
  5-field set, readKeySealed role 0x02), `PublishedNode` (plaintext envelope, sealed body wire
  format base64(IV||ct+tag)), `NodeContent` (self-sealed role 0x03, fileKey as Uint8Array),
  `VersionEntry` (mandatory encryptionMode), `NodeWriteBody`/`WriteChildRef` (write-chain,
  writeKeySealed role 0x04, separation invariant), VaultKeyBlob v3 (0x03|u16_BE|...|u16_BE|...).
- Section 10 "Invariants" documents both SC#6 items:
  1. generation-as-convergence-witness: authoritative only on child's own PublishedNode;
     SealedChildRef.generation and shares.rootGeneration are staleness mirrors only; distinct
     from keyEpoch and sequenceNumber (counter table provided, CONTEXT.md cited)
  2. fileKey semantic type change: ECIES hex string (258 chars) → raw 32-byte Uint8Array inside
     sealed body; applies to NodeContent.fileKey and every VersionEntry.fileKey; presented as a
     type change with a before/after comparison table
- Section 2 encryption hierarchy updated for node/v3 (2 sealed bodies, NodeContent embedded)
- Sections 12-15 retain DeviceRegistry/DeviceEntry/IPNS derivation; parity table updated for
  Phase-69 Rust twin status
- Explicit deferral callout block for flow docs (phases 63-69) in section 1 Overview
- markdownlint clean; prettier-formatted; no bold-as-heading violations

### Task 2: METADATA_EVOLUTION_PROTOCOL.md and FILESYSTEM_SPECIFICATION.md pointer updates

METADATA_EVOLUTION_PROTOCOL.md changes:

- Section 5 version table: replaced legacy schema rows with node/v3 entries; `schema: 'node/v3'`
  as version lever (SealedChildRef/NodeContent/VersionEntry etc. evolve through parent Node);
  VaultKeyBlob uses binary version byte; legacy schemas marked as retired
- New "node/v3 schema discriminator lever" subsection: explains schema bump mechanics and cost
- New "node/v3 cross-language vector lockstep discipline" subsection: PRIMARY LOCK and FULL-SEAL
  vector discipline from tests/vectors/node-codec.json; lockstep rule (new role byte extends
  both node-aad.json and node-codec.json); Phase 69 Rust gate
- Section 6.4 extended: node-codec.json body-byte and full-seal vectors added alongside
  existing node-aad.json KAT; Phase-69 Rust cross_language.rs requirement

FILESYSTEM_SPECIFICATION.md changes:

- "Metadata Storage" section expanded from 3 lines to a full node/v3 storage description:
  PublishedNode as IPFS blob + IPNS k51 name; readSealed/writeSealed two-body split; vault v3
  blob at dedicated IPNS name; AAD sealed body wire format; links to METADATA_SCHEMAS.md,
  METADATA_EVOLUTION_PROTOCOL.md, and ADR 0003

## Verification Results

```
npx markdownlint docs/METADATA_SCHEMAS.md                            -> no errors
npx markdownlint docs/METADATA_EVOLUTION_PROTOCOL.md docs/FILESYSTEM_SPECIFICATION.md -> no errors
grep -c "node/v3" docs/METADATA_SCHEMAS.md                           -> 15
grep -c "SealedChildRef" docs/METADATA_SCHEMAS.md                    -> 11
grep -c "PublishedNode" docs/METADATA_SCHEMAS.md                     -> 9
grep -ci "semantic type change" docs/METADATA_SCHEMAS.md             -> 5
grep -c "node/v3" docs/METADATA_EVOLUTION_PROTOCOL.md                -> 10
grep -c "node-codec.json" docs/METADATA_EVOLUTION_PROTOCOL.md        -> 4
grep -c "node/v3" docs/FILESYSTEM_SPECIFICATION.md                   -> 3
```

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None - documents the shipped implementation from Plans 01-03 accurately. No placeholders or
TODOs in the doc content.

## Threat Flags

No new trust-boundary surface introduced. This plan documents static schema only.

T-62-09 (doc drift) mitigated: all field tables and type descriptions were verified against
`packages/core/src/node/types.ts` and `packages/core/src/vault/blob.ts` as-shipped.
T-62-SC: no new packages added.

## Self-Check: PASSED

Files exist:

- FOUND: docs/METADATA_SCHEMAS.md (modified)
- FOUND: docs/METADATA_EVOLUTION_PROTOCOL.md (modified)
- FOUND: docs/FILESYSTEM_SPECIFICATION.md (modified)

Commits exist:

- FOUND: 8e93db6b2 (Task 1 - METADATA_SCHEMAS.md rewrite)
- FOUND: a4b95092e (Task 2 - METADATA_EVOLUTION_PROTOCOL + FILESYSTEM_SPECIFICATION)

---
phase: quick-019
plan: 01
subsystem: documentation
tags: [metadata, schema, evolution, protocol, documentation]
dependency-graph:
  requires: []
  provides: [metadata-schema-reference, schema-evolution-protocol]
  affects: [phase-14-sharing, any-metadata-changes]
tech-stack:
  added: []
  patterns: [additive-field-evolution, version-bump-breaking-changes]
key-files:
  created:
    - docs/METADATA_SCHEMAS.md
    - docs/METADATA_EVOLUTION_PROTOCOL.md
  modified: []
decisions:
  - id: q019-d01
    description: 'All 10 metadata objects documented with field tables, encryption, storage, and source references'
    rationale: 'Ground truth before Phase 14 adds shared folder metadata'
  - id: q019-d02
    description: 'Formal additive vs breaking change classification with dual-platform checklist'
    rationale: 'Prevents ad-hoc field additions without considering cross-platform compat'
metrics:
  duration: 5m
  completed: 2026-02-21
---

# Quick Task 019: Metadata Schema Evolution Protocol Summary

**One-liner:** Complete metadata schema reference (10 objects) and formal evolution protocol with dual-platform checklist for additive vs breaking changes.

## What Was Done

### Task 1: METADATA_SCHEMAS.md -- Complete Metadata Reference

Created `docs/METADATA_SCHEMAS.md` documenting all 10 metadata objects in the system:

1. **FolderMetadata (v2)** -- top-level folder with children array
2. **FolderChild** -- discriminated union (folder | file)
3. **FolderEntry** -- subfolder with ECIES-wrapped keys
4. **FilePointer** -- slim per-file IPNS reference
5. **FileMetadata (v1)** -- per-file crypto material with optional encryptionMode and versions
6. **VersionEntry** -- past file version with full crypto context
7. **EncryptedVaultKeys** -- ECIES-wrapped root keys for server storage
8. **DeviceRegistry (v1)** -- encrypted device list on IPFS
9. **DeviceEntry** -- individual device record with auth status
10. **Wire Format** -- shared `{iv, data}` JSON envelope for IPFS storage

Each object includes:

- Field table with types, encoding, and required/optional
- Encryption algorithm and key used
- Storage location and IPNS addressing
- Source file cross-references (TypeScript and Rust with line numbers)
- Version history documenting when fields were added and whether version was bumped

Also includes encryption hierarchy table, cross-implementation parity matrix (TS vs Rust), and IPNS key derivation summary (HKDF salt/info for vault, registry, and per-file).

### Task 2: METADATA_EVOLUTION_PROTOCOL.md -- Formal Evolution Rules

Created `docs/METADATA_EVOLUTION_PROTOCOL.md` with:

- **Change classification:** Additive (optional field + sensible default, no version bump) vs Breaking (version bump required)
- **Dangerous gray areas:** Changing defaults, widening unions, reordering arrays, renaming fields
- **Evolution checklist:** 5-section checklist covering before-implementation, TypeScript, Rust, cross-platform verification, and downstream updates
- **Version field convention:** Table showing which schemas have version fields and how versionless schemas (FolderEntry, FilePointer, etc.) evolve through their parent
- **Testing requirements:** Backward compatibility test patterns, cross-platform round-trip tests, unknown field resilience tests
- **Recovery tool compatibility matrix:** When the recovery tool must vs need not be updated

### Task 3: Claude Memory Reference

Added "Metadata Schema Documentation" section to MEMORY.md with references to both docs and key rules for future sessions.

## Decisions Made

1. **All 10 metadata objects get dedicated sections** -- not just the versioned ones. Wire format, union types, and embedded objects (VersionEntry, DeviceEntry) are documented with the same rigor.
2. **Evolution protocol formalizes the existing informal pattern** -- optional fields with serde defaults are now explicitly classified as "additive non-breaking changes" with documented rules.
3. **Checklist is the central deliverable** -- Section 4 of the protocol is designed for copy-paste into tickets and PRs.

## Deviations from Plan

None -- plan executed exactly as written.

## Commits

| Task | Commit      | Description                            |
| ---- | ----------- | -------------------------------------- |
| 1    | `b65e7629c` | Add complete metadata schema reference |
| 2    | `dcb49e1bc` | Add metadata schema evolution protocol |
| 3    | --          | MEMORY.md update (not in git repo)     |

## Next Phase Readiness

These docs are ready for Phase 14 (Sharing) which will add shared folder metadata. The evolution protocol and checklist should be followed when designing the sharing metadata schema.

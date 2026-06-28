---
phase: 61-aad-bound-seal-primitive-and-cross-language-kat
plan: "05"
subsystem: docs/crypto-encoding
tags: [adr, aes-gcm, aad, cross-language, documentation]
requires: [61-01, 61-03]
provides: [ADR-0003, docs-aad-seal-freeze]
affects: [docs/adr, docs/METADATA_SCHEMAS.md, docs/METADATA_EVOLUTION_PROTOCOL.md, docs/FILESYSTEM_SPECIFICATION.md]
tech_stack:
  added: []
  patterns: [ADR freeze discipline, markdownlint-clean doc updates]
key_files:
  created:
    - docs/adr/0003-aad-bound-node-seal-encoding.md
  modified:
    - docs/METADATA_SCHEMAS.md
    - docs/METADATA_EVOLUTION_PROTOCOL.md
    - docs/FILESYSTEM_SPECIFICATION.md
decisions:
  - "ADR 0003 is the single authoritative freeze for the 45-byte AAD encoding, AEAD parameters, and the standing rule that every new role byte must extend the cross-language KAT"
  - "The three metadata/filesystem docs link ADR 0003 rather than restating the byte layout (DRY)"
  - "Node schema documentation deferred to phase 62 per D-05 scope boundary"
metrics:
  duration: "~10 minutes"
  completed: 2026-06-28
  tasks_completed: 2
  tasks_total: 2
  files_changed: 4
status: complete
---

# Phase 61 Plan 05: Documentation — AAD-bound node-seal encoding freeze Summary

ADR 0003 authored and committed as the authoritative freeze of the AES-256-GCM AAD-bound
node-seal encoding; METADATA_SCHEMAS.md, METADATA_EVOLUTION_PROTOCOL.md, and
FILESYSTEM_SPECIFICATION.md updated to link the ADR rather than restate the encoding.

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | Author ADR 0003 | 1f6d0be | docs/adr/0003-aad-bound-node-seal-encoding.md |
| 2 | Link ADR 0003 from three docs | 374f5b1 | docs/METADATA_SCHEMAS.md, docs/METADATA_EVOLUTION_PROTOCOL.md, docs/FILESYSTEM_SPECIFICATION.md |

## What Was Built

### ADR 0003 (docs/adr/0003-aad-bound-node-seal-encoding.md)

The authoritative freeze of the AAD-bound node-seal encoding. Contains:

- The 45-byte AAD byte-encoding table: domain `"cipherbox/node-seal/v1"` (22 bytes UTF-8)
  + `0x00` null separator + `nodeId` (16 bytes raw RFC-4122 UUID) + `kind` (1 byte) +
  `generation` (4 bytes big-endian u32) + `role` (1 byte)
- Kind-byte table: `0x01` folder / `0x02` file / `0x03` root
- Role-byte table: `0x01` body / `0x02` child-readkey / `0x03` content / `0x04` child-writekey
- AEAD parameters: AES-256-GCM, 12-byte random IV per seal, 16-byte GCM tag,
  `[IV(12)][ciphertext+tag]` sealed blob layout
- Standing rules: every new role byte must extend the cross-language KAT; any layout change
  bumps domain to `node-seal/v2`; `buildNodeAad` is fail-closed
- Pointers to TS and Rust implementations and the KAT fixture

### Doc updates

- **METADATA_SCHEMAS.md** §2: added "AAD-bound seal primitive" subsection summarising the
  primitive and linking ADR 0003. No Node-schema text added (phase 62 scope).
- **METADATA_EVOLUTION_PROTOCOL.md** §5: added "AAD domain-separator version lever" explaining
  the `node-seal/v1` → `node-seal/v2` bump mechanism. §6: added §6.4 "Cross-language KAT
  discipline" recording the merge-gate rule and linking ADR 0003.
- **FILESYSTEM_SPECIFICATION.md** Metadata Storage: one-line note that node metadata bodies
  use the AAD-bound AES-256-GCM seal primitive, with link to ADR 0003.

## Deviations from Plan

None — plan executed exactly as written. The ADR byte-encoding table matches
`packages/crypto/src/aes/seal.ts` `buildNodeAad` implementation byte-for-byte. The
`6.4` subsection number in METADATA_EVOLUTION_PROTOCOL.md was chosen to preserve the
existing 6.1–6.3 numbering rather than inserting out of order.

## Verification

- `test -f docs/adr/0003-aad-bound-node-seal-encoding.md` PASS
- `grep -q "node-seal/v1" docs/adr/0003-aad-bound-node-seal-encoding.md` PASS
- `grep -qi "every new role byte" docs/adr/0003-aad-bound-node-seal-encoding.md` PASS
- `grep -q "0003-aad-bound-node-seal-encoding" docs/METADATA_SCHEMAS.md` PASS
- `grep -q "0003-aad-bound-node-seal-encoding" docs/METADATA_EVOLUTION_PROTOCOL.md` PASS
- `grep -q "0003-aad-bound-node-seal-encoding" docs/FILESYSTEM_SPECIFICATION.md` PASS
- `npx markdownlint docs/adr/0003-aad-bound-node-seal-encoding.md` PASS (no violations)
- `npx markdownlint docs/METADATA_SCHEMAS.md docs/METADATA_EVOLUTION_PROTOCOL.md docs/FILESYSTEM_SPECIFICATION.md` PASS

## Self-Check: PASSED

All files exist and all commits verified in git log.

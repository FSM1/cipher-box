---
created: 2026-07-03T00:00:00Z
title: Deduplicate sdk/sdk-core write-plane helper sequences
area: sdk
files:
  - packages/sdk/src/client.ts:2825
  - packages/sdk/src/client.ts:851
  - packages/sdk/src/bin/index.ts:72
  - packages/sdk-core/src/file/index.ts:276
source: ship-phase 68.1 simplify review
---

## Problem

Phase 68.1's wave-parallel execution left self-documented copy-pastes across the
write plane:

- `replaceFile` / `restoreFileVersion` / `deleteFileVersion` (client.ts:2825/2906/2988)
  are near-byte-identical (requireFolder → resolveFileWriteChainKeys → 14-field
  updateFileMetadata → identical 3-key-zeroing finally); only `createVersion` /
  `deletedCid` vary. Includes dead `void versionIndex;` slots at :2919/:3001.
- The write-chain hop walk (find WriteChildRef by UUID → unsealChildWriteKey under
  parent mirror generation → unsealNode validate-before-trust) appears at 7 sites
  (client.ts:851, :2561, :2715, :3810, :4224, :4416, :4530) with divergent
  fail-open/fail-closed choices — needs a designed `walkChildWriteKey` primitive,
  not a mechanical extract.
- `packages/sdk/src/bin/index.ts:72/:102` — `getWriteBodyParams` +
  `adoptPublishedFolderState` copied from client.ts:669/:701 ("Mirrors
  CipherBoxClient...").
- The "is real non-zero 32-byte writeKey" predicate is spelled 4 different ways at
  7 sites.
- The TEE fail-closed enrollment gate (validate → hexToBytes → wrapKey →
  bytesToHex) is triplicated verbatim in sdk-core (file/index.ts:276,
  vault/index.ts:130, folder/registration.ts:88) — extract `wrapIpnsKeyForTee`.

## Solution

Design-first refactor (zeroization ownership must stay with the terminal owner —
D-09): extract the version-op core, a `walkChildWriteKey` primitive with explicit
fail-open/fail-closed mode, a single writeKey-validity predicate, and
`wrapIpnsKeyForTee`; then re-point bin/index.ts at the client helpers. Gate with
the sdk unit suites plus a full web-e2e run — this is high-blast-radius code.

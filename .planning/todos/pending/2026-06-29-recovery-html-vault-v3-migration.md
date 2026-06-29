---
created: 2026-06-29
title: Migrate recovery.html emergency page from vault blob v2 to v3
area: web
files:
  - apps/web/public/recovery.html
---

## Problem

Phase 62 hard-cut the vault recovery blob to v3 (D-05): two-key layout
`0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)`,
and deleted the v1/v2 serializers plus `encryptedRootFolderKey`.

The static emergency-recovery page `apps/web/public/recovery.html` still
implements `deserializeVaultBlobV2` and references `encryptedRootFolderKey`. It
is a standalone HTML/JS page (not TypeScript source, not imported by any phase-62
plan), so it was out of scope and the typecheck gate never saw it. Against a real
v3 vault blob it would fail to recover.

No real-world impact yet: the app is intentionally non-runnable mid-milestone
(D-01) and staging is wiped/greenfield.

## Solution

When the vault v3 flows are wired end-to-end (recovery/export path restored),
rewrite the inline JS in `recovery.html` to parse the v3 blob layout: read the
`0x03` version byte, then the `u16_BE`-prefixed `ECIES(rootReadKey)` and
`ECIES(rootWriteKey)` segments, and decrypt both with the recovery private key.
Drop all v2 / `encryptedRootFolderKey` code. Mirror `deserializeVaultBlobV3` in
`packages/core/src/vault/blob.ts` and validate against `tests/vectors/vault-v3-blob.json`.

Deferred from phase 62 (`/ship-phase`) — out of the core-codec TypeScript scope.

---
created: 2026-07-07T00:00:00.000Z
title: desktop-e2e bump-ipns-sequence.ts still on the legacy folder model (missed 69-25 migration)
area: desktop-e2e
severity: medium
source: Phase 69 ship — desktop-e2e conflict-detection failure (run 28876436226, Windows); verified against live code 2026-07-07
files:
  - tests/desktop-e2e/scripts/bump-ipns-sequence.ts
  - tests/desktop-e2e/scripts/test-conflict-detection.sh
  - tests/desktop-e2e/scripts/test-conflict-detection.ps1
---

## Problem

Phase 69-25 migrated the desktop-e2e verifier helpers (`verify-filepointer.mts`,
`edit-filepointer.mts`, `rename-folder.mts`) to the node/v3 read chain, but
`bump-ipns-sequence.ts` — the helper the **conflict-detection** test uses to advance
the vault root IPNS sequence with a real signed record — was NOT migrated. It still
reads the LEGACY model:

- `vaultKeyBlob.rootFolderKey` (node/v3 uses `rootReadKey`/`rootWriteKey`)
- `folder.metadata.children` + `publishFolderMetadata({ children, baseChildren, folderKey })`
  (legacy folder-metadata shape / publish API)

Under node/v3 `folder.metadata.children` is `undefined`, so the helper crashes:
`bump-ipns-sequence failed: Cannot read properties of undefined (reading 'length')`
→ `Conflict detection script error: Failed to bump server sequence ... (exit 1)`.

Because the helper can't even set up the scenario, **conflict-detection is effectively
un-tested on desktop node/v3** (it is not evidence that the mount's conflict handling is
broken — the FUSE ops, cross-client sync, and move-content tests all pass). The failure
surfaced on Windows in CI (run 28876436226); it flaky-passed on macOS in the same run
(state/timing dependent), which is why it slipped by.

## Fix

Migrate `bump-ipns-sequence.ts` to the node/v3 write chain, mirroring the 69-25
helper migration: load the two-key root (`rootReadKey`/`rootWriteKey`), fetch the
current root **Node** (not legacy folder metadata), and republish it UNCHANGED at
`sequence+1` via the node/v3 publish path (seal the root node, CAS-publish the IPNS
record signed by the derived vault IPNS keypair). Keep the "republish current
children unchanged → no-op 3-way merge" intent so the test still just advances the
sequence without mutating the tree.

## Acceptance

`test-conflict-detection.{sh,ps1}` advances the root IPNS sequence via a real signed
node/v3 record on all platforms, the mount detects the bumped sequence, and the
conflict-detection e2e passes on macOS, Linux, and Windows.

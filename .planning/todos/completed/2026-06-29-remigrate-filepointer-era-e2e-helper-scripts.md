---
created: 2026-06-29
title: Re-migrate FilePointer-era E2E helper scripts to Node model and re-add to compile gate
area: sdk-core
files:
  - packages/sdk-core/scripts/edit-filepointer.mts
  - packages/sdk-core/scripts/verify-filepointer.mts
  - packages/sdk-core/scripts/rename-folder.mts
  - tests/desktop-e2e/scripts/bump-ipns-sequence.ts
  - tsconfig.scripts.json
---

## Problem

Phase 62 retired `FilePointer` / `FolderEntry` / `FolderMetadata` / `FileMetadata`
and replaced the single vault `rootFolderKey` with `rootReadKey` + `rootWriteKey`.
Four E2E helper scripts still operate on the old model and fail the
`tsconfig.scripts.json` typecheck (44 errors): they read `SealedChildRef.type`,
`.fileMetaIpnsName`, `.ipnsPrivateKeyEncrypted`, `.folderKeyEncrypted`, `.id`,
and `vault.rootFolderKey`, none of which exist on the new types.

These helpers were typechecked deliberately (#532 / #537) to catch SDK contract
drift. The drift detector is firing a true positive — but the new-model
equivalents depend on read-chain navigation (`unsealChildReadKey`, node resolve)
that is stubbed until the phase 63-65 consumer re-wire, so they cannot be
migrated yet. They were quarantined via an `exclude` block in
`tsconfig.scripts.json` to keep the compile gate green.

## Solution

During the phase 63-65 consumer re-wire (once read-chain navigation and the
write-chain are un-stubbed):

- Rewrite the helpers against the `Node` / `SealedChildRef` model — resolve
  children via `unsealChildReadKey`, use `rootReadKey` / `rootWriteKey` instead
  of `rootFolderKey`, and drop the retired `FilePointer` field accesses.
  (`edit-filepointer` / `verify-filepointer` likely become `edit-node` /
  `verify-node`.)
- Remove the `exclude` block from `tsconfig.scripts.json` so the helpers are
  typechecked again and drift detection resumes.

Deferred from phase 62 (`/ship-phase`): the helpers' logic depends on runtime
that is intentionally stubbed mid-milestone (D-01); migrating them now is not
possible.

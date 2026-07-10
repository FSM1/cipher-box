---
created: 2026-06-29
title: Fix upload-batch.test.ts mock type-drift to SealedChildRef
area: sdk
files:
  - packages/sdk/src/__tests__/upload-batch.test.ts
---

## Problem

Phase 62 retired `FilePointer`/`FolderEntry` and introduced `SealedChildRef`.
`packages/sdk/src/__tests__/upload-batch.test.ts` still builds mock child refs
with the old `type` / `fileMetaIpnsName` / `ipnsPrivateKeyEncrypted` field shape,
which is not assignable to `SealedChildRef`. The phase-62 verifier flagged this
as a `WARNING` (D-02 quarantine not applied to this suite).

This does NOT break CI: vitest transpiles without typechecking so all 20 tests
pass at runtime, and the production build (`tsconfig.build.json`) excludes test
files. It is type-level drift only, invisible to the typecheck gate.

## Solution

During the phase 63-65 consumer re-wire (when the SDK upload path is restored
from throwing stubs to real `Node`/`SealedChildRef` logic), update the mock
helpers in this suite to construct valid `SealedChildRef` objects
(`{ name, ipnsName, generation, versionFloor, readKeySealed }`) instead of the
retired field shape. Re-enable real assertions against the live upload path.

Deferred from phase 62 (`/ship-phase`) — out of the core-codec domain; correct
home is the consumer re-wire phase that un-stubs the upload path.

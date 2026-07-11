---
created: 2026-07-11T00:00:00.000Z
title: Deep scope-exit e2e — Carol retained-access check derives folderB from a stale pre-rotation SealedChildRef
area: desktop-fuse-rotation
severity: medium
source: Phase 74 PR #607 review — coderabbit Major (functional correctness, shared-scope-exit-rotation.mts:947)
files:
  - tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts
resolves_phase: null
---

## Problem

In Part C (deep + retained-vs-revoked) of the shared-scope-exit-rotation
desktop-e2e, the retained-recipient (Carol, SC2) check derives her new folderB
read key from `folderBRef` — the SealedChildRef captured BEFORE the rotation
(`shared-scope-exit-rotation.mts` ~:697, ~:943):

```
const { childReadKey: carolNewFolderBKey } = await deriveChildReadKey(
  folderBRef,            // <-- pre-rotation seal
  carolNewGrantRootKey,  // <-- post-rotation grant-root key
  carol.ctx
);
```

`deriveChildReadKey` unwraps `childRef.readKeySealed` with the parent key.
`folderBRef.readKeySealed` was sealed under the OLD grant-root key; the
scope-exit rotation re-seals folderB under the NEW grant-root key and
republishes. Unwrapping the STALE seal with `carolNewGrantRootKey` cannot
succeed, so this SC2 acceptance check does not exercise the intended
retained-recipient path (it either false-FAILs, or the assertion is not being
reached on the currently infra-gated desktop-e2e run).

## Fix

Reload folderB's CURRENT SealedChildRef from the grant root using the new key
before deriving Carol's folder key — mirror the pattern already used elsewhere
in this file:

```
const refreshedFolderBRef = await pollFindChild(
  deepGrantIpnsName,
  carolNewGrantRootKey,
  folderBName,
  carol.ctx
);
const { childReadKey: carolNewFolderBKey } = await deriveChildReadKey(
  refreshedFolderBRef,
  carolNewGrantRootKey,
  carol.ctx
);
```

Left as a todo rather than a live edit: desktop-e2e is dispatch-gated / CI-only,
so the assertion cannot be validated locally, and this is subtle
rotation-crypto test logic — the fix must be confirmed against a green
desktop-e2e run.

## Acceptance

The SC2 retained-recipient check derives Carol's folderB key from the
POST-rotation SealedChildRef and passes on a real desktop-e2e run, genuinely
proving retained-vs-revoked distinction (retained recipient still decrypts the
freshly-rotated folderB).

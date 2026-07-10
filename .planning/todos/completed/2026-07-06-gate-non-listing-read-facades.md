---
created: 2026-07-06
title: Gate the non-listing read facades (resolveNodeIdentity, resolveFileMetadata) with the ROT-07 floor
area: sdk
files:
  - packages/sdk/src/client.ts
resolves_phase: null
---

## Problem

Phase 68.2 moved the LISTING/navigation read chain behind the ROT-07 gate
(`RotationHighWater.enforceResolved`, fail-closed on unverified signature) —
verified and SECURED. Two secondary read facades still call
`resolvePublishedNode` directly, so they do NOT enforce the anti-rollback floor
(flagged by CodeRabbit on the ship review):

- `resolveNodeIdentity(ipnsName)` (~`client.ts:1191`) — returns plaintext
  `id`/`kind` for `deleteFromSharedFolder`'s childNodeId resolution.
- `resolveFileMetadata(fileRef, folderKey)` (~`client.ts:3897`) — resolves a
  file's own IPNS record for the detail dialog.
- `downloadFromIpns(fileRef, ...)` (~`client.ts:3925`) — resolves `fileRef.ipnsName`
  directly on the download path (same `gatedResolveChild(fileRef)` fix applies).

**Severity is low, not a hole:** content integrity is still protected by AEAD —
a tampered `published.id` derives the wrong child read key and `unsealNode` /
`sdkCore.resolveFileMetadata` fail closed. The residual gap is *anti-rollback*:
an attacker able to serve an old, validly-signed record could show stale file
metadata/identity. That is a staleness/availability issue, not a
confidentiality/integrity breach — which is why it was deferred rather than
fixed late in ship.

## Solution

- `resolveFileMetadata` HAS a `SealedChildRef` (`fileRef`) — route it through
  `gatedResolveChild(fileRef)` (enforces `signatureVerified` + `versionFloor` +
  `rotationHighWater`) instead of `resolvePublishedNode`, then unseal as today.
- `resolveNodeIdentity` takes only an `ipnsName` (no `SealedChildRef`, no
  generation), so it cannot call `gatedResolveChild` as-is. Either thread a
  `SealedChildRef` from the caller, or add an explicit
  `signatureVerified`/floor check on the `resolvePublishedNode` result and
  reject when rotation enforcement is enabled.

Add the two fail-closed tests CodeRabbit requested alongside the fix
(`resolve-child-identity.test.ts`, `descend-shared-child.test.ts`): a
`signatureVerified: false` case that still rejects.

---
created: 2026-07-04T00:00:00Z
title: Remove the dead getShareKeys/resolveFolderIpnsPrivateKey folder-ipns path
area: web
files:
  - apps/web/src/hooks/useSharedNavigationActions.ts:175
  - apps/web/src/services/share.service.ts:201
source: PR #588 Greptile review (P1 thread — consequence invalid, dead code real)
---

## Problem

`resolveFolderIpnsPrivateKey` (useSharedNavigationActions.ts:175) asks
`getShareKeys()`/`fetchShareKeys()` for a `folder-ipns` key, but under the
descriptor-ref grant model `fetchShareKeys` always returns `[]`
(share.service.ts, fail-closed by design), so it always falls through to
`new Uint8Array(32)` — an all-zero IPNS private key seeded into
`state.ipnsPrivateKey` for every write share.

Greptile flagged this as P1 "write shares lose signing key". The CONSEQUENCE is
INVALID: shared writes do NOT sign with the seeded key —
`buildSharedWriteContextFromState` (client.ts:3553) excludes `ipnsPrivateKey`, and
the shared-write ops recover the real Ed25519 IPNS key from the unsealed
`writeBody` via `state.writeKey` (client.ts:3730,
`unsealNode(parentPublished, folderKey, writeKey)`). Verified green by sdk-e2e
share-operations (7/7) and the writable-shares web-e2e. So the seeded key is
vestigial, not a live bug.

## Solution

Remove the dead path: delete `resolveFolderIpnsPrivateKey` + the `getShareKeys`
param plumbing, and stop threading a seeded `ipnsPrivateKey` into
`seedActiveSharedFolder`/`sharedFolderTree` for shared folders (the write path
recovers it from the write-body). Then `fetchShareKeys` and its `folder-ipns`
keyType may be removable too. Gate with the writable-shares + shared-folder
web-e2e specs. Relates to [[consolidate-web-shared-navigation-dup]].

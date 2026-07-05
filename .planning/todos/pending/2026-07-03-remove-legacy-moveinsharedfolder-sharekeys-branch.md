---
created: 2026-07-03T00:00:00Z
title: Remove unreachable moveInSharedFolder shareKeys branch — latent wrong-key bug inside
area: sdk
files:
  - packages/sdk/src/client.ts:4125
  - packages/sdk/src/client.ts:4168
source: ship-phase 68.1 simplify review
---

## Problem

`moveInSharedFolder`'s legacy `shareKeys.length > 0` branch (~45 lines at
client.ts:4125) plus its `getShareKeysFn` parameter are unreachable: the sole
producer `fetchShareKeys` hard-returns `[]`. Worse, the dead branch contains a
latent bug — at :4168 it assigns an Ed25519 `ipnsPrivateKey` as the AES
`destWriteKey`, which would corrupt the write chain if the branch ever became
reachable again.

## Solution

Delete the branch and the `getShareKeysFn` parameter (it is nominally a
back-compat API surface — confirm no external consumer contract before removal,
then simplify the signature). Never resurrect the branch without fixing the
key-type confusion. Gate with sdk unit suites + the writable-shares web-e2e spec.

---
created: 2026-07-11T00:00:00.000Z
title: TS rotatedNodes stores readKey by reference (aliased with parentNewReadKey) — add defensive copy for Rust parity
area: sdk-core-rotation
severity: low
source: Phase 74 crypto-privacy-review (2026-07-11) — LOW finding
files:
  - packages/sdk-core/src/rotation/engine.ts
---

## Problem

The Rust engine `.clone()`s each node's key into `rotated_nodes` (an
independent `Zeroizing<[u8;32]>` owned by the returned map). The TS engine
instead stores the SAME `Uint8Array` reference:

- `engine.ts:2064` (root)  `readKey: rootResult.childReadKey`
- `engine.ts:2235` (child) `readKey: result.childReadKey`

That same buffer is also aliased into `ParentTrackingState.parentNewReadKey`
(`engine.ts:2075` / `:2296`). This is currently SAFE only because
`parentNewReadKey` is never zeroed (teardown at `engine.ts:1663` zeroes
`parentOldReadKey` only). It is NOT a live bug today.

## Risk

If a future change ever zeroes `parentNewReadKey` on teardown — a
natural-looking D-09 tightening — it would silently zero the returned
`rotatedNodes` map entry. The FUSE consumer
(`grant_scope.rs::refresh_rotated_inode_read_keys`, which `copy_from_slice`s
`rotated.read_key` into inode buffers) would then refresh an inode read key to
ALL-ZEROS, causing mis-decryption / data loss on the next relink/reseal.

## Fix

Store a defensive copy for robustness + Rust parity (cheap, 32 bytes):

- `readKey: new Uint8Array(rootResult.childReadKey)` (root site)
- `readKey: new Uint8Array(result.childReadKey)` (child site)

## Acceptance

`rotatedNodes` entries hold independent buffers not aliased with
`parentNewReadKey`; add a TS regression test asserting every `rotatedNodes`
value's `readKey` is non-zero and equals the node's expected new key after
`rotateReadFromNode`.

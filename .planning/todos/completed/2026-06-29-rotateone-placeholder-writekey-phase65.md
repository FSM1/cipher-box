---
created: 2026-06-29
title: rotateOne passes an all-zeros placeholder writeKey to sealNode — wire the real writeKey in Phase 65
area: sdk-core
resolves_phase: 65
files:
  - packages/sdk-core/src/rotation/engine.ts
---

## Problem

Surfaced by the Phase-63 security audit as **FLAG-63-U1** (non-blocking).

`rotateOne` in `packages/sdk-core/src/rotation/engine.ts` (~L329-330) passes `new Uint8Array(32)` (all-zeros) as the `writeKey` argument to `sealNode`. This is **safe in Phase 63**: `unsealNode` without a write key produces a node with no `writeBody`, and `sealNode` skips the write-body reseal when there is no `writeBody` (confirmed at `packages/core/src/node/seal.ts` ~L118). Phase 63 is read-chain only.

Latent risk: if a Phase-65+ code path invokes `rotateOne` on a node that **does** carry a `writeBody` before the real write-chain key is wired, the write body would be resealed under an all-zeros key. The Phase-65 seam comment in `engine.ts` (~L324-328) acknowledges this.

## Solution

When Phase 65 adds write-chain rotation:

- Thread the node's real `writeKey` (or a freshly minted `writeKey'`) into `rotateOne` instead of the all-zeros placeholder, and reseal the write body under it.
- Remove the `PLACEHOLDER_WRITE_KEY` and its seam comment once the real key is wired.
- Add a test covering rotation of a node that has a `writeBody`.

## References

- `.planning/phases/63-read-chain-navigation-and-rotation-core/63-SECURITY.md` FLAG-63-U1
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` (write-body context, Phase 65)
- ROADMAP Phase 65

---
created: 2026-06-29
title: Deduplicate base64 helpers across the node/ codec module
area: core
files:
  - packages/core/src/node/seal.ts
  - packages/core/src/node/encode.ts
  - packages/core/src/node/decode.ts
resolves_phase: 77
---

## Problem

The chunk-based `uint8ArrayToBase64` / `base64ToUint8Array` helpers (originally
copied from the now-deleted `folder/metadata.ts`) are duplicated across three
files in the new node codec: `node/seal.ts`, `node/encode.ts`, and
`node/decode.ts`. Minor DRY nit surfaced during `/ship-phase` simplify review —
not a correctness, security, or over-engineering issue.

## Solution

Consolidate into a single internal helper (e.g. `packages/core/src/node/base64.ts`
or an existing `@cipherbox/crypto` byte-encoding util) and import it from the
three node modules. base64 encoding is deterministic, so this does not change any
sealed-envelope bytes — but verify against the frozen golden vectors
(`tests/vectors/node-codec.json`, `vault-v3-blob.json`) after the change, since
the codec is freeze-first (D-04).

Deferred from phase 62 (`/ship-phase`): low-value refactor touching three
freeze-first codec files; not worth the risk immediately before shipping the
keystone. Safe to pick up once the milestone consumers are re-wired.

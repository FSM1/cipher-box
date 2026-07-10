---
created: 2026-07-10
title: Make wrapIpnsKeyForTee bytes-in/bytes-out, move hex to the transport boundary
area: crypto
files:
  - packages/sdk-core/src/tee/wrap.ts
  - packages/sdk-core/src/folder/registration.ts
  - packages/sdk-core/src/file/index.ts
  - packages/sdk-core/src/vault/index.ts
source: Phase 72 ship-loop CodeRabbit review (major finding on tee/wrap.ts)
resolves_phase: 77
---

## Problem

`wrapIpnsKeyForTee` (`packages/sdk-core/src/tee/wrap.ts`, extracted in Phase 72 / 72-09) currently
takes a hex `currentPublicKey` string and returns a hex-encoded wrapped key — it does `hexToBytes`
on the way in and `bytesToHex` on the way out. CodeRabbit suggests the shared crypto helper should
operate purely on `Uint8Array` (accept `teePublicKey: Uint8Array`, return `Uint8Array`) and push
the hex encode/decode out to the transport/persistence boundary, keeping key material in bytes
inside the crypto layer.

Not a correctness or security bug — the extraction faithfully deduped the three call sites'
existing hex-in/hex-out behavior, and the security review verified the helper is a correct pure
borrow (no D-09 issue). This is a code-organization/style improvement, deferred to keep the
Phase 72 PR scoped to behavioral fixes.

## Solution

Change `wrapIpnsKeyForTee` to `(ipnsPrivateKey: Uint8Array, teePublicKey: Uint8Array) => Promise<Uint8Array>`
(rename `currentPublicKey` → `teePublicKey`), and move the `hexToBytes(publicKey)` /
`bytesToHex(wrapped)` conversions into each caller at the point where the value crosses into the
`encryptedIpnsPrivateKey` transport field (`registration.ts`, `file/index.ts`, `vault/index.ts`).
Keep the fail-closed validation (a short/empty key must still throw).

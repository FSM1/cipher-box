---
created: 2026-07-10
title: Zero createSubfolder-generated keys when a later seal/upload/publish throws
area: crypto
files:
  - packages/sdk-core/src/folder/registration.ts
source: Phase 72 ship-loop CodeRabbit review (major finding on registration.ts:92-94)
---

## Problem

`createSubfolder` (`packages/sdk-core/src/folder/registration.ts:40-127`) generates
`ipnsPrivateKey`, `readKey`, and `writeKey`, then wraps/ seals/ uploads/ publishes before
returning them to the caller (the terminal owner, D-09 — correctly NOT zeroed on the success
path). But if any step between generation and return throws (`wrapIpnsKeyForTee`, `sealNode`,
`addToIpfs`, `createAndPublishIpnsRecord`), the function throws WITHOUT handing the keys to
the caller, so nobody ever zeroes them — they linger in the heap until GC.

Pre-existing (the try-less generate-then-return structure predates Phase 72; Phase 72 only
re-pointed line 94 to `wrapIpnsKeyForTee`). Low severity (un-zeroed-on-throw hygiene, not a
direct exploit) — the crypto security review did not flag it as exploitable. Deferred from the
Phase 72 ship loop to keep that PR scoped to the shipped write-plane fixes.

## Solution

Wrap the generate→wrap→seal→upload→publish body in a try/catch that zeroes
`ipnsPrivateKey`/`readKey`/`writeKey` before rethrowing, preserving the success-path ownership
transfer (do NOT zero on successful return). Audit the sibling key-gen flows for the same
pattern: `createRootVault`/vault init (`packages/sdk-core/src/vault/index.ts`) and any other
`generateRandomBytes`/`generateEd25519Keypair` → return flow. Relates to
[[zeroize-file-keys-on-unwrap-error-path]] (the same D-09-error-path class, fixed for
`updateSharedSingleFile` in Phase 72).

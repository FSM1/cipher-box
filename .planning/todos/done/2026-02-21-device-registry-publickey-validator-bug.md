---
created: 2026-02-21T00:00
title: Fix DeviceEntry publicKey validator length check (130 → 64 hex chars)
area: crypto
files:
  - packages/crypto/src/registry/schema.ts
  - packages/crypto/src/__tests__/registry.test.ts
  - docs/METADATA_SCHEMAS.md
---

## Summary

The `DeviceEntry.publicKey` validator enforces 130 hex characters (65 bytes = uncompressed secp256k1), but device keypairs are Ed25519 (32-byte public key = 64 hex chars).

## Bug details

- `packages/crypto/src/device/keygen.ts` generates Ed25519 keypairs via `generateEd25519Keypair()`
- `apps/web/src/services/device-registry.service.ts:241` stores `bytesToHex(params.deviceKeypair.publicKey)` → 64 hex chars
- `packages/crypto/src/registry/schema.ts:94` validates `publicKey.length !== 130` → would reject real Ed25519 keys
- The 130 value was likely copy-pasted from secp256k1 uncompressed public key validation

## Why it hasn't broken in production

The validator runs inside `decryptRegistry()`, which is called on registry sync. The test data at `registry.test.ts:32` uses `'04' + 'b'.repeat(128)` (fake 130-char secp256k1-style key) which passes the validator. Real device entries created by `generateDeviceKeypair()` would fail validation if they round-tripped through encrypt → decrypt.

This likely means either: (a) the decrypt path isn't fully exercised with real device data in production, or (b) there's an intermediary that transforms the key format. Needs investigation.

## Fix

- Change `schema.ts:94` from `publicKey.length !== 130` to `publicKey.length !== 64`
- Update test fixture at `registry.test.ts:32` to use 64-char hex key
- Update `docs/METADATA_SCHEMAS.md` line 340 to say 64 hex chars (currently says 130)
- Verify the desktop Rust side doesn't have a similar validator

## Found by

CodeRabbit review on PR #175 (flagged docs inconsistency, but root cause is a validator bug).

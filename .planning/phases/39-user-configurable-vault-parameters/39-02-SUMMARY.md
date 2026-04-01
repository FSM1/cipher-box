# Plan 39-02 Summary: Vault settings store and IPNS persistence

## Status: COMPLETE

## Changes Made

Added `deriveVaultSettingsIpnsKeypair` HKDF derivation to `@cipherbox/crypto` with domain-separated key derivation. Created vault settings Zustand store (`vault-settings.store.ts`) and IPNS load/save service (`vault-settings.service.ts`), following the established BYO-IPFS config pattern.

## Delivered In

PR #423 — merged 2026-03-31

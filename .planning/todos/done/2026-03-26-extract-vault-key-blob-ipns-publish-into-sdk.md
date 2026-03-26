---
created: 2026-03-26T02:04:24.457Z
title: Extract vault key blob IPNS publish into SDK
area: core
priority: high
files:
  - apps/web/src/hooks/useAuth.ts:162-185
  - packages/sdk/src/client.ts
  - packages/sdk-core/src/folder/index.ts
  - packages/crypto/src/vault/derive-ipns.ts:88
  - tests/sdk-e2e/src/fixtures/test-harness.ts
  - tests/web-e2e/tests/recovery.spec.ts
---

## Problem

The vault key blob IPNS publish (deriveVaultKeyIpnsKeypair → serializeVaultBlobV2 → addToIpfs → createAndPublishIpnsRecord) lives entirely in the web app's `useAuth.ts` hook (lines 162-185), not in the SDK. This means:

1. `CipherBoxClient` and `createTestAccount` skip it — vaults created via the SDK have no vault key blob IPNS record
2. The recovery tool can't recover SDK-created vaults (no vault key blob to resolve)
3. The desktop app would need to duplicate the same logic
4. The recovery E2E test is skipped in CI because the test harness uses the SDK which doesn't publish the blob

## Solution

1. Add `publishVaultKeyBlob()` to `@cipherbox/sdk-core` or `@cipherbox/sdk` that handles the full flow: derive keypair → wrap rootFolderKey → serialize v2 blob → upload to IPFS → publish IPNS
2. Call it from `CipherBoxClient` during vault initialization
3. Simplify `useAuth.ts` to call the SDK function instead of inlining the logic
4. `createTestAccount` automatically gets vault key blob publish via the SDK
5. Remove `test.skip(!!process.env.CI)` from `recovery.spec.ts` — test should pass with blob published
6. Consider also reading the vault key blob via SDK (currently inline in useAuth.ts lines 137-150)

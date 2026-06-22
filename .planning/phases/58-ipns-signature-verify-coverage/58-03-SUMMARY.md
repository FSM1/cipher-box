---
phase: 58-ipns-signature-verify-coverage
plan: "03"
subsystem: web
tags:
  - ipns
  - security
  - dedup
  - delegation
dependency_graph:
  requires:
    - "58-01: sdk-core CBOR cid/sequence binding"
  provides:
    - "D-13: web resolveIpnsRecord delegates to sdk-core chokepoint with apiAxios ctx"
    - "Eliminated lockstep divergence risk between web and sdk-core verify paths"
  affects:
    - "apps/web/src/services/ipns.service.ts"
tech_stack:
  added: []
  patterns:
    - "SdkContext ctx injection pattern (apiUrl + getAccessToken + axiosInstance)"
    - "Module aliasing: import { resolveIpnsRecord as resolveIpnsRecordCore } from '@cipherbox/sdk-core'"
key_files:
  created: []
  modified:
    - "apps/web/src/services/ipns.service.ts"
decisions:
  - "D-13: web resolveIpnsRecord delegates to sdk-core; local verifyIpnsSignature deleted"
  - "withPerf satisfied by sdk-core internal wrapper — web does not double-wrap"
  - "getAccessToken constructed inline from useAuthStore rather than adding a new api-config.ts export"
metrics:
  duration: "~15min"
  completed_date: "2026-06-22"
  tasks_completed: 1
  files_modified: 1
---

# Phase 58 Plan 03: Web resolveIpnsRecord Delegation Summary

One-liner: Web IPNS resolve path de-duplicated by delegating to sdk-core chokepoint with the web axios instance threaded via SdkContext, eliminating the lockstep divergence risk and automatically picking up 58-01 CBOR binding.

## Tasks Completed

### Task 1: Delete web verify/resolve duplicates; delegate to sdk-core

Removed `verifyIpnsSignature` (lines 139-151) and the full `resolveIpnsRecord` body (lines 163-231) from `apps/web/src/services/ipns.service.ts`. Replaced with a thin delegating wrapper calling `resolveIpnsRecordCore(ipnsName, { apiUrl, getAccessToken, axiosInstance: apiAxios })`.

Imports removed (were only used by deleted functions):

- `IPNS_SIGNATURE_PREFIX` from `@cipherbox/core`
- `verifyEd25519`, `concatBytes`, `deriveIpnsName` from `@cipherbox/crypto`
- `ipnsControllerResolveRecord` from `@cipherbox/api-client`
- `logger` from `../lib/logger`

Imports added:

- `resolveIpnsRecord as resolveIpnsRecordCore` from `@cipherbox/sdk-core`
- `apiAxios`, `apiUrl` from `../lib/api-config`
- `useAuthStore` from `../stores/auth.store`

Retained (still used by publish functions):

- `createIpnsRecord`, `marshalIpnsRecord` from `@cipherbox/core`
- `deriveEd25519PublicKey` from `@cipherbox/crypto`
- `ipnsControllerPublishRecord`, `ipnsControllerPublishBatch` from `@cipherbox/api-client`
- `PublishIpnsEntryDtoRecordType` from `@cipherbox/api-client`

## withPerf Timing

The plan requirement "preserve perf instrumentation" is satisfied by the sdk-core internal `withPerf('ipns:resolve', …)` wrapper. The web wrapper does NOT add its own `withPerf` (the web version never had one — only the sdk-core version did). Timing is preserved at the same granularity as before.

## SdkContext Threading

The ctx passed to sdk-core:

```typescript
{
  apiUrl,                                               // from apps/web/src/lib/api-config.ts
  getAccessToken: async () => useAuthStore.getState().accessToken || '',
  axiosInstance: apiAxios,                              // web singleton axios
}
```

`apiAxios` is the same instance registered as the orval singleton via `setApiClientConfig(apiConfig, apiAxios)`. Threading it explicitly via ctx ensures sdk-core uses the same authenticated, token-refreshing client rather than relying on the singleton fallback path.

## Caller Impact

All 14 callers of `resolveIpnsRecord` in the web app are unaffected — the public signature `(ipnsName: string) => Promise<{cid, sequenceNumber, signatureVerified}|null>` is unchanged. No caller file was modified (`git diff --name-only` lists only `ipns.service.ts`).

Callers verified:

- `apps/web/src/components/settings/StorageTab.tsx` (2 calls)
- `apps/web/src/components/file-browser/useFileBrowserActions.ts` (1 call)
- `apps/web/src/components/file-browser/DetailsDialog.tsx` (1 call)
- `apps/web/src/components/file-browser/ShareDialog.tsx` (1 call)
- `apps/web/src/hooks/useAuth.ts` (2 calls)
- `apps/web/src/hooks/useSharedNavigationActions.ts` (3 calls)
- `apps/web/src/hooks/folder-helpers.ts` (1 call)
- `apps/web/src/lib/crypto/key-wrapping.ts` (1 call)
- `apps/web/src/services/file-metadata.service.ts` (2 calls)
- `apps/web/src/services/device-registry.service.ts` (2 calls)
- `apps/web/src/services/invite.service.ts` (1 call)
- `apps/web/src/services/vault-settings.service.ts` (1 import — no call visible in grep but imports the function)

## Verification Results

- `tsc --project apps/web/tsconfig.json --noEmit` — PASS (no errors)
- `eslint apps/web/src/services/ipns.service.ts` — PASS (lint-staged auto-fix applied prettier formatting on commit)
- `grep -c "function verifyIpnsSignature" apps/web/src/services/ipns.service.ts` — 0
- `grep "from '@cipherbox/sdk-core'"` — present, includes `resolveIpnsRecord` alias
- `grep "export async function resolveIpnsRecord("` — present, unchanged signature
- `grep "apiAxios"` — present in ctx delegation
- `git diff --name-only` — only `apps/web/src/services/ipns.service.ts`

## Security Posture

The web now inherits the 58-01 CBOR cid/sequence binding (D-07/D-08) automatically. The web previously lacked this check — it verified the Ed25519 signature but did not bind the signed CBOR back to the response `cid` and `sequenceNumber`. After this plan, the web is no longer a bypass path for D-07/D-08.

Threat T-58-13 (lockstep drift) is resolved: future verify changes apply everywhere automatically.
Threat T-58-14 (wrong axios context) is resolved: `apiAxios` is threaded explicitly.
Threat T-58-15 (accidental downgrade during deletion) is resolved: the web copy is deleted, not relaxed.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None.

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check: PASSED

- `apps/web/src/services/ipns.service.ts` modified — confirmed present
- commit `80cf782fb` — verified in git log
- tsc typecheck — PASS
- eslint — PASS
- `verifyIpnsSignature` count == 0 — verified
- sdk-core import present — verified
- apiAxios threaded — verified
- no caller files modified — verified

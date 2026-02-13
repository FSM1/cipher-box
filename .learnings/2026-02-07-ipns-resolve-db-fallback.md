# IPNS Resolve DB-Cached CID Fallback

**Date:** 2026-02-07

## Original Prompt

> IPNS resolve 502 — add DB-cached CID fallback. When delegated-ipfs.dev is unreliable, fall back to the CID stored in folder_ipns.latest_cid.

## What I Learned

- The `folder_ipns.latest_cid` column already existed and was updated on every `publishRecord` call via `upsertFolderIpns` — no migration needed
- Extracting the delegated routing call into a private method (`resolveFromDelegatedRouting`) and wrapping the public method with try/catch was the cleanest pattern for adding fallback behavior without touching the retry logic
- The `mockFolderEntity` object in the test suite is shared and **mutated** by earlier tests (e.g. `existing.sequenceNumber = ...` in `upsertFolderIpns`). New tests that reference it need fresh spread copies to get predictable values
- IPNS resolution is inherently public (anyone with the name can resolve via the IPFS network), so scoping the DB fallback by `ipnsName` alone (vs `userId + ipnsName`) doesn't change the threat model — the CID points to encrypted metadata anyway
- Skipping a `fromCache` response flag was the right call — staleness risk is minimal since `latestCid` is updated on every publish through our API

## What Would Have Helped

- Knowing upfront that `latest_cid` already existed on the entity would have saved the initial investigation time
- The mock IPNS routing service (`tools/mock-ipns-routing`) requires a separate `npm install` — it's not a pnpm workspace member, so `pnpm install` from root doesn't cover it

## Key Files

- `apps/api/src/ipns/ipns.service.ts` — `resolveRecord` + `resolveFromDelegatedRouting`
- `apps/api/src/ipns/ipns.service.spec.ts` — unit tests including fallback cases
- `apps/api/src/ipns/entities/folder-ipns.entity.ts` — `latestCid` column
- `tools/mock-ipns-routing/` — mock delegated routing for E2E tests (needs its own `npm install`)

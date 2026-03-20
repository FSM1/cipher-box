# SDK Rewiring: Dual-Path IPNS State Pitfalls

**Date:** 2026-03-20
**Phase:** 19.1-05 (Rewire web app hooks to SDK)
**Severity:** Multiple blocking bugs found during UAT

## Summary

Plan 19.1-05 rewired folder CRUD hooks to use the new `CipherBoxClient` SDK while leaving file upload on the old service path. This created a **dual-path IPNS write problem** where two independent code paths (SDK + old service) published to the same IPNS records with conflicting sequence numbers, causing 409 Conflict errors and data corruption.

## Root Causes

### 1. Missing `setApiClientConfig()` call

The `@cipherbox/api-client` package requires `setApiClientConfig({ baseUrl, getAccessToken })` before any generated API functions work. The SDK-core's IPNS operations (`ipnsControllerPublishRecord`, `ipnsControllerResolveRecord`) use these generated functions. Without the config, **every** SDK operation that touches IPNS silently failed.

**Why it wasn't caught earlier:** The agent-generated SDK code used `@cipherbox/api-client` for IPNS but direct `axios` calls for IPFS. IPFS operations worked (uploads succeeded), masking the IPNS failure. The plan didn't include an integration test against a live API.

**Prevention:** Any plan that introduces a new dependency requiring runtime configuration (api-client, auth providers, etc.) should have a "configuration wiring" task that's verified before other operations.

### 2. Dual-path IPNS writes (the architectural mistake)

The plan explicitly decided to keep `useFileUpload` on the old service because "the SDK's upload flow is architecturally different." This created two independent IPNS writers:

- **SDK path:** folder create/rename/delete incremented seq via SDK's internal `FolderTree`
- **Old service path:** file upload incremented seq via Zustand store + old IPNS publish

Neither writer knew about the other's sequence number changes, causing 409 Conflicts on every operation after the first.

**The `ensureFolderRegistered` bridge was not a solution.** Multiple iterations tried to sync state between SDK and store:

1. "Always overwrite" → SDK's sequence number reset to stale store value → 409
2. "Skip if SDK has it" → old service uploaded files SDK didn't know about → "Item not found" on rename
3. "Sync children but preserve seq" → old service incremented seq externally → 409 anyway
4. "Use max(sdk, store) seq" → still broke because keys got corrupted

**Fix:** Rewired file upload to also use `client.uploadFile()`, eliminating the dual-path entirely. The `ensureFolderRegistered` bridge became simple again: "skip if SDK has it."

**Prevention:** When planning SDK migration, **all writers to the same mutable resource (IPNS records) must be migrated together**. Partial migration of readers is safe; partial migration of writers is not. The plan should have flagged file upload as a mandatory co-migration with folder CRUD.

### 3. Wrong folder ID in store (UUID vs ipnsName)

`handleCreate` stored the new folder with `id: result.ipnsName` but folder children use a UUID (`FolderEntry.id`). The file browser navigates by child UUID, so navigating into SDK-created folders failed silently (folder not found → empty state).

**Why it wasn't caught:** The agent's `createFolder` return type only included `{ ipnsName, folderKey }` — the UUID wasn't returned. The agent assumed ipnsName could serve as the store ID.

**Prevention:** When an SDK operation creates entities that the UI references by ID, the return type must include whatever ID the UI uses. Cross-reference the store's `FolderNode.id` type with the SDK's return type during planning.

### 4. Download/edit used old IPNS resolution path

After rewiring upload to SDK, download still used the old `file-metadata.service.ts` → `ipns.service.ts` chain. Although both paths hit the same API, the SDK published file IPNS records via `batchPublishIpnsRecords` (using `@cipherbox/api-client`) while download resolved via the web app's own API client. Subtle timing differences caused "decryption failed" errors.

**Fix:** Added `downloadFromIpns()` to the SDK client and rewired both `useFileDownload` and `TextEditorDialog` to use it.

**Prevention:** Upload and download paths for the same data must use the same resolution chain. When rewiring writes, always check that the corresponding reads are also rewired.

### 5. SDK bin state never loaded

The SDK's `deleteToBin()` requires `binState` to be loaded via `client.loadBin()`. This was never called because the old `initializeBin` service created the bin independently. `deleteToBin` silently fell back to `deleteItem` (hard delete, no bin entry).

**Fix:** Call `client.loadBin()` after `initializeBin()` completes.

## Testing Approach Lessons

### Unit tests weren't enough

The SDK had passing unit tests with mocked dependencies. All the bugs were **integration-level**: API client config not wired, sequence numbers conflicting across code paths, wrong IDs crossing module boundaries.

### Integration test against live API was essential

Writing `integration.test.ts` that ran the full lifecycle (login → vault → folder → upload → download → rename → delete) against the real API immediately found the correct behavior and proved the SDK worked. This should have been the **first test written**, before any UI rewiring.

### Playwright-driven UAT caught what code review couldn't

The user's manual testing found bugs (rename broken, download failing, bin empty) that weren't visible in code review or unit tests. Automating this with Playwright MCP was more effective than scripted E2E tests (which had their own environment issues with the mock IPNS service).

## Recommendations for Future SDK Migration Phases

1. **Write a live-API integration test first**, before any UI rewiring
2. **Never partially migrate writers** to a shared mutable resource
3. **Return all IDs the consumer needs** from SDK operations
4. **Rewire reads and writes together** for any data path
5. **Check runtime configuration wiring** for every new package dependency
6. **Test with Playwright against the real app** — don't rely only on programmatic tests

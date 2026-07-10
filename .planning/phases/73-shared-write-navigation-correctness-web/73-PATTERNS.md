# Phase 73: Shared Write/Navigation Correctness (Web) - Pattern Map

**Mapped:** 2026-07-10
**Files analyzed:** 12 (new tests: 3, modified-with-new-pattern: 6, e2e extensions: 3)
**Analogs found:** 10 / 12

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|--------------------|------|-----------|-----------------|----------------|
| `packages/sdk-core/src/ipns/index.ts` (`createAndPublishIpnsRecord` 410 handling) | service | request-response | same file, `resolveIpnsRecord` 404 idiom (lines 317-325) | exact (sibling function, same file) |
| `packages/sdk-core/src/__tests__/ipns.test.ts` (NEW test for 410→tombstoned) | test | request-response | same file, `resolveIpnsRecord` "returns null on 404 error" test (lines 142-151) | exact |
| `packages/sdk/src/client.ts` (`buildWriteTransportSeams`/`publishNodeFn` tombstoned mapping) | service | request-response | `packages/sdk/src/share/shared-write.ts` `PublishNodeResult` type (lines 56-61) | exact (consumer contract already defined) |
| `packages/sdk/src/__tests__/resolve-node-identity.test.ts` (signature change to `SealedChildRef`) | test | request-response | `packages/sdk/src/__tests__/resolve-child-identity.test.ts` (fixture pattern, lines 32-66) | exact |
| NEW `packages/sdk/src/__tests__/file-metadata-facade.test.ts` (or extension) — `resolveFileMetadata`/`downloadFromIpns` fail-closed | test | request-response | `resolve-child-identity.test.ts` full file (fixture + fail-closed case, lines 95-110) | exact |
| `apps/web/src/hooks/useSharedNavigationActions.ts` (`NavStackEntry.writeKey`, consolidated restore helper) | hook | event-driven | same file, existing `NavStackEntry.folderKey` threading + zeroing discipline | exact (self-analog, same file convention) |
| `apps/web/src/hooks/useSharedWriteOps.ts` (`resolveChildNodeId` → pass `SealedChildRef`) | hook | request-response | `packages/sdk/src/__tests__/resolve-child-identity.test.ts` (`resolveChildIdentity` sibling signature) | role-match |
| `apps/web/src/hooks/useSharedWriteOps.ts` (wire `runWithFailureUx`) | hook | request-response | `apps/web/src/hooks/useFolderMutations.ts` (`createFolder` handler, lines 116-123) | exact |
| `tests/web-e2e/tests/writable-shares.spec.ts` (NEW case: descend 2, up 1, write) | test | event-driven | same file, test `8.4` (lines 657-696) | exact |
| `tests/web-e2e/tests/shared-folder-desync.spec.ts` (NEW case: mutate-while-deeper, then up) | test | event-driven | same file, existing two-client harness cases (2.1/3.1 pattern) | exact |
| `tests/web-e2e/tests/rotation-ux.spec.ts` (rewrite D-01/WRITE-03 case, lines 278-333) | test | event-driven | same file, own prior version (direct-injection) — no external analog needed, rewrite in place | n/a (in-place rewrite) |
| `apps/web/src/components/file-browser/SharedFolderRow.tsx` (drag-kind fix) | component | transform | `apps/web/src/components/file-browser/SharedFileBrowser.tsx` (`isFileRefResolved` usage, lines 777, 841) | exact |

## Pattern Assignments

### `packages/sdk-core/src/ipns/index.ts` — `createAndPublishIpnsRecord` 410 detection

**Analog:** same file, `resolveIpnsRecord`'s existing 404-detection catch block (lines 317-328)

```typescript
} catch (error) {
  // 404 means IPNS name not found - return null
  // Other errors should propagate (including signature verification failures)
  if (error instanceof Error) {
    const anyError = error as Error & { status?: number; response?: { status?: number } };
    const status = anyError.status ?? anyError.response?.status;
    if (status === 404) {
      return null;
    }
  }
  throw error;
}
```

Apply the identical `anyError.status ?? anyError.response?.status` idiom around the `ipnsControllerPublishRecord` call (line 95 in `createAndPublishIpnsRecord`, currently un-try/catch'd), checking `status === 410` and returning `{ success: false, sequenceNumber: 0n, tombstoned: true }` instead of rethrowing. Extend the function's return type from `Promise<{ success: boolean; sequenceNumber: bigint }>` (line 51) to add `tombstoned?: boolean`.

D-05 caller-owns-key comment block (lines 53-64) above the function documents the "CALLEE MUST NOT zero `ipnsPrivateKey`" contract — do not touch that logic, only wrap the publish call itself.

---

### `packages/sdk-core/src/__tests__/ipns.test.ts` — NEW 410→tombstoned test

**Analog:** same file, "returns null on 404 error" (lines 142-151) — mirror its mock-error-shape idiom

```typescript
it('returns null on 404 error', async () => {
  // ... error.status = 404 injected on the mocked rejection
  const result = await resolveIpnsRecord('k51missing');
  // asserts null
});
```

New test should live under `describe('createAndPublishIpnsRecord', ...)` (lines 40-95 in that file), mock `ipnsControllerPublishRecord` to reject with `{ response: { status: 410 } }` (axios shape, not bare `.status` — since this is the publish path via api-client, not resolve), and assert `result.tombstoned === true` / `result.success === false`.

---

### `packages/sdk/src/client.ts` — `publishNodeFn` tombstoned mapping

**Analog:** `packages/sdk/src/share/shared-write.ts` — `PublishNodeResult` type (lines 56-61) and its three throw sites (238, 362, 505)

```typescript
export type PublishNodeResult =
  | { tombstoned: true }
  | { tombstoned: false; newSequenceNumber: bigint };
// ...
if (result.tombstoned) {
  throw new CannotWriteUntilRefetchError(...)
}
```

`publishNodeFn` (client.ts `buildWriteTransportSeams`, ~line 5140-5172) must read the new `tombstoned` field off `sdkCore.createAndPublishIpnsRecord`'s result and map straight through — no change needed to `shared-write.ts` itself (already correct, Phase-66 seam).

---

### `packages/sdk/src/__tests__/resolve-node-identity.test.ts` — signature change to `SealedChildRef`

**Analog:** `packages/sdk/src/__tests__/resolve-child-identity.test.ts` (full file) — `buildChildFixture()` (lines 32-66) and the fail-closed case (lines 95-110)

Current `resolve-node-identity.test.ts` calls `client.resolveNodeIdentity(NODE_IPNS)` with a bare string (lines 65, 73) — both cases must be rewritten to construct a `SealedChildRef` fixture mirroring:

```typescript
const childRef: SealedChildRef = {
  name: 'report.pdf',
  ipnsName: CHILD_IPNS,
  generation: node.generation,
  versionFloor: 0n,
  readKeySealed,
};
```

and pass `childRef` instead of the bare ipnsName. The existing `sealNode`/`vi.mock('@cipherbox/sdk-core', ...)` scaffolding in `resolve-node-identity.test.ts` (lines 12-27) stays as-is — only the call-argument and null-case fixture need updating. Add a new fail-closed case (`signatureVerified: false` → `rejects.toThrow`) matching `resolve-child-identity.test.ts`'s pattern is NOT present today in either file — SC3 test coverage requires adding this to both.

---

### NEW `resolveFileMetadata`/`downloadFromIpns` fail-closed test file

**Analog:** `packages/sdk/src/__tests__/resolve-child-identity.test.ts` (full file, esp. lines 95-110)

```typescript
it('throws when the child IPNS record cannot be resolved (fail-closed, no gate bypass)', async () => {
  vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);
  // ...
  await expect(client.resolveChildIdentity(childRef, PARENT_READ_KEY)).rejects.toThrow(
    /IPNS record not found/
  );
});
```

New file (`file-metadata-facade.test.ts` or extend an existing suite) should build the same `sealNode` + `SealedChildRef` fixture, then add a `signatureVerified: false` mocked resolve (not just `null`) for both `resolveFileMetadata` and `downloadFromIpns`, asserting fail-closed rejection through `gatedResolveChild`'s `RotationHighWater.enforceResolved` path. Do NOT test `getFolderMetadata` here — that's `folder-metadata-facade.test.ts`'s existing scope, a different method.

---

### `apps/web/src/hooks/useSharedNavigationActions.ts` — `NavStackEntry.writeKey` + consolidated restore

**Analog:** same file, existing `NavStackEntry` shape and zeroing discipline (self-analog)

```typescript
type NavStackEntry = {
  folderId: string;
  folderName: string;
  children: SealedChildRef[];
  folderKey: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint | null;
};
```

Add `writeKey: Uint8Array | null` alongside `folderKey`. Follow the file's documented D-09 discipline (header comment, lines 14-16): "Minted intermediates (share-root/subfolder readKeys) are zeroed on every exit path once they are no longer the live state." Apply the identical zero-on-exit pattern used today for `folderKey` at every stack-discard site (`navigateToRoot`'s loop ~427-429, `navigateToBreadcrumb`'s discard loop ~545-547) to the new `writeKey` field, and mirror the existing `childWriteKey?.fill(0)` / `rootWriteKey?.fill(0)` finally-block idiom already present in `navigateToSubfolder`/`navigateUp` for the CLONE that gets stored (clone-before-zero, per RESEARCH.md's concrete-change note).

RESEARCH.md (Landmine 4/5) is authoritative on the exact wiring — this entry only maps WHERE the existing zeroing pattern lives so the new field follows the same shape.

---

### `apps/web/src/hooks/useSharedWriteOps.ts` — `resolveChildNodeId` signature + `runWithFailureUx` wiring

**Analog 1 (signature):** `packages/sdk/src/__tests__/resolve-child-identity.test.ts` — sibling method `resolveChildIdentity(childRef: SealedChildRef, parentReadKey)` already takes a full ref; `resolveNodeIdentity`'s new signature should match this shape.

Current call site (useSharedWriteOps.ts line ~190):
```typescript
const childNodeId = await resolveChildNodeId(item.ipnsName);
```
becomes `resolveChildNodeId(item)` once `resolveNodeIdentity` takes a `SealedChildRef` — `item: SealedChildRef` is already in scope in `deleteItemHandler`.

**Analog 2 (runWithFailureUx wiring):** `apps/web/src/hooks/useFolderMutations.ts` (lines 116-123) — the only correctly-wired owned-tree analog:

```typescript
import { runWithFailureUx } from './useMutationFailureUx';
// ...
await runWithFailureUx(async () => {
  result = await client.createFolder(parentFolder.ipnsName, name);
});
```

`useMutationFailureUx.ts` exposes `refreshWriteAccess?: () => Promise<void>` as an option (line 77) consumed inside `runWithFailureUx`'s retry branch (lines 193-224, `retryAfterRefresh`). `useSharedWriteOps.ts` currently only has `withRevocationGuard` (imported from `@cipherbox/sdk` as `sdkWithRevocationGuard`, line 16) wrapping ops — it never imports or calls `runWithFailureUx`. Compose as `withRevocationGuard(() => runWithFailureUx(() => op(shareId), { refreshWriteAccess }))` per RESEARCH.md's SC4 concrete-change #3 (403 revocation is a harder failure than a stale writeKey).

---

### `tests/web-e2e/tests/writable-shares.spec.ts` — NEW case (descend 2, up 1, write)

**Analog:** same file, test `8.4` "Bob navigates back to root and re-enters subfolder with write access" (lines 657-696) — covers descend-then-write but not the up-one-level-then-write gap. Also reference `8.3` (lines 620-656, depth-2 descent) for the setup pattern.

```
test('8.4 Bob navigates back to root and re-enters subfolder with write access', async () => { ... });
```

New case should follow this same `test.describe.serial` numbered-case style (e.g., `8.4b` or renumber), reusing the same page/context setup already established earlier in the serial block (Alice/Bob accounts from `1.1`).

---

### `tests/web-e2e/tests/shared-folder-desync.spec.ts` — NEW case (mutate-while-deeper)

**Analog:** same file, existing two-client harness pattern (owner + grantee accounts, test 2.1/3.1 style)

Extend with: descend deeper as grantee, mutate from the owner client, then `navigateUp()` as grantee and assert children reflect the fresh listing (not the frozen snapshot). Reuse the harness's existing dual-context/dual-page setup rather than introducing a new fixture.

---

### `apps/web/src/components/file-browser/SharedFolderRow.tsx` — drag-kind fix

**Analog:** `apps/web/src/components/file-browser/SharedFileBrowser.tsx` (lines 777, 841) — already-correct usage of `isFileRefResolved`

```typescript
// SharedFileBrowser.tsx already does this at 777/841:
isFileRefResolved(item, resolvedByIpnsName)
```

Replace `SharedFolderRow.tsx`'s two `isFileRef(...)` calls (lines 111, 116 in `handleDragStart`) with `isFileRefResolved(i, resolvedByIpnsName)` / `isFileRefResolved(item, resolvedByIpnsName)`, after threading a new `resolvedByIpnsName: Map<string, ResolvedChild>` prop from the `<SharedFolderRow>` call site in `SharedFileBrowser.tsx` (~line 759-805), matching the existing `resolved={resolvedByIpnsName.get(item.ipnsName)}` prop already passed there (line 762).

## Shared Patterns

### `runWithFailureUx` wiring for mutation hooks
**Source:** `apps/web/src/hooks/useFolderMutations.ts` (lines 116-123, comment explains WHY: "a stale local sequence (ReconcileStaleError, SC#3/D-04) retries with bounded backoff")
**Apply to:** `useSharedWriteOps.ts`'s every write op (`updateSharedFileHandler`, `moveItemHandler`, `batchMoveItemsHandler`, delete/rename handlers)
```typescript
await runWithFailureUx(async () => {
  result = await client.someMutation(...);
});
```
With `refreshWriteAccess` supplied for the shared-write case (owned-tree callers omit it since they have no analogous stale-write-key concept).

### 404/410-style HTTP status detection idiom
**Source:** `packages/sdk-core/src/ipns/index.ts` (lines 317-325, `resolveIpnsRecord`)
**Apply to:** `createAndPublishIpnsRecord`'s new 410 handling — same file, same idiom, different status code and different field name in the returned shape (`tombstoned` vs `null`)
```typescript
const anyError = error as Error & { status?: number; response?: { status?: number } };
const status = anyError.status ?? anyError.response?.status;
```

### D-09 zero-on-every-exit-path discipline for minted key buffers
**Source:** `apps/web/src/hooks/useSharedNavigationActions.ts` header comment (lines 14-16) + existing `folderKey`/`childWriteKey`/`rootWriteKey` zeroing sites throughout the file
**Apply to:** the new `NavStackEntry.writeKey` field — every place `folderKey` is zeroed today, add the identical zero call for `writeKey`

### Fixture-building pattern for SealedChildRef-based SDK facade tests
**Source:** `packages/sdk/src/__tests__/resolve-child-identity.test.ts` (`buildChildFixture`, lines 32-66)
**Apply to:** `resolve-node-identity.test.ts`'s rewrite and the new `resolveFileMetadata`/`downloadFromIpns` fail-closed test file — `sealNode` + (`sealChildReadKey` where a parent readKey wrap is needed) + `vi.mock('@cipherbox/sdk-core', ...)` mocking `resolveIpnsRecord`/`fetchFromIpfs`

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `tests/web-e2e/tests/rotation-ux.spec.ts` (D-01/WRITE-03 rewrite) | test | event-driven | This is an in-place rewrite of an existing test's OWN prior version (direct toast injection → real classifier flow); no external analog needed — the file's own `SCOPE NOTE` comment (lines 279-290) documents the target end-state |
| `useSharedWriteOps.ts`'s `refreshWriteAccess` supplier body itself | hook | event-driven | Per RESEARCH.md's sequencing note, this most naturally reuses the SC1/SC6-consolidated "re-derive writeKey + reseed for current depth" helper in `useSharedNavigationActions.ts` — that helper does not exist yet at mapping time (it's produced by this same phase), so there is no pre-existing analog; the planner should treat the SC6 extraction as the analog once it lands within the phase's own task sequence |

## Metadata

**Analog search scope:** `apps/web/src/hooks/`, `apps/web/src/components/file-browser/`, `packages/sdk/src/`, `packages/sdk/src/__tests__/`, `packages/sdk-core/src/ipns/`, `packages/sdk-core/src/__tests__/`, `packages/sdk/src/share/`, `tests/web-e2e/tests/`
**Files scanned:** ~15 (targeted reads, all cited above with line numbers)
**Pattern extraction date:** 2026-07-10

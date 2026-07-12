# Phase 78: Recovery Tool v3, Vault-Load Guards, Web UX and CI Guards - Pattern Map

**Mapped:** 2026-07-12
**Files analyzed:** 11
**Analogs found:** 9 / 11

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `apps/web/recovery-src/main.ts` (NEW) | utility (standalone entry, UI wiring) | event-driven | `apps/web/public/recovery.html` (current `<script>` body) | exact (port target) |
| `apps/web/recovery-src/walk.ts` (NEW) | service (recursive tree walk) | streaming/transform | `packages/sdk/src/folder-listing.ts::resolveChildren` (lines ~87-127) | exact |
| `apps/web/recovery-src/gateway.ts` (NEW) | service (HTTP transport) | request-response | `packages/crypto/src/ipns/parse-record.ts` + `verify-record.ts` | role-match |
| `apps/web/recovery-src/build.ts` (NEW) | config (esbuild script) | batch | repo-wide `tsup` build scripts (every package's `package.json build`) | role-match |
| `apps/web/public/recovery.html` (MODIFIED — template) | component | request-response | current file itself (keep DOM ids/testids) | exact |
| `tests/web-e2e/tests/recovery.spec.ts` (MODIFIED — un-fixme) | test | request-response | itself (remove `test.fixme` only) | exact |
| `apps/web/src/components/file-browser/useFileBrowserActions.ts` (MODIFIED — `handleDownload`/`handleBatchDownload`) | hook | request-response | `apps/web/src/hooks/useFileDownload.ts::downloadFromIpns` | exact |
| `apps/web/src/hooks/useBin.ts` (MODIFIED — `restore`/`restoreMultiple`) | hook | CRUD | `apps/web/src/hooks/useFileDownload.ts` (store-driven status pattern) | role-match |
| `eslint.config.js` (MODIFIED — new D-07 rule block) | config | static-analysis | existing rule block at lines 25-31 | exact |
| `apps/web/src/hooks/useSyncPolling.ts` (MODIFIED — `invalidateOpenFolder`) | hook | event-driven | `apps/web/src/stores/folder.store.ts` sequence-guard (`updateFolderSequence`) | exact |
| `apps/web/src/hooks/useSharedNavigationActions.ts` (MODIFIED — `navigateToSubfolder`) | hook | event-driven | itself — existing `generation`/mirror-capture pattern at lines 345-440, 584, 855 | exact |
| `docs/DEVELOPMENT.md` (MODIFIED — testing section) | config/docs | — | existing Testing section, lines 112-148 | exact |
| new spec: item-3 poll-monotonicity | test | event-driven | `tests/web-e2e/tests/shared-folder-desync.spec.ts` (multi-account, nav-triggered re-resolve pattern) | role-match |
| new spec: item-11 descent-vs-restore | test | event-driven | `tests/web-e2e/tests/writable-shares.spec.ts` / `shared-folder-desync.spec.ts` | role-match |

## Pattern Assignments

### `apps/web/recovery-src/walk.ts` (service, streaming)

**Analog:** `packages/sdk/src/folder-listing.ts` (`resolveChildren`, ~lines 87-127)

Copy the walk algorithm verbatim, swapping the SDK's API-backed resolve for a plain gateway fetch:

```typescript
for (const childRef of node.children ?? []) {
  const publishedBytes = await fetchFromGateway(childRef.ipnsName, gatewayConfig); // NEW: gateway-only resolve
  const published: PublishedNode = JSON.parse(new TextDecoder().decode(publishedBytes));

  const childReadKey = await unsealChildReadKey(
    childRef.readKeySealed,
    parentReadKey,
    published.id,
    published.kind,
    childRef.generation   // PARENT MIRROR — never published.generation (§2.6 rule)
  );
  const childNode = await unsealNode(published, childReadKey);
  // file: childNode.content.fileKey already raw; folder: recurse
}
```

Critical: the `childRef.generation` (parent mirror) vs `published.generation` distinction is the #1 porting bug risk (RESEARCH.md Pitfall 2). `useSharedNavigationActions.ts` lines 345-440 shows the same generation-source rule already correctly implemented in the web app — cross-check against it.

### `apps/web/recovery-src/gateway.ts` (service, request-response)

**Analog:** `packages/crypto/src/ipns/parse-record.ts`, `verify-record.ts`

```typescript
async function resolveIpnsVerified(ipnsName: string, gatewayUrl: string): Promise<string> {
  const resp = await fetch(`${gatewayUrl}/routing/v1/ipns/${ipnsName}`, {
    headers: { Accept: 'application/vnd.ipfs.ipns-record' },
  });
  if (!resp.ok) throw new Error(`IPNS resolve failed: ${resp.status}`);
  const marshalledRecord = new Uint8Array(await resp.arrayBuffer());
  const valid = await verifyIpnsRecordSignature(ipnsName, marshalledRecord);
  if (!valid) throw new Error('IPNS record signature verification failed — possible tampering');
  const parsed = await parseIpnsRecord(marshalledRecord);
  return parsed.value.startsWith('/ipfs/') ? parsed.value.slice(6) : parsed.value;
}
```

Never import `sdk-core`'s `resolveIpnsRecord` (API-relayed, violates D-02). Keep the current recovery.html's 3-rung fallback ladder (delegated-routing → `/ipns/` HEAD → Kubo `/api/v0/name/resolve`), but only run signature verification on the primary rung.

### `apps/web/src/components/file-browser/useFileBrowserActions.ts` (hook, request-response)

**Analog:** `apps/web/src/hooks/useFileDownload.ts::downloadFromIpns` (lines 8-52, read in full)

Current bug: `handleDownload` (line 413-426) and `handleBatchDownload` (line 478-491) call `downloadFileFromIpns` (the raw service function from `services/download.service.ts`, imported line 34) directly — never touching `useDownloadStore`, so `isDownloading` stays `false`.

Copy this exact store-driven wrapping pattern from `useFileDownload.ts`:

```typescript
const downloadFromIpns = useCallback(
  async (params: { fileRef: SealedChildRef; folderKey: Uint8Array; fileName: string }) => {
    try {
      startDownload(params.fileName);
      if (!hasSdkClient()) throw new Error('SDK not initialized — please log in again');
      const client = getSdkClient();
      const decryptedBytes = await client.downloadFromIpns(
        params.fileRef, params.folderKey, (loaded, total) => setProgress(loaded, total)
      );
      setDecrypting();
      await new Promise((resolve) => setTimeout(resolve, 100));
      triggerBrowserDownload(decryptedBytes, params.fileName);
      setSuccess();
    } catch (err) {
      const message = (err as Error).message || 'Download failed';
      setError(message);
      logger.error('[Download] Download failed:', err);
      throw err;
    }
  }, [...]
);
```

`useFileBrowserActions.ts`'s `handleDownload`/`handleBatchDownload` must call `useDownloadStore`'s `startDownload`/`setProgress`/`setDecrypting`/`setSuccess`/`setError` around the existing `downloadFileFromIpns` call (or switch to calling `useFileDownload().downloadFromIpns` directly if the SDK client signature matches — verify at plan time). `download.store.ts` (lines 1-58, read in full) is the state shape to drive: `status: 'idle'|'downloading'|'decrypting'|'success'|'error'`, `progress: 0-100`.

### `apps/web/src/hooks/useBin.ts` (hook, CRUD)

**Analog:** `apps/web/src/hooks/useFileDownload.ts` (store-driven status pattern), but note restore is metadata-only (no byte stream) — D-05 / RESEARCH.md flags this needs a **new** UX affordance, not a literal reuse of `download.store`'s progress percentage. Reuse the `status` state-machine shape (idle/loading/success/error) but drop `progress`/`loadedBytes`/`totalBytes` fields that don't apply to a metadata-only op — or add a lightweight `restore.store.ts` sibling with just `status`/`error` if the planner wants store-based state.

### `eslint.config.js` (config, static-analysis)

**Analog:** existing rule block, lines 25-31 (own file, append a new config object)

```javascript
{
  files: ['apps/web/src/**/*.{ts,tsx}'],
  ignores: ['apps/web/src/**/__tests__/**'],
  rules: {
    '@typescript-eslint/no-restricted-imports': ['error', {
      patterns: [{
        group: ['@cipherbox/sdk-core', '@cipherbox/core'],
        message: 'apps/web/src must not import runtime bindings from @cipherbox/sdk-core or @cipherbox/core (D-07 boundary) — use the @cipherbox/sdk facade instead.',
        allowTypeImports: true,
      }],
    }],
    'no-restricted-syntax': ['error', {
      selector: 'CallExpression[callee.name=/^(fetchFromIpfs|addToIpfs|unpinFromIpfs)$/]',
      message: 'Raw IPFS calls are forbidden in apps/web/src (D-07) — use the SDK client facade.',
    }],
  },
},
```

Flat config uses a plain array (`export default [...]`, no `defineConfig`/`FlatCompat` wrapper) — imports are `globals`, `@eslint/js`, `typescript-eslint`, `eslint-plugin-prettier/recommended`. Append the new object to the existing array after the current rules block (line 31). Verify `allowTypeImports` on a mixed `import { type Foo, bar }` fixture before trusting it (RESEARCH.md Assumption A1) — fall back to `no-restricted-syntax` on `ImportDeclaration` if it under/over-fires.

### `apps/web/src/hooks/useSyncPolling.ts` (hook, event-driven — item 3)

**Analog:** `apps/web/src/stores/folder.store.ts`'s existing `updateFolderSequence` sequence-guard call at `useSyncPolling.ts:46` (`store.updateFolderSequence(currentFolderId, state.sequenceNumber)`) — this is the existing monotonicity pattern to extend/replicate for the `invalidateOpenFolder` (lines 26-... ) race: a slow poll response must not overwrite a newer nav-triggered folder state. Compare `state.sequenceNumber` before applying an async poll result, mirroring how `folder.store.ts` already gates writes by sequence number elsewhere.

### `apps/web/src/hooks/useSharedNavigationActions.ts` (hook, event-driven — item 11)

**Analog:** itself — the file already contains the correct generation-mirror capture pattern (`navigateToSubfolder`, lines 345-440; envelope capture note at line 584; mirrored again at line 855) to model a cancellation/generation token on. Fix needs a monotonic token/AbortController threaded through `navigateToSubfolder` so a fast navigateUp/breadcrumb click during an in-flight descent doesn't leave the SDK's active writeKey pointed at the wrong depth (per RESEARCH.md's exact trace).

### New e2e specs (item 3 + item 11)

**Analog:** `tests/web-e2e/tests/shared-folder-desync.spec.ts` (lines 1-50, read in full) — `test.describe.serial`, multi-account scaffolding via `createWalletTestAccount`/`closeWalletTestAccounts` from `utils/multi-account-wallet.ts`, page-object imports (`FileListPage`, `ContextMenuPage`, `ShareDialogPage`, `SharedFileBrowserPage`). This is the house style for a new deterministic race-regression spec: no reliance on poll timing, explicit nav-triggered trigger, `test.describe.serial`, never `test.skip`/`test.fixme` on a permanent regression test. For item 11 specifically, `writable-shares.spec.ts` is the secondary analog (extend rather than duplicate scaffolding, per RESEARCH.md's Wave 0 Gaps note).

## Shared Patterns

### Store-driven async status (SC2)

**Source:** `apps/web/src/stores/download.store.ts` (Zustand `create<DownloadState>`)
**Apply to:** any new/modified hook needing a UI-visible async status (`useFileBrowserActions.ts` download wiring, `useBin.ts` restore wiring)

```typescript
export const useDownloadStore = create<DownloadState>((set) => ({
  status: 'idle', progress: 0, loadedBytes: 0, totalBytes: 0, currentFile: null, error: null,
  startDownload: (filename) => set({ status: 'downloading', progress: 0, currentFile: filename, error: null }),
  setProgress: (loaded, total) => set({ loadedBytes: loaded, totalBytes: total, progress: total > 0 ? Math.round((loaded * 100) / total) : 0 }),
  setDecrypting: () => set({ status: 'decrypting' }),
  setSuccess: () => set({ status: 'success', progress: 100, currentFile: null }),
  setError: (error) => set({ status: 'error', error, currentFile: null }),
}));
```

### No-hand-roll crypto/codec (SC1)

**Source:** `packages/crypto` + `packages/core` barrels (`packages/crypto/src/index.ts`, `packages/core/src/index.ts`)
**Apply to:** every seal/unseal/parse call in the new `recovery-src/*` files — never reimplement AES-GCM+AAD, ECIES, or IPNS protobuf parsing by hand (RESEARCH.md "Don't Hand-Roll" table is authoritative; treat it as the canonical function list).

### Flat ESLint config append (SC3a)

**Source:** `eslint.config.js` itself (root, plain array export)
**Apply to:** the new D-07 rule block — append as a new array entry, do not restructure existing entries.

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `apps/web/recovery-src/build.ts` (esbuild script) | config | batch | No existing package uses a standalone esbuild script outside `tsup`; every other package's build is `tsup`-driven via `package.json` script, not a bespoke `.ts` build file. Use RESEARCH.md's Pattern/Architecture section (esbuild `--bundle` + HTML-splice) as the primary reference instead of a codebase analog. |
| SC2 restore-spinner UI affordance | component | — | No existing Playwright spec or component asserts on `useDownloadStore`/restore-driven spinner DOM state (RESEARCH.md Wave 0 Gaps) — flag for manual/Puppeteer verification per CLAUDE.md if a Playwright assertion proves impractical. |

## Metadata

**Analog search scope:** `packages/crypto/src`, `packages/core/src`, `packages/sdk/src/folder-listing.ts`, `apps/web/src/{hooks,stores,components/file-browser,services}`, `eslint.config.js`, `tests/web-e2e/tests`
**Files scanned:** ~20 (via RESEARCH.md's prior full reads + targeted greps in this pass)
**Pattern extraction date:** 2026-07-12
**Note:** RESEARCH.md (same phase dir) already contains exhaustive line-cited excerpts for SC1's crypto/codec calls and the D-07 grep-gate replication; this file focuses on the file→analog mapping table and the SC2/SC3c hook-level analogs RESEARCH.md described but didn't excerpt as copy-paste code.

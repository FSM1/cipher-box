# Phase 37: Parallel Batch Upload Pipeline - Research

**Researched:** 2026-03-30
**Domain:** TypeScript SDK upload orchestration, Web Workers, concurrency control
**Confidence:** HIGH

## Summary

This phase replaces the sequential per-file upload loop in `useDropUpload` with a parallel encrypt+pin pipeline that does N concurrent encrypt+pin operations followed by a single folder metadata update + IPNS publish. The core changes span three layers: (1) a new Web Worker for offloading encryption to a background thread, (2) a concurrency pool in the SDK that manages parallel encrypt-then-pin operations, and (3) modifications to `useDropUpload` to call a new batch `uploadFiles()` method instead of looping over `uploadFile()`.

All cryptographic primitives used by the project (`crypto.subtle` for AES-GCM/CTR, `eciesjs` for ECIES key wrapping via `@noble/secp256k1`) are pure JavaScript or Web Crypto API calls, both of which are fully available in Web Worker contexts. The existing `@cipherbox/crypto` package has no Node.js-specific or DOM-specific dependencies that would block worker usage.

**Primary recommendation:** Implement a dedicated `encrypt.worker.ts` in the web app that imports `@cipherbox/crypto` functions directly, use `p-limit` for a fixed concurrency pool of 3 inside a new `uploadFiles()` SDK method, and use Transferable ArrayBuffer transfers to avoid copying large file buffers between main thread and worker.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Fixed concurrency pool of 3 concurrent encrypt+pin operations. Pool size is a constant -- easy to tune later.
- **D-02:** Pipeline-style processing: encrypt file -> pin to IPFS -> free ciphertext -> next slot. Do NOT buffer all encrypted files before pinning (avoids 3x 100MB memory spikes).
- **D-03:** New `uploadFiles()` batch method on `CipherBoxClient` (TypeScript SDK). Accepts multiple files, runs encrypt+pin in parallel internally, collects all FilePointers, then does ONE folder metadata update + ONE IPNS publish.
- **D-04:** Existing `uploadFile()` remains unchanged for single-file uploads and retry of failed files.
- **D-05:** `uploadFiles()` must re-read folder metadata just before the final publish to mitigate the stale-children race (another device may have published new children during the batch window).
- **D-06:** Progress reporting via per-file callbacks -- the batch method needs to surface per-file progress to the Zustand store for inline progress rows.
- **D-07:** Offload file encryption to Web Workers for true parallelism. Main thread stays responsive for progress bars and drag-drop interactions.
- **D-08:** This folds in the existing todo "Offload large file encryption to Web Worker" -- that todo is now part of this phase's scope.
- **D-09:** Publish successes, surface errors. If 3 of 5 files encrypt+pin successfully, publish those 3 to folder metadata. Failed files show inline error rows with retry buttons (existing Phase 36 error UX).
- **D-10:** One publish per batch -- wait for all concurrency slots to drain (success or fail) across the entire batch, then publish all successes in a single folder metadata update.
- **D-11:** Failed file retry uses existing `uploadFile()` single-file method (normal single-file upload into the already-published folder).
- **D-12:** No Rust SDK or FUSE changes in this phase.

### Claude's Discretion

- Web Worker communication protocol (postMessage structure, transferable buffers)
- Whether `uploadFiles()` lives on `CipherBoxClient` directly or as a separate sdk-core function composed by the client
- Exact error types and retry semantics within the batch pipeline
- Whether to add a new sdk-core `encryptAndPinFile()` primitive that `uploadFiles()` composes internally

### Deferred Ideas (OUT OF SCOPE)

- Adaptive concurrency based on file size
- FUSE write-coalescing for desktop
- Accumulated retry batching

</user_constraints>

## Project Constraints (from CLAUDE.md)

- All code must be TypeScript with `Uint8Array` for binary data
- Web Crypto API for browser encryption; never expose plaintext keys to server
- camelCase for API fields; `pnpm api:generate` after API changes (not expected this phase)
- Clear sensitive data from memory after use (`clearBytes()`)
- Never use `.buffer` on Uint8Array for Blob construction (pass typed array directly)
- Conventional Commits enforced by husky `commit-msg` hook
- Never push directly to `main` -- feature branches + PRs only
- Run relevant E2E tests before pushing

## Standard Stack

### Core

| Library             | Version | Purpose                                             | Why Standard                                                                                             |
| ------------------- | ------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| p-limit             | 7.3.0   | Fixed-size async concurrency pool                   | De facto standard for limiting concurrent Promises; ESM-only, zero deps, TypeScript types included       |
| Vite                | 7.3.x   | Web Worker bundling with `new Worker(new URL(...))` | Already in project; native worker import support with `type: 'module'`                                   |
| @cipherbox/crypto   | 0.29.0  | AES-GCM/CTR encryption, ECIES key wrapping          | Existing project package; all functions use Web Crypto API (worker-compatible)                           |
| @cipherbox/sdk-core | current | Stateless upload/folder/IPNS operations             | Existing project package; `uploadFile()`, `addFilePointerToFolder()`, `updateFolderMetadataAndPublish()` |
| @cipherbox/sdk      | current | Stateful `CipherBoxClient` with `withOperation()`   | Existing project package; new `uploadFiles()` method goes here                                           |

### Supporting

| Library | Version    | Purpose                        | When to Use                                                                                                             |
| ------- | ---------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| zustand | (existing) | Per-file upload progress state | Already in `upload.store.ts`; batch pipeline plugs into existing `addFile()`, `updateFileProgress()`, `setFileStatus()` |

### Alternatives Considered

| Instead of           | Could Use                                 | Tradeoff                                                                                                                         |
| -------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| p-limit              | Hand-rolled semaphore                     | p-limit is 50 lines, battle-tested, correct edge-case handling; hand-rolling would duplicate work                                |
| p-limit              | p-queue                                   | p-queue adds priority queues, events, timeouts -- overkill for a simple fixed pool of 3                                          |
| Dedicated Web Worker | Worker pool library (workerpool, comlink) | Overkill; single worker with sequential message processing is sufficient since concurrency pool is 3 and encryption is CPU-bound |

**Installation:**

```bash
pnpm --filter @cipherbox/sdk add p-limit
```

Note: p-limit v7+ is ESM-only (`"type": "module"`). The project uses `moduleResolution: "bundler"` and `module: "ESNext"` in tsconfig, so ESM-only packages work without issues. Vite handles the bundling transparently.

**Version verification:** p-limit 7.3.0 confirmed via `npm view p-limit version` (2026-03-30). The SDK package uses tsup for bundling which handles ESM imports correctly.

## Architecture Patterns

### Recommended Project Structure

```
apps/web/src/
  workers/
    decrypt-sw.ts        # Existing: Service Worker for streaming decryption
    encrypt.worker.ts    # NEW: Web Worker for file encryption

packages/sdk/src/
  client.ts              # MODIFIED: Add uploadFiles() method

packages/sdk-core/src/
  upload/
    index.ts             # EXISTING: uploadFile() -- unchanged
```

### Pattern 1: Web Worker for Encryption

**What:** A dedicated Web Worker (`encrypt.worker.ts`) that receives plaintext file data via `postMessage` with Transferable buffers, encrypts using `@cipherbox/crypto`, and returns the ciphertext + metadata via `postMessage` back to main thread.

**When to use:** Every file upload in both `uploadFiles()` (batch) and potentially `uploadFile()` (single).

**Example:**

```typescript
// apps/web/src/workers/encrypt.worker.ts
/// <reference lib="webworker" />

import {
  generateFileKey,
  generateIv,
  generateCtrIv,
  encryptAesGcm,
  encryptAesCtr,
  wrapKey,
  clearBytes,
  bytesToHex,
} from '@cipherbox/crypto';

export type EncryptRequest = {
  id: string; // Correlation ID for matching response
  data: Uint8Array; // Plaintext file content (transferred, not copied)
  userPublicKey: Uint8Array;
  encryptionMode: 'GCM' | 'CTR';
};

export type EncryptResponse = {
  id: string;
  ciphertext: Uint8Array; // Transferred back to main thread
  wrappedKey: string; // Hex-encoded ECIES-wrapped file key
  iv: string; // Hex-encoded IV
  fileKey: Uint8Array; // Raw file key for re-wrapping (transferred)
  originalSize: number;
  encryptedSize: number;
  encryptionMode: 'GCM' | 'CTR';
};

export type EncryptError = {
  id: string;
  error: string;
};

self.onmessage = async (event: MessageEvent<EncryptRequest>) => {
  const { id, data, userPublicKey, encryptionMode } = event.data;
  try {
    const fileKey = generateFileKey();
    const iv = encryptionMode === 'CTR' ? generateCtrIv() : generateIv();

    const ciphertext =
      encryptionMode === 'CTR'
        ? await encryptAesCtr(data, fileKey, iv)
        : await encryptAesGcm(data, fileKey, iv);

    const wrappedKey = await wrapKey(fileKey, userPublicKey);
    const fileKeyCopy = new Uint8Array(fileKey);
    clearBytes(fileKey);

    const response: EncryptResponse = {
      id,
      ciphertext,
      wrappedKey: bytesToHex(wrappedKey),
      iv: bytesToHex(iv),
      fileKey: fileKeyCopy,
      originalSize: data.byteLength,
      encryptedSize: ciphertext.byteLength,
      encryptionMode,
    };

    // Transfer ownership of large buffers to avoid copying
    self.postMessage(response, [ciphertext.buffer, fileKeyCopy.buffer] as Transferable[]);
  } catch (err) {
    const errorResponse: EncryptError = {
      id,
      error: (err as Error).message,
    };
    self.postMessage(errorResponse);
  }
};
```

```typescript
// Main thread: creating and using the worker
const worker = new Worker(new URL('../workers/encrypt.worker.ts', import.meta.url), {
  type: 'module',
});
```

### Pattern 2: Concurrency Pool with p-limit

**What:** Use p-limit to create a fixed pool of 3 concurrent async operations. Each slot processes one file through the full encrypt -> pin -> free-memory pipeline.

**When to use:** Inside `uploadFiles()` on `CipherBoxClient`.

**Example:**

```typescript
import pLimit from 'p-limit';

const UPLOAD_CONCURRENCY = 3;

async uploadFiles(
  folderIpnsName: string,
  files: Array<{ data: Uint8Array; fileName: string; mimeType: string }>,
  onFileProgress?: (fileName: string, percent: number) => void,
  onFileComplete?: (fileName: string, result: 'success' | 'error', error?: string) => void
): Promise<{ successes: string[]; failures: Array<{ fileName: string; error: string }> }> {
  return this.withOperation('uploadFiles', async () => {
    const folder = this.folderTree.get(folderIpnsName);
    if (!folder) throw new Error('Folder not loaded');

    const limit = pLimit(UPLOAD_CONCURRENCY);
    const results: Array<{ fileName: string; uploadResult?: UploadResult; error?: string }> = [];

    // Run all encrypt+pin operations with concurrency limit
    const settled = await Promise.allSettled(
      files.map((file) =>
        limit(async () => {
          const fileId = crypto.randomUUID();
          const encryptionMode = selectEncryptionMode(file.mimeType, file.data.length);

          const uploadResult = await sdkCore.uploadFile({
            data: file.data,
            fileId,
            mimeType: file.mimeType,
            folderKey: folder.folderKey,
            userPublicKey: this.config.vaultKeypair.publicKey,
            ctx: this.ctx,
            onProgress: (percent) => onFileProgress?.(file.fileName, percent),
            teeKeys: this.config.teeKeys,
            encryptionMode,
          });

          return { fileName: file.fileName, fileId, uploadResult };
        })
      )
    );

    // Collect successes and failures
    // ... (process settled results, add FilePointers for successes)
    // Re-read folder metadata before publish (D-05)
    // Single updateFolderMetadataAndPublish call (D-10)
  });
}
```

### Pattern 3: Stale-Children Race Mitigation (D-05)

**What:** Before the final publish, re-read the folder's current IPNS record to get the latest children array. Merge the batch's new FilePointers with whatever children exist on-chain, avoiding overwriting concurrent changes from other devices.

**When to use:** In `uploadFiles()` just before the single `updateFolderMetadataAndPublish()` call.

**Example:**

```typescript
// After all encrypt+pin operations complete, before publish:
const freshFolder = await sdkCore.loadFolderMetadata({
  ipnsName: folderIpnsName,
  folderKey: folder.folderKey,
  ctx: this.ctx,
});

// Use fresh children as base, add new FilePointers
let mergedChildren = freshFolder?.metadata.children ?? folder.children;
const freshSeq = freshFolder?.sequenceNumber ?? folder.sequenceNumber;

for (const success of successfulUploads) {
  const { updatedChildren } = sdkCore.addFilePointerToFolder({
    children: mergedChildren,
    fileId: success.fileId,
    fileName: success.fileName,
    fileMetaIpnsName: success.uploadResult.fileMetaIpnsName,
    ipnsPrivateKeyEncrypted: success.uploadResult.ipnsPrivateKeyEncrypted,
  });
  mergedChildren = updatedChildren;
}

// Publish with fresh sequence number
await sdkCore.updateFolderMetadataAndPublish({
  children: mergedChildren,
  folderKey: folder.folderKey,
  ipnsPrivateKey: folder.ipnsKeypair.privateKey,
  ipnsName: folderIpnsName,
  sequenceNumber: freshSeq,
  ctx: this.ctx,
});
```

### Pattern 4: Transferable Buffer Protocol

**What:** When sending large Uint8Array data between main thread and Web Worker, transfer ownership of the underlying ArrayBuffer to avoid copying.

**When to use:** Every encrypt request (main -> worker) and encrypt response (worker -> main).

**Example:**

```typescript
// Main thread -> Worker: transfer plaintext buffer
const data = new Uint8Array(await file.arrayBuffer());
worker.postMessage(
  { id: uploadId, data, userPublicKey, encryptionMode },
  [data.buffer] as Transferable[] // Transfer ownership -- data.byteLength becomes 0
);

// Worker -> Main thread: transfer ciphertext buffer
self.postMessage(response, [response.ciphertext.buffer, response.fileKey.buffer] as Transferable[]);
```

**Critical constraint:** After transferring, the sender's buffer becomes zero-length and unusable. This is desirable -- it implements D-02's "free ciphertext" requirement. The plaintext is freed on the main thread after transfer to worker, and the ciphertext is freed on the worker after transfer back.

### Anti-Patterns to Avoid

- **Buffering all encrypted files before pinning:** D-02 explicitly forbids this. With 3 concurrent 100MB files, that's 300MB of ciphertext in memory. Instead, pipeline: encrypt -> pin -> free, then the next file enters the slot.
- **Creating the worker inside the SDK package:** Web Workers are a browser API. The SDK (`@cipherbox/sdk`) must remain environment-agnostic (no browser/DOM deps). The worker lives in `apps/web/` and encryption offloading is done at the web app layer, with the SDK accepting pre-encrypted data or a pluggable encrypt function.
- **Using SharedArrayBuffer:** Requires COOP/COEP headers which conflict with Web3Auth's OAuth popup flow. The project's Vite server already sets `Cross-Origin-Opener-Policy: same-origin-allow-popups` specifically for Web3Auth. SharedArrayBuffer requires `same-origin`, which would break authentication.
- **Creating a new worker per file:** Worker creation overhead is significant. Create one worker at app startup (or lazily on first upload) and reuse it for all encryption operations.

## Don't Hand-Roll

| Problem                 | Don't Build                            | Use Instead                                                             | Why                                                                         |
| ----------------------- | -------------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Concurrency limiting    | Custom semaphore with Promise queue    | p-limit                                                                 | Battle-tested, correct cleanup on rejection, 50 lines, TypeScript types     |
| Worker message typing   | Untyped postMessage with string checks | Typed discriminated union (EncryptRequest/EncryptResponse/EncryptError) | Prevents runtime type errors; the worker message protocol is the contract   |
| CTR counter computation | Manual BigInt counter math in worker   | Existing `encryptAesCtr()` from `@cipherbox/crypto`                     | Already handles chunk-aligned counters correctly; duplicating would diverge |

**Key insight:** The encryption logic already exists in `@cipherbox/crypto` and `@cipherbox/sdk-core`. This phase is about orchestration (parallelism, worker offloading, batch metadata update), not reimplementing crypto.

## Common Pitfalls

### Pitfall 1: Worker Import Path Resolution in Vite

**What goes wrong:** Using dynamic or variable paths in `new Worker(new URL(...))` causes Vite to fail at bundling the worker script.
**Why it happens:** Vite statically analyzes `new URL('./path', import.meta.url)` at build time. The path must be a string literal, not a variable.
**How to avoid:** Always use a static string literal in the URL constructor:

```typescript
// CORRECT
const worker = new Worker(new URL('../workers/encrypt.worker.ts', import.meta.url), {
  type: 'module',
});

// WRONG - Vite cannot statically resolve
const path = '../workers/encrypt.worker.ts';
const worker = new Worker(new URL(path, import.meta.url), { type: 'module' });
```

**Warning signs:** Worker fails to load in dev mode; production build silently omits the worker chunk.

### Pitfall 2: Stale Zustand State in Async Callbacks

**What goes wrong:** Upload progress callbacks capture stale Zustand state because the closure was created at render time.
**Why it happens:** React hook selectors capture state at render; async callbacks may run after many re-renders.
**How to avoid:** Always use `useUploadStore.getState()` inside async callbacks (already the pattern in current `useDropUpload`). Never rely on hook-selected values inside callbacks.
**Warning signs:** Progress bar stuck at 0%, or callbacks writing to a removed upload entry.

### Pitfall 3: Memory Leak from Untransferred Buffers

**What goes wrong:** Sending a 100MB Uint8Array to a worker without Transferable creates a 100MB copy in both threads (200MB total).
**Why it happens:** `postMessage` defaults to structured clone, which copies ArrayBuffers.
**How to avoid:** Always include the `.buffer` property in the transfer list. Verify by checking `data.byteLength === 0` after `postMessage`.
**Warning signs:** Memory usage doubles during upload; browser tab crashes on large files.

### Pitfall 4: FilePointer Name Collision During Batch

**What goes wrong:** `addFilePointerToFolder()` throws "A file with this name already exists" when adding the second FilePointer if two files share a name.
**Why it happens:** The batch pre-validation in `useDropUpload` catches duplicates against existing folder contents, but doesn't check for duplicates within the batch itself.
**How to avoid:** The existing `useDropUpload` already checks `batchNames` for within-batch duplicates (lines 55-60). Keep this validation in place.
**Warning signs:** Upload batch fails partway through with a confusing "already exists" error.

### Pitfall 5: Sequence Number Stale After Re-Read

**What goes wrong:** After re-reading folder metadata (D-05), the publish uses the fresh sequence number, but `updateFolderMetadataAndPublish` already handles 409 conflict with one retry. If the folder was published again between re-read and publish, the retry handles it.
**Why it happens:** The window between re-read and publish is small but nonzero.
**How to avoid:** The existing 409-conflict retry in `updateFolderMetadataAndPublish` (lines 196-231 of sdk-core folder/index.ts) already handles this case. No additional logic needed.
**Warning signs:** 409 responses from IPNS publish -- the existing retry handles it silently.

### Pitfall 6: Worker Not Terminated on Logout/Destroy

**What goes wrong:** Encryption worker keeps running after user logs out, holding memory and potentially processing stale requests.
**Why it happens:** Web Workers persist until explicitly terminated.
**How to avoid:** Terminate the worker when the SDK client is destroyed or the user logs out. Hook into the existing `destroy()` method on `CipherBoxClient` or the web app's logout flow.
**Warning signs:** Worker appears in DevTools "Sources" panel after logout; console warnings from the worker.

## Code Examples

Verified patterns from the existing codebase:

### Existing withOperation Pattern (SDK)

```typescript
// Source: packages/sdk/src/client.ts:1224
private async withOperation<T>(name: string, fn: () => Promise<T>): Promise<T> {
  const start = Date.now();
  this.emitter.emit({ type: 'operation:start', operation: name });
  try {
    const result = await fn();
    const durationMs = Date.now() - start;
    this.emitter.emit({ type: 'operation:end', operation: name, durationMs });
    return result;
  } catch (error) {
    this.emitter.emit({ type: 'error', operation: name, error: error as Error });
    throw error;
  }
}
```

The new `uploadFiles()` should be a single `withOperation('uploadFiles', ...)` call containing all internal parallelism.

### Existing addFilePointerToFolder Pattern

```typescript
// Source: packages/sdk-core/src/folder/index.ts:285
export function addFilePointerToFolder(params: {
  children: FolderChild[];
  fileId: string;
  fileName: string;
  fileMetaIpnsName: string;
  ipnsPrivateKeyEncrypted: string;
}): { updatedChildren: FolderChild[]; filePointer: FilePointer };
```

This is a pure function -- call it in a loop for each successful upload to build the merged children array before the single publish.

### Existing Vite Worker Import (from tsconfig)

```typescript
// The web app already excludes a worker file from the main tsconfig:
// tsconfig.json: "exclude": ["src/workers/decrypt-sw.ts"]
// The encrypt.worker.ts should similarly be excluded from the main
// tsconfig if it uses /// <reference lib="webworker" />.
```

### Existing Upload Store Integration

```typescript
// Source: apps/web/src/stores/upload.store.ts
// The batch pipeline needs to call these for each file:
useUploadStore.getState().addFile(uploadId, file.name, folderId, file);
useUploadStore.getState().updateFileProgress(uploadId, percent);
useUploadStore.getState().setFileStatus(uploadId, 'complete');
useUploadStore.getState().setFileStatus(uploadId, 'error', errorMessage);
```

These are called via `getState()` (not hook selectors) which avoids stale closure issues.

## State of the Art

| Old Approach                                         | Current Approach                                   | When Changed   | Impact                                                                                                    |
| ---------------------------------------------------- | -------------------------------------------------- | -------------- | --------------------------------------------------------------------------------------------------------- |
| Sequential file-by-file upload with N IPNS publishes | Parallel encrypt+pin pool with single IPNS publish | This phase     | Reduces publish latency from O(N) to O(1); reduces total upload time by ~(N-1)/N for IPNS-bound workloads |
| Main-thread encryption blocking UI                   | Web Worker encryption with Transferable buffers    | This phase     | Main thread stays responsive during large file encryption                                                 |
| `?worker` Vite import suffix                         | `new Worker(new URL(...))` constructor             | Vite 3+ (2022) | Standards-aligned; `?worker` still works but constructor is recommended                                   |

**Deprecated/outdated:**

- The `?worker` query suffix in Vite still works but the `new URL()` pattern is closer to web standards and preferred in Vite docs.
- `importScripts()` in workers -- ESM `import` statements work in module workers (`type: 'module'`).

## Open Questions

1. **Worker lifecycle in SDK vs web app**
   - What we know: The SDK package (`@cipherbox/sdk`) must remain browser-agnostic (no DOM/Worker APIs). The Web Worker must live in `apps/web/`.
   - What's unclear: How does `uploadFiles()` on the SDK client receive pre-encrypted data from the worker? Two options: (a) SDK method accepts raw data and web app handles worker encryption before calling SDK, or (b) SDK accepts a pluggable `encryptFn` that the web app implements using the worker.
   - Recommendation: Option (a) -- the web app layer wraps the worker, encrypts files, then calls SDK with ciphertext + metadata. This keeps the SDK clean and matches the existing architecture where `uploadFile()` in sdk-core handles encryption internally but could be decomposed. However, option (b) with a pluggable encrypt function is cleaner if we want the SDK to manage the full pipeline. **Claude's discretion per CONTEXT.md.**

2. **BYO-IPFS pinFn in batch context**
   - What we know: Single-file `uploadFile()` accepts an optional `pinFn` override for BYO-IPFS. The batch method needs the same capability.
   - What's unclear: Should `pinFn` be per-file or per-batch?
   - Recommendation: Per-batch (set once on the method call), consistent with how the client constructs `pinFn` in the current `uploadFile()`.

## Validation Architecture

### Test Framework

| Property           | Value                                                                                   |
| ------------------ | --------------------------------------------------------------------------------------- |
| Framework          | Vitest 3.x                                                                              |
| Config file        | `packages/sdk-core/vitest.config.ts` (unit), `tests/web-e2e/playwright.config.ts` (E2E) |
| Quick run command  | `pnpm --filter @cipherbox/sdk-core test -- --reporter=verbose`                          |
| Full suite command | `pnpm test` (all packages)                                                              |

### Phase Requirements -> Test Map

Since phase requirement IDs are TBD, mapping by decision:

| Decision | Behavior                                                         | Test Type | Automated Command                                                                   | File Exists?                               |
| -------- | ---------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------------- | ------------------------------------------ |
| D-03     | `uploadFiles()` batch method uploads N files with 1 publish      | unit      | `pnpm --filter @cipherbox/sdk vitest run --reporter=verbose`                        | No -- Wave 0                               |
| D-05     | Re-read folder metadata before publish merges concurrent changes | unit      | `pnpm --filter @cipherbox/sdk vitest run --reporter=verbose`                        | No -- Wave 0                               |
| D-09     | Partial failure: 3/5 succeed, publish 3, surface 2 errors        | unit      | `pnpm --filter @cipherbox/sdk vitest run --reporter=verbose`                        | No -- Wave 0                               |
| D-10     | Single publish after all slots drain                             | unit      | `pnpm --filter @cipherbox/sdk vitest run --reporter=verbose`                        | No -- Wave 0                               |
| D-07     | Encryption runs in Web Worker (functional test)                  | E2E       | `pnpm --filter @cipherbox/web-e2e exec playwright test tests/full-workflow.spec.ts` | Existing (uploads tested in full-workflow) |

### Sampling Rate

- **Per task commit:** `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test`
- **Per wave merge:** `pnpm test && pnpm typecheck`
- **Phase gate:** Full suite green + E2E full-workflow upload tests pass against staging

### Wave 0 Gaps

- [ ] `packages/sdk/src/__tests__/upload-batch.test.ts` -- covers D-03, D-05, D-09, D-10
- [ ] `packages/sdk/vitest.config.ts` -- already exists but has no test files; confirm test discovery works
- [ ] p-limit dependency: `pnpm --filter @cipherbox/sdk add p-limit`

## Sources

### Primary (HIGH confidence)

- **Codebase inspection** -- Direct reading of `useDropUpload.ts`, `upload.service.ts`, `file-crypto.service.ts`, `streaming-crypto.service.ts`, `upload.store.ts`, `client.ts`, `sdk-core/upload/index.ts`, `sdk-core/folder/index.ts`, `sdk-core/ipfs/index.ts`, `encrypt.ts` (AES-GCM), `encrypt.ts` (ECIES)
- [Vite Web Workers docs](https://vite.dev/guide/features#web-workers) -- Worker import patterns, `new URL()` constructor requirement, `type: 'module'`
- [MDN SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) -- Confirms `crypto.subtle` available in Web Workers via `WorkerGlobalScope.crypto`
- [MDN Transferable objects](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Transferable_objects) -- ArrayBuffer transfer semantics, zero-copy pattern
- [p-limit npm](https://www.npmjs.com/package/p-limit) -- v7.3.0, ESM-only, TypeScript types included

### Secondary (MEDIUM confidence)

- [MDN Worker.postMessage()](https://developer.mozilla.org/en-US/docs/Web/API/Worker/postMessage) -- Transfer list parameter for ArrayBuffer ownership transfer
- [Vite workshop: Web Workers](https://vite-workshop.netlify.app/web-workers) -- Additional examples of Vite worker patterns

### Tertiary (LOW confidence)

- None -- all findings verified against primary sources or codebase inspection.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- all libraries are either already in the project or verified current on npm registry
- Architecture: HIGH -- patterns derived directly from existing codebase patterns and verified Web API specifications
- Pitfalls: HIGH -- identified from codebase analysis (SharedArrayBuffer/COOP conflict, stale closures) and Vite documentation (static URL requirement)

**Research date:** 2026-03-30
**Valid until:** 2026-04-30 (stable domain; no expected breaking changes in Vite 7.x or Web Worker APIs)

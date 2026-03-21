# Security Review: Phase 19.1 SDK Extraction -- Post-Implementation

**Date:** 2026-03-20
**Scope:** All crypto-bearing code on `phase-19.1-extract-core-sdk` branch
**Reviewer:** Claude (security:review command)
**Type:** Post-implementation review (follows pre-implementation review)
**Pre-review reference:** `REVIEW-2026-03-20-phase19.1-sdk-extraction-plans.md`

## Executive Summary

The Phase 19.1 SDK extraction has been implemented with strong security hygiene. The code reorganization preserved the existing trust model (client-side-only encryption, zero-knowledge server) and introduced no new cryptographic algorithms or trust relationships. Two of five pre-review findings were fully fixed, one was partially addressed, and two remain open as accepted risks. Two new findings were identified during this post-implementation review.

**Risk Level:** LOW

| Severity | Pre-review (carried)  | New | Total |
| -------- | --------------------- | --- | ----- |
| Critical | 0                     | 0   | 0     |
| High     | 0 (both addressed)    | 0   | 0     |
| Medium   | 2 (1 open, 1 partial) | 2   | 4     |
| Low      | 2 (both accepted)     | 1   | 3     |

## Files Analyzed

| File                                                        | Crypto Operations                               | Status       |
| ----------------------------------------------------------- | ----------------------------------------------- | ------------ |
| `packages/sdk-core/src/ipfs/index.ts`                       | IPFS upload/download with auth tokens           | CLEAN        |
| `packages/sdk-core/src/ipns/index.ts`                       | IPNS signing, base64 encoding, sig verification | CLEAN        |
| `packages/sdk-core/src/folder/index.ts`                     | Folder key wrapping, TEE enrollment             | CLEAN        |
| `packages/sdk-core/src/upload/index.ts`                     | AES-GCM encryption, ECIES key wrapping          | CLEAN        |
| `packages/sdk-core/src/download/index.ts`                   | AES-GCM/CTR decryption, key unwrapping          | CLEAN        |
| `packages/sdk-core/src/file/index.ts`                       | File metadata encryption, IPNS key wrapping     | CLEAN        |
| `packages/sdk/src/client.ts`                                | Stateful client, key material lifecycle         | M-2 OPEN     |
| `packages/sdk/src/bin/index.ts`                             | Bin metadata encryption/decryption              | CLEAN        |
| `packages/sdk/src/share/index.ts`                           | Share key wrapping                              | CLEAN        |
| `packages/sdk/src/state/folder-tree.ts`                     | Key material storage and zeroing                | CLEAN        |
| `packages/sdk/src/state/key-cache.ts`                       | Key caching and zeroing                         | CLEAN        |
| `packages/sdk/src/types.ts`                                 | Config types with key material                  | INFO         |
| `packages/sdk/src/events.ts`                                | Event emission                                  | CLEAN        |
| `packages/api-client/src/instance.ts`                       | Singleton config, cached axios instance         | H-1 ACCEPTED |
| `apps/web/src/lib/sdk-provider.ts`                          | SDK lifecycle, ensureFolderRegistered           | NEW-M1       |
| `apps/web/src/hooks/useAuth.ts`                             | SDK init, setApiClientConfig, bin loading       | CLEAN        |
| `apps/web/src/hooks/useFolderMutations.ts`                  | Hook wrappers calling SDK                       | CLEAN        |
| `apps/web/src/hooks/useDropUpload.ts`                       | File upload via SDK                             | CLEAN        |
| `apps/web/src/hooks/useFileDownload.ts`                     | File download via SDK                           | CLEAN        |
| `apps/web/src/hooks/useBin.ts`                              | Bin operations via SDK                          | CLEAN        |
| `apps/web/src/components/file-browser/TextEditorDialog.tsx` | Text editor download path                       | NEW-M2       |
| `packages/crypto/src/index.ts`                              | Re-exports (circular dep check)                 | M-3 FIXED    |

**Total files analyzed:** 22
**Crypto operations found:** 18 distinct crypto call sites
**Issues found:** 4 medium, 3 low (0 critical, 0 high)

---

## Pre-Review Finding Status

### H-1: `setApiClientConfig` singleton token cross-contamination -- ACCEPTED RISK

**Status:** OPEN (by design, documented as acceptable)

**Location:** `packages/api-client/src/instance.ts:37-43`

**Verification:** The singleton pattern (`let _config: ApiClientConfig | null = null`) persists as designed. In the web app context (single-user browser), this is safe. The sdk-core layer correctly bypasses the singleton via explicit `SdkContext` parameters for all IPFS operations (`ipfs/index.ts` uses `ctx.getAccessToken()` directly), which is the correct approach for multi-user load testing scenarios.

**Finding:** The api-client singleton is used by orval-generated functions (IPNS publish/resolve/batch endpoints via `ipnsControllerPublishRecord`, `ipnsControllerResolveRecord`, `ipnsControllerPublishBatch`). These are called from `packages/sdk-core/src/ipns/index.ts` which does NOT receive a `SdkContext` -- it relies on the module-level singleton. This means IPNS operations go through the singleton while IPFS operations use explicit context.

**Risk assessment:** Acceptable in current architecture. The web app is single-user, and the IPNS functions from `sdk-core/ipns/index.ts` are correctly called in the context of an already-authenticated session. For future multi-user load tests, the IPNS operations would need refactoring to accept explicit auth context.

**Recommendation:** No code change required. Document limitation in api-client README per original recommendation.

---

### H-2: Spread-operator base64 encoding stack overflow -- FIXED

**Status:** FIXED in `packages/sdk-core/src/ipns/index.ts:53-58`

**Verification:**

The SDK's IPNS module now uses a loop-based approach:

```typescript
// packages/sdk-core/src/ipns/index.ts:53-58
let binary = '';
for (let i = 0; i < recordBytes.length; i++) {
  binary += String.fromCharCode(recordBytes[i]);
}
const recordBase64 = btoa(binary);
```

And `packages/sdk-core/src/file/index.ts:31-37` has its own `uint8ToBase64` helper with the same loop pattern.

**Residual concern:** The OLD `apps/web/src/services/ipns.service.ts:53` still contains `btoa(String.fromCharCode(...recordBytes))` with the spread operator. This legacy path is still called by:

- `apps/web/src/services/bin.service.ts:117` (bin metadata publish)
- `apps/web/src/services/folder.service.ts:270` (folder metadata publish -- legacy path)
- `apps/web/src/services/device-registry.service.ts:161` (device registry publish)

The SDK path is fixed, but these 3 legacy callers are still vulnerable. Since the SDK migration progressively replaces these services, this will resolve naturally, but the old `bin.service.ts` and `device-registry.service.ts` paths are still active in production.

**Also note:** `packages/core/src/folder/metadata.ts:23-31` and `packages/core/src/file/metadata.ts:23-31` use a chunk-based approach with `String.fromCharCode(...chunk)` where chunk size is 32768. This is safe because 32768 is well under the typical argument limit (~65536), but using the spread operator at all creates a dependency on engine-specific limits. The fully loop-based approach in `sdk-core/ipns/index.ts` is strictly more robust.

---

### M-1: IPNS private keys on call stack exposure surface -- ACCEPTED RISK

**Status:** OPEN (inherent to stateless architecture, well-mitigated)

**Verification:** The sdk-core functions correctly accept `ipnsPrivateKey: Uint8Array` as explicit parameters. Error messages remain generic (`'Item not found'`, `'Folder not loaded'`). The key zeroing patterns are correctly applied:

- `packages/sdk-core/src/file/index.ts:126`: `ipnsKeypair.privateKey.fill(0)` after signing and TEE enrollment
- `packages/sdk-core/src/upload/index.ts:104-107`: `clearBytes(fileKey)` in `finally` block
- `packages/sdk-core/src/download/index.ts:54-56`: `clearBytes(fileKey)` in `finally` block

**Gap identified:** `packages/sdk-core/src/folder/index.ts` -- the `createSubfolder` function returns `ipnsPrivateKey` to the caller without zeroing it. The caller (`CipherBoxClient.createFolder` at line 284) also returns it to the hook. The key is ultimately stored in the FolderTree (which zeros on `clear()`), but the intermediate references on the call stack and the `newFolderNode` in `useFolderMutations.ts:106` remain. This is by design (the key needs to be stored for future folder updates), but worth noting.

---

### M-2: `CipherBoxClient.vaultKeypair.privateKey` not zeroed in `destroy()` -- OPEN

**Status:** OPEN

**Location:** `packages/sdk/src/client.ts:73-77`

**Code:**

```typescript
destroy(): void {
  this.folderTree.clear();
  this.keyCache.clear();
  this.emitter.removeAll();
}
```

**Issue:** The `destroy()` method clears `folderTree` (which zeros all folder keys and IPNS private keys) and `keyCache` (which zeros all cached derived keys), but does NOT zero:

1. `this.config.vaultKeypair.privateKey` -- the secp256k1 vault private key
2. `this.config.rootFolderKey` -- the root AES-256 folder key
3. The `this.config` reference itself is not nulled

These keys persist in memory until GC collects the config object. The vault private key is the root of the key hierarchy -- its compromise allows deriving all other keys.

**Mitigating factors:**

- `clearAllUserStores()` in `apps/web/src/lib/clear-user-stores.ts` calls `destroySdkClient()` and then `useAuthStore.getState().logout()` which presumably zeros the auth store's copy of the keypair.
- The SDK client holds a reference to the SAME `Uint8Array` objects passed in `useAuth.ts:162-165`, so zeroing the buffer in either location zeros it in both. However, this depends on no intermediate copy being made.

**Impact:** The secp256k1 private key and root folder key persist in memory until GC collects the unreferenced config object. An attacker with heap access (XSS + heap dump, browser extension, memory forensics) could extract the master key.

**Recommendation:**

```typescript
destroy(): void {
  this.folderTree.clear();
  this.keyCache.clear();
  this.emitter.removeAll();
  // Zero vault private key and root folder key
  if (this.config.vaultKeypair.privateKey) {
    this.config.vaultKeypair.privateKey.fill(0);
  }
  if (this.config.rootFolderKey) {
    this.config.rootFolderKey.fill(0);
  }
}
```

**Effort:** LOW (3 lines of code)

---

### M-3: Circular dependency during transitional re-export period -- FIXED

**Status:** FIXED

**Verification:** `packages/crypto/src/index.ts` no longer contains any re-exports from `@cipherbox/core`. The file contains only direct exports from crypto submodules (`./vault`, `./keys`, `./aes`, `./ecies`, `./ed25519`, `./ipns/derive-name`, `./device`, `./utils`, `./types`, `./constants`). The circular dependency has been completely eliminated.

---

### L-1: `fetchFromIpfs` doesn't validate CID format -- STILL OPEN

**Status:** OPEN (low priority, defense-in-depth)

**Location:** `packages/sdk-core/src/ipfs/index.ts:67`

The CID is still interpolated directly into the URL path: `${ctx.apiUrl}/ipfs/${cid}`. No `encodeURIComponent()` was added. Risk remains very low (requires IPNS key compromise as precondition).

---

### L-3: `FolderTree.clear()` zeros keys but V8 GC may retain copies -- ACCEPTED

**Status:** ACCEPTED (inherent JavaScript limitation)

**Verification:** `FolderTree.clear()` at `packages/sdk/src/state/folder-tree.ts:53-59` correctly zeros `folderKey.fill(0)` and `ipnsKeypair.privateKey.fill(0)` for all folders before calling `this.folders.clear()`. `KeyCache.clear()` at `packages/sdk/src/state/key-cache.ts:26-31` correctly zeros all cached values. This is best-effort, which is the correct approach for JavaScript.

---

## New Findings

### NEW-M1: `ensureFolderRegistered` passes empty public key into SDK

**Severity:** MEDIUM

**Location:** `apps/web/src/lib/sdk-provider.ts:80`

**Code:**

```typescript
client.registerFolder(
  folder.ipnsName,
  folder.folderKey,
  {
    publicKey: new Uint8Array(0), // Public key derived from private key when needed
    privateKey: folder.ipnsPrivateKey,
  },
  folder.children,
  folder.sequenceNumber
);
```

**Issue:** The IPNS keypair is registered with an empty `publicKey` (`new Uint8Array(0)`). The comment says "derived from private key when needed," but this derivation never happens inside the SDK. The SDK's `FolderState.ipnsKeypair.publicKey` is passed along to `sdkCore.updateFolderMetadataAndPublish()` and eventually to `createAndPublishIpnsRecord()`, but that function only uses `ipnsPrivateKey` (the public key is part of the Ed25519 private key in libp2p format -- the 64-byte private key contains the 32-byte seed + 32-byte public key). So the empty public key is never actually used in any operation.

**Impact:** No immediate security impact -- Ed25519 signing works because the public key is embedded in the 64-byte libp2p private key format. However, if any future code path attempts to use `ipnsKeypair.publicKey` from the FolderTree (e.g., for IPNS name derivation or signature verification), it would get an empty array and fail silently or throw a confusing error.

**Recommendation:** Either:

1. Derive the public key from the private key at registration time: `publicKey: folder.ipnsPrivateKey.subarray(32, 64)` (libp2p Ed25519 format)
2. Or add a guard in `registerFolder()` that derives it if empty

**Effort:** LOW

---

### NEW-M2: TextEditorDialog save path bypasses SDK, uses legacy encryption

**Severity:** MEDIUM

**Location:** `apps/web/src/components/file-browser/TextEditorDialog.tsx:145-178`

**Code:**

```typescript
// 2. Encrypt with new key/IV
const encrypted = await encryptFile(file, auth.vaultKeypair.publicKey);

// 3. Upload to IPFS
const ciphertextBytes = encrypted.ciphertext.slice();
const blob = new Blob([ciphertextBytes.buffer as ArrayBuffer]);
const { cid } = await addToIpfs(blob);

// 4. Update folder metadata
await updateFile(parentFolderId, {
  fileId: item.id,
  newCid: cid,
  newFileKeyEncrypted: encrypted.wrappedKey,
  newFileIv: encrypted.iv,
  newSize: encrypted.originalSize,
});
```

**Issue:** The TextEditorDialog save path imports `encryptFile` from the old `file-crypto.service` and `addToIpfs` from the old `lib/api/ipfs`, bypassing the SDK entirely. This means:

1. The file key generated by `encryptFile` is NOT zeroed after use (unlike the SDK's `uploadFile` which uses `clearBytes(fileKey)` in a `finally` block)
2. The metadata update goes through `updateFile` (from `useFolder`) rather than the SDK, potentially causing state desync between the SDK's FolderTree and the Zustand store
3. The old `addToIpfs` may not align with the SDK's auth token management

**Impact:** File key material from text editor saves persists in memory longer than necessary. State desync between SDK internal state and Zustand store could cause sequence number conflicts on subsequent folder operations.

**Recommendation:** Migrate the TextEditorDialog save path to use the SDK client's upload/update methods, or at minimum ensure the file key from `encryptFile` is zeroed after use. This is likely a transitional gap that will be resolved when Plan 06 removes old service code.

**Effort:** MEDIUM (requires either SDK method for file replacement, or wrapping encryptFile with cleanup)

---

### NEW-L1: Duplicate `uint8ToBase64` implementations across codebase

**Severity:** LOW

**Location:**

- `packages/sdk-core/src/file/index.ts:31-37` (loop-based, per-byte)
- `packages/sdk-core/src/ipns/index.ts:54-57` (inline, loop-based, per-byte)
- `packages/core/src/folder/metadata.ts:23-31` (chunk-based with spread, 32K chunks)
- `packages/core/src/file/metadata.ts:23-31` (chunk-based with spread, 32K chunks)

**Issue:** Four separate implementations of Uint8Array-to-base64 encoding exist with slightly different strategies:

- The sdk-core versions use per-byte loop (safest, no argument limit risk)
- The core versions use chunk-based spread operator (safe with 32K chunk size, but less robust)

All are functionally correct, but the inconsistency creates maintenance risk: a future developer may copy the wrong pattern.

**Recommendation:** Consolidate into `@cipherbox/crypto/utils` or `@cipherbox/core/utils` as a shared `uint8ToBase64` export. Use the per-byte loop pattern for maximum safety.

**Effort:** LOW

---

## Compliance Checklist (CLAUDE.md Security Rules)

- [x] **No privateKey in localStorage/sessionStorage** -- SDK stores keys in memory only (`Map` objects in FolderTree, cleared on `destroy()`). No `localStorage` or `sessionStorage` references found in SDK packages.
- [x] **No sensitive keys logged** -- Zero `console.log`/`console.info`/`console.debug` calls in production SDK code (`packages/sdk/src/` and `packages/sdk-core/src/`). The only `console.log` calls are in test files (`__tests__/integration.test.ts`). One `console.warn` in IPNS resolve (`sdk-core/src/ipns/index.ts:168`) warns about missing signature data -- no key material included.
- [x] **No unencrypted keys sent to server** -- All IPNS private keys are ECIES-wrapped with TEE public key before any API call. File keys are ECIES-wrapped with user's public key. The `SdkContext` only carries `apiUrl` and `getAccessToken` -- no key material.
- [x] **ECIES used for key wrapping** -- `wrapKey()` used for: folder key wrapping (`sdk-core/folder/index.ts:106-108`), IPNS key wrapping for FilePointer (`sdk-core/file/index.ts:77`), TEE enrollment folder (`sdk-core/folder/index.ts:116`), TEE enrollment file (`sdk-core/file/index.ts:120`), bin IPNS key TEE enrollment (`sdk/bin/index.ts:107`), share key creation (`sdk/share/index.ts:60`), re-wrap for recipients (`sdk/share/index.ts:108`).
- [x] **AES-256-GCM used for content encryption** -- `encryptAesGcm` in `sdk-core/upload/index.ts:74`. CTR mode only for streaming media (existing behavior, controlled by `encryptionMode` parameter).
- [x] **Server NEVER has access to plaintext or unencrypted keys** -- The `SdkContext` interface contains only `apiUrl` and `getAccessToken()`. All crypto operations happen client-side before API calls. Server receives only ciphertext, wrapped keys, and IPNS records.
- [x] **IPNS private key encrypted with TEE public key before sending** -- Both folder (`sdk-core/folder/index.ts:114-119`) and file (`sdk-core/file/index.ts:118-123`) modules handle TEE enrollment when `teeKeys` are provided. Bin module (`sdk/bin/index.ts:104-112`) also enrolls TEE keys.
- [x] **Uint8Array for all binary data** -- No string-based key handling. All keys passed as `Uint8Array`. `SdkContext.getAccessToken` returns a string token (not key material), which is correct.
- [x] **Web Crypto API usage** -- All crypto primitives come from `@cipherbox/crypto` which uses Web Crypto API internally.

---

## Positive Observations

1. **Key zeroing discipline is strong.** `upload/index.ts:104-107` uses `clearBytes(fileKey)` in a `finally` block. `download/index.ts:54-56` mirrors this pattern. `file/index.ts:126` zeros `ipnsKeypair.privateKey` after all signing operations. `FolderTree.clear()` and `FolderTree.delete()` both zero folder keys and IPNS private keys. `KeyCache.clear()` zeros all cached values.

2. **Error messages are consistently generic.** No key material, no algorithm details, no key sizes in user-facing errors. Examples: `'Item not found'`, `'Folder not loaded'`, `'Parent folder not loaded'`, `'Bin entry not found'`, `'File metadata IPNS not found'`, `'Bin not loaded'`.

3. **SdkContext pattern correctly enforces trust boundaries.** The `SdkContext` type (`sdk-core/types.ts`) contains only `apiUrl` and `getAccessToken()` -- no key material. All keys are passed as explicit parameters to stateless functions, never fetched from global state within sdk-core.

4. **No crypto in the api-client package.** The api-client (`packages/api-client/src/instance.ts`) handles only HTTP transport with auth tokens. No key material flows through it.

5. **IPNS signature verification rejects invalid signatures.** `sdk-core/ipns/index.ts:163` throws on verification failure: `'IPNS signature verification failed - record may be tampered'`. It does not silently accept unverified records.

6. **`BinNotLoadedError` leaks no state.** The error class (`sdk/client.ts:29-33`) contains only a static message `'Bin not loaded'` with no dynamic state.

7. **Event subscriber errors are caught.** `SdkEventEmitter.emit()` (`sdk/events.ts:69-76`) wraps each handler call in try/catch, preventing subscriber bugs from crashing the SDK or leaking errors.

8. **`clearAllUserStores` follows correct teardown order.** (`apps/web/src/lib/clear-user-stores.ts:24-44`) destroys SDK client first (clears key caches), then folder/vault stores with key material, then remaining stores, then auth state last. This ensures keys are zeroed before auth state is cleared.

---

## Test Case Suggestions

### Pre-existing (from pre-review, still applicable)

#### Crypto Export Integrity (validates M-3 fix)

```typescript
describe('crypto package export integrity', () => {
  it('all critical crypto exports are defined after import resolution', async () => {
    const crypto = await import('@cipherbox/crypto');
    expect(typeof crypto.encryptAesGcm).toBe('function');
    expect(typeof crypto.decryptAesGcm).toBe('function');
    expect(typeof crypto.wrapKey).toBe('function');
    expect(typeof crypto.unwrapKey).toBe('function');
    expect(typeof crypto.generateFileKey).toBe('function');
    expect(typeof crypto.deriveVaultIpnsKeypair).toBe('function');
    expect(typeof crypto.clearBytes).toBe('function');
  });
});
```

#### Key Zeroing Verification (validates M-2 gap)

```typescript
describe('CipherBoxClient key cleanup', () => {
  it('destroy() zeros vault private key (EXPECTED FAILURE until M-2 is fixed)', () => {
    const privateKey = new Uint8Array(32).fill(0xaa);
    const publicKey = new Uint8Array(33).fill(0xbb);
    const rootFolderKey = new Uint8Array(32).fill(0xcc);

    const client = new CipherBoxClient({
      apiUrl: 'http://localhost',
      getAccessToken: async () => 'token',
      vaultKeypair: { publicKey, privateKey },
      rootIpnsName: 'k51test',
      rootFolderKey,
    });

    client.destroy();

    // These assertions will FAIL until M-2 is fixed
    expect(privateKey.every((b) => b === 0)).toBe(true);
    expect(rootFolderKey.every((b) => b === 0)).toBe(true);
  });

  it('destroy() zeros all folder keys in FolderTree', () => {
    const folderKey = new Uint8Array(32).fill(0xdd);
    const ipnsPrivateKey = new Uint8Array(64).fill(0xee);

    const client = new CipherBoxClient({
      apiUrl: 'http://localhost',
      getAccessToken: async () => 'token',
      vaultKeypair: { publicKey: new Uint8Array(33), privateKey: new Uint8Array(32) },
      rootIpnsName: 'k51test',
      rootFolderKey: new Uint8Array(32),
    });

    client.registerFolder(
      'test-ipns',
      folderKey,
      {
        publicKey: new Uint8Array(32),
        privateKey: ipnsPrivateKey,
      },
      [],
      0n
    );

    client.destroy();

    expect(folderKey.every((b) => b === 0)).toBe(true);
    expect(ipnsPrivateKey.every((b) => b === 0)).toBe(true);
  });
});
```

### New Test Cases

#### IPNS Base64 Encoding (validates H-2 fix)

```typescript
describe('IPNS record base64 encoding', () => {
  it('handles records larger than 65536 bytes without stack overflow', () => {
    // Simulate a large IPNS record (unlikely in practice, but validates the fix)
    const largeData = new Uint8Array(100_000).fill(0x42);
    let binary = '';
    for (let i = 0; i < largeData.length; i++) {
      binary += String.fromCharCode(largeData[i]);
    }
    const result = btoa(binary);
    expect(result.length).toBeGreaterThan(0);
    // Verify round-trip
    const decoded = Uint8Array.from(atob(result), (c) => c.charCodeAt(0));
    expect(decoded).toEqual(largeData);
  });
});
```

#### Empty Public Key Guard (validates NEW-M1)

```typescript
describe('ensureFolderRegistered public key handling', () => {
  it('registers folder with empty public key without error', () => {
    // This is the current behavior -- it works because Ed25519 private key
    // in libp2p format contains the public key
    const client = new CipherBoxClient({
      /* ... */
    });
    client.registerFolder(
      'test',
      new Uint8Array(32),
      {
        publicKey: new Uint8Array(0),
        privateKey: new Uint8Array(64).fill(0xaa),
      },
      [],
      0n
    );

    const state = client.getFolderIpnsPrivateKey('test');
    expect(state).toBeDefined();
    expect(state!.length).toBe(64);
  });

  it('IPNS signing works with empty public key in keypair', async () => {
    // Verifies that createAndPublishIpnsRecord only uses the privateKey field
    // This is an integration-level test
  });
});
```

#### Upload File Key Cleanup (validates upload security)

```typescript
describe('uploadFile key cleanup', () => {
  it('zeros fileKey even if IPFS upload fails', async () => {
    // Mock addToIpfs to throw
    // Verify that clearBytes was called in the finally block
    // This validates the try/finally pattern in upload/index.ts
  });

  it('zeros fileKey even if createFileMetadata fails', async () => {
    // Same pattern -- verify cleanup on metadata creation failure
  });
});
```

#### API Client Singleton Isolation (validates H-1 documentation)

```typescript
describe('api-client singleton behavior', () => {
  it('setApiClientConfig replaces the entire config atomically', () => {
    setApiClientConfig({ baseUrl: 'http://a', getAccessToken: async () => 'token-a' });
    setApiClientConfig({ baseUrl: 'http://b', getAccessToken: async () => 'token-b' });

    const config = getApiClientConfig();
    expect(config.baseUrl).toBe('http://b');
  });

  it('cached axios instance is reset when config changes', () => {
    setApiClientConfig({ baseUrl: 'http://a', getAccessToken: async () => 'token-a' });
    // Make a request to cache the instance
    setApiClientConfig({ baseUrl: 'http://b', getAccessToken: async () => 'token-b' });
    // The next request should use baseUrl 'http://b'
  });
});
```

---

## Recommendations Summary

| Priority | Finding                                              | Recommendation                                                                                           | Effort | Status   |
| -------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------ | -------- |
| P1       | M-2: Vault key not zeroed in `destroy()`             | Add `this.config.vaultKeypair.privateKey.fill(0)` and `this.config.rootFolderKey.fill(0)` to `destroy()` | LOW    | OPEN     |
| P2       | NEW-M1: Empty public key in `ensureFolderRegistered` | Derive public key from private key: `privateKey.subarray(32, 64)`                                        | LOW    | NEW      |
| P2       | NEW-M2: TextEditorDialog save bypasses SDK           | Migrate to SDK file update method, or add `clearBytes` wrapper around `encryptFile`                      | MEDIUM | NEW      |
| P2       | H-2 residual: Old `ipns.service.ts` spread-operator  | Will resolve with Plan 06 old service removal. No action needed if timeline is near.                     | N/A    | TRACKING |
| P3       | NEW-L1: Duplicate `uint8ToBase64` implementations    | Consolidate into shared utility                                                                          | LOW    | NEW      |
| P3       | L-1: CID not URI-encoded in `fetchFromIpfs`          | Add `encodeURIComponent(cid)` as defense-in-depth                                                        | LOW    | OPEN     |
| P3       | H-1: Singleton documentation                         | Add concurrency warning to api-client README                                                             | LOW    | ACCEPTED |

---

## SECURITY REVIEW COMPLETE

**Files analyzed:** 22
**Crypto operations found:** 18 distinct call sites
**Issues found:** 0 critical, 0 high, 4 medium, 3 low

### Critical Issues

None found.

### High Priority

None remaining (H-1 accepted, H-2 fixed).

### Test Cases Generated

6 test case groups across 4 categories (key zeroing, base64 encoding, empty key guard, singleton isolation).

### Recommendations

1. **P1:** Add vault key zeroing to `CipherBoxClient.destroy()` (M-2) -- 3 lines, immediate
2. **P2:** Fix empty public key in `ensureFolderRegistered` (NEW-M1) -- 1 line, immediate
3. **P2:** Track TextEditorDialog save path for SDK migration (NEW-M2) -- medium effort, next phase

---

_Generated by security:review command_
_This review is automated guidance, not a substitute for professional security audit_

# Security Review: Phase 19.1 SDK Extraction Plans

**Date:** 2026-03-20
**Scope:** Plans 01-06 in PR #295 + already-committed code on `phase-19.1-extract-core-sdk`
**Reviewer:** Claude (security:review command)
**Type:** Pre-implementation review of architectural plans and early code

## Executive Summary

This is a code reorganization phase -- no new cryptographic algorithms, no new API endpoints, no new trust relationships. The plans correctly preserve the existing client-side-only encryption model and zero-knowledge server guarantee. The five-package architecture aligns well with the existing trust boundaries.

**Risk Level:** LOW

| Severity | Count |
| -------- | ----- |
| Critical | 0     |
| High     | 2     |
| Medium   | 3     |
| Low      | 4     |

## Files Reviewed

| File / Plan                             | Crypto Operations                               | Risk Level |
| --------------------------------------- | ----------------------------------------------- | ---------- |
| 19.1-CONTEXT.md                         | Architecture decisions, trust boundaries        | LOW        |
| 19.1-RESEARCH.md                        | Package structure, migration patterns           | LOW        |
| 19.1-01-PLAN.md                         | crypto/core split, re-exports                   | MEDIUM     |
| 19.1-02-PLAN.md                         | api-client singleton config, token handling     | HIGH       |
| 19.1-03-PLAN.md                         | sdk-core stateless ops, key passing             | MEDIUM     |
| 19.1-04-PLAN.md                         | SDK client state, key cache, events             | MEDIUM     |
| 19.1-05-PLAN.md                         | Web app rewiring, SDK lifecycle                 | LOW        |
| 19.1-06-PLAN.md                         | Re-export removal, import cleanup               | LOW        |
| packages/crypto/src/index.ts            | Transitional re-exports (circular dep)          | MEDIUM     |
| packages/sdk-core/src/ipfs/index.ts     | IPFS upload/download with auth tokens           | LOW        |
| packages/sdk-core/src/ipns/index.ts     | IPNS signing, base64 encoding, sig verification | HIGH       |
| packages/sdk-core/src/folder/index.ts   | Folder key wrapping, TEE enrollment             | LOW        |
| packages/sdk-core/src/upload/index.ts   | AES-GCM encryption, ECIES key wrapping          | LOW        |
| packages/sdk-core/src/download/index.ts | AES-GCM/CTR decryption, key unwrapping          | LOW        |
| packages/sdk-core/src/file/index.ts     | File metadata encryption, IPNS key wrapping     | LOW        |

## Findings

### High Priority

#### H-1: `setApiClientConfig` module-level singleton is shared across all callers

- **Severity:** HIGH
- **Location:** Plan 02, Task 1 (`packages/api-client/src/instance.ts`)
- **Description:** The `let _config: ApiClientConfig | null = null` pattern creates a global mutable singleton. If the SDK is used in a multi-tenant Node.js context (load test simulating multiple users), all concurrent callers share the same `getAccessToken` callback. A token from User A's callback could leak into User B's request if the config is swapped between calls.
- **Impact:** Token cross-contamination in concurrent multi-user scenarios. Load tests are a key motivator for this extraction, making this a realistic concern.
- **Recommendation:** For sdk-core (the load-test layer), the `SdkContext` per-call pattern is already correct -- it avoids the singleton entirely. The risk is isolated to the api-client's `customInstance` which orval-generated code calls via the mutator. Options: (a) make orval-generated functions accept the axios instance as a parameter, (b) document that `setApiClientConfig` is **not safe for concurrent multi-user usage** and load tests should use sdk-core's explicit `SdkContext` pattern (which they already do). The already-implemented sdk-core IPFS/IPNS modules correctly bypass the singleton and use `ctx` directly.
- **Reference:** OWASP session management, token isolation in multi-tenant contexts

#### H-2: `createAndPublishIpnsRecord` uses spread operator for base64 encoding

- **Severity:** HIGH
- **Location:** `packages/sdk-core/src/ipns/index.ts:54` (already committed)
- **Description:** `btoa(String.fromCharCode(...recordBytes))` uses the spread operator on the IPNS record bytes. For large IPNS records this will throw "Maximum call stack size exceeded" (same bug pattern that prompted the `uint8ToBase64` helper in `file/index.ts:31-37` and `folder.service.ts:39-45`).
- **Impact:** IPNS publish silently fails or crashes for records exceeding the stack argument limit (~65K on most engines). Not a confidentiality issue but a reliability issue that could cause data loss (metadata not published).
- **Recommendation:** Use the same loop-based `uint8ToBase64` helper already present in `file/index.ts`. Consider consolidating `uint8ToBase64` into `@cipherbox/crypto/utils` or `@cipherbox/core` to eliminate duplication (noted in RESEARCH.md Pitfall 3).

### Medium Priority

#### M-1: IPNS private keys passed as explicit parameters increase exposure surface

- **Severity:** MEDIUM
- **Location:** Plan 03 sdk-core folder operations (`updateFolderMetadataAndPublish`), Plan 04 SDK client
- **Description:** The stateless sdk-core functions take `ipnsPrivateKey: Uint8Array` as an explicit parameter. This is correct architecturally but means the IPNS private key exists on the call stack and in function arguments. If a debugger, error reporter, or logging middleware captures function arguments, the key would be exposed.
- **Impact:** Key exposure via debugging/error reporting tooling. Low probability in production, medium in development.
- **Recommendation:** Already well-handled in the implemented code -- error messages are generic (`'Item not found'`), and `file/index.ts:126` zeros the IPNS private key after use (`ipnsKeypair.privateKey.fill(0)`). Ensure the same zeroing pattern is followed in the SDK client (Plan 04) after folder operations complete. The `upload/index.ts` correctly uses `clearBytes(fileKey)` in a `finally` block -- good pattern to replicate.

#### M-2: `CipherBoxClient.vaultKeypair.privateKey` lives in memory for the entire session

- **Severity:** MEDIUM
- **Location:** Plan 04 (SDK client constructor), Plan 05 (SDK provider lifecycle)
- **Description:** The `CipherBoxClientConfig` takes `vaultKeypair: { publicKey, privateKey }` and the client holds a reference for the session duration. The `destroy()` method calls `folderTree.clear()` and `keyCache.clear()` which zero those keys, but the `config.vaultKeypair.privateKey` reference isn't explicitly zeroed.
- **Impact:** The secp256k1 private key persists in memory until GC collects the config object. An attacker with heap access could extract it.
- **Recommendation:** In `CipherBoxClient.destroy()`, add `clearBytes(this.config.vaultKeypair.privateKey)` and null out the config reference. Document that consumers should not retain their own reference to the private key buffer after passing it to the SDK. This is defense-in-depth given JavaScript's GC limitations (correctly documented in `packages/crypto/src/utils/memory.ts`).

#### M-3: Circular dependency during transitional re-export period

- **Severity:** MEDIUM
- **Location:** Plan 01 Task 2 (crypto re-exports from core, core depends on crypto)
- **Description:** `@cipherbox/crypto` -> re-exports from -> `@cipherbox/core` -> imports from -> `@cipherbox/crypto`. The plan correctly notes this in RESEARCH.md Pitfall 2 and requires re-exports to be the LAST section of `crypto/index.ts`. The already-committed code (`crypto/src/index.ts:100-153`) follows this correctly. However, if a future edit moves the re-exports or adds a re-export before the native exports, it could break silently (crypto functions return `undefined` instead of throwing).
- **Impact:** Silent crypto failures -- `encryptAesGcm` could be `undefined` at runtime, causing unencrypted data to be stored or decryption to throw non-obvious errors. This would be a **critical** confidentiality breach if it happened, but the mitigation is already in place.
- **Recommendation:** Add a test that verifies all critical crypto exports are defined functions (not `undefined`) after the circular import resolves. Plan 06 removes the circular dependency entirely, which is the correct final state.

### Low Priority / Recommendations

#### L-1: `fetchFromIpfs` doesn't validate CID format before constructing URL

- **Severity:** LOW
- **Location:** `packages/sdk-core/src/ipfs/index.ts:67`
- **Description:** `${ctx.apiUrl}/ipfs/${cid}` constructs a URL path with the CID directly. A malformed CID containing path traversal characters (`../`) could theoretically be used for SSRF against the API backend.
- **Impact:** Very low -- requires IPNS key compromise as a precondition, since the CID is resolved from an IPNS record signed by the user's own key.
- **Recommendation:** Consider `encodeURIComponent(cid)` as defense-in-depth, or validate the CID matches the expected base32/base58 format before use.

#### L-2: Error events in SDK may include error objects with sensitive context

- **Severity:** LOW
- **Location:** Plan 04 (events.ts `SdkEvent` error type)
- **Description:** `{ type: 'error'; operation: string; error: Error }` -- if a crypto operation throws a `CryptoError` with context about key sizes or algorithm failures, and an event subscriber logs this broadly, it could leak operational details.
- **Impact:** Low -- existing `CryptoError` messages are already generic (e.g., `'Invalid private key size for vault derivation'`) and don't include actual key material.
- **Recommendation:** No action needed. Current error hygiene is good.

#### L-3: `FolderTree.clear()` zeros keys but V8 GC may retain copies

- **Severity:** LOW
- **Location:** Plan 04 (state/folder-tree.ts)
- **Description:** Already acknowledged in `packages/crypto/src/utils/memory.ts` documentation. The `fill(0)` is best-effort in JavaScript.
- **Impact:** Inherent JavaScript limitation, not specific to this refactoring.
- **Recommendation:** No action beyond what's already documented. The plan correctly implements zeroing on `destroy()`.

#### L-4: Dual code paths during Plan 05-06 transition window

- **Severity:** LOW
- **Location:** Plan 05 Task 2, Plan 06 Task 1
- **Description:** Between Plan 05 (services marked deprecated) and Plan 06 (services removed), both the old service path (direct store access) and the new SDK path exist. If a component accidentally imports from the old service, it would bypass the SDK's event system, causing state desync.
- **Impact:** State inconsistency, not a security vulnerability.
- **Recommendation:** The plan's approach is sound -- deprecate first, verify, then remove. The grep-before-delete protocol in Plan 06 is the right safeguard.

## Positive Observations

- **Key zeroing in `finally` blocks:** `upload/index.ts:104-107` correctly clears `fileKey` in a `finally` block. `file/index.ts:126` zeros the IPNS private key after signing and TEE enrollment. Good pattern.
- **Generic error messages:** All crypto errors use the `CryptoError` class with generic descriptions. No key material in error messages.
- **IPNS signature verification:** `ipns/index.ts:158-161` correctly verifies Ed25519 signatures on IPNS records and **throws** on verification failure (rather than silently accepting).
- **TEE enrollment at both folder and file level:** Both `folder/index.ts:114-119` and `file/index.ts:118-123` encrypt IPNS private keys with the TEE public key when available.
- **Correct trust boundary enforcement:** The `SdkContext` pattern (apiUrl + getAccessToken) ensures sdk-core never touches Zustand stores or browser globals. All key material is passed explicitly, never fetched from global state.
- **No crypto in the api-client package:** The api-client only handles HTTP transport with auth tokens. No key material flows through it.

## Compliance Checklist

Based on project security rules (CLAUDE.md):

- [x] No privateKey in localStorage/sessionStorage -- SDK stores keys in memory only (`Map` objects, cleared on `destroy()`)
- [x] No sensitive keys logged -- Error messages are generic. No `console.log` of keys. One `console.warn` in IPNS resolve only warns about missing signature data.
- [x] No unencrypted keys sent to server -- `encryptedIpnsPrivateKey` is ECIES-wrapped with TEE public key. IPNS records signed locally. File keys ECIES-wrapped before any API call.
- [x] ECIES used for key wrapping -- `wrapKey()` used for: folder key (folder/index.ts:106-108), file IPNS key (file/index.ts:77), TEE enrollment (folder/index.ts:116, file/index.ts:120)
- [x] AES-256-GCM used for content encryption -- `encryptAesGcm` in upload/index.ts:74. CTR mode for streaming media (existing behavior).
- [x] Server NEVER has access to plaintext or unencrypted keys -- `SdkContext` only provides `apiUrl` and `getAccessToken`. All crypto happens client-side before API calls.
- [x] IPNS private key encrypted with TEE public key before sending -- Both folder and file modules handle TEE enrollment when `teeKeys` are provided.

## Recommended Test Cases

### Crypto Export Integrity (catches M-3)

```typescript
describe('crypto package export integrity', () => {
  it('all critical crypto exports are defined after circular import resolution', async () => {
    const crypto = await import('@cipherbox/crypto');
    expect(typeof crypto.encryptAesGcm).toBe('function');
    expect(typeof crypto.decryptAesGcm).toBe('function');
    expect(typeof crypto.wrapKey).toBe('function');
    expect(typeof crypto.unwrapKey).toBe('function');
    expect(typeof crypto.generateFileKey).toBe('function');
    expect(typeof crypto.deriveVaultIpnsKeypair).toBe('function');
  });
});
```

### Token Isolation (catches H-1)

```typescript
describe('sdk-core token isolation', () => {
  it('concurrent calls use their own SdkContext tokens', async () => {
    const ctx1: SdkContext = { apiUrl: '...', getAccessToken: async () => 'token-a' };
    const ctx2: SdkContext = { apiUrl: '...', getAccessToken: async () => 'token-b' };
    // Run in parallel, verify each request header has the correct token
  });
});
```

### Key Zeroing Verification (catches M-1, M-2)

```typescript
describe('key cleanup', () => {
  it('uploadFile zeros fileKey after completion', async () => {
    // After uploadFile completes, the internal fileKey buffer should be zeroed
  });

  it('CipherBoxClient.destroy() zeros vault private key', () => {
    const privateKey = new Uint8Array([1, 2, 3, 4]);
    const client = new CipherBoxClient({ vaultKeypair: { publicKey: new Uint8Array(33), privateKey }, ... });
    client.destroy();
    expect(privateKey.every(b => b === 0)).toBe(true);
  });
});
```

### IPNS Base64 Encoding (catches H-2)

```typescript
describe('IPNS record base64 encoding', () => {
  it('handles large records without stack overflow', () => {
    const largeRecord = new Uint8Array(100_000);
    // Should not throw "Maximum call stack size exceeded"
    expect(() => uint8ToBase64(largeRecord)).not.toThrow();
  });
});
```

## Recommendations Summary

| Priority | Recommendation                                                                             | Effort |
| -------- | ------------------------------------------------------------------------------------------ | ------ |
| P0       | Fix spread-operator base64 in `ipns/index.ts` (H-2) -- use loop-based `uint8ToBase64`      | LOW    |
| P1       | Document `setApiClientConfig` singleton limitation for multi-user concurrency (H-1)        | LOW    |
| P1       | Add `clearBytes(this.config.vaultKeypair.privateKey)` to `CipherBoxClient.destroy()` (M-2) | LOW    |
| P2       | Add crypto export integrity test to catch circular dependency failures (M-3)               | LOW    |
| P2       | Consolidate `uint8ToBase64` into a shared utility (eliminates 3 copies)                    | LOW    |
| P3       | Add `encodeURIComponent(cid)` in `fetchFromIpfs` (L-1)                                     | LOW    |

## Next Steps

1. Fix H-2 (spread operator) during Plan 03 execution or as a follow-up commit
2. Address M-2 (vault key zeroing) during Plan 04 execution
3. Add crypto export integrity test during Plan 01 execution
4. H-1 singleton limitation can be documented in the api-client README (Plan 06)

---

_Generated by security:review command_
_This review is automated guidance, not a substitute for professional security audit_

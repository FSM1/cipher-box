# Phase 77: Crypto Hygiene and Terminology Canonicalization - Research

**Researched:** 2026-07-11
**Domain:** TypeScript crypto-adjacent hygiene refactor (zeroization, base64 dedup, field-name canonicalization, dead-code retirement) across `packages/crypto`, `packages/core`, `packages/sdk-core`, `packages/sdk`, `apps/api`, `apps/tee-worker`, `apps/web`
**Confidence:** HIGH — every claim below is grounded in a `Read`/`grep` of the actual worktree source; no web search was needed (this is an internal-codebase mechanical refactor, not a library-selection problem)

## Summary

This phase is 12 independent, mostly-small mechanical fixes with **no behavior change**. All 12 todos were verified against the actual current code (not assumed from the todo titles) — three of the twelve turned out to be **narrower or differently-scoped** than their titles imply, which materially changes the plan:

- Todo #8/#9 (the "misnamed field" rename) is **not** a single global rename. `encryptedIpnsPrivateKey` is ALREADY the canonical name in `packages/sdk-core/src/folder/registration.ts` and `packages/sdk-core/src/vault/index.ts`. The actual non-canonical holdouts are narrower: (a) `ipnsPrivateKeyEncrypted` (adjective-last) in `packages/sdk-core/src/file/index.ts` + `packages/sdk-core/src/upload/index.ts` + ~9 test files, and (b) `encryptedIpnsKey` (missing "Private") as the TEE wire-contract field name in `apps/api/src/tee/tee.service.ts` (`RepublishEntry`) + `apps/tee-worker/src/routes/republish.ts` + `apps/tee-worker/src/services/key-manager.ts` + their specs. The DB column is **already** `encrypted_ipns_private_key` (see `ipns-record.entity.ts:64-65`) — no migration needed, no DB-column rename in scope.
- Todo #12's "Phase 71 root-ownership gate" duplication is a byte-identical 6-line block appearing in exactly 2 files (`shares.service.ts` and `share-invite.service.ts`), both of which already inject `ipnsRecordRepo` directly — extraction is a plain exported function, no new DI wiring.
- Todo #10's dead-scaffolding surface is **larger** than "ShareCallbacks/addShareKeysFn" alone: the `shareCallbacks` config field, the whole `ShareCallbacks` type, `addShareKeysFn` threaded through `SharedWriteContext`/`SharedWriteContextParams`, and (newly discovered) `updateSharePermission`/`updatePermissionFn` in `shared-write.ts` plus the orphaned `UpdatePermissionDto`/`UpdatePermissionDtoPermission` generated models (no live `update-permission` route exists in the current `openapi.json` at all) are all dead. `packages/sdk` re-exports `ShareCallbacks` publicly from `index.ts` but nothing in `apps/web` imports it.
- Todo #1's `wrapIpnsKeyForTee` signature change only affects 3 current call sites (`registration.ts`, `vault/index.ts`, `file/index.ts`) — but there are **3 additional un-consolidated inline duplicates** of the same hex→wrap→hex sequence in `client.ts`, `bin/index.ts` (packages/sdk), and `apps/web/src/services/vault-settings.service.ts` that do NOT call the shared helper today. These are out of strict todo-#1 scope (signature rename) but the planner should decide explicitly whether to fold them in now or leave them (see Pitfall 6).
- Todo #3's "AES-GCM helpers" scope is **7 functions across 4 files** (GCM + CTR both leak an un-zeroed key copy), not just GCM.
- Todo #6 and #7 overlap: `packages/core/src/node/{encode,decode,seal}.ts}` duplicate a THIRD base64 implementation (`uint8ArrayToBase64`/`base64ToUint8Array`) that is separate from the sdk-core `share/`+`rotation/` duplicates. Once base64 helpers are hoisted into `@cipherbox/crypto` (todo #5), BOTH todo #6 (sdk-core) and todo #7 (packages/core node/ codec) should consume the same hoisted helper — do not create a second shared copy inside `packages/core`.

**Primary recommendation:** Sequence the plan bottom-up through the dependency graph: (1) `@cipherbox/crypto` — hoist base64 helpers + add `.fill(0)` to the 7 AES helper functions' internal key-buffer copies (todos #3, #5); (2) `packages/core/src/node/*` — consume the hoisted base64 helper (todo #7); (3) `packages/sdk-core` — dedup base64 in `share/`+`rotation/` (todo #6), rename `ipnsPrivateKeyEncrypted`→`encryptedIpnsPrivateKey` in `file/index.ts`+`upload/index.ts` (todo #8), change `wrapIpnsKeyForTee` signature (todo #1), add error-path zeroization to `createSubfolder` (todo #2); (4) `packages/sdk` — retire dead share scaffolding (todo #10), drop the discarded wrapKey if confirmed (todo #11), zeroize e2e scripts (todo #4); (5) `apps/api`+`apps/tee-worker` — rename the TEE wire-contract field (todo #9), extract `assertRootOwnership` (todo #12); run `pnpm api:generate` only if a DTO/controller actually changed (it does NOT for todo #9 — see below).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Base64 codec (bytes↔string) | Shared library (`@cipherbox/crypto`) | Consumers: `packages/core`, `packages/sdk-core` | Pure encoding utility with zero crypto-specific logic; belongs at the lowest shared layer, same tier as the existing `hexToBytes`/`bytesToHex` in `crypto/src/utils/encoding.ts` |
| Key-buffer zeroization (error paths) | Owning function (SDK-core / crypto) | — | D-09 convention: only the terminal owner of a buffer may `.fill(0)` it; a function that mints or copies a key locally and fails before handing it to the caller is that owner |
| TEE wire-contract field naming | API / Backend (`apps/api` relay ↔ `apps/tee-worker`) | SDK-core (`packages/sdk-core/src/tee/wrap.ts`) produces the value that flows onto the wire | The relay and worker share a private HTTP contract (not exposed via OpenAPI) — rename is internal to that pair, no client generation needed |
| Root-ownership authorization gate | API / Backend (`apps/api/src/shares/*.service.ts`) | — | Server-side defense-in-depth check reading `ipns_records`; correctly lives in the API tier next to the two callers |
| Dead share-scaffolding retirement | SDK (`packages/sdk`) | Web (`apps/web` — already stopped calling it) | The SDK owns the type surface (`ShareCallbacks`, `SharedWriteContext`); web has already migrated away, confirming safety of removal |

## Package Legitimacy Audit

Not applicable — this phase installs no new external packages. All work touches existing first-party code (`packages/crypto`, `packages/core`, `packages/sdk-core`, `packages/sdk`, `apps/api`, `apps/tee-worker`, `apps/web`, `packages/sdk-core/scripts/`). No `npm install` / `pip install` / `cargo add` occurs in this phase.

## Standard Stack

No new libraries. This phase only touches first-party TypeScript already in the repo. Existing crypto primitives already in use and NOT to be changed:

| Library | Version (as installed) | Purpose | Why unchanged |
|---------|---------|---------|--------------|
| Web Crypto API (`crypto.subtle`) | browser/Node built-in | AES-256-GCM/CTR encrypt/decrypt | CLAUDE.md rule 5 — always AES-256-GCM for content; already correctly used, only the *key-copy zeroization* around it changes |
| `eciesjs` (via `@cipherbox/crypto`'s `wrapKey`/`unwrapKey`) | unchanged | ECIES key wrapping (CLAUDE.md rule 4) | No change to the ECIES primitive itself — only call-site plumbing (hex boundary, param naming) |

## Architecture Patterns

### System Architecture Diagram (data flow for the TEE-wrap + wire-rename todos)

```
createSubfolder / createFileMetadata / publishEmptyRootNode   (packages/sdk-core)
        │  ipnsPrivateKey: Uint8Array, teeKeys.currentPublicKey: string (hex)
        ▼
  wrapIpnsKeyForTee(ipnsPrivateKey: Uint8Array, teePublicKey: Uint8Array)  ← todo #1 signature change
        │  returns Uint8Array (was: hex string)
        ▼
  caller hex-encodes ONLY at this boundary → encryptedIpnsPrivateKey: string
        │
        ▼
createAndPublishIpnsRecord → apps/api IpnsRecord entity
        column: encrypted_ipns_private_key (bytea)          ← ALREADY canonical, no migration
        │
        ▼  (async, TEE-03 republish cron)
apps/api/src/republish/republish.service.ts
        builds RepublishEntry.encryptedIpnsKey (base64)      ← todo #9: rename to encryptedIpnsPrivateKey
        │  HTTP POST /republish (private relay↔worker contract, NOT in openapi.json)
        ▼
apps/tee-worker/src/routes/republish.ts  (RepublishEntry.encryptedIpnsKey)  ← rename in lockstep
        │
        ▼
apps/tee-worker/src/services/key-manager.ts (decryptIpnsKey param encryptedIpnsKey)  ← rename in lockstep
```

### Recommended Task Sequencing (bottom-up through the dependency graph)

```
packages/crypto           (todos #3, #5 — no internal deps beyond itself)
   │
   ├──▶ packages/core/src/node/*        (todo #7 — consumes crypto's new base64 export)
   │
   └──▶ packages/sdk-core               (todos #1, #2, #6, #8 — consumes crypto + core)
             │
             └──▶ packages/sdk          (todos #4, #10, #11 — consumes sdk-core)

apps/api ⇄ apps/tee-worker  (todo #9 — independent HTTP contract, no package dep on the above)
apps/api                    (todo #12 — independent, no package dep on the above)
```

Todo #9 and #12 (both `apps/api`) have zero dependency on the `packages/*` chain and can be planned as a separate wave in parallel with the `packages/*` wave.

### Anti-Patterns to Avoid

- **Zeroing a caller-owned buffer:** Per project convention (D-09, confirmed repeatedly in this codebase's own comments — e.g. `tee/wrap.ts:25-28`, `registration.ts:8-11`, `node/seal.ts:19`), a function that only *reads* a caller-supplied key (like `wrapIpnsKeyForTee` borrowing `ipnsPrivateKey`, or `updateFolderMetadataAndPublish` receiving `readKey`/`writeKey`/`ipnsPrivateKey`) must NEVER `.fill(0)` it. Only `.fill(0)` buffers this function itself allocated (e.g. `createSubfolder`'s minted `readKey`/`writeKey`/`ipnsPrivateKey` — before they are returned to the caller — and the local `keyBuffer` copies inside the AES helpers). Getting this backwards previously broke 48/89 E2E tests (project memory).
- **Reintroducing a 4th base64 copy:** Do not add a NEW local `base64ToBytes` function anywhere as part of this phase — every todo in #5/#6/#7 should end with call sites importing from `@cipherbox/crypto`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Base64 encode/decode | A 5th/6th/7th local `bytesToBase64`/`base64ToBytes` | The hoisted `@cipherbox/crypto` export (todo #5) | 12 files currently duplicate ~15-line chunked-btoa/atob implementations; one canonical copy with one test suite |
| Zeroing sensitive buffers | Manual `for` loops or ad-hoc `.fill(0)` scattered inline | `clearBytes()` / `clearAll()` from `@cipherbox/crypto/utils/memory.ts` (already exists, already used by `createFileMetadata`, `edit-filepointer.mts`, `rename-folder.mts`) | Consistent null-safe helper already proven in the codebase; todo #2/#3/#4 should call it, not write new `.fill(0)` call sites by hand |

**Key insight:** Almost nothing in this phase requires new code — it requires *consistently applying patterns that already exist elsewhere in the same codebase* (the sibling scripts, `createFileMetadata`'s try/catch, `clearBytes`). Use the already-correct sibling as the template for the fix, don't invent a new pattern.

## Findings Per Todo (grounded in current code)

### Todo #1 — `wrapipnskeyfortee-bytes-in-bytes-out`

**Current signature** (`packages/sdk-core/src/tee/wrap.ts:30-37`):

```typescript
export async function wrapIpnsKeyForTee(
  ipnsPrivateKey: Uint8Array,
  currentPublicKey: string          // hex string — NOT bytes
): Promise<string> {                 // hex string — NOT bytes
  const teePublicKeyBytes = hexToBytes(currentPublicKey);
  const wrappedBytes = await wrapKey(ipnsPrivateKey, teePublicKeyBytes);
  return bytesToHex(wrappedBytes);
}
```

**Target:** `wrapIpnsKeyForTee(ipnsPrivateKey: Uint8Array, teePublicKey: Uint8Array): Promise<Uint8Array>`. Callers hex-decode `teeKeys.currentPublicKey` before calling, and hex-encode the result immediately before it is placed into the `encryptedIpnsPrivateKey?: string` wire field.

**Current callers (all 3 need the `hexToBytes`/`bytesToHex` moved to the call site):**
| File | Line | Current call |
|---|---|---|
| `packages/sdk-core/src/folder/registration.ts` | 94 | `encryptedIpnsPrivateKey = await wrapIpnsKeyForTee(ipnsPrivateKey, currentPublicKey);` |
| `packages/sdk-core/src/vault/index.ts` | 142-145 | `encryptedIpnsPrivateKey = await wrapIpnsKeyForTee(params.rootIpnsKeypair.privateKey, currentPublicKey);` |
| `packages/sdk-core/src/file/index.ts` | 313 | `encryptedIpnsPrivateKey = await wrapIpnsKeyForTee(fileIpnsPrivateKey, currentPublicKey);` |

None of these 3 files currently import `hexToBytes`/`bytesToHex` from `@cipherbox/crypto` — add to each import list.

**`TeeKeys` type** (`packages/sdk-core/src/types.ts:21-26`) keeps `currentPublicKey: string` (hex) unchanged — it is populated from the API/DTO boundary and stays hex there; only the internal function's parameter changes.

**Pitfall — 3 un-consolidated duplicate call sites NOT touched by todo #1** (same hex→wrap→hex sequence reimplemented inline, none call the shared helper):
- `packages/sdk/src/client.ts:2484-2492` (inside `createFolder`, comment literally says "mirrors createSubfolder, registration.ts:85-109")
- `packages/sdk/src/bin/index.ts:108-116` (`saveBinMetadata`) — **note this one wraps the whole block in try/catch and treats TEE-enrollment failure as non-blocking** (different fail-closed semantics than registration.ts's throw-on-missing-currentPublicKey)
- `apps/web/src/services/vault-settings.service.ts:133-138`

These are NOT in the literal scope of "make wrapIpnsKeyForTee bytes-in/bytes-out" but are the same anti-pattern; recommend the planner explicitly decide in-scope vs. deferred rather than silently leaving them (Common Pitfall 6 below).

### Todo #2 — `zeroize-createsubfolder-keys-on-error-path`

`createSubfolder` (`packages/sdk-core/src/folder/registration.ts:40-127`) mints `ipnsPrivateKey`/`readKey`/`writeKey` at the top (steps 1-3) then does `sealNode` → `addToIpfs` → `createAndPublishIpnsRecord` (steps 6-8) with **no try/catch at all** — if any of those three throw, the minted keys leak (nothing zeroes them, they are simply garbage-collected... eventually).

**Reference pattern already implemented correctly** — `createFileMetadata` in `packages/sdk-core/src/file/index.ts:260-360` wraps the equivalent sequence in `try { ... } catch (err) { fileReadKey.fill(0); fileWriteKey.fill(0); fileIpnsPrivateKey?.fill(0); throw err; }`. Model the `createSubfolder` fix directly on this.

Fix shape: wrap steps 4-8 (node build through publish) in `try/catch`, and in `catch`, `.fill(0)` on `ipnsPrivateKey`, `readKey`, `writeKey` before re-throwing. The success-path return (line 118-126, "do NOT zero — caller is terminal owner, D-09") must remain unchanged — zeroization is error-path only.

**Test gap:** `packages/sdk-core/src/__tests__/folder.test.ts` line 366 tests "does NOT zero minted keys before return" (success path) but has no test forcing `sealNode`/`addToIpfs`/`createAndPublishIpnsRecord` to throw and asserting the keys are all-zero afterward — this test does not exist yet and must be added (Wave 0 gap, see Validation Architecture).

### Todo #3 — `zeroize-local-key-plaintext-copies-in-aes-helpers`

**Scope is 7 functions across 4 files**, all following the identical leak pattern: `const keyBuffer = new Uint8Array(key).buffer as ArrayBuffer;` — a fresh owned copy of the caller's key, fed into `crypto.subtle.importKey`, never zeroed:

| File | Function | Line of `keyBuffer` copy |
|---|---|---|
| `packages/crypto/src/aes/encrypt.ts` | `encryptAesGcm` | 40 |
| `packages/crypto/src/aes/encrypt.ts` | `encryptAesGcmAad` | 101 |
| `packages/crypto/src/aes/decrypt.ts` | `decryptAesGcm` | 45 |
| `packages/crypto/src/aes/decrypt.ts` | `decryptAesGcmAad` | 110 |
| `packages/crypto/src/aes/encrypt-ctr.ts` | `encryptAesCtr` | 49 |
| `packages/crypto/src/aes/decrypt-ctr.ts` | `decryptAesCtr` | 43 |
| `packages/crypto/src/aes/decrypt-ctr.ts` | `decryptAesCtrRange` | 143 |

Fix pattern for each: keep a reference to the `Uint8Array` view (not just the raw `.buffer`), e.g. `const keyView = new Uint8Array(key); const keyBuffer = keyView.buffer as ArrayBuffer;`, then in a `finally` block (wrapping the existing `try`) call `keyView.fill(0)`. This is safe because (a) it is a local copy this function itself allocated — the function IS the terminal owner of this specific copy (the caller's own `key` param is untouched, satisfying D-09), and (b) `crypto.subtle.importKey` has already consumed the bytes into an opaque `CryptoKey` by the time zeroization runs, so no functional change to encryption/decryption output.

`sealAesGcm`/`unsealAesGcm`/`sealAesGcmAad`/`unsealAesGcmAad` in `packages/crypto/src/aes/seal.ts` are pure composition wrappers over the above (no independent `keyBuffer` copy) — no change needed there.

**Test parity:** `packages/crypto/src/__tests__/aes.test.ts` and `aes-ctr.test.ts` have no aliasing/mutation assertions on the `key` parameter — adding internal zeroization is safe and won't break any existing assertion. No test currently proves the internal copy is zeroed; a new assertion is needed (see Validation Architecture) — but since `keyBuffer`/`keyView` is a function-local variable never returned, this can only be tested by intercepting `crypto.subtle.importKey` via a spy or by refactoring the zeroization into a small exported-for-testing helper. Simpler approach: extract the copy+import+zero sequence into one small internal `importAesKey(key, algorithm, usages)` helper shared by all 7 functions, and unit test THAT helper directly.

### Todo #4 — `e2e-helper-scripts-zeroize-userprivatekey`

`packages/sdk-core/scripts/verify-filepointer.mts` is the ONE outlier in its own directory:

| Script | `userPrivateKey`/key zeroization |
|---|---|
| `packages/sdk-core/scripts/edit-filepointer.mts` | ✅ Already zeroizes (`clearBytes(fileReadKey)`, `clearBytes(fileWriteKey)`, `clearBytes(rootReadKey)`, `clearBytes(rootWriteKey)`, `clearBytes(userPrivateKey)` at lines 236-240) |
| `packages/sdk-core/scripts/rename-folder.mts` | ✅ Already zeroizes (`clearBytes(rootReadKey)`, `clearBytes(rootWriteKey)`, `clearBytes(userPrivateKey)` at lines 151-153) |
| `packages/sdk-core/scripts/verify-filepointer.mts` | ❌ No `clearBytes` import at all; `userPrivateKey` (line 107), `vaultKeyBlob.rootReadKey`/`rootWriteKey` (line 121), and any derived `fileReadKey`/`subReadKey` from `deriveChildReadKey` are never cleared |

Fix: add `import { clearBytes } from '@cipherbox/crypto';`, wrap `main()`'s body from after `vaultKeyBlob` load onward in try/finally, and `clearBytes()` on `userPrivateKey`, `vaultKeyBlob.rootReadKey`, `vaultKeyBlob.rootWriteKey`, and `fileReadKey`/`subReadKey` (if the `--folder-name` branch was taken) at the end — mirroring the sibling scripts' pattern exactly.

`tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts` was also checked (a different e2e-helper family) and already correctly zeroizes — not in scope, no action needed.

### Todo #5 — `hoist-base64tobytes-into-crypto-package`

`@cipherbox/crypto`'s `packages/crypto/src/utils/encoding.ts` currently has ONLY hex helpers (`hexToBytes`, `bytesToHex`, `uuidToBytes`, `concatBytes`) — **no base64 helper exists at all** in the crypto package today. Add `base64ToBytes`/`bytesToBase64` there (chunked implementation, matching the existing pattern used everywhere else in the codebase — see todo #6/#7 for the exact reference implementation to copy), export from `packages/crypto/src/utils/index.ts` (`export { base64ToBytes, bytesToBase64 } from './encoding';`) and from the top-level `packages/crypto/src/index.ts` alongside the existing `hexToBytes, bytesToHex` re-export (line ~86-87).

No existing test file covers hex helpers directly either (`hexToBytes`/`bytesToHex` are only exercised indirectly through other tests) — for base64, add a small new `packages/crypto/src/__tests__/encoding.test.ts` (or extend an existing generically-named test file if the planner prefers) asserting round-trip correctness against known byte/base64 pairs — this becomes the canonical golden-vector test all downstream dedups (todo #6, #7) can point back to for parity proof.

### Todo #6 — `dedup-base64-helpers-sdk-core-share`

4 duplicate `bytesToBase64`/`base64ToBytes` pairs inside `packages/sdk-core`, all functionally byte-identical (chunked `btoa`/`atob`, only the chunk-size constant differs cosmetically: 8192 in three of them, 32768 in the fourth):

| File | Lines | Chunk size | Notable comment |
|---|---|---|---|
| `packages/sdk-core/src/rotation/engine.ts` | 462-483 | 8192 | **"Local copy — dedup with share/grant.ts is deferred per CONTEXT.md."** — this comment is the literal origin of this todo |
| `packages/sdk-core/src/share/grant.ts` | 58-75 | 8192 | both functions |
| `packages/sdk-core/src/share/navigate.ts` | 59-66 | 8192 | `base64ToBytes` only (no encode side needed there) |
| `packages/sdk-core/src/file/index.ts` | 62-79 | 32768 | both functions (also in scope of todo #8's rename work in the same file — sequence these together) |

Todo #6's literal title says "extract a shared `share/codec.ts`" — but `rotation/engine.ts` and `file/index.ts` are NOT inside `share/`, so a `share/codec.ts`-local file would only fix 2 of 4 duplicates. **Recommend importing directly from the newly-hoisted `@cipherbox/crypto` export (todo #5) in all 4 files instead of creating an intermediate `share/codec.ts` re-export** — this avoids a redundant indirection layer and is consistent with how `hexToBytes`/`bytesToHex` are already imported directly from `@cipherbox/crypto` throughout `sdk-core`.

### Todo #7 — `node-codec-base64-helper-dedup`

3 duplicate `uint8ArrayToBase64`/`base64ToUint8Array` pairs inside `packages/core/src/node/` (a DIFFERENT package from todo #6's sdk-core duplicates, and a different function-name convention: `uint8ArrayToBase64` not `bytesToBase64`):

| File | Lines | Notable comment |
|---|---|---|
| `packages/core/src/node/encode.ts` | 25-33 | "Copied verbatim from packages/core/src/folder/metadata.ts lines 23-31" — that source file no longer exists (already deleted in an earlier refactor), confirming this is stale copy-paste debt |
| `packages/core/src/node/seal.ts` | 41-59 | same base64ToBytes AND bytesToBase64 pair |
| `packages/core/src/node/decode.ts` | 29-42 | `base64ToUint8Array(b64, expectedLength?)` — **has an extra optional `expectedLength` param not present in the other two copies** — preserve this superset signature when consolidating (or keep the length assertion as a thin wrapper around the shared bytes-only helper) |

`packages/core` already depends on `@cipherbox/crypto` (`package.json` — `"@cipherbox/crypto": "workspace:*"`), and `seal.ts` already imports `sealAesGcmAad, unsealAesGcmAad, buildNodeAad, CryptoError` from it. Once todo #5 hoists `base64ToBytes`/`bytesToBase64` into `@cipherbox/crypto`, all 3 `packages/core/src/node/*.ts` files should import from there directly — do not invent a `packages/core`-local shared file. `decode.ts`'s length-check wrapper stays local (thin, ~5 lines) since it's decode-specific validation logic, not a codec duplicate.

**Golden-vector parity:** `packages/core/src/__tests__/node-codec-vectors.test.ts` + `node-codec.test.ts` already round-trip through `sealNode`/`unsealNode` (which internally call these base64 helpers) against frozen byte vectors in `tests/vectors/node-codec.json` (3 lock levels: body-hex, full-seal-bytes, round-trip). **Re-running this existing suite after the dedup is sufficient proof of parity — no new golden vectors need to be authored for todo #7.**

### Todo #8 — `rename-ipnsprivatekeyencrypted-to-encryptedipnsprivatekey`

**This is NOT a global rename** — `encryptedIpnsPrivateKey` is already used correctly in `packages/sdk-core/src/folder/registration.ts` (return field, line 50) and `packages/sdk-core/src/vault/index.ts` (local var, line 125). The actual non-canonical holdout is `ipnsPrivateKeyEncrypted` (words reversed), confined to:

| File | What | Line(s) |
|---|---|---|
| `packages/sdk-core/src/file/index.ts` | `createFileMetadata`'s return-type field `ipnsPrivateKeyEncrypted?: string` | 230, 351 (note: the SAME function ALSO builds `ipnsRecord.encryptedIpnsPrivateKey` at line 335 with the correct name for the SAME value — this exact same-function double-naming is the bug) |
| `packages/sdk-core/src/upload/index.ts` | `UploadResult.ipnsPrivateKeyEncrypted?: string` field + its one assignment | 60, 199 |
| `packages/sdk/src/client.ts` | 3 doc-comment mentions only (no live field reference — these are outdated comments describing removed legacy fields, e.g. line 1632 "legacy `folderKeyEncrypted`/`ipnsPrivateKeyEncrypted` fields no longer exist") — **leave these comments as-is or update wording, they are historical, not a rename target** | 1632, 3779, 3905 |
| Test files (blast radius, all need the field renamed in fixtures/assertions) | `packages/sdk/src/__tests__/helpers.ts:43`, `client-pinning.test.ts:38,47`, `client-extended.test.ts:224,291`, `upload-batch.test.ts:77`, `client-upload-concurrency.test.ts:67`, `packages/sdk-core/src/__tests__/upload.test.ts:26,68`, `packages/sdk-core/src/__tests__/file/file-node.test.ts:145,157,176-177` | — |

**`file-node.test.ts:177`** currently asserts `expect(result.ipnsRecord.encryptedIpnsPrivateKey).toBe(result.ipnsPrivateKeyEncrypted)` — i.e. it documents the SAME value under two different names. Post-rename this becomes `expect(result.ipnsRecord.encryptedIpnsPrivateKey).toBe(result.encryptedIpnsPrivateKey)`.

**Out of scope — do not touch:** `landing/src/scripts/demo-data.ts` (lines 101, 111) also uses `ipnsPrivateKeyEncrypted`, but this is static untyped marketing/demo JSON representing a legacy v2 wire format for a landing-page animation — it has no type import connecting it to the real SDK types (confirmed no `import type` from `@cipherbox/sdk` in the file), and `client.ts`'s own comments describe this exact field name as an intentionally-retained "legacy" artifact. Renaming it would misleadingly imply it reflects the current schema.

### Todo #9 — `rename-encrypted-ipns-key-canonical-field`

The TEE wire contract (relay ↔ tee-worker HTTP, a **private, non-OpenAPI-documented** contract — confirmed absent from `packages/api-client/openapi.json`) uses `encryptedIpnsKey` (missing "Private") as the field name in 3 places that must be renamed together (`encryptedIpnsKey` → `encryptedIpnsPrivateKey`):

| File | Symbol | Lines |
|---|---|---|
| `apps/api/src/tee/tee.service.ts` | `RepublishEntry.encryptedIpnsKey: string` (JSDoc + field) | 13-15 |
| `apps/api/src/republish/republish.service.ts` | builds the `teeEntries` array: `encryptedIpnsKey: record.encryptedIpnsPrivateKey!.toString('base64')` (note: reads FROM the already-canonical entity field, writes TO the non-canonical wire field — the entity is fine, only the wire DTO name is wrong) | 141-146 |
| `apps/tee-worker/src/routes/republish.ts` | request-body field type + decode call | 58, 121-123 |
| `apps/tee-worker/src/services/key-manager.ts` | `decryptIpnsKey(encryptedIpnsKey: Uint8Array, ...)` param name (JSDoc + 2 call sites) | 43, 49, 54, 71, 78, 92, 102 |

**Test blast radius:** `apps/tee-worker/src/__tests__/republish.test.ts` (~18 occurrences, straightforward find/replace including destructured helper `makeEntry()`), `apps/api/src/tee/tee.service.spec.ts` (2 occurrences), `apps/api/src/republish/republish.service.spec.ts` (7 occurrences, **including negative assertions** `expect(savedSchedule).not.toHaveProperty('encryptedIpnsKey')` at lines 364, 513, 789, 807 that must become `.not.toHaveProperty('encryptedIpnsPrivateKey')` — these prove the schedule row does NOT persist this field, unrelated to the rename itself but the assertion string must track it).

**`packages/api-client` / `pnpm api:generate` is NOT triggered by this todo** — `RepublishEntry`/`RepublishResult` are plain TypeScript interfaces internal to `apps/api` and `apps/tee-worker`; there is no NestJS controller/DTO decorator exposing them via Swagger/OpenAPI (confirmed: no `/republish` or `/tee/*` path exists in `packages/api-client/openapi.json`, and the TEE worker is a separate Node service, not part of the `apps/api` Nest app that `api:generate` introspects). This matches the existing project precedent noted in STATE.md: "[Phase 60-05]: api:generate NOT required; changes are internal service/codec logic with no OpenAPI surface change."

**Separately-discovered, unrelated `encryptedIpnsKey` occurrences NOT part of this todo's wire-contract rename** (different subsystem — the legacy per-share wrapped-key path, already flagged `@deprecated`):
- `apps/web/src/stores/share.store.ts:31` — `ReceivedShare.encryptedIpnsKey?: string | null`, explicitly commented `@deprecated legacy per-share wrapped IPNS key; superseded by encryptedWriteKey (SC#2)` and "nothing in the web app reads them anymore". This is dead-scaffolding territory (candidate for todo #10, not #9).
- `packages/sdk/src/share/shared-write.ts:915-928` — `updateSharePermission`/`updatePermissionFn` callback with an `encryptedIpnsKey?: string` field. **Newly discovered dead code**: `grep` confirms no live caller in `apps/web` or `packages/sdk/src/client.ts` — only the SDK's own test (`shared-write.test.ts`) calls `updateSharePermission` directly. Confirmed further: `packages/api-client/src/models/updatePermissionDto.ts` (`UpdatePermissionDto`/`UpdatePermissionDtoPermission`) has **no corresponding route in the current `openapi.json`** — the live share-permission endpoint uses a different, newer DTO (`apps/api/src/shares/dto/update-grant.dto.ts`). Recommend folding `updateSharePermission` + the orphaned generated models into todo #10's dead-scaffolding retirement scope rather than renaming a field on dead code — flag this explicitly for planner/user confirmation since it expands todo #10's stated scope.
- `apps/web/src/services/device-registry.service.ts:151,160` and `packages/sdk/src/bin/index.ts:105,112` — local variable named `encryptedIpnsKey` that is immediately assigned into the correctly-named `encryptedIpnsPrivateKey:` wire field. Cosmetic only (local var name doesn't reach any DTO/wire boundary) — optional minor polish, not required for success criteria.

### Todo #10 — `retire-dead-sdk-share-scaffolding`

Confirmed dead via `grep` (no live caller/consumer anywhere in `apps/web` or `packages/sdk/src/client.ts`'s active logic):

| Symbol | Definition | Dead because |
|---|---|---|
| `ShareCallbacks` type | `packages/sdk/src/types.ts:35-43` | `client.ts` never reads `config.shareCallbacks.getCoveringShares`/`.addShareKeys` (confirmed 0 matches in `client.ts`) |
| `shareCallbacks?: ShareCallbacks` config field | `packages/sdk/src/types.ts:139` (on `ClientConfig`) | Same as above; `apps/web/src/hooks/useAuth.ts:337-340` comment explicitly documents removal: "shareCallbacks (getCoveringShares/addShareKeys) removed: the SDK's per-recipient key fan-out is dead code (D-03 already skips it at upload time) and the web addShareKeys fan-out it called into is deleted (SC#2/D-12)" |
| Public re-export of `ShareCallbacks` | `packages/sdk/src/index.ts:44` | Exported but unused by any consumer (confirmed 0 matches for `ShareCallbacks` anywhere in `apps/web/src`) |
| `addShareKeysFn` field | `SharedWriteContextParams` (`packages/sdk/src/share/context.ts:36-39`), `SharedWriteContext` (`shared-write.ts`), threaded through `buildSharedWriteContext` (`context.ts:65`) | `shared-write.ts` doc-comments at 6+ call sites explicitly state "addShareKeysFn is NEVER called (D-02)"; every production construction site passes a no-op (`client.ts:5579` `async () => {}`, `useSharedNavigation.ts:234` `async () => {}`) |
| Construction sites requiring the field to be dropped in lockstep | `packages/sdk/src/client.ts:5135,5333,5579`; `apps/web/src/hooks/shared-folder-projection.ts:68,108`; `apps/web/src/hooks/useSharedNavigationActions.ts:119`; `apps/web/src/hooks/useSharedNavigation.ts:226,234` | Must all drop the now-removed field from their param/type signatures |
| Test assertions on the never-called invariant (must be DELETED, not renamed — the assertion becomes meaningless once the field doesn't exist) | `packages/sdk/src/__tests__/shared-write.test.ts` (5 `expect(swCtx.addShareKeysFn).not.toHaveBeenCalled()` at lines 285,324,409,518,576) + mock setup at 125; `resolve-shared-subfolder-write-key.test.ts:141`; `move-in-shared-folder.test.ts:222`; `context.test.ts:41,62,95-100`; `folder-listing.test.ts:196`; `client-shared-write.test.ts:92`; `shared-folder-tree.test.ts:34`; `enumerate-shared-subtree.test.ts:315`; `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts:168,179` | ~13 test files touch this mock; removing the field is a genuine multi-file mechanical sweep — largest single blast radius in this phase |
| **Newly discovered, same dead-scaffolding family** — `updateSharePermission`/`updatePermissionFn` (`shared-write.ts:907-928`), plus orphaned `packages/api-client/src/models/updatePermissionDto.ts` + `updatePermissionDtoPermission.ts` | See todo #9 finding above | No live caller; no matching route in current `openapi.json` (superseded by `update-grant.dto.ts`) — recommend planner explicitly confirm with user whether to fold this in, since it's not named in the phase's literal todo list |

### Todo #11 — `drop-discarded-per-upload-ecies-wrapkey`

**Could not locate a currently-live discarded per-upload `wrapKey` call** matching the todo's description in `packages/sdk-core/src/upload/index.ts` or `packages/sdk-core/src/file/index.ts` — the file already documents (comment at `upload/index.ts:136-139`) that this exact step was **already retired**: *"the legacy ECIES-wrap-of-fileKey step is retired: the v3 model stores fileKey raw inside the sealed content, no per-recipient wrap needed at upload time (READ-03 — the parent readKey already gates access)."* A full grep of every `wrapKey(` call site in `packages/sdk` + `packages/sdk-core` (14 call sites total) found no unused/discarded result — every `wrapped`/`wrappedBytes`/`wrappedKey` local variable is consumed (assigned into a field that is returned or persisted).

**Recommendation for the planner:** re-scope or drop this todo, or treat it as **already satisfied** by a prior phase (the comment attributes the retirement to "READ-03," a different, earlier requirement). If the todo author had a SPECIFIC call site in mind that has since been removed, flag this to the user for confirmation rather than inventing a change — do not have the executor hunt for a phantom target. If kept in the plan, the task should be a **verification-only** step (grep for orphaned `wrapKey(` results, confirm none exist, document as already-clean) rather than a code-change task.

### Todo #12 — `extract-assert-root-ownership-helper`

Byte-identical duplicate block, confirmed via `grep -n "You are not the registered owner"` → exactly 2 hits:

```typescript
// apps/api/src/shares/shares.service.ts:40-45 (createShare)
// apps/api/src/shares/share-invite.service.ts:43-48 (createInvite)
const owned = await this.ipnsRecordRepo.findOne({
  where: { ipnsName: dto.shareRootIpnsName, userId: sharerId },
});
if (!owned) {
  throw new ForbiddenException('You are not the registered owner of this node');
}
```

Both surrounding comment blocks are also identical (5-line "D-01/SC#1 root-ownership gate" doc comment). Both services already inject `ipnsRecordRepo: Repository<IpnsRecord>` directly via `@InjectRepository(IpnsRecord)` (not through an intermediate `IpnsService`), and both are registered in `shares.module.ts`'s single `TypeOrmModule.forFeature([Share, ShareInvite, User, IpnsRecord])`.

**Recommended extraction:** a plain exported async function (not a new `@Injectable()` — no new DI wiring needed since callers already have the repo):

```typescript
// apps/api/src/shares/root-ownership.util.ts (new file)
export async function assertRootOwnership(
  ipnsRecordRepo: Repository<IpnsRecord>,
  ipnsName: string,
  userId: string
): Promise<void> {
  const owned = await ipnsRecordRepo.findOne({ where: { ipnsName, userId } });
  if (!owned) {
    throw new ForbiddenException('You are not the registered owner of this node');
  }
}
```

Both `shares.service.ts:createShare` and `share-invite.service.ts:createInvite` replace their inline block with `await assertRootOwnership(this.ipnsRecordRepo, dto.shareRootIpnsName, sharerId);`.

**Test blast radius:** `apps/api/src/shares/shares.service.spec.ts` and `share-invite.service.spec.ts` both have existing tests asserting the `ForbiddenException` throw — these should continue to pass unmodified against the extracted helper (same error message, same behavior) but should be checked for any mock structure that assumed the inline `ipnsRecordRepo.findOne` call shape.

**`pnpm api:generate` NOT required** — no DTO/controller signature changes, purely internal service refactor (same precedent as todo #9).

## Common Pitfalls

### Pitfall 1: Zeroizing a caller-owned buffer (double-zero / D-09 violation)
**What goes wrong:** Adding `.fill(0)` to a buffer the function only *borrows* (e.g. mistakenly zeroing `ipnsPrivateKey` inside `wrapIpnsKeyForTee`, or zeroing `readKey`/`writeKey` inside `updateFolderMetadataAndPublish`) corrupts state the caller still needs, or double-zeroes a buffer the caller already cleared.
**Why it happens:** "Add zeroization" tasks tend to be applied uniformly without checking which function is the terminal owner.
**How to avoid:** Before adding `.fill(0)` anywhere, check the function's OWN doc comment for "D-09" / "terminal owner" / "does NOT zero" language — every function touched in todos #1-#4 already has this documented. If the function documents "does NOT zero — caller is terminal owner," do not add zeroization to that function on the SUCCESS path; only add it on paths where THIS function becomes the owner (i.e., an error path before the value reaches the caller, as in todo #2).
**Warning signs:** A previously-passing test starts failing with a key that decrypts to garbage/all-zero, or a "48/89 E2E tests failed" style regression (this exact class of bug already occurred once in this codebase per project memory).

### Pitfall 2: Chunk-size drift breaking golden vectors
**What goes wrong:** The 4 sdk-core base64 duplicates use chunk size 8192 in three places and 32768 in `file/index.ts`; the 3 packages/core duplicates use 32768. Picking the "wrong" one when consolidating doesn't change correctness (chunking is purely a call-stack-depth optimization, output is byte-identical either way) but a careless refactor that changes chunking logic itself (not just the constant) could alter behavior on edge-case input sizes.
**Why it happens:** Copy-paste-and-tweak refactors sometimes "simplify" the loop while consolidating.
**How to avoid:** When hoisting to `@cipherbox/crypto`, copy one of the existing implementations VERBATIM (recommend the `32768`-chunk version from `file/index.ts` / `packages/core/src/node/encode.ts`, matching the `[SECURITY: MEDIUM-08]` comment that documents WHY chunking exists — spread-operator argument limits) rather than writing a new implementation from scratch. Prove parity by re-running `node-codec-vectors.test.ts` (existing golden vectors) after the swap.

### Pitfall 3: Renaming `ipnsPrivateKeyEncrypted` without renaming BOTH the type field and every string-literal test fixture key
**What goes wrong:** TypeScript will catch missed field renames at the type level in `.ts` source, but test fixture objects using loose typing (e.g., `helpers.ts:43`'s mock object) or `toHaveProperty('ipnsPrivateKeyEncrypted')`-style string assertions will NOT be caught by the compiler — they silently stop testing anything (the assertion becomes a false negative that always "passes" because the property never existed under the old name to begin with, post-rename it's checking for a property that's now correctly absent under a DIFFERENT name than intended).
**Why it happens:** String-keyed assertions (`toHaveProperty('fieldName')`, object literal fixtures) aren't type-checked against the real interface.
**How to avoid:** `grep -rn "ipnsPrivateKeyEncrypted"` across the WHOLE repo (not just `packages/sdk-core`) as a final verification step after the rename — the research above already enumerates all ~11 hit files; confirm zero remain except the deliberately-untouched `client.ts` doc comments and `landing/demo-data.ts`.

### Pitfall 4: Assuming `pnpm api:generate` is needed for every apps/api change in this phase
**What goes wrong:** Running `pnpm api:generate` unnecessarily (todos #9, #12 touch `apps/api` but neither changes a DTO/controller signature) wastes a build cycle and — per the pre-commit hook `scripts/check-api-client.sh` — will FAIL if the regenerated client has no diff to stage (or worse, produces a spurious diff from an unrelated stale generation).
**Why it happens:** CLAUDE.md's blanket instruction ("After modifying API endpoints, DTOs, or controllers, regenerate the API client") is easy to over-apply to internal service-only refactors.
**How to avoid:** Only run `pnpm api:generate` if a `@Controller`/`@Get`/`@Post`/DTO class decorated with `@ApiProperty`-style Swagger metadata actually changed shape. Todos #9 and #12 in this phase do NOT — `RepublishEntry`/`RepublishResult` are plain internal interfaces (no Nest decorators, no controller route), and the `assertRootOwnership` extraction changes zero DTOs. This matches the precedent already set by "[Phase 60-05]: api:generate NOT required" in STATE.md.

### Pitfall 5: Removing `addShareKeysFn` breaks TypeScript compilation transitively across 3 packages before all call sites are updated
**What goes wrong:** `addShareKeysFn` is a REQUIRED (non-optional) field on `SharedWriteContextParams`/`SharedWriteContext` — removing it from the type but leaving even one construction site (`client.ts`, 3 web hooks, ~13 test files) unmodified breaks `tsc` for that package. Given the monorepo's documented "cross-package dist staleness" gotcha (project memory), a partial removal in `packages/sdk` will not surface as a build error in `apps/web` until `apps/web`'s own typecheck runs against a rebuilt `packages/sdk` dist.
**Why it happens:** Large mechanical renames/removals spanning `packages/sdk` → `apps/web` require the SDK to be rebuilt before the consumer's typecheck is meaningful.
**How to avoid:** After removing `addShareKeysFn`/`ShareCallbacks` from `packages/sdk`, rebuild `packages/sdk`'s dist (`pnpm --filter @cipherbox/sdk build` or equivalent) BEFORE running `apps/web`'s typecheck, per the existing project convention "rebuild sdk-core/sdk dist before consumer typecheck after API changes."

### Pitfall 6: Silently expanding todo #1's scope to the 3 un-consolidated inline TEE-wrap duplicates
**What goes wrong:** It's tempting to "fix it everywhere while you're in there" and refactor `client.ts`/`bin/index.ts`/`vault-settings.service.ts` to call the now-bytes-in/bytes-out `wrapIpnsKeyForTee` helper instead of their own inline hex→wrap→hex sequences. This is a reasonable follow-up but is NOT what todo #1 asked for (it only asked for the signature change) and `bin/index.ts`'s version has different fail-closed semantics (best-effort try/catch vs. registration.ts's fail-closed throw) that must be preserved if consolidated.
**Why it happens:** Once you see the pattern duplicated 6 times, deduping all 6 feels like the "complete" fix.
**How to avoid:** Flag this explicitly as a scope decision for the plan/discuss step — either (a) strictly scope todo #1 to the signature change + its 3 current callers only, or (b) explicitly expand scope to consolidate all 6 call sites onto the shared helper, documenting the semantic difference (bin/index.ts is best-effort) in the helper's caller contract. Do not let the executor decide silently.

## Code Examples

### Zeroization on error path (todo #2 — model directly on the existing `createFileMetadata` pattern)

```typescript
// Source: packages/sdk-core/src/file/index.ts:260,353-360 (EXISTING correct pattern)
try {
  // ... mint keys, seal, upload, publish ...
  return { /* success — do NOT zero, caller is terminal owner */ };
} catch (err) {
  // Keys never reached the caller on this path — zero them.
  fileReadKey.fill(0);
  fileWriteKey.fill(0);
  fileIpnsPrivateKey?.fill(0);
  throw err;
}
```

### Chunked base64 (todo #5 — verbatim copy target for the hoisted helper)

```typescript
// Source: packages/core/src/node/encode.ts:20-33 (pick this implementation, MEDIUM-08 documented rationale)
function uint8ArrayToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 32768;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `wrapIpnsKeyForTee` hex-string public-key param | bytes-in/bytes-out, hex only at API/wire boundary | This phase (todo #1) | Matches the existing `hexToBytes`/`bytesToHex` boundary convention already used everywhere else in `sdk-core` (e.g. `AAD` building, `Ed25519` keys) — TEE wrap was the one outlier still doing hex internally |
| DB column `encrypted_ipns_key` (bytea, on `ipns_republish_schedule` and briefly on `shares`) | `encrypted_ipns_private_key` on `ipns_records`; the schedule/shares copies were already DROPPED by migrations `1751000000000-ScheduleCollapse` (TEE-03/D-02, "data-minimisation") and `1743000000000-AddWritableShares`'s own down() | Already done in a prior phase | Confirms todo #9 is TS-interface-only, zero DB/migration work in this phase |

**Deprecated/outdated:**
- `ShareCallbacks`/`addShareKeysFn`/`updateSharePermission` (packages/sdk): superseded by the v2.0 grant model's `encryptedReadKey`/`encryptedWriteKey` direct-fan-out (SC#2/D-12), per `useAuth.ts` comment.
- `UpdatePermissionDto`/`UpdatePermissionDtoPermission` (packages/api-client generated models): superseded by `update-grant.dto.ts` — orphaned generated code with no backing route.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Todo #11 ("discarded per-upload ECIES wrapKey") has no currently-live target and should be re-scoped to a verification-only task or dropped | Todo #11 findings | If a live discarded-wrapKey call DOES exist somewhere not found by this grep sweep (e.g. behind a feature flag or in an untested code path), the plan under-delivers on this success criterion. Mitigate: planner should re-grep at plan time and, if still nothing found, get explicit user sign-off to descope rather than assume. |
| A2 | `updateSharePermission`/`updatePermissionFn` + the orphaned `UpdatePermissionDto` generated models are safe to fold into todo #10's dead-scaffolding retirement even though not literally named in the phase's todo list | Todo #9/#10 findings | If there's an undiscovered caller (e.g. a feature-flagged or not-yet-wired UI path planned for a future phase), removing it could block that future work. Mitigate: flag explicitly to the user during planning/discuss for confirmation before removing, rather than silently deleting. |
| A3 | Chunk-size differences (8192 vs 32768) across the base64 duplicates are purely cosmetic/perf and produce byte-identical output for any input — no functional divergence | Pitfall 2 | Low risk (chunking a stateless string-append loop cannot change output), but if wrong, could subtly break the FULL-SEAL LOCK golden vector byte comparison. Mitigate: the plan should re-run `node-codec-vectors.test.ts` after any base64 consolidation as the parity gate — already recommended above. |

## Open Questions

1. **Should todo #1's scope include the 3 un-consolidated inline TEE-wrap duplicates in `client.ts`, `bin/index.ts`, and `vault-settings.service.ts`?**
   - What we know: none of the 3 currently call the shared `wrapIpnsKeyForTee` helper; `bin/index.ts` has different (best-effort) fail-closed semantics than the other 5 call sites.
   - What's unclear: whether "make wrapIpnsKeyForTee bytes-in/bytes-out" was meant to also trigger consolidating these, or just the signature.
   - Recommendation: default to narrow scope (signature change + its 3 current callers only) unless the user/planner explicitly wants the full consolidation; document the semantic difference either way (see Pitfall 6).

2. **Is todo #11 still a live requirement, or already satisfied by a prior phase's READ-03 retirement?**
   - What we know: the exact code path the todo describes ("per-upload ECIES wrapKey that is immediately discarded") is not present in current `upload/index.ts`/`file/index.ts`; a comment in `upload/index.ts` explicitly says this step "is retired."
   - What's unclear: whether the todo was written before that retirement landed (stale todo) or refers to a different, still-live call site not found by this search.
   - Recommendation: re-verify at plan time with a fresh grep; if still nothing found, convert to a verification-only task (assert-and-document, not code change) and confirm with the user.

## Environment Availability

Not applicable — this phase has no external tool/service dependencies beyond the monorepo's existing toolchain (Node, pnpm, vitest, jest — all already verified working per every other phase in this milestone).

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Vitest (packages/crypto, packages/core, packages/sdk-core, packages/sdk, apps/tee-worker) + Jest (apps/api) |
| Config files | `packages/crypto/vitest.config.ts`, `packages/core/vitest.config.ts` (implied, same pattern), `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts`, `apps/tee-worker/vitest.config.ts`, `apps/api/jest.config.js` |
| Quick run command (per package) | `pnpm --filter @cipherbox/crypto test`, `pnpm --filter @cipherbox/core test`, `pnpm --filter @cipherbox/sdk-core test`, `pnpm --filter @cipherbox/sdk test`, `pnpm --filter cipherbox-tee-worker test`, `pnpm --filter cipherbox-api test` |
| Full suite command | root `pnpm test` (runs all workspace packages) — per project memory, CI's `Test` job covers exactly api/crypto/core/sdk-core/sdk/api-client; apps/web is web-e2e-gated (main-push only) and NOT exercised by this phase's changes (no web-facing UI touched) |

### Phase Requirements → Test Map

| Success Criterion | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SC1 (no key leak on throw) — createSubfolder | Forcing `sealNode`/`addToIpfs`/`createAndPublishIpnsRecord` to throw zeroes `ipnsPrivateKey`/`readKey`/`writeKey` | unit | `pnpm --filter @cipherbox/sdk-core test -- folder.test.ts` | ❌ Wave 0 — new test needed in `packages/sdk-core/src/__tests__/folder.test.ts` |
| SC1 — AES helpers key-buffer zeroization | Internal `keyBuffer`/`keyView` copy is `.fill(0)`'d after `crypto.subtle.importKey` (both success and throw paths) | unit | `pnpm --filter @cipherbox/crypto test -- aes.test.ts aes-ctr.test.ts` | ❌ Wave 0 — recommend extracting a shared `importAesKey()` helper and unit-testing IT directly (function-local `keyBuffer` is otherwise unobservable from outside) |
| SC1 — verify-filepointer.mts zeroization | `userPrivateKey`/derived read keys cleared before process exit | manual/smoke | run the script against a local dev stack and eyeball no crash (scripts in this directory have no automated test harness — matches sibling scripts' own precedent, none of `edit-filepointer.mts`/`rename-folder.mts` have dedicated unit tests either) | ❌ N/A — matches existing convention for this script family, manual-only is acceptable here (documented, not a gap) |
| SC2 (base64 dedup, parity preserved) | `@cipherbox/crypto`'s new `base64ToBytes`/`bytesToBase64` round-trips correctly | unit | `pnpm --filter @cipherbox/crypto test -- encoding.test.ts` | ❌ Wave 0 — new file `packages/crypto/src/__tests__/encoding.test.ts` |
| SC2 — node/ codec parity after consolidation | `sealNode`/`unsealNode` golden vectors still pass byte-for-byte | unit (golden vector) | `pnpm --filter @cipherbox/core test -- node-codec-vectors.test.ts node-codec.test.ts` | ✅ Already exists — re-run as the parity gate, no new file needed |
| SC3 (canonical field names, dead code gone, full typecheck+unit green) | `encryptedIpnsPrivateKey` used everywhere; `ShareCallbacks`/`addShareKeysFn` fully removed and no orphaned references remain | typecheck + unit | root `pnpm typecheck` + root `pnpm test` | N/A — existing infra, no new file, but MUST be run as the final phase gate given the ~25+ file blast radius across todos #8, #9, #10 |
| SC12 (root-ownership helper) | `assertRootOwnership` throws `ForbiddenException` when caller doesn't own the node, in both `createShare` and `createInvite` | unit | `pnpm --filter cipherbox-api test -- shares.service.spec.ts share-invite.service.spec.ts` | ✅ Already exists (tests the behavior, not the internal structure) — should pass unmodified against the extracted helper |

### Sampling Rate
- **Per task commit:** run the specific package's quick test command for whatever package that task touched (e.g. after the crypto AES zeroization task, `pnpm --filter @cipherbox/crypto test`).
- **Per wave merge:** run the full-chain quick commands in dependency order — crypto → core → sdk-core → sdk (rebuilding dist between each per Pitfall 5) — plus `apps/api`/`apps/tee-worker` tests for the independent wave.
- **Phase gate:** root `pnpm typecheck` && root `pnpm test` green before `/gsd-verify-work`, given the cross-package blast radius (Pitfall 5's dist-staleness gotcha makes a partial local-only test run insufficient proof).

### Wave 0 Gaps
- [ ] `packages/crypto/src/__tests__/encoding.test.ts` — new file, base64 round-trip golden vectors (SC2)
- [ ] New test case in `packages/sdk-core/src/__tests__/folder.test.ts` — forced-throw zeroization assertion for `createSubfolder` (SC1)
- [ ] New test(s) for AES helper key-buffer zeroization — recommend extracting `importAesKey()` first so it's independently testable (SC1)
- [ ] Framework install: none — all frameworks (vitest, jest) already present and configured

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | Unrelated to this phase — no auth-flow code touched |
| V3 Session Management | no | Unrelated |
| V4 Access Control | yes | Todo #12 (`assertRootOwnership`) is exactly an ASVS V4-class server-side authorization gate; extraction must preserve the exact same-repository-query semantics (no behavior change) |
| V5 Input Validation | no (unchanged) | No new external input parsing introduced by this phase |
| V6 Cryptography | yes | Todos #1-#4 directly touch key-material handling (ECIES wrap boundary, AES key buffers, IPNS private keys) — CLAUDE.md rules 1-8 apply throughout: never log key material (already correctly absent per every file's own doc comments — T-62-03 references), never persist plaintext keys, always ECIES for wrapping (unchanged, only the byte/hex boundary moves), always AES-256-GCM/CTR for content (unchanged) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Sensitive key material lingering in memory after use (heap-scan / memory-dump exposure) | Information Disclosure | `.fill(0)` zeroization at the terminal-owner boundary (todos #2, #3, #4) — best-effort per `memory.ts`'s own doc comment, not a hard guarantee, but reduces the exposure window |
| Confused-deputy / spoofed share creation for a node the caller doesn't own | Spoofing / Elevation of Privilege | `assertRootOwnership` server-side gate (todo #12) — explicitly documented as "defense-in-depth, non-authoritative" (the TRUE boundary is cryptographic: only the real owner holds the key needed to wrap grants) — extraction must not weaken or bypass this check |
| Hex/bytes boundary confusion causing a malformed key to silently pass validation | Tampering | `hexToBytes` already throws on malformed input (odd-length, non-hex chars) — todo #1's refactor must keep the hex-decode happening BEFORE any crypto operation, not defer it past a point where a bad value could reach `wrapKey` unchecked |

## Sources

### Primary (HIGH confidence — direct `Read`/`grep` of the actual worktree)
- `packages/sdk-core/src/tee/wrap.ts`, `folder/registration.ts`, `vault/index.ts`, `file/index.ts`, `upload/index.ts`, `rotation/engine.ts`, `share/grant.ts`, `share/navigate.ts`, `types.ts` — todo #1, #2, #6, #8 grounding
- `packages/crypto/src/aes/{encrypt,decrypt,encrypt-ctr,decrypt-ctr,seal}.ts`, `utils/{encoding,memory}.ts`, `index.ts` — todo #3, #5 grounding
- `packages/core/src/node/{encode,decode,seal}.ts`, `__tests__/node-codec-vectors.test.ts` — todo #7 grounding
- `packages/sdk-core/scripts/{verify-filepointer,edit-filepointer,rename-folder}.mts` — todo #4 grounding
- `packages/sdk/src/{client,types}.ts`, `share/{context,shared-write,index}.ts`, `bin/index.ts`, and ~15 test files under `packages/sdk/src/__tests__/` — todo #1, #9, #10 grounding
- `apps/api/src/tee/tee.service.ts`, `republish/republish.service.ts`, `shares/{shares.service,share-invite.service,shares.module}.ts`, `ipns/entities/ipns-record.entity.ts`, migrations `1700000000000-FullSchema.ts`/`1743000000000-AddWritableShares.ts`/`1751000000000-ScheduleCollapse.ts` — todo #9, #12 grounding
- `apps/tee-worker/src/{routes/republish.ts,services/key-manager.ts}` — todo #9 grounding
- `apps/web/src/{stores/share.store.ts,services/{device-registry,vault-settings}.service.ts,hooks/{useAuth,useSharedNavigation,useSharedNavigationActions,shared-folder-projection}.ts}` — todo #1, #9, #10 grounding
- `packages/api-client/openapi.json`, `src/models/updatePermissionDto.ts` — todo #9 orphaned-DTO finding
- `.planning/STATE.md` (project decisions/precedents), worktree `CLAUDE.md` (terminology standard + security rules + api:generate workflow) — project-constraint grounding

No `WebSearch`/`Context7`/external documentation lookups were performed — this phase is a pure internal-codebase mechanical refactor with no library-selection or external-API question in scope.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new libraries, all existing patterns confirmed by direct code read
- Architecture: HIGH — dependency ordering (crypto → core → sdk-core → sdk) confirmed via each package's own `package.json` dependency declarations
- Pitfalls: HIGH — every pitfall is grounded in an actual doc comment, test assertion, or migration file already in the codebase, not speculative

**Research date:** 2026-07-11
**Valid until:** 30 days (stable internal refactor scope; re-verify if any of packages/crypto, packages/core, packages/sdk-core, packages/sdk, apps/api, or apps/tee-worker receive further phases before this one executes — re-grep the exact line numbers cited above, as they will drift)

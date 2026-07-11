# Phase 77: Crypto Hygiene and Terminology Canonicalization - Pattern Map

**Mapped:** 2026-07-11
**Files analyzed:** ~40 (across 12 todos)
**Analogs found:** All todos have an in-repo analog — this is a pure "copy the already-correct sibling" refactor, no external patterns needed.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `packages/sdk-core/src/folder/registration.ts` (`createSubfolder`) | service (crypto mint) | request-response | `packages/sdk-core/src/file/index.ts` (`createFileMetadata`) | exact — same mint→seal→publish shape, already has correct zeroization |
| `packages/crypto/src/aes/{encrypt,decrypt,encrypt-ctr,decrypt-ctr}.ts` | utility (crypto primitive) | transform | each other (7 near-identical functions) | exact — extract shared `importAesKey()` internal helper |
| `packages/sdk-core/scripts/verify-filepointer.mts` | utility (CLI script) | file I/O | `packages/sdk-core/scripts/edit-filepointer.mts` / `rename-folder.mts` | exact — same script family, same `clearBytes` pattern |
| `packages/crypto/src/utils/encoding.ts` (new base64 exports) | utility (codec) | transform | same file's existing `hexToBytes`/`bytesToHex` | exact — same file, same export/error convention |
| `packages/sdk-core/src/{rotation/engine,share/grant,share/navigate,file/index}.ts` (base64 dedup) | service | transform | `@cipherbox/crypto` hoisted `base64ToBytes`/`bytesToBase64` (todo #5 output) | exact — direct import, no local re-export |
| `packages/core/src/node/{encode,decode,seal}.ts` (base64 dedup) | utility (codec) | transform | `@cipherbox/crypto` hoisted base64 export; `seal.ts`'s existing `sealAesGcmAad` import line | exact — same file already imports from `@cipherbox/crypto` |
| `packages/sdk-core/src/file/index.ts` + `upload/index.ts` (field rename) | model/service (field naming) | CRUD | `packages/sdk-core/src/folder/registration.ts:50` / `vault/index.ts:125` (already-canonical `encryptedIpnsPrivateKey`) | exact — literal naming template |
| `apps/api/src/tee/tee.service.ts`, `apps/api/src/republish/republish.service.ts`, `apps/tee-worker/src/routes/republish.ts`, `apps/tee-worker/src/services/key-manager.ts` (wire field rename) | model/service (DTO field) | request-response | `apps/api/src/ipns/entities/ipns-record.entity.ts:64-65` (`encryptedIpnsPrivateKey` entity column, already canonical) | exact |
| `apps/api/src/shares/root-ownership.util.ts` (new) | utility (auth guard) | request-response | inline block duplicated in `shares.service.ts:40-45` / `share-invite.service.ts:43-48` (the two call sites become the extraction source, not a distinct analog) | exact — pure extraction, no new DI |
| `packages/sdk/src/types.ts`, `share/context.ts`, `share/shared-write.ts`, `client.ts`, `index.ts` + ~13 test files (dead-code removal) | type/service (removal) | event-driven (dead callback) | n/a — deletion task; template is the existing no-op call sites (`client.ts:5579`, `useSharedNavigation.ts:234`) that prove the field is already inert | role-match |

## Pattern Assignments

### `packages/sdk-core/src/folder/registration.ts` (`createSubfolder`) — service, request-response

**Analog:** `packages/sdk-core/src/file/index.ts` (`createFileMetadata`, lines 253-360)

**Core pattern to copy** — mint keys outside try, wrap seal→upload→publish in try/catch, zero-on-error only, never zero on the success path (D-09: caller is terminal owner):

```typescript
// Source: packages/sdk-core/src/file/index.ts:253-260 (mint, pre-try)
const fileReadKey = generateRandomBytes(32);
const fileWriteKey = generateRandomBytes(32);
const fileKeypair = generateEd25519Keypair();
let fileIpnsPrivateKey: Uint8Array | null = fileKeypair.privateKey;

try {
  // ... seal, addToIpfs, createAndPublishIpnsRecord ...
  return { /* success — do NOT zero, caller is terminal owner */ };
} catch (err) {
  // Keys never reached the caller on this path — zero them.
  fileReadKey.fill(0);
  fileWriteKey.fill(0);
  fileIpnsPrivateKey?.fill(0);
  throw err;
}
```

Apply directly to `createSubfolder` (`registration.ts:40-127`): wrap steps 4-8 (node build through publish) in try/catch; in catch, `.fill(0)` the minted `ipnsPrivateKey`, `readKey`, `writeKey`; success-path return (lines 118-126) stays untouched. Add the matching negative test to `packages/sdk-core/src/__tests__/folder.test.ts` (currently only tests the success "does NOT zero" path at line 366).

---

### `packages/crypto/src/aes/{encrypt,decrypt,encrypt-ctr,decrypt-ctr}.ts` — utility, transform

**Analog:** the 7 sibling functions themselves (identical leak pattern); no external analog needed, this is a same-package internal-helper extraction.

**Current leak pattern** (all 7 call sites, e.g. `encrypt.ts:40`):
```typescript
const keyBuffer = new Uint8Array(key).buffer as ArrayBuffer;
// ... crypto.subtle.importKey(keyBuffer, ...) — copy never zeroed
```

**Target pattern** — extract one internal `importAesKey()` helper, zero the local copy in `finally` (function IS the terminal owner of this specific copy; caller's own `key` param is untouched):
```typescript
async function importAesKey(
  key: Uint8Array,
  algorithm: AesKeyAlgorithm,
  usages: KeyUsage[]
): Promise<CryptoKey> {
  const keyView = new Uint8Array(key);
  try {
    return await crypto.subtle.importKey('raw', keyView.buffer as ArrayBuffer, algorithm, false, usages);
  } finally {
    keyView.fill(0);
  }
}
```
Unit-test `importAesKey` directly (it's otherwise unobservable) in a new/extended `packages/crypto/src/__tests__/aes.test.ts` case. Do NOT touch `seal.ts`'s wrappers (`sealAesGcm` etc.) — they have no independent `keyBuffer` copy.

---

### `packages/sdk-core/scripts/verify-filepointer.mts` — utility, file I/O

**Analog:** `packages/sdk-core/scripts/edit-filepointer.mts:236-240` and `rename-folder.mts:151-153`

**Pattern to copy:**
```typescript
import { clearBytes } from '@cipherbox/crypto';
// ... after vaultKeyBlob load, wrap main() body in try/finally ...
} finally {
  clearBytes(userPrivateKey);
  clearBytes(vaultKeyBlob.rootReadKey);
  clearBytes(vaultKeyBlob.rootWriteKey);
  // clearBytes(fileReadKey / subReadKey) if the --folder-name branch was taken
}
```
No automated test exists for this script family (matches sibling precedent) — manual/smoke verification only.

---

### `packages/crypto/src/utils/encoding.ts` — utility, transform (todo #5)

**Analog:** same file's existing `hexToBytes`/`bytesToHex` (lines 7-30) for export/error-handling convention; verbatim body source is `packages/core/src/node/encode.ts:20-33`.

**Imports pattern** (existing file header, line 7):
```typescript
import { CryptoError } from '../types';
```

**New exports to add** (copy VERBATIM from `packages/core/src/node/encode.ts` per Pitfall 2 — do not rewrite the chunking loop):
```typescript
export function bytesToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 32768;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
```
Export from `packages/crypto/src/utils/index.ts` and top-level `packages/crypto/src/index.ts` alongside `hexToBytes, bytesToHex` (~line 86-87). New golden-vector test file: `packages/crypto/src/__tests__/encoding.test.ts`.

---

### sdk-core / packages/core base64 dedup (todos #6, #7) — service/utility, transform

**Analog:** the just-hoisted `@cipherbox/crypto` export (above), imported directly — no intermediate `share/codec.ts` re-export layer (matches how `hexToBytes`/`bytesToHex` are already imported directly from `@cipherbox/crypto` throughout `sdk-core`, and how `packages/core/src/node/seal.ts` already imports `sealAesGcmAad` etc. from `@cipherbox/crypto`).

**Delete these 7 duplicate definitions, replace with import:**
- `packages/sdk-core/src/rotation/engine.ts:462-483`
- `packages/sdk-core/src/share/grant.ts:58-75`
- `packages/sdk-core/src/share/navigate.ts:59-66`
- `packages/sdk-core/src/file/index.ts:62-79`
- `packages/core/src/node/encode.ts:25-33`
- `packages/core/src/node/seal.ts:41-59`
- `packages/core/src/node/decode.ts:29-42` — **keep the `expectedLength?` param as a thin local wrapper** around the shared bytes-only helper (superset signature, decode-specific validation, not a codec duplicate)

**Parity gate:** re-run `packages/core/src/__tests__/node-codec-vectors.test.ts` + `node-codec.test.ts` (already exist, already exercise these functions via `sealNode`/`unsealNode`) — sufficient proof, no new golden vectors needed for todo #7.

---

### Field rename `ipnsPrivateKeyEncrypted` → `encryptedIpnsPrivateKey` (todo #8) — model, CRUD

**Analog (the canonical naming template, already correct):**
```typescript
// packages/sdk-core/src/folder/registration.ts:50 (return field)
// packages/sdk-core/src/vault/index.ts:125 (local var)
encryptedIpnsPrivateKey
```

**Holdout sites to rename:** `packages/sdk-core/src/file/index.ts:230,351` (return-type field; note line 335 in the SAME function already builds `ipnsRecord.encryptedIpnsPrivateKey` correctly — this double-naming within one function is the bug), `packages/sdk-core/src/upload/index.ts:60,199`. Test blast radius: `packages/sdk/src/__tests__/{helpers.ts:43, client-pinning.test.ts:38,47, client-extended.test.ts:224,291, upload-batch.test.ts:77, client-upload-concurrency.test.ts:67}`, `packages/sdk-core/src/__tests__/{upload.test.ts:26,68, file/file-node.test.ts:145,157,176-177}`.

`file-node.test.ts:177` assertion changes shape:
```typescript
// before: expect(result.ipnsRecord.encryptedIpnsPrivateKey).toBe(result.ipnsPrivateKeyEncrypted);
// after:  expect(result.ipnsRecord.encryptedIpnsPrivateKey).toBe(result.encryptedIpnsPrivateKey);
```
**Leave untouched:** `packages/sdk/src/client.ts:1632,3779,3905` (historical doc comments describing removed legacy fields) and `landing/src/scripts/demo-data.ts:101,111` (untyped legacy v2 marketing JSON, no type import from `@cipherbox/sdk`).

---

### TEE wire-contract field rename `encryptedIpnsKey` → `encryptedIpnsPrivateKey` (todo #9) — model/service, request-response

**Analog:** `apps/api/src/ipns/entities/ipns-record.entity.ts:64-65` — the entity column is already named `encryptedIpnsPrivateKey`; the DTO should match it exactly.

**Rename in lockstep across:**
```typescript
// apps/api/src/tee/tee.service.ts:13-15
interface RepublishEntry {
  encryptedIpnsKey: string;   // → encryptedIpnsPrivateKey
}
// apps/api/src/republish/republish.service.ts:141-146
encryptedIpnsKey: record.encryptedIpnsPrivateKey!.toString('base64'),  // → key renamed, value unchanged
// apps/tee-worker/src/routes/republish.ts:58,121-123
// apps/tee-worker/src/services/key-manager.ts:43,49,54,71,78,92,102 — decryptIpnsKey(encryptedIpnsKey: Uint8Array, ...) param
```
Test blast radius: `apps/tee-worker/src/__tests__/republish.test.ts` (~18 occurrences incl. `makeEntry()` helper), `apps/api/src/tee/tee.service.spec.ts` (2), `apps/api/src/republish/republish.service.spec.ts` (7, including **negative** `.not.toHaveProperty('encryptedIpnsKey')` assertions at lines 364,513,789,807 → must become `.not.toHaveProperty('encryptedIpnsPrivateKey')`).

**`pnpm api:generate` is NOT required** — `RepublishEntry`/`RepublishResult` are plain internal interfaces, no Nest controller/DTO decorator, absent from `openapi.json` (precedent: STATE.md "[Phase 60-05]").

**Do NOT touch** (different subsystem, `@deprecated` legacy path — candidate for todo #10 instead): `apps/web/src/stores/share.store.ts:31`, `packages/sdk/src/share/shared-write.ts:915-928` (`updateSharePermission`).

---

### `apps/api/src/shares/root-ownership.util.ts` (new) — utility (auth guard), request-response

**Analog:** the two byte-identical inline blocks being replaced (not an external analog — this IS the extraction):
```typescript
// apps/api/src/shares/shares.service.ts:40-45 and share-invite.service.ts:43-48 (identical)
const owned = await this.ipnsRecordRepo.findOne({
  where: { ipnsName: dto.shareRootIpnsName, userId: sharerId },
});
if (!owned) {
  throw new ForbiddenException('You are not the registered owner of this node');
}
```

**Target extraction** (plain exported function, no new `@Injectable()` — both callers already inject `ipnsRecordRepo` directly):
```typescript
// apps/api/src/shares/root-ownership.util.ts
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
Callers become: `await assertRootOwnership(this.ipnsRecordRepo, dto.shareRootIpnsName, sharerId);`. `pnpm api:generate` NOT required (no DTO/controller change). Existing spec files (`shares.service.spec.ts`, `share-invite.service.spec.ts`) should pass unmodified.

---

### Dead-code retirement `ShareCallbacks`/`addShareKeysFn`/`updateSharePermission` (todo #10) — type/service, deletion

**Analog/proof-of-deadness:** the existing no-op construction sites already prove the field is inert — use these as confirmation the removal is safe, not as a pattern to copy:
```typescript
// packages/sdk/src/client.ts:5579 and useSharedNavigation.ts:234
async () => {}   // addShareKeysFn is NEVER called (D-02) — passed only to satisfy the (soon-removed) required field
```
Remove: `ShareCallbacks` type + `shareCallbacks` config field + public re-export (`packages/sdk/src/types.ts:35-43,139`, `index.ts:44`); `addShareKeysFn` from `SharedWriteContextParams`/`SharedWriteContext` (`share/context.ts:36-39,65`, `share/shared-write.ts`) and all 6 construction sites (`client.ts:5135,5333,5579`; `apps/web/src/hooks/{shared-folder-projection.ts:68,108, useSharedNavigationActions.ts:119, useSharedNavigation.ts:226,234}`); delete (not rename) the ~13 test files' `expect(...addShareKeysFn).not.toHaveBeenCalled()` assertions since the field won't exist. Fold in (flag to user first — Assumption A2) `updateSharePermission`/`updatePermissionFn` (`shared-write.ts:907-928`) + orphaned `packages/api-client/src/models/updatePermissionDto.ts`/`updatePermissionDtoPermission.ts` (no matching route in current `openapi.json`).

**Per Pitfall 5:** rebuild `packages/sdk` dist before running `apps/web`'s typecheck — a partial removal won't surface as a build error in web until sdk's dist is rebuilt.

---

## Shared Patterns

### D-09 zeroization discipline (todos #1-#4)
**Source:** `packages/sdk-core/src/file/index.ts:253-360` (mint outside try, zero-on-error only inside catch, never zero the success-path return)
**Apply to:** `createSubfolder` (todo #2), the 7 AES helpers via `importAesKey()` (todo #3), `verify-filepointer.mts` (todo #4)
**Constraint (project memory, confirmed by RESEARCH Pitfall 1):** only `.fill(0)` a buffer this function itself minted/copied and that has NOT yet reached the caller. Never zero a caller-owned/borrowed buffer (e.g. `wrapIpnsKeyForTee`'s `ipnsPrivateKey` param must NOT be zeroed inside that function — todo #1 is a pure signature change, zero zeroization added there).

### Base64 codec consolidation (todos #5-#7)
**Source:** `packages/crypto/src/utils/encoding.ts` (new `base64ToBytes`/`bytesToBase64`, hoisted from `packages/core/src/node/encode.ts:20-33` verbatim)
**Apply to:** all 7 downstream duplicate sites (4 in sdk-core, 3 in packages/core) — direct import from `@cipherbox/crypto`, no intermediate re-export file.
**Parity gate:** `packages/core/src/__tests__/node-codec-vectors.test.ts` (existing golden vectors) must still pass byte-for-byte after every consolidation step.

### `encryptedIpnsPrivateKey` canonical naming (todos #8, #9)
**Source:** `apps/api/src/ipns/entities/ipns-record.entity.ts:64-65` (DB entity, already canonical) and `packages/sdk-core/src/folder/registration.ts:50` (SDK-core return field, already canonical)
**Apply to:** `file/index.ts` + `upload/index.ts` (SDK-side rename), TEE wire DTO (API/tee-worker rename) — same target name, two independent call-site sweeps, no shared code path.

### `pnpm api:generate` skip precedent (todos #9, #12)
**Source:** STATE.md "[Phase 60-05]: api:generate NOT required; changes are internal service/codec logic with no OpenAPI surface change."
**Apply to:** both `apps/api` todos in this phase — neither changes a `@Controller`/DTO with Swagger decorators.

## No Analog Found

None — every todo in this phase has a concrete in-repo analog (this is a "make the codebase consistent with its own best sibling" phase, not a greenfield-pattern phase). Todo #11 (`drop-discarded-per-upload-ecies-wrapkey`) has no live target at all per RESEARCH — recommend the planner treat it as verification-only (re-grep, confirm already-clean, no code change) rather than search for a pattern to copy.

## Metadata

**Analog search scope:** `packages/crypto`, `packages/core`, `packages/sdk-core`, `packages/sdk`, `apps/api`, `apps/tee-worker` (scope fully bounded by 77-RESEARCH.md's exhaustive grep/read sweep — no additional codebase search was needed beyond confirming 2 excerpts directly)
**Files scanned:** confirmed directly: `packages/crypto/src/utils/encoding.ts`, `packages/sdk-core/src/file/index.ts:250-270`; remainder sourced from 77-RESEARCH.md's already-grounded `Read`/`grep` citations
**Pattern extraction date:** 2026-07-11

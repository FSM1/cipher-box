---
phase: 38-retire-deprecated-web-services
verified: 2026-06-27T00:00:00Z
status: passed
score: 6/6 must-haves verified
---

# Phase 38: Retire deprecated web services Verification Report

**Phase Goal:** Remove `folder.service.ts` (1,059 LOC) and `bin.service.ts` (971 LOC) by migrating all callers to `@cipherbox/sdk` / `@cipherbox/sdk-core`, and break the `@cipherbox/crypto` -> `@cipherbox/core` circular devDependency via hardcoded vault-ipns test vectors.
**Verified:** 2026-06-27
**Status:** PASSED
**Re-verification:** Retroactive milestone-audit closure (phase shipped 2026-03-31, PR #422 — commit `96455b3be`; VERIFICATION.md was never authored)

## Goal Achievement

This phase maps to **NO formal REQ-ID** — it is internal tech-debt cleanup (ROADMAP: "Requirements: None (tech debt cleanup, deferred from Phase 31)"). The ROADMAP section (line 517) does not enumerate "Observable Truths" bullets; the plan must-haves (D-01..D-04, expressed across the four plans' `<must_haves>`) are the observable success criteria and are used as the truth table below.

### Observable Truths (from plan must-haves / ROADMAP goal)

| #   | Truth                                                                                                  | Status   | Evidence (file:line)                                                                                                                                                              |
| --- | ----------------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `folder.service.ts` and `bin.service.ts` no longer exist anywhere under `apps/web`                     | VERIFIED | `find apps/web -name "folder.service.ts"` / `"bin.service.ts"` -> 0 results; git deletion commit `96455b3be` ("retire deprecated folder.service and bin.service (#422)")          |
| 2   | Re-exports of folder.service/bin.service removed from `apps/web/src/services/index.ts`                 | VERIFIED | `apps/web/src/services/index.ts:7-15` — exports only delete/download/file-crypto/file-metadata/streaming-crypto/ipns/upload/search-index; `grep folder.service\|bin.service` -> 0 |
| 3   | No remaining imports of folder.service/bin.service in `apps/web` (only stale comments)                 | VERIFIED | `grep -rn "folder\.service\|bin\.service" apps/web/src --include=*.ts(x)` -> only 2 doc comments (`device-registry.service.ts:8`, `share.service.ts:597`), zero imports          |
| 4   | Folder ops migrated to SDK: file-reg fns + path utils + fetchAndDecryptMetadata live in sdk-core       | VERIFIED | `packages/sdk-core/src/folder/registration.ts:281,348,422` (addFileToFolder/addFilesToFolder/replaceFileInFolder); `tree.ts:24,44,73`; `load.ts:20` (fetchAndDecryptMetadata)    |
| 5   | Bin ops migrated to SDK: `purgeExpiredEntries` + `CipherBoxClient.purgeExpired` in `@cipherbox/sdk`    | VERIFIED | `packages/sdk/src/bin/index.ts:822` (`export async function purgeExpiredEntries`); `packages/sdk/src/client.ts:2049` (`async purgeExpired`) calling `binOps.purgeExpiredEntries` |
| 6   | `@cipherbox/crypto` has no `@cipherbox/core` devDep; vault-ipns test uses embedded vectors             | VERIFIED | `packages/crypto/package.json` devDeps has no `@cipherbox/core`; `vault-ipns.test.ts` zero `@cipherbox/core` imports; embedded vectors at L28/L31 + "domain separation" test L68  |

**Score: 6/6 truths verified**

---

### Required Artifacts (per plan)

Plan 38-01 — Migrate folder.service callers to SDK imports (D-01, D-03)

| Artifact                                              | Expected                                                    | Status   | Details (file:line)                                                                                                          |
| ---------------------------------------------------- | ----------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------- |
| `packages/sdk-core/src/folder/registration.ts`       | `addFileToFolder` / `addFilesToFolder` / `replaceFileInFolder` exported | VERIFIED | Lines 281, 348, 422 — all three `export async function` (post-phase the fat `folder/index.ts` was split into named files; deliverable holds) |
| `packages/sdk-core/src/folder/tree.ts`               | `getDepth` / `isDescendantOf` / `calculateSubtreeDepth`     | VERIFIED | Lines 24, 73, 44                                                                                                            |
| `packages/sdk-core/src/folder/load.ts`               | `fetchAndDecryptMetadata`                                   | VERIFIED | Line 20 `export async function fetchAndDecryptMetadata`                                                                      |
| `packages/sdk-core/src/index.ts`                     | Public barrel re-exports the migrated functions             | VERIFIED | Lines 29 (fetchAndDecryptMetadata), 37-39 (add/replace), 44 (getDepth/calculateSubtreeDepth/isDescendantOf)                 |
| `apps/web/src/hooks/folder-helpers.ts`               | imports from `@cipherbox/sdk-core` not folder.service       | VERIFIED | Line 6 `import { fetchAndDecryptMetadata, getDepth } from '@cipherbox/sdk-core'`; line 5 withConflictRetry from `@cipherbox/sdk` |
| `apps/web/src/hooks/useFolderMutations.ts`           | path utils from sdk-core                                    | VERIFIED | Line 4 `import { getDepth, isDescendantOf, calculateSubtreeDepth } from '@cipherbox/sdk-core'`                              |
| `apps/web/src/components/file-browser/MoveDialog.tsx`| getDepth/isDescendantOf from sdk-core                       | VERIFIED | Line 5 `import { getDepth, isDescendantOf } from '@cipherbox/sdk-core'`                                                     |
| `apps/web/src/components/file-browser/useFileBrowserActions.ts` | fetchAndDecryptMetadata from sdk-core             | VERIFIED | Line 30 `import { fetchAndDecryptMetadata } from '@cipherbox/sdk-core'`                                                     |

Plan 38-02 — Migrate bin.service callers to SDK client (D-02)

| Artifact                              | Expected                                          | Status   | Details (file:line)                                                                                            |
| ------------------------------------- | ------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| `packages/sdk/src/bin/index.ts`       | `purgeExpiredEntries` exported                    | VERIFIED | Line 822 `export async function purgeExpiredEntries(`                                                          |
| `packages/sdk/src/client.ts`          | `CipherBoxClient.purgeExpired(retentionDays)`     | VERIFIED | Line 2049 `async purgeExpired(...)`; line 2058 delegates to `binOps.purgeExpiredEntries`                       |
| `apps/web/src/hooks/useBin.ts`        | uses `getSdkClient().loadBin()` / `.purgeExpired()`| VERIFIED | Line 4 imports `getSdkClient`; line 38 `getSdkClient().loadBin()`; lines 48-49 `getSdkClient().purgeExpired(...)` |
| `apps/web/src/hooks/useAuth.ts`       | bin init via SDK `loadBin`, no `initializeBin`     | VERIFIED | Line 378 `getSdkClient().loadBin()`; `grep initializeBin` -> 0 matches                                         |

Plan 38-03 — Fix @cipherbox/crypto circular devDependency (D-04)

| Artifact                                            | Expected                                                | Status   | Details (file:line)                                                                                            |
| --------------------------------------------------- | ------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| `packages/crypto/package.json`                      | no `@cipherbox/core` in deps or devDeps                 | VERIFIED | devDeps: `@noble/secp256k1`, `@vitest/coverage-v8`, `tsup`, `typescript`, `vitest` — no `@cipherbox/core`      |
| `packages/crypto/src/__tests__/vault-ipns.test.ts`  | embedded vectors; no `@cipherbox/core` import           | VERIFIED | Imports only `../vault/derive-ipns` + `../types`; `EXPECTED_VAULT_IPNS_NAME` L28, `EXPECTED_REGISTRY_IPNS_NAME` L31 |
| vault-ipns test — domain separation + determinism   | preserved with static vectors                           | VERIFIED | L68 "produces a different IPNS name than registry derivation (domain separation)"; L97 determinism test         |

Plan 38-04 — Delete deprecated services and clean barrel (final cleanup)

| Artifact                              | Expected                          | Status   | Details                                                                          |
| ------------------------------------- | --------------------------------- | -------- | ------------------------------------------------------------------------------- |
| `apps/web/src/services/folder.service.ts` | deleted (file absent)         | VERIFIED | `test ! -f` -> DELETED; absent in `find apps/web`; git diff-filter=D at `96455b3be` |
| `apps/web/src/services/bin.service.ts`    | deleted (file absent)         | VERIFIED | `test ! -f` -> DELETED; absent in `find apps/web`                                |
| `apps/web/src/services/index.ts`          | barrel cleaned                | VERIFIED | No `folder.service`/`bin.service` exports (lines 7-15)                           |

---

### Key Link Verification

| From                                          | To                       | Via                                  | Status | Details                                                                 |
| --------------------------------------------- | ------------------------ | ------------------------------------ | ------ | ---------------------------------------------------------------------- |
| `apps/web/src/hooks/folder-helpers.ts`        | `@cipherbox/sdk-core`    | `fetchAndDecryptMetadata`, `getDepth`| WIRED  | Line 6 import; used L24, L108                                          |
| `apps/web/src/hooks/useFolderMutations.ts`    | `@cipherbox/sdk-core`    | path utils                           | WIRED  | Line 4 import; used L101, L266, L271-272                               |
| `apps/web/src/components/file-browser/MoveDialog.tsx` | `@cipherbox/sdk-core` | `getDepth`, `isDescendantOf`      | WIRED  | Line 5 import; used L69-70, L76, L93                                   |
| `apps/web/src/hooks/useBin.ts`                | `@cipherbox/sdk` client  | `getSdkClient().loadBin/purgeExpired`| WIRED  | L38 loadBin, L48-49 purgeExpired                                       |
| `apps/web/src/hooks/useAuth.ts`               | `@cipherbox/sdk` client  | `getSdkClient().loadBin()`           | WIRED  | L378; replaced removed `initializeBin`                                 |
| `packages/sdk/src/client.ts:2049`             | `packages/sdk/src/bin/index.ts:822` | `binOps.purgeExpiredEntries`| WIRED  | client.ts:2058 calls into bin module                                   |
| `packages/sdk-core/src/index.ts`              | `./folder` (registration/tree/load) | barrel re-export          | WIRED  | L29, L37-39, L44                                                       |

---

### Requirements Coverage

This phase maps to **no formal REQ-ID** (internal tech-debt cleanup, deferred from Phase 31). Verification tracks the four internal plan deliverables instead:

| Deliverable | Source Plan | Description                                                                  | Status    | Evidence                                                                                          |
| ----------- | ----------- | --------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------------------------- |
| D-01        | 38-01       | Migrate all folder.service callers to SDK; extract add/replace file fns      | SATISFIED | Hooks import from `@cipherbox/sdk-core`; fns in `registration.ts:281/348/422`; 0 folder.service imports |
| D-02        | 38-02       | Migrate bin.service callers to SDK client; add purgeExpired                  | SATISFIED | `client.ts:2049` purgeExpired; `bin/index.ts:822` purgeExpiredEntries; useBin/useAuth migrated   |
| D-03        | 38-01       | Path utils -> sdk-core, fetchAndDecryptMetadata -> SDK package               | SATISFIED | `tree.ts:24/44/73`, `load.ts:20`; web callers import them from `@cipherbox/sdk-core`             |
| D-04        | 38-03       | Remove `@cipherbox/crypto` -> `@cipherbox/core` circular devDep; embed vectors| SATISFIED | package.json devDeps clean; test embeds `EXPECTED_*` vectors + domain-separation assertion       |

All four plan deliverables are accounted for and satisfied.

---

### Anti-Patterns Found

No anti-patterns detected:

- No `<FILL_FROM_SCRIPT_OUTPUT>` placeholders left in `vault-ipns.test.ts` — real `k51...` vectors embedded (L28, L31).
- The two residual `folder.service` / `bin.service` string matches in `apps/web/src` are stale documentation comments (`device-registry.service.ts:8`, `share.service.ts:597`), not imports — harmless but could be tidied.
- No stubbed/empty implementations: `addFileToFolder`/`purgeExpiredEntries` have full bodies; the deleted files are genuinely gone (git diff-filter=D).

---

### Human Verification Required

None — fully verifiable statically. The phase is a pure refactor/cleanup; the runtime behavior it preserves (file upload, bin load/purge) is exercised by existing SDK/web test suites and unchanged at the API boundary. Static analysis confirms file deletion, import migration, and dependency-graph cleanup.

---

### Gaps Summary

No gaps found against the phase's deliverables. All six observable truths verify and all four plan deliverables (D-01..D-04) are satisfied.

Notable post-phase supersessions (deliverable still holds, noted for audit trail):

1. **`folder/index.ts` was later split into named files.** Phase 38 added the three file-registration functions to a single fat `folder/index.ts`; a subsequent refactor split them into `registration.ts` / `tree.ts` / `load.ts` / `merge.ts` / `metadata-ops.ts`. All remain exported via the `folder/index.ts` barrel and `sdk-core/src/index.ts`. (See MEMORY: sdk-core coverage/barrel-split pattern.)

2. **`useFileOperations.ts` / `useFileVersions.ts` no longer call the extracted sdk-core fns directly.** A later phase migrated these hooks to higher-level `CipherBoxClient` methods (`getSdkClient().replaceFile()` at `useFileOperations.ts:112`; `.restoreFileVersion()`/`.deleteFileVersion()` at `useFileVersions.ts:103/211`). The Phase 38 invariant — no `folder.service` import, ops routed through the SDK — still holds; the extracted `addFileToFolder`/`addFilesToFolder`/`replaceFileInFolder` now have no live web consumers but remain exported in sdk-core.

3. **`fetchAndDecryptMetadata` lives in `@cipherbox/sdk-core`, not `@cipherbox/sdk`.** The audit prompt listed it under `@cipherbox/sdk`; per plan 38-01 (D-03) and the live tree it is in `@cipherbox/sdk-core/folder/load.ts:20`, which is the correct domain placement. Not a gap — prompt imprecision.

---

_Verified: 2026-06-27_
_Verifier: Claude (retroactive milestone-audit closure)_

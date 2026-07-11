---
phase: 77-crypto-hygiene-and-terminology-canonicalization
verified: 2026-07-11T09:59:50Z
status: passed
score: 3/3 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 77: Crypto Hygiene and Terminology Canonicalization Verification Report

**Phase Goal:** Low-risk, mechanical cleanup that removes latent key-leak surface, deduplicates copy-pasted crypto helpers, and canonicalizes field names to the CLAUDE.md terminology standard — no behavior change. Error-path zeroization is added where owned key buffers can leak on throw, `base64` helpers are consolidated, the misnamed `ipnsPrivateKeyEncrypted`/`encryptedIpnsKey` fields are renamed to `encryptedIpnsPrivateKey`, dead share scaffolding is retired, and the duplicated Phase 71 root-ownership gate is extracted.

**Verified:** 2026-07-11
**Status:** passed
**Re-verification:** No — initial verification

Requirement mapping: this phase maps to no `REQ-*` IDs (`phase_req_ids` is null). Verification is against the 3 ROADMAP Success Criteria and the `must_haves` blocks of all 10 phase plans, checked directly against source.

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth (Success Criterion) | Status | Evidence |
|---|------|--------|----------|
| 1 | No owned key/plaintext buffer copy survives a throw on the audited crypto/upload paths (error-path zeroization present + tested) | VERIFIED | `packages/crypto/src/aes/import-key.ts` — `importAesKey` allocates `keyView`, `finally { keyView.fill(0) }`; all 7 AES functions route through it (`grep -rc "importAesKey" encrypt.ts decrypt.ts encrypt-ctr.ts decrypt-ctr.ts` → 3/3/2/3, all ≥1); zero leftover inline `new Uint8Array(key).buffer` copies. `packages/sdk-core/src/folder/registration.ts` `createSubfolder` wraps `sealNode→addToIpfs→createAndPublishIpnsRecord` in try/catch, zeroing `ipnsPrivateKey`/`readKey`/`writeKey` in the catch, success-path D-09 comment retained unchanged. `packages/sdk-core/src/__tests__/folder.test.ts` has a passing forced-throw test (`zeroes the minted ipnsPrivateKey/readKey/writeKey when createAndPublishIpnsRecord throws`) AND the pre-existing success-path "does NOT zero" test — both ran green (`folder.test.ts`: 15/15 pass, part of full 371-pass sdk-core run). `packages/sdk-core/scripts/verify-filepointer.mts` imports `clearBytes`, `finally` block clears `userPrivateKey`/`rootReadKey`/`rootWriteKey`/`fileReadKey`/`subReadKey`. `pnpm --filter @cipherbox/crypto test -- aes.test.ts` → 207/207 pass (ran directly). |
| 2 | `base64` encode/decode helpers exist once per package boundary; the ~10 copy-pasted copies are removed with golden-vector parity preserved | VERIFIED | `packages/crypto/src/index.ts` exports canonical `bytesToBase64`/`base64ToBytes`; `packages/crypto/src/__tests__/encoding.test.ts` golden-vector suite (8 tests) ran green. All 7 known duplicate sites now import from `@cipherbox/crypto` instead of defining local codecs, confirmed by direct read/grep: `packages/core/src/node/{encode,decode,seal}.ts` (decode.ts keeps a thin `expectedLength` wrapper delegating to `base64ToBytes`), `packages/sdk-core/src/rotation/engine.ts`, `packages/sdk-core/src/share/{grant,navigate}.ts`, `packages/sdk-core/src/file/index.ts`. Repo-wide grep for `CHUNK_SIZE`/local codec function definitions in `packages/core/src`, `packages/sdk-core/src`, `packages/sdk/src`, `apps/` found only test-local helper functions (not production duplicates) and one unrelated `CHUNK_SIZE` in `apps/web/src/services/streaming-crypto.service.ts` (1MB file-streaming chunk size — a different concept, not a base64 codec). `pnpm --filter @cipherbox/core test -- node-codec-vectors.test.ts node-codec.test.ts` → 20+15 = 35/35 pass (golden-vector parity, ran directly). |
| 3 | All IPNS-key fields use the canonical `encryptedIpnsPrivateKey` name across in-memory, wire, and tests; dead share scaffolding and the discarded wrapKey are gone; full typecheck + unit suites green | VERIFIED | TEE wire contract: `grep -rn "encryptedIpnsKey\b" apps/api/src apps/tee-worker/src` → 0 matches; canonical name present in `tee.service.ts` and `key-manager.ts`. In-memory field: `grep -rn "ipnsPrivateKeyEncrypted" packages/sdk-core/src packages/sdk/src/__tests__` → 0 matches; `packages/sdk-core/src/upload/index.ts` exposes `encryptedIpnsPrivateKey`. `wrapIpnsKeyForTee` is bytes-in/bytes-out with canonical `teePublicKey` param (`packages/sdk-core/src/tee/wrap.ts`), all 3 callers (`registration.ts`, `vault/index.ts`, `file/index.ts`) confirmed calling it. Dead share scaffolding: `grep -rn "ShareCallbacks\|addShareKeysFn\|shareCallbacks\b" packages/sdk/src apps/web/src` (excluding tests) → 0 matches; `updateSharePermission`/`UpdatePermissionDto` fully removed (`test ! -f packages/api-client/src/models/updatePermissionDto.ts` confirmed gone). Discarded wrapKey: `upload/index.ts` retirement comment present and confirmed by direct read. Duplicated root-ownership gate: `apps/api/src/shares/root-ownership.util.ts` exports `assertRootOwnership`; both `shares.service.ts` and `share-invite.service.ts` call it; `apps/api` `shares.service.spec.ts` + `share-invite.service.spec.ts` → 57/57 pass (ran directly). Full-suite spot checks ran directly by this verifier (not just SUMMARY claims): `@cipherbox/crypto` build+test (207 pass), `@cipherbox/core` node-codec suites (35 pass), `@cipherbox/sdk-core` full suite (371 pass, 12 skipped, includes `folder.test.ts`), `@cipherbox/sdk` full suite (411 pass, 3 skipped), `cipherbox-tee-worker` full suite (76 pass, 8 todo), `@cipherbox/api` shares specs (57 pass), `@cipherbox/sdk-core` typecheck (exit 0), `@cipherbox/crypto` build (exit 0) — all green, matching the orchestrator's reported gate results. |

**Score:** 3/3 truths verified (0 present-but-behavior-unverified)

### Residual Terminology Occurrences (assessed, not gaps)

The orchestrator flagged 11 source occurrences of the old field names for honest assessment. Independently re-verified by reading each site directly:

| Site | Occurrence | Assessment |
|------|-----------|------------|
| `packages/sdk/src/client.ts` (~1632, 3779, 3905) | `ipnsPrivateKeyEncrypted` in doc comments | Intentional — explains a removed legacy field no longer exists on `SealedChildRef`. Explicitly out-of-scope in Plan 77-09's `<artifacts_this_phase_produces>` ("OUT OF SCOPE: client.ts doc comments"). Not a functional gap. |
| `apps/web/src/stores/share.store.ts` (~9, 12) | `encryptedIpnsKey` in doc comments | Same — documents a removed legacy field (Plan 77-06 removed the actual `encryptedIpnsKey` field from `ReceivedShare`; comment explains the removal). Not a functional gap. |
| `packages/sdk/src/bin/index.ts` (~105-125) | `let encryptedIpnsKey` local variable | Confirmed by direct read: the local variable is assigned into the wire-canonical `encryptedIpnsPrivateKey: encryptedIpnsKey` field at the `publishWithVerify` call site (line ~125). Functional wire contract is canonical; only the local identifier is legacy-named. This file is explicitly excluded in Plan 77-05's `SCOPE DECISION` ("does NOT consolidate... `packages/sdk/src/bin/index.ts` (which has different best-effort fail-closed semantics)"). No plan in this phase lists this file in `files_modified`. Cosmetic residue, not a phase-goal gap. |
| `apps/web/src/services/device-registry.service.ts` (~151-169) | `let encryptedIpnsKey` local variable | Same pattern, confirmed by direct read: assigned into `encryptedIpnsPrivateKey: encryptedIpnsKey` at the `publishConfigBlob` call site. Not in any plan's `files_modified`. Cosmetic residue, not a phase-goal gap. |
| `landing/src/scripts/demo-data.ts` (~101, 111) | `ipnsPrivateKeyEncrypted` in marketing demo data | Untyped legacy v2 marketing JSON, explicitly out-of-scope per Plan 77-09. No SDK type import — cannot silently drift the real contract. |

None of these residuals affect SC3 (the wire contract and in-memory field are canonical everywhere it matters); they are cosmetic local-identifier or documentation residue in files deliberately out of scope for this phase, as documented in the plans themselves. Judged as acceptable — not gaps.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/crypto/src/utils/encoding.ts` | `bytesToBase64`/`base64ToBytes` canonical codec | VERIFIED | Exported from `packages/crypto/src/index.ts`; golden-vector test green |
| `packages/crypto/src/aes/import-key.ts` | Shared `importAesKey` helper with finally-zeroization | VERIFIED | `finally { keyView.fill(0) }`; caller key never touched |
| `apps/api/src/tee/tee.service.ts` | `RepublishEntry` field renamed | VERIFIED | `encryptedIpnsPrivateKey` present, old name gone |
| `apps/tee-worker/src/services/key-manager.ts` | `decryptIpnsKey` param renamed | VERIFIED | 7 occurrences of canonical name, 0 of old name |
| `apps/api/src/shares/root-ownership.util.ts` | New shared `assertRootOwnership` helper | VERIFIED | Exported, both callers delegate |
| `packages/sdk-core/src/tee/wrap.ts` | Bytes-in/bytes-out `wrapIpnsKeyForTee` | VERIFIED | No internal hex helpers; `teePublicKey` param name present |
| `packages/sdk/src/types.ts` | `ShareCallbacks`/`shareCallbacks` removed | VERIFIED | 0 matches repo-wide (excl. tests) |
| `packages/core/src/node/encode.ts` | Local base64 removed, imports from `@cipherbox/crypto` | VERIFIED | Imports `bytesToBase64`; no local codec body |
| `packages/sdk-core/src/rotation/engine.ts` | Local base64 removed | VERIFIED | Imports `bytesToBase64`/`base64ToBytes` |
| `packages/sdk-core/src/file/index.ts` | Base64 deduped + field renamed to canonical | VERIFIED | Imports shared codec; `encryptedIpnsPrivateKey` on return type |
| `packages/sdk-core/src/upload/index.ts` | `UploadResult` field renamed to canonical | VERIFIED | `encryptedIpnsPrivateKey?: string` present |
| `packages/sdk-core/src/__tests__/folder.test.ts` | New forced-throw zeroization test | VERIFIED | Test present and passing (part of 371-pass suite) |
| `packages/sdk-core/scripts/verify-filepointer.mts` | `clearBytes` on `userPrivateKey` + derived keys | VERIFIED | Import + finally block present; typecheck exit 0 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `packages/crypto/src/index.ts` | Wave-2 consumers (core, sdk-core) | re-export of `bytesToBase64`/`base64ToBytes` | WIRED | 7 downstream files confirmed importing |
| All 7 AES functions | `importAesKey` | direct call | WIRED | `encrypt.ts`(3), `decrypt.ts`(3), `encrypt-ctr.ts`(2), `decrypt-ctr.ts`(3) |
| `republish.service.ts` | `tee.service.ts` / tee-worker | renamed wire field `encryptedIpnsPrivateKey` | WIRED | Value unchanged (`record.encryptedIpnsPrivateKey!.toString('base64')`), only key name changed |
| `shares.service.ts` / `share-invite.service.ts` | `assertRootOwnership` | direct call with injected `ipnsRecordRepo` | WIRED | Both call sites confirmed; 57/57 specs pass |
| `registration.ts` / `vault/index.ts` / `file/index.ts` | `wrapIpnsKeyForTee` | hex-decode before call, hex-encode after | WIRED | All 3 call sites confirmed calling with bytes; `hexToBytes`/`bytesToHex` present at boundary |
| `packages/sdk` dist | `apps/web` typecheck | rebuild-before-typecheck (Pitfall 5) | WIRED | Orchestrator-confirmed full workspace typecheck exit 0; spot-checked sdk-core typecheck directly (exit 0) |

### Behavioral Spot-Checks (run directly by this verifier, not sourced from SUMMARY claims)

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Crypto package builds + AES/encoding suites pass | `pnpm --filter @cipherbox/crypto test -- aes.test.ts` / `encoding.test.ts` (via full run) | 207/207 pass | PASS |
| Core node-codec golden vectors pass | `pnpm --filter @cipherbox/core test -- node-codec-vectors.test.ts node-codec.test.ts` | 35/35 pass | PASS |
| sdk-core full suite (incl. forced-throw zeroization test) | `pnpm --filter @cipherbox/sdk-core test -- folder.test.ts` (full run) | 371 pass, 12 skipped | PASS |
| sdk full suite (renamed field consumers) | `pnpm --filter @cipherbox/sdk test` | 411 pass, 3 skipped | PASS |
| tee-worker republish suite | `pnpm --filter cipherbox-tee-worker test` | 76 pass, 8 todo | PASS |
| API shares/share-invite specs (assertRootOwnership) | `pnpm --filter @cipherbox/api test -- shares.service.spec.ts share-invite.service.spec.ts` | 57/57 pass | PASS |
| sdk-core typecheck | `pnpm --filter @cipherbox/sdk-core typecheck` | exit 0 | PASS |
| crypto package build | `pnpm --filter @cipherbox/crypto build` | exit 0 | PASS |

### Probe Execution

No probes declared or applicable — this is a mechanical refactor/cleanup phase with no `scripts/*/tests/probe-*.sh` referenced in any plan or SUMMARY. Skipped (no runnable probe entry points for this phase type).

### Requirements Coverage

Phase maps to no `REQ-*` IDs (`phase_req_ids` is null per orchestrator instructions). All 12 Source todos listed in ROADMAP.md for Phase 77 are covered by the 10 plans and verified above:

| Todo | Plan | Status |
|------|------|--------|
| `wrapipnskeyfortee-bytes-in-bytes-out` | 77-05 | VERIFIED |
| `zeroize-createsubfolder-keys-on-error-path` | 77-10 | VERIFIED |
| `zeroize-local-key-plaintext-copies-in-aes-helpers` | 77-02 | VERIFIED |
| `e2e-helper-scripts-zeroize-userprivatekey` | 77-10 | VERIFIED |
| `hoist-base64tobytes-into-crypto-package` | 77-01 | VERIFIED |
| `dedup-base64-helpers-sdk-core-share` | 77-08, 77-09 | VERIFIED |
| `node-codec-base64-helper-dedup` | 77-07 | VERIFIED |
| `rename-ipnsprivatekeyencrypted-to-encryptedipnsprivatekey` | 77-09 | VERIFIED |
| `rename-encrypted-ipns-key-canonical-field` | 77-03 | VERIFIED |
| `retire-dead-sdk-share-scaffolding` | 77-06 | VERIFIED |
| `drop-discarded-per-upload-ecies-wrapkey` | 77-06 | VERIFIED |
| `extract-assert-root-ownership-helper` | 77-04 | VERIFIED |

No orphaned requirements found.

### Anti-Patterns Found

Scanned all 21 unique files across `files_modified` in the 10 plans for `TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER` debt markers:

- **0 debt markers found** in any phase-77-modified file.
- One incidental match: `PLACEHOLDER_PUBLISHED_NODE` in `apps/web/src/hooks/shared-folder-projection.ts` / `useSharedNavigationActions.ts` — confirmed by direct read to be a pre-existing named sentinel constant from Phase 65/68 (a legitimate typed default value, not a "not implemented" stub), predating this phase and outside its scope. Not a blocker.

No `TBD`/`FIXME`/`XXX` unreferenced debt markers found — the debt-marker gate is clean.

### Human Verification Required

None. All must-haves are either directly verified via passing automated tests (including a genuine forced-throw behavioral test for the createSubfolder cleanup invariant) or confirmed via direct source reading of simple, unconditional, single-branch code (e.g., the `importAesKey` `finally { keyView.fill(0) }` block, which cannot be black-box tested because the internal buffer is never exposed to any caller by design — this is an inherent limitation of the JS zeroization pattern used consistently elsewhere in this codebase, not new uncertainty introduced by this phase).

### Gaps Summary

No gaps found. All 3 ROADMAP Success Criteria are verified against actual source code (not SUMMARY claims), all 10 plans' `must_haves` truths/artifacts/key_links check out, all spot-run test suites (crypto, core, sdk-core, sdk, tee-worker, api shares specs) pass when run directly by this verifier, and the two flagged out-of-scope local-variable residuals are confirmed cosmetic (assigned into the canonical wire field) and explicitly documented as out-of-scope by the plans themselves. Phase goal achieved.

---

*Verified: 2026-07-11T09:59:50Z*
*Verifier: Claude (gsd-verifier)*

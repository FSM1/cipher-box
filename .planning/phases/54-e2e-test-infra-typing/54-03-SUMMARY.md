---
phase: 54-e2e-test-infra-typing
plan: 03
subsystem: e2e-test-infra
tags: [typescript-migration, e2e-scripts, crypto-vectors, ipns]
requires: [54-01, 54-02]
provides:
  - tests/desktop-e2e/scripts/bump-ipns-sequence.ts
  - tests/desktop-e2e/scripts/test-move-content.ts
  - tests/web-e2e/staging-perf-wallet.ts
  - apps/desktop/src-tauri/generate-test-vectors.ts
affects:
  - apps/desktop/package.json
  - pnpm-lock.yaml
tech-stack:
  added: ["@cipherbox/core (devDep on apps/desktop)"]
  patterns: ["entrypoint imports over dist-relative paths", "tsx interpreter for .ts child spawn", "in-narrowing for ipns IPNSRecord union"]
key-files:
  created:
    - tests/desktop-e2e/scripts/bump-ipns-sequence.ts
    - tests/desktop-e2e/scripts/test-move-content.ts
    - tests/web-e2e/staging-perf-wallet.ts
    - apps/desktop/src-tauri/generate-test-vectors.ts
  modified:
    - apps/desktop/package.json
    - pnpm-lock.yaml
decisions:
  - "deriveEd25519PublicKey is a verified drop-in for ed.getPublicKey (no @noble/ed25519 fallback needed)"
  - "@noble/secp256k1 already declared at ^3.0.0 in apps/desktop dependencies — no devDep duplication added"
  - "@cipherbox/core added as workspace devDep on apps/desktop to satisfy the corrected IPNS-symbol import at tsx runtime"
metrics:
  duration: ~20m
  completed: 2026-06-20
---

# Phase 54 Plan 03: Migrate Remaining E2E Helper Scripts to TypeScript Summary

Migrated bump-ipns-sequence, test-move-content, staging-perf-wallet, and the highest-risk generate-test-vectors to typed `.ts`, correcting the latent `@cipherbox/core` IPNS-symbol import gap and routing the verify-filepointer child-spawn through the tsx interpreter.

## What Was Done

### Task 1 — bump-ipns-sequence.ts + test-move-content.ts (commit fc8b81f89)

- `bump-ipns-sequence.ts`: replaced the three `../../../packages/*/dist/index.mjs` imports with `@cipherbox/sdk-core` + `@cipherbox/crypto` entrypoints and the shared `../../e2e-helpers/auth` helper (`authenticate`, `buildSdkContext`, `parseCliArgs`). CLI contract `--api-url [--email]` + `TEST_SECRET` env preserved (D-07).
- `test-move-content.ts`: Node-stdlib only. Sole substantive change is the verify child-spawn — `VERIFY_SCRIPT` now points at `verify-filepointer.ts` and is spawned via `spawnSync('node', [join(REPO_ROOT, 'node_modules/.bin/tsx'), VERIFY_SCRIPT, ...cliArgs], opts)`, because `node` cannot run a `.ts` directly. All args, the `TEST_SECRET` env block, timeout, and stdio preserved.

### Task 2 — staging-perf-wallet.ts + generate-test-vectors.ts (commit aa6a267e9)

- `staging-perf-wallet.ts`: clean rename. No `@cipherbox` imports (Playwright + viem + wallet-mock only). Hardcoded `STAGING_URL` and zero-arg contract intact. Added minimal types (`ApiCall` interface, `Request` map keys, `instanceof Error` error guards) for strict mode.
- `generate-test-vectors.ts` (D-02 fix): `createIpnsRecord` + `marshalIpnsRecord` now import from `@cipherbox/core` (NOT `@cipherbox/crypto` — confirmed crypto's dist does not re-export them). `@noble/secp256k1` deep path replaced with the declared `@noble/secp256k1` entrypoint. `ed.getPublicKey(privateKey)` replaced with `deriveEd25519PublicKey(privateKey)` from `@cipherbox/crypto`.

## Key Decisions / Findings

### A1: deriveEd25519PublicKey is a verified drop-in (no @noble/ed25519 fallback)

`packages/crypto/dist/ed25519/keygen.d.ts` exposes `deriveEd25519PublicKey(privateKey: Uint8Array): Uint8Array` — synchronous, Uint8Array → Uint8Array. Source (`keygen.ts`) wraps `ed.getPublicKey(privateKey)` from the same `@noble/ed25519` library with only a 32-byte length guard added. The emitted public-key bytes are therefore byte-identical to the old `ed.getPublicKey` call. **No `@noble/ed25519` devDep was needed.**

### @noble/secp256k1 already declared

`@noble/secp256k1@^3.0.0` is already present in `apps/desktop/package.json` **dependencies** (line 14), matching root. v3 exports `getPublicKey(privKey, isCompressed?)` returning `Bytes` (Uint8Array) — a drop-in for the `.mjs`'s `getPublicKey(eciesPrivateKey, false)`. No devDep duplication was added; the plan's grep gate (`grep -q '"@noble/secp256k1"'`) passes against the existing dependencies entry.

### @cipherbox/core devDep added (correctness requirement, Rule 2/3)

The corrected IPNS-symbol import creates a new dependency on `@cipherbox/core` from apps/desktop. `@cipherbox/core` was not previously a declared dependency there, so `@cipherbox/core: workspace:*` was added to `apps/desktop` devDependencies and `pnpm install` regenerated the lockfile (committed alongside in the same commit). tsc resolves it via the `tsconfig.scripts.json` `paths` mapping; the workspace symlink covers tsx runtime.

## Symbol Drift Reconciled From the Phase-51 Merge

`IPNSRecord` (re-exported by `@cipherbox/core` from the upstream `ipns@10.1.3` package) is now the discriminated union `IPNSRecordV1V2 | IPNSRecordV2`, and `signatureV1` exists only on the V1V2 variant. The `.mjs`'s `if (ipnsRecord.signatureV1)` guard does not typecheck against the union. Reconciled to `if ('signatureV1' in ipnsRecord && ipnsRecord.signatureV1)` — a type-safe `in`-narrowing that preserves the exact runtime behavior (emit the V1 signature only when present). No other symbol drift: all `@cipherbox/crypto` symbols (`encryptAesGcm`, `decryptAesGcm`, `sealAesGcm`, `unsealAesGcm`, `wrapKey`, `unwrapKey`, `signEd25519`, `verifyEd25519`, `deriveIpnsName`, `deriveEd25519PublicKey`, `hexToBytes`, `bytesToHex`, `deriveVaultIpnsKeypair`, `clearBytes`) and `@cipherbox/sdk-core` symbols (`loadVaultKeyBlob`, `loadFolderMetadata`, `updateFolderMetadataAndPublish`, `SdkContext`) confirmed present and unrenamed in the current built dist.

## Emitted Test-Vector Integrity (D-07)

generate-test-vectors' emitted hex vectors are **unchanged**. The migration is import-only plus the `ed.getPublicKey → deriveEd25519PublicKey` swap, which calls the same underlying `@noble/ed25519` primitive (byte-identical output). The `signatureV1` `in`-narrowing only gates whether the optional line prints — it does not alter any computed value. The stdout JSON/label shape and all hex values consumed by `crates/crypto/tests/cross_language.rs` are preserved.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] bump-ipns-sequence.ts: SdkContext.axiosInstance is optional + newSequenceNumber is bigint**

- **Found during:** Task 1 tsc verify.
- **Issue:** `SdkContext.axiosInstance` is `?:` optional in the typed contract (tsc could not narrow it for `ctx.axiosInstance.get('/vault')`), and `updateFolderMetadataAndPublish` returns `newSequenceNumber: bigint`, not `number`.
- **Fix:** Hoisted `axiosInstance` to a local with a presence guard; typed `newSequenceNumber` as `bigint`. Runtime behavior unchanged.
- **Files modified:** tests/desktop-e2e/scripts/bump-ipns-sequence.ts
- **Commit:** fc8b81f89

**2. [Rule 3 - Blocking] eslint flags `catch (_e)` (no caughtErrorsIgnorePattern configured)**

- **Found during:** Task 1 eslint verify.
- **Issue:** The repo eslint config sets `no-unused-vars` `argsIgnorePattern: '^_'` but no `caughtErrorsIgnorePattern`; `@typescript-eslint`'s default `caughtErrors: 'all'` flags `_e`. The plan suggested `catch (_e)`.
- **Fix:** Used bare `catch {` (optional catch binding, valid ES2022) for all unused catch clauses in test-move-content.ts — matches the original `.mjs` behavior.
- **Files modified:** tests/desktop-e2e/scripts/test-move-content.ts
- **Commit:** fc8b81f89

**3. [Rule 2/3 - Missing dependency] @cipherbox/core not declared on apps/desktop**

- **Found during:** Task 2.
- **Issue:** Moving the IPNS symbols to `@cipherbox/core` introduced an undeclared dependency from apps/desktop.
- **Fix:** Added `@cipherbox/core: workspace:*` to apps/desktop devDependencies; ran `pnpm install`; committed the lockfile change.
- **Files modified:** apps/desktop/package.json, pnpm-lock.yaml
- **Commit:** aa6a267e9

**4. [Rule 1 - Bug] IPNSRecord union has no signatureV1 (Phase-51 merge drift)**

- See "Symbol Drift Reconciled" above. Reconciled via `in`-narrowing.
- **Files modified:** apps/desktop/src-tauri/generate-test-vectors.ts
- **Commit:** aa6a267e9

## Verification Results

- Task 1 automated verify block: PASS (file existence + grep gates + `tsc -p tsconfig.scripts.json --noEmit` + eslint → `ok`).
- Task 2 automated verify block: PASS (file existence + grep gates + `tsc -p tsconfig.scripts.json --noEmit` + eslint → `ok`).

## Not Done (out of scope)

- The `.mjs` originals were intentionally NOT deleted (Wave 3 / plan 04 owns deletion + runner-script `node → tsx` updates).

## Self-Check: PASSED

All four created `.ts` files exist on disk; both task commits (fc8b81f89, aa6a267e9) are present in git history.

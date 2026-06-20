# Phase 54: E2E Test-Infra Typing — Research

**Researched:** 2026-06-19
**Domain:** TypeScript migration of untyped `.mjs` E2E helper scripts; monorepo tsconfig wiring; CI typecheck ordering
**Confidence:** HIGH

---

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01 (runtime):** tsx — execute `.ts` helpers directly via `tsx` (already a devDependency at v4.21.0); no build step.
- **D-02 (imports):** Import the package entrypoint (`@cipherbox/sdk-core`, `@cipherbox/crypto`, `@cipherbox/api-client`) NOT `../dist/*.mjs` relative paths. CI typecheck job MUST rebuild consumed packages' `dist` BEFORE typechecking the helpers.
- **D-03 (wiring):** Dedicated scripts tsconfig covering all E2E helper scripts, wired into CI typecheck + root eslint scope.
- **D-04 (shared lib):** Factor a small typed shared helper module for duplicated auth/ctx/key-derivation. Location is planner's discretion; must be importable from all 4 consumer locations.
- **D-05:** Migrate all 7 scripts to `.ts`; drop every `../dist/*.mjs` relative import.
- **D-06:** Update BOTH bash and PowerShell runners together; cross-platform parity is mandatory.
- **D-07:** Behavior-preserving — identical flows, typing only.

### Claude's Discretion

- Shared helper module location (within the constraint that it must be importable from all 4 consumer locations).

### Deferred Ideas (OUT OF SCOPE)

- None discussed.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                                     | Research Support                                                                                   |
| ------- | --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| HARD-05 | E2E test-infra typing — migrate untyped .mjs E2E helper scripts to TypeScript wired into typecheck and lint | All 7 scripts read; entrypoint gap identified; tsconfig + CI ordering strategy documented below |

</phase_requirements>

---

## Summary

Phase 54 converts 7 hand-written `.mjs` E2E helper scripts to TypeScript so SDK/crypto/api-client contract drift is caught at tsc/eslint time. The scripts fall into three groups: three `sdk-core` helpers invoked via node by the `.sh`/`.ps1` test scripts, two `desktop-e2e` helpers (one invoked by `run-all.{sh,ps1}` and one by `.sh`/`.ps1` conflict tests), one `web-e2e` performance measurement script (manually invoked only), and one `src-tauri` test-vector generator (manually invoked only).

The most critical finding is that `generate-test-vectors.mjs` imports `createIpnsRecord` and `marshalIpnsRecord` from `packages/crypto/dist/index.mjs` — but these symbols live in `@cipherbox/core`, NOT `@cipherbox/crypto`. The current `.mjs` silently works via a stale or coincidentally-in-scope import path. Migrating to `@cipherbox/core` entrypoint import is the correct fix per D-02 and also fixes an incorrect source reference. This is the highest-risk D-02 entrypoint gap.

The `generate-test-vectors.mjs` also directly imports `@noble/secp256k1` and `@noble/ed25519` from `packages/crypto/node_modules/` — deep internal paths that should be replaced by using the public `@cipherbox/crypto` re-exports (which already surface the necessary operations via `wrapKey`, `unwrapKey`, etc.) or by adding `@noble/ed25519`/`@noble/secp256k1` as devDependencies to the new shared scripts package.

All other 6 scripts use correct package-group imports (just from wrong `dist/` relative paths rather than entrypoints). The auth/ctx/key-derivation pattern is duplicated across 5 of the 7 scripts and is the correct target for D-04 extraction.

**Primary recommendation:** Create a new `tests/e2e-helpers/` package (or `packages/test-helpers/`) as the D-04 shared module home, add it to the pnpm workspace, and place a dedicated `tsconfig.scripts.json` at repo root that covers all 7 script locations. Wire that tsconfig into the CI `typecheck` job after the dep build step.

---

## Project Constraints (from CLAUDE.md)

- TypeScript everywhere; string literals over enums
- `Uint8Array` for binary data; Web Crypto API for browser encryption
- camelCase for API fields
- No private key logging; no keys in localStorage
- `pnpm api:generate` after API endpoint changes (not applicable here — no API changes)
- Conventional commit format; no parens in subject
- Branch protection: no direct push to `main`; use feature branches

---

## Architectural Responsibility Map

| Capability                     | Primary Tier       | Secondary Tier  | Rationale                                                   |
| ------------------------------ | ------------------ | --------------- | ----------------------------------------------------------- |
| Auth/ctx construction          | Shared helper (D-04) | Each script  | 5 of 7 scripts duplicate this; extraction eliminates drift  |
| SDK operations (folder/file)   | `@cipherbox/sdk-core` entrypoint | — | All scripts use sdk-core; must flow through typed entrypoint |
| Crypto operations              | `@cipherbox/crypto` entrypoint | — | All scripts except staging-perf-wallet use crypto functions  |
| API client                     | `@cipherbox/api-client` entrypoint | — | All auth-calling scripts create an axiosInstance from this  |
| IPNS record creation/marshal   | `@cipherbox/core` entrypoint | — | generate-test-vectors MUST import from core, NOT crypto    |
| Typecheck gate                 | CI `typecheck` job | Root tsc command | Dedicated tsconfig added to CI job; D-02 ordering enforced |
| Lint gate                      | Root eslint (flat config) | — | `.mjs` are already in scope; `.ts` replacement is too      |
| Runner invocation              | `run-all.sh` + `run-all.ps1` | `.sh`/`.ps1` sub-scripts | Both bash and PS1 call `node *.mjs`; must change to `tsx *.ts` |

---

## Current State of Each Script

### 1. `packages/sdk-core/scripts/edit-filepointer.mjs`

**Purpose:** Edit a file's content via the SDK (used to test FUSE→SDK roundtrip writes).

**Current imports (all dist-relative):**

| Imported From                              | Symbols                                                                                                  |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `../../api-client/dist/index.mjs`          | `createAxiosInstance`                                                                                    |
| `../dist/index.mjs` (sdk-core)             | `loadVaultKeyBlob`, `loadFolderMetadata`, `resolveFileMetadata`, `updateFileMetadata`, `updateFolderMetadataAndPublish`, `addToIpfs` |
| `../../crypto/dist/index.mjs`              | `encryptAesGcm`, `generateFileKey`, `generateIv`, `wrapKey`, `unwrapKey`, `bytesToHex`, `hexToBytes`, `deriveVaultIpnsKeypair`, `clearBytes` |

**CLI contract:** `--api-url <url> --email <email> --file-name <name> --new-content <text>`, env: `TEST_SECRET`

**Auth/ctx/key-derivation:** Full auth block (fetch `/auth/test-login`, extract `accessToken` + `privateKeyHex` + `publicKeyHex`), `createAxiosInstance`, `ctx` construction. **Shared with:** rename-folder, verify-filepointer, bump-ipns-sequence.

**Invoked by:** `tests/desktop-e2e/scripts/test-cross-client-sync.sh` (line 68) and `test-cross-client-sync.ps1` (line 91).

**D-02 gap:** None — all symbols are exported from the correct packages (`@cipherbox/sdk-core`, `@cipherbox/crypto`, `@cipherbox/api-client`). Just need to change from `../../crypto/dist/index.mjs` → `@cipherbox/crypto` etc.

---

### 2. `packages/sdk-core/scripts/rename-folder.mjs`

**Purpose:** Rename a folder in the vault root (cross-client sync test).

**Current imports:**

| Imported From                     | Symbols                                                                 |
| --------------------------------- | ----------------------------------------------------------------------- |
| `../../api-client/dist/index.mjs` | `createAxiosInstance`                                                   |
| `../dist/index.mjs` (sdk-core)    | `loadVaultKeyBlob`, `loadFolderMetadata`, `renameInFolder`, `updateFolderMetadataAndPublish` |
| `../../crypto/dist/index.mjs`     | `deriveVaultIpnsKeypair`, `clearBytes`                                  |

**CLI contract:** `--api-url <url> --email <email> --folder-name <name> --new-name <name>`, env: `TEST_SECRET`

**Auth/ctx/key-derivation:** Full duplicate auth block. **Shared with:** edit-filepointer, verify-filepointer, bump-ipns-sequence.

**Invoked by:** `test-cross-client-sync.sh` (line 76). NOT in `.ps1` (the Windows port of cross-client-sync does not call rename-folder).

**D-02 gap:** None — all symbols on correct package entrypoints.

---

### 3. `packages/sdk-core/scripts/verify-filepointer.mjs`

**Purpose:** Read back a file via fresh SDK client and verify decrypted content.

**Current imports:**

| Imported From                     | Symbols                                                                               |
| --------------------------------- | ------------------------------------------------------------------------------------- |
| `../../api-client/dist/index.mjs` | `createAxiosInstance`                                                                 |
| `../dist/index.mjs` (sdk-core)    | `downloadAndDecrypt`, `resolveFileMetadata`, `loadFolderMetadata`, `loadVaultKeyBlob` |
| `../../crypto/dist/index.mjs`     | `unwrapKey`, `hexToBytes`                                                             |

**CLI contract:** `--api-url <url> --email <email> --file-name <name> [--folder-name <subfolder>] [--expected-content <text>]`, env: `TEST_SECRET`

**Auth/ctx/key-derivation:** Full auth block but does NOT extract `publicKeyHex`. **Shared with:** edit-filepointer, rename-folder, bump-ipns-sequence.

**Invoked by:**
- `test-round-trip.sh` (line 53) and `test-round-trip.ps1` (line 78) — via `node`
- `test-cross-client-sync.sh` (line 60) and `test-cross-client-sync.ps1` (line 81) — via `node`
- `test-move-content.mjs` — via `spawnSync(process.execPath, [VERIFY_SCRIPT, ...])` where `VERIFY_SCRIPT` is set to `verify-filepointer.mjs` path

**D-02 gap:** None — all symbols on correct package entrypoints.

**Spawn path note:** `test-move-content.mjs` hardcodes `VERIFY_SCRIPT = join(REPO_ROOT, 'packages/sdk-core/scripts/verify-filepointer.mjs')` and calls `spawnSync(process.execPath, [VERIFY_SCRIPT, ...])` — `process.execPath` is `node`. After migration, this must become `spawnSync('tsx', [VERIFY_SCRIPT_TS_PATH, ...])` or `spawnSync(process.execPath, ['node_modules/.bin/tsx', VERIFY_SCRIPT_TS_PATH, ...])`.

---

### 4. `tests/desktop-e2e/scripts/test-move-content.mjs`

**Purpose:** Cross-platform file move re-encryption test (writes via FUSE mount, moves, verifies via SDK).

**Current imports:**

| Imported From    | Symbols                                         |
| ---------------- | ----------------------------------------------- |
| `node:fs`        | `mkdirSync`, `writeFileSync`, `readdirSync`, `statSync`, `rmSync`, `renameSync` |
| `node:path`      | `join`, `dirname`, `resolve`                    |
| `node:url`       | `fileURLToPath`                                 |
| `node:child_process` | `spawnSync`                                 |

**No SDK/crypto/api-client imports** — this script is pure Node stdlib + spawns `verify-filepointer.mjs` as a child process.

**CLI contract:** `--mount <path> --api-url <url>`, env: `TEST_SECRET`

**Invoked by:**
- `run-all.sh` step 7: `node "$SCRIPT_DIR/test-move-content.mjs" --mount "$MOUNT_POINT" --api-url "$API_URL"`
- `run-all.ps1` step 7: `& node "$PSScriptRoot\test-move-content.mjs" --mount $MountPoint --api-url $ApiUrl`

**D-02 gap:** None — no package imports. The one behavioral change needed is the `VERIFY_SCRIPT` path variable (see note above).

---

### 5. `tests/desktop-e2e/scripts/bump-ipns-sequence.mjs`

**Purpose:** Advance vault root IPNS sequence with a real signed record (simulates a second device publishing).

**Current imports:**

| Imported From                                       | Symbols                                                             |
| --------------------------------------------------- | ------------------------------------------------------------------- |
| `../../../packages/api-client/dist/index.mjs`       | `createAxiosInstance`                                               |
| `../../../packages/sdk-core/dist/index.mjs`         | `loadVaultKeyBlob`, `loadFolderMetadata`, `updateFolderMetadataAndPublish` |
| `../../../packages/crypto/dist/index.mjs`           | `deriveVaultIpnsKeypair`, `clearBytes`                              |

**CLI contract:** `--api-url <url> [--email <email>]`, env: `TEST_SECRET`

**Auth/ctx/key-derivation:** Full auth block. **Shared with:** edit-filepointer, rename-folder, verify-filepointer.

**Invoked by:**
- `test-conflict-detection.sh` (line 95): `node "$SCRIPT_DIR/bump-ipns-sequence.mjs" --api-url "$API_URL" --email "$TEST_EMAIL"`
- `test-conflict-detection.ps1` (line 115): `& node $BumpScript --api-url $ApiUrl --email $TestEmail` (where `$BumpScript` is `bump-ipns-sequence.mjs`)

**D-02 gap:** None — all symbols on correct package entrypoints.

---

### 6. `tests/web-e2e/staging-perf-wallet.mjs`

**Purpose:** Playwright-based staging performance measurement (wallet login path, API waterfall).

**Current imports:**

| Imported From                      | Symbols                                       |
| ---------------------------------- | --------------------------------------------- |
| `@playwright/test`                 | `chromium`                                    |
| `@johanneskares/wallet-mock`       | `installMockWallet`                           |
| `viem/accounts`                    | `privateKeyToAccount`                         |
| `viem/chains`                      | `mainnet`                                     |
| `viem`                             | `custom`                                      |

**No `@cipherbox/*` imports** — this script does NOT use the SDK, crypto, or api-client at all.

**CLI contract:** No CLI args. Hardcoded `STAGING_URL = 'https://app-staging.cipherbox.cc'`. Requires Playwright browser installed.

**Invoked by:** Manual only — no CI workflow reference found. Not in run-all.sh or run-all.ps1. Referenced only in `.planning/perf/staging-baseline-2026-03-24.md`.

**D-02 gap:** None — only uses `@playwright/test`, `viem`, `@johanneskares/wallet-mock` which are already in `tests/web-e2e/package.json` devDependencies.

**Dependency note:** `@johanneskares/wallet-mock` is a `devDependency` in `tests/web-e2e/package.json`. After migration to `.ts`, `@types/node` (already present) covers Node globals.

---

### 7. `apps/desktop/src-tauri/generate-test-vectors.mjs`

**Purpose:** Generate cross-language test vectors for Rust crypto verification (stdout hex values).

**Current imports:**

| Imported From                                                | Symbols                                                                                                            |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `../../../packages/crypto/dist/index.mjs`                    | `encryptAesGcm`, `decryptAesGcm`, `sealAesGcm`, `unsealAesGcm`, `wrapKey`, `unwrapKey`, `signEd25519`, `verifyEd25519`, **`createIpnsRecord`**, **`marshalIpnsRecord`**, `deriveIpnsName`, `hexToBytes`, `bytesToHex` |
| `../../../packages/crypto/node_modules/@noble/secp256k1/index.js` | `getPublicKey`                                                                                               |
| `../../../packages/crypto/node_modules/@noble/ed25519/index.js`   | `ed` (namespace import `* as ed`)                                                                            |

**CLI contract:** No args. `node generate-test-vectors.mjs` → stdout vectors.

**Invoked by:** Manual only — referenced in `docs/VAULT_EXPORT_FORMAT.md` and `scripts/generate-test-vectors.ts` context. Not invoked by any CI workflow or runner script.

**D-02 gaps — CRITICAL:**

1. **`createIpnsRecord` and `marshalIpnsRecord` are NOT in `@cipherbox/crypto`** — they live in `@cipherbox/core` (confirmed in `packages/core/src/index.ts`). The script currently reaches them via `packages/crypto/dist/index.mjs` which is **incorrect** — this works today only because the crypto dist may re-export them transitionally or via hoisting. After migration, these MUST be imported from `@cipherbox/core`.

2. **`@noble/secp256k1` and `@noble/ed25519` are internal `devDependencies` of `packages/crypto`** — they are not exposed on any public `@cipherbox/*` entrypoint. The script currently reaches them via deep internal path `packages/crypto/node_modules/@noble/secp256k1/index.js`. After migration, the options are:
   - Add `@noble/secp256k1` and `@noble/ed25519` as devDependencies to `apps/desktop` or the new shared scripts package, and import them directly.
   - Replace `ed.getPublicKey(key)` with `deriveEd25519PublicKey(key)` from `@cipherbox/crypto` (which is exported). Check if `getPublicKey` from `@noble/secp256k1` (for ECIES) has a crypto equivalent.

3. **`deriveIpnsName`** is exported from BOTH `@cipherbox/crypto` and `@cipherbox/core` — either works after D-02 migration.

---

## Duplicated Auth/Ctx/Key-Derivation Logic (D-04 Extraction Target)

The following pattern is duplicated across 5 scripts (edit-filepointer, rename-folder, verify-filepointer, bump-ipns-sequence, and conceptually in the staging-perf-wallet but for a different auth mechanism):

```typescript
// Shared pattern — D-04 will extract this:

async function authenticate(apiUrl: string, email: string, secret: string) {
  const response = await fetch(`${apiUrl}/auth/test-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, secret }),
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`test-login failed (${response.status}): ${body}`);
  }
  const payload = await response.json();
  if (!payload.accessToken || !payload.privateKeyHex) {
    throw new Error('test-login response missing accessToken or privateKeyHex');
  }
  return payload as { accessToken: string; privateKeyHex: string; publicKeyHex?: string };
}

// ctx construction pattern (identical in edit-filepointer, rename-folder,
// verify-filepointer, bump-ipns-sequence):
function buildSdkContext(apiUrl: string, accessToken: string): SdkContext {
  const axiosInstance = createAxiosInstance({
    baseUrl: apiUrl,
    getAccessToken: async () => accessToken,
  });
  return { apiUrl, getAccessToken: async () => accessToken, axiosInstance };
}
```

The `SdkContext` type is exported from `@cipherbox/sdk-core`.

---

## Runner Invocation Map (D-06)

### run-all.sh / run-all.ps1 (the two scripts D-06 explicitly requires updating)

| Script                  | Current invocation (bash)                                              | New invocation (bash)                                                   |
| ----------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `test-move-content.mjs` | `node "$SCRIPT_DIR/test-move-content.mjs" --mount ... --api-url ...`   | `pnpm exec tsx "$SCRIPT_DIR/test-move-content.ts" --mount ... --api-url ...` |

| Script                  | Current invocation (PS1)                                               | New invocation (PS1)                                                    |
| ----------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `test-move-content.mjs` | `& node "$PSScriptRoot\test-move-content.mjs" --mount ... --api-url ...` | `& pnpm exec tsx "$PSScriptRoot\test-move-content.ts" --mount ... --api-url ...` |

### Shell sub-scripts (also need updating — these are called from run-all which calls them)

The following call `node *.mjs` directly and also must be updated as part of D-06:

| Sub-script                     | Invocations to change                                                                        |
| ------------------------------ | -------------------------------------------------------------------------------------------- |
| `test-round-trip.sh`           | Line 53: `node "$REPO_ROOT/packages/sdk-core/scripts/verify-filepointer.mjs" ...`           |
| `test-round-trip.ps1`          | Line 78: `& node $verifierPath ...` where `$verifierPath = ...verify-filepointer.mjs`       |
| `test-cross-client-sync.sh`    | Lines 60/68/76: `node "...verify-filepointer.mjs"`, `node "...edit-filepointer.mjs"`, `node "...rename-folder.mjs"` |
| `test-cross-client-sync.ps1`   | Lines 81/93: `& node $verifierPath ...`, `& node $editorPath ...`                           |
| `test-conflict-detection.sh`   | Line 95: `node "$SCRIPT_DIR/bump-ipns-sequence.mjs" ...`                                    |
| `test-conflict-detection.ps1`  | Line 115: `& node $BumpScript ...`                                                           |

**Note:** `test-round-trip.sh` and `test-round-trip.ps1` also contain a `ensure_verifier_runtime` / `Ensure-VerifierRuntime` guard that checks for `dist/index.mjs` existence and runs `pnpm build` if missing. After D-02 migration, these guards still serve the same purpose (dist must be built for entrypoint imports to typecheck). Keep the guard but optionally update the `dist` presence check to be package-aware.

### `test-move-content.mjs` internal spawn of `verify-filepointer.mjs`

```javascript
// Current (line 27-28):
const VERIFY_SCRIPT = join(REPO_ROOT, 'packages/sdk-core/scripts/verify-filepointer.mjs');
// spawned via:
spawnSync(process.execPath, [VERIFY_SCRIPT, ...args], ...)
```

After migration to TypeScript, this must become:

```typescript
// New:
const VERIFY_SCRIPT = join(REPO_ROOT, 'packages/sdk-core/scripts/verify-filepointer.ts');
// spawned via pnpm exec tsx (or direct tsx path from node_modules/.bin):
spawnSync('node', [
  join(REPO_ROOT, 'node_modules/.bin/tsx'),
  VERIFY_SCRIPT,
  ...cliArgs,
], { env: { ...process.env, TEST_SECRET: secret }, ... })
```

Or alternatively: `spawnSync(join(REPO_ROOT, 'node_modules/.bin/tsx'), [VERIFY_SCRIPT, ...cliArgs], ...)`.

---

## Package Entrypoints: D-02 Verification

### `@cipherbox/sdk-core` — exports confirmed [ASSUMED from source reading]

| Symbol used by scripts                                 | In sdk-core index.ts? |
| ------------------------------------------------------ | --------------------- |
| `loadVaultKeyBlob`                                     | YES                   |
| `loadFolderMetadata`                                   | YES                   |
| `resolveFileMetadata`                                  | YES                   |
| `updateFileMetadata`                                   | YES                   |
| `updateFolderMetadataAndPublish`                       | YES                   |
| `renameInFolder`                                       | YES                   |
| `downloadAndDecrypt`                                   | YES                   |
| `addToIpfs`                                            | YES                   |
| `SdkContext` (type)                                    | YES                   |

### `@cipherbox/crypto` — exports confirmed [ASSUMED from source reading]

| Symbol used by scripts               | In crypto index.ts? |
| ------------------------------------ | ------------------- |
| `encryptAesGcm`                      | YES                 |
| `decryptAesGcm`                      | YES                 |
| `sealAesGcm`                         | YES                 |
| `unsealAesGcm`                       | YES                 |
| `wrapKey`                            | YES                 |
| `unwrapKey`                          | YES                 |
| `signEd25519`                        | YES                 |
| `verifyEd25519`                      | YES                 |
| `deriveVaultIpnsKeypair`             | YES                 |
| `clearBytes`                         | YES                 |
| `hexToBytes`                         | YES                 |
| `bytesToHex`                         | YES                 |
| `generateFileKey`                    | YES                 |
| `generateIv`                         | YES                 |
| `deriveIpnsName`                     | YES                 |
| `deriveEd25519PublicKey`             | YES (replacement for `ed.getPublicKey`) |
| **`createIpnsRecord`**               | **NO — in `@cipherbox/core`** |
| **`marshalIpnsRecord`**              | **NO — in `@cipherbox/core`** |

### `@cipherbox/core` — confirmed symbols

| Symbol needed                | In core index.ts? |
| ---------------------------- | ----------------- |
| `createIpnsRecord`           | YES               |
| `marshalIpnsRecord`          | YES               |
| `deriveIpnsName`             | YES (also in crypto) |

### `@cipherbox/api-client` — exports confirmed [ASSUMED from source reading]

| Symbol used by scripts  | In api-client index.ts? |
| ----------------------- | ----------------------- |
| `createAxiosInstance`   | YES                     |

---

## tsx Availability and Invocation

- **Version:** `tsx@4.21.0` — already a root devDependency [VERIFIED: package.json]
- **Invocation in monorepo:** `pnpm exec tsx <file.ts>` or `node node_modules/.bin/tsx <file.ts>` (for spawnSync contexts where pnpm is not available)
- **ESM interop:** tsx handles ESM TypeScript natively; the workspace packages are all ESM-first (`"type": "module"` or `"module": "./dist/index.mjs"`). tsx strips types at runtime and runs ESM directly — no `moduleResolution` mismatch issues.
- **`moduleResolution: bundler`** in tsconfig.base.json: This works for tsx execution (tsx uses esbuild internally which uses bundler-like resolution). However, the dedicated scripts tsconfig should use `"moduleResolution": "node16"` or `"bundler"` — `bundler` is fine since tsx is the runtime.

---

## Dedicated Scripts Tsconfig (D-03)

### Recommended: `tsconfig.scripts.json` at repo root

```json
{
  "extends": "./tsconfig.base.json",
  "compilerOptions": {
    "noEmit": true,
    "moduleResolution": "bundler",
    "paths": {
      "@cipherbox/sdk-core": ["./packages/sdk-core/dist/index.d.ts"],
      "@cipherbox/crypto": ["./packages/crypto/dist/index.d.ts"],
      "@cipherbox/api-client": ["./packages/api-client/dist/index.d.ts"],
      "@cipherbox/core": ["./packages/core/dist/index.d.ts"]
    }
  },
  "include": [
    "packages/sdk-core/scripts/*.ts",
    "tests/desktop-e2e/scripts/*.ts",
    "tests/web-e2e/staging-perf-wallet.ts",
    "apps/desktop/src-tauri/generate-test-vectors.ts",
    "tests/e2e-helpers/**/*.ts"
  ]
}
```

The `paths` entries are the mechanism by which D-02 entrypoint imports resolve to the built `dist/*.d.ts` — so drift IS caught at tsc time if the dist is stale/wrong. This is the cross-package dist-staleness mechanism working as designed.

### Alternative: Per-location tsconfig references

Not recommended — five separate tsconfigs is more fragile and harder to lint-scope.

### Wiring into CI typecheck

The current `typecheck` root script is:

```bash
pnpm --filter @cipherbox/crypto build && pnpm --filter @cipherbox/core build && \
pnpm --filter @cipherbox/api-client build && pnpm --filter @cipherbox/sdk-core build && \
pnpm --filter @cipherbox/sdk build && pnpm --filter @cipherbox/web exec tsc -b
```

After this phase, add a `tsc -p tsconfig.scripts.json --noEmit` step at the end:

```bash
# In root package.json "typecheck" script:
... existing ... && tsc -p tsconfig.scripts.json --noEmit
```

The `pnpm typecheck` CI job in `.github/workflows/ci.yml` (step: "Run type checker") runs `pnpm typecheck` — this will pick up the new step automatically once the root script is updated.

The dep build order is already correct in the existing `typecheck` script (crypto → core → api-client → sdk-core → sdk → web). The new `tsc -p tsconfig.scripts.json` appended at the end will type-check the scripts against the already-built dist packages.

### Wiring into ESLint

The root `eslint.config.js` already covers `**/*.{js,mjs,cjs,ts,tsx}` globally with `ignores` for `dist`, `node_modules`, `.planning`, `.claude`. The `.ts` replacements will be picked up by eslint automatically — no config change needed for basic lint. For type-aware lint rules (`@typescript-eslint/no-unsafe-*` etc.), the tsconfig path would need to be registered in the flat config. Since the current config does NOT use type-aware rules (no `parserOptions.project`), no change is needed.

---

## Shared Helper Module Location (D-04)

### Option A: `tests/e2e-helpers/` (recommended)

Create `tests/e2e-helpers/` as a minimal TypeScript module (NOT a pnpm workspace package — no `package.json` needed, just a directory):

```
tests/e2e-helpers/
  auth.ts          # authenticate(), buildSdkContext(), parseArgs()
  types.ts         # AuthPayload type
```

Imported via relative path from each consumer:
- `packages/sdk-core/scripts/edit-filepointer.ts` → `import { authenticate, buildSdkContext } from '../../../tests/e2e-helpers/auth'`
- `tests/desktop-e2e/scripts/bump-ipns-sequence.ts` → `import { ... } from '../../e2e-helpers/auth'`
- `tests/web-e2e/staging-perf-wallet.ts` → `import { ... } from '../e2e-helpers/auth'` (but staging-perf-wallet doesn't use auth — so may not import at all)
- `apps/desktop/src-tauri/generate-test-vectors.ts` → `import { ... } from '../../../tests/e2e-helpers/auth'` (also no auth needed — so may not import)

**Concern:** `tests/e2e-helpers/` must be included in `tsconfig.scripts.json`'s `include` glob — it is, via `"tests/e2e-helpers/**/*.ts"`.

**pnpm workspace:** `tests/*` is a workspace glob in `pnpm-workspace.yaml`. A plain directory without a `package.json` is not a workspace package — it's just a directory. No workspace registration needed for relative imports.

### Option B: Dedicated `packages/test-helpers/` workspace package

Full workspace package with `package.json`, name `@cipherbox/test-helpers`, devDep in consumers. More formal but heavier for 2-3 utility functions.

**Recommendation: Option A** — a bare directory with no package.json, imported via relative paths, included in `tsconfig.scripts.json`. Lower ceremony.

---

## CI Typecheck Ordering (D-02 Companion)

The current `pnpm typecheck` (root `package.json` `scripts.typecheck`) already builds all dependency packages before running `tsc -b` on the web app. The scripts tsconfig must be checked AFTER this build, not before.

**Required order in `pnpm typecheck`:**

1. `pnpm --filter @cipherbox/crypto build`
2. `pnpm --filter @cipherbox/core build`
3. `pnpm --filter @cipherbox/api-client build`
4. `pnpm --filter @cipherbox/sdk-core build`
5. `pnpm --filter @cipherbox/sdk build`
6. `pnpm --filter @cipherbox/web exec tsc -b` (existing)
7. `tsc -p tsconfig.scripts.json --noEmit` (NEW — must be last, after all deps built)

This ordering ensures that if a symbol is removed from a `@cipherbox/*` package and the `dist` is rebuilt, the scripts tsconfig check in step 7 will catch any broken imports in the helper scripts.

---

## generate-test-vectors.mjs: Noble Library Resolution Strategy

The `generate-test-vectors.mjs` uses two `@noble` functions:

1. `getPublicKey` from `@noble/secp256k1` — used to derive ECIES public key from a fixed private key for the test vector.
2. `ed.getPublicKey` from `@noble/ed25519` — used to derive Ed25519 public key from a private key.

**Strategy for migration:**

- `ed.getPublicKey(privateKey)` → replace with `deriveEd25519PublicKey(privateKey)` which IS exported from `@cipherbox/crypto`. [ASSUMED: signature matches — `deriveEd25519PublicKey` takes a `Uint8Array` private key and returns the public key]
- `getPublicKey(eciesPrivateKey, false)` from `@noble/secp256k1` — no public `@cipherbox/crypto` equivalent. Options:
  - Add `@noble/secp256k1` as a direct devDependency to `apps/desktop` or `tests/e2e-helpers`. It is already a root-level `node_modules/@noble/secp256k1` (hoisted by pnpm). Import as `import { getPublicKey } from '@noble/secp256k1'` directly.
  - Note: `@noble/secp256k1` appears in root `node_modules` (confirmed above). The planner should add it as an explicit devDep to prevent hoist-dependent imports.

---

## Runner Update Inventory (Comprehensive)

Files that must change as part of D-06 (complete list):

| File                                                          | Change required                                             |
| ------------------------------------------------------------- | ----------------------------------------------------------- |
| `tests/desktop-e2e/scripts/run-all.sh`                        | `node test-move-content.mjs` → `pnpm exec tsx test-move-content.ts` |
| `tests/desktop-e2e/scripts/run-all.ps1`                       | `& node ... test-move-content.mjs` → `& pnpm exec tsx ... test-move-content.ts` |
| `tests/desktop-e2e/scripts/test-round-trip.sh`                | `node .../verify-filepointer.mjs` → `pnpm exec tsx .../verify-filepointer.ts` |
| `tests/desktop-e2e/scripts/test-round-trip.ps1`               | `& node $verifierPath` → `& pnpm exec tsx $verifierPath` (path updated to `.ts`) |
| `tests/desktop-e2e/scripts/test-cross-client-sync.sh`         | 3 `node` calls: verify/edit/rename → tsx                   |
| `tests/desktop-e2e/scripts/test-cross-client-sync.ps1`        | 2 `node` calls: verify/edit → tsx                          |
| `tests/desktop-e2e/scripts/test-conflict-detection.sh`        | `node .../bump-ipns-sequence.mjs` → tsx                    |
| `tests/desktop-e2e/scripts/test-conflict-detection.ps1`       | `& node $BumpScript` → tsx                                 |
| `packages/sdk-core/scripts/test-move-content.ts` (internal)   | `spawnSync(process.execPath, [VERIFY_SCRIPT, ...])` → spawnSync with tsx |

**staging-perf-wallet.mjs** has no runner — it is manually invoked. No runner file needs updating for it, but its comment `node staging-perf-wallet.mjs` should become `tsx staging-perf-wallet.ts` or `pnpm exec tsx staging-perf-wallet.ts`.

**generate-test-vectors.mjs** similarly has no runner — manual only. No runner file needs updating.

---

## Common Pitfalls

### Pitfall 1: `moduleResolution: bundler` vs node16 for tsconfig.scripts.json

**What goes wrong:** `moduleResolution: bundler` does not enforce `.ts` extension in imports (it uses bundler semantics). `node16` requires explicit extensions. tsx handles both at runtime. Using `bundler` is consistent with the rest of the monorepo.
**How to avoid:** Use `moduleResolution: bundler` in tsconfig.scripts.json (matches tsconfig.base.json). Relative imports should NOT include `.ts` extension in import statements when using bundler resolution.

### Pitfall 2: generate-test-vectors `@noble` deep path imports

**What goes wrong:** The current `.mjs` reaches `packages/crypto/node_modules/@noble/secp256k1/index.js` — a deep internal path. After migration to `.ts`, this path won't typecheck and may not resolve. Must explicitly add `@noble/secp256k1` as a devDependency.
**How to avoid:** Add `@noble/secp256k1` as devDep in the appropriate package (apps/desktop or a new scripts tsconfig scope). Import `{ getPublicKey } from '@noble/secp256k1'` directly. Replace `ed.getPublicKey` with `deriveEd25519PublicKey` from `@cipherbox/crypto`.

### Pitfall 3: test-move-content spawnSync uses `process.execPath`

**What goes wrong:** After renaming `verify-filepointer.mjs → verify-filepointer.ts`, the `spawnSync(process.execPath, [VERIFY_SCRIPT, ...])` pattern tries to run a `.ts` file with `node` directly (not tsx), which fails with a syntax error.
**How to avoid:** Change to `spawnSync('node', ['node_modules/.bin/tsx', VERIFY_SCRIPT, ...])` using the tsx shim, or use `pnpm exec tsx` via shell. The tsx path from `node_modules/.bin/tsx` is the most portable cross-platform option.

### Pitfall 4: `createIpnsRecord`/`marshalIpnsRecord` wrong package

**What goes wrong:** Migrating generate-test-vectors.mjs with the import from `@cipherbox/crypto` will produce a TypeScript error because those symbols are not exported from crypto. If the planner doesn't catch this, tsc will report the error at migration time (which is the desired outcome — but the executor must fix it, not ignore it).
**How to avoid:** Import `createIpnsRecord`, `marshalIpnsRecord` from `@cipherbox/core`.

### Pitfall 5: `test-cross-client-sync.sh` ensure_runtime guard checks for dist existence

**What goes wrong:** The dist existence check (`[ -f "$REPO_ROOT/packages/sdk-core/dist/index.mjs" ]`) still works correctly after D-02 migration since the entrypoint imports are resolved against dist at tsc time AND at runtime (tsx still resolves the workspace entrypoint to `dist/index.mjs`). The guard is benign and can remain.
**Warning signs:** If the guard triggers a build that breaks tsx entrypoint resolution — unlikely since tsx invokes pnpm workspace resolution the same way.

### Pitfall 6: `noUnusedLocals`/`noUnusedParameters` in tsconfig.base.json

**What goes wrong:** The base tsconfig sets `"noUnusedLocals": true` and `"noUnusedParameters": true`. Helper scripts that destructure but don't use every field will fail tsc. Pattern: `const { newSequenceNumber } = await updateFolderMetadataAndPublish(...)` where only `newSequenceNumber` is used — this is fine. Watch for catch clauses like `catch { /* noop */ }` which need `catch (_e) { }` under strict mode.
**How to avoid:** Add `_` prefix to intentionally unused catch bindings. Review scripts for bare `catch {}` blocks.

---

## Don't Hand-Roll

| Problem                    | Don't Build             | Use Instead                   | Why                                               |
| -------------------------- | ----------------------- | ----------------------------- | ------------------------------------------------- |
| Running `.ts` directly     | Custom esbuild pipeline | `tsx` (already installed)     | tsx handles ESM + TS in one command, no config    |
| Type-safe axios instance   | Custom HTTP wrapper     | `createAxiosInstance` from `@cipherbox/api-client` | Already typed with token injection |
| IPNS record creation       | Manual protobuf impl    | `createIpnsRecord` from `@cipherbox/core` | Verified correct wire format |
| Shared auth helper         | Auth in each script     | D-04 shared module            | 5-way duplication; one place to absorb drift      |

---

## Validation Architecture

### Test Framework

| Property           | Value                                     |
| ------------------ | ----------------------------------------- |
| Framework          | tsc (typecheck) + eslint (lint) + tsx dry-run |
| Config file        | `tsconfig.scripts.json` (new)             |
| Quick run command  | `tsc -p tsconfig.scripts.json --noEmit`   |
| Full suite command | `pnpm typecheck` (includes scripts tsconfig) |

No unit test framework is appropriate for this migration — these are CLI scripts, not libraries. Validation is behavioral (the E2E suites themselves) and static (tsc + eslint).

### Phase Requirements → Test Map

| Req ID  | Behavior                                             | Test Type   | Automated Command                                                      | File Exists? |
| ------- | ---------------------------------------------------- | ----------- | ---------------------------------------------------------------------- | ------------ |
| HARD-05 | Migrated scripts typecheck without errors            | tsc         | `tsc -p tsconfig.scripts.json --noEmit`                               | Wave 0: create tsconfig.scripts.json |
| HARD-05 | Migrated scripts pass eslint                         | lint        | `eslint packages/sdk-core/scripts/ tests/desktop-e2e/scripts/ tests/web-e2e/staging-perf-wallet.ts apps/desktop/src-tauri/generate-test-vectors.ts` | Auto (flat config) |
| HARD-05 | tsx can execute each migrated script (smoke)         | smoke       | `tsx packages/sdk-core/scripts/verify-filepointer.ts --help 2>&1; echo exit:$?` (will fail on missing args, not syntax) | Manual |
| HARD-05 | Desktop E2E suite passes post-migration              | e2e (manual) | `bash tests/desktop-e2e/scripts/run-all.sh` (requires live stack)     | Existing     |
| HARD-05 | run-all.sh and run-all.ps1 updated in lockstep       | manual review | diff both files — both must change `node *.mjs` → `tsx *.ts`          | Existing     |

### Sampling Rate

- **Per script migration commit:** `tsc -p tsconfig.scripts.json --noEmit && eslint <migrated-file.ts>`
- **Phase gate:** `pnpm typecheck` green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `tsconfig.scripts.json` — does not yet exist; must be created before any `.ts` files are written
- [ ] `tests/e2e-helpers/auth.ts` — shared helper does not yet exist
- [ ] `packages/sdk-core/scripts/*.ts`, `tests/desktop-e2e/scripts/*.ts`, etc. — none exist yet (all `.mjs`)

---

## Security Domain

> ASVS check: this phase is tooling/test-infra only — no app-runtime code changes. No server-side auth, session, or cryptographic logic is changed. The scripts themselves handle test credentials (TEST_SECRET env var) but these are not production secrets. No ASVS controls apply to the migration itself.

| ASVS Category         | Applies  | Standard Control                    |
| --------------------- | -------- | ----------------------------------- |
| V2 Authentication     | no       | —                                   |
| V3 Session Management | no       | —                                   |
| V4 Access Control     | no       | —                                   |
| V5 Input Validation   | no       | Scripts parse CLI args (no change)  |
| V6 Cryptography       | no       | Crypto operations unchanged         |

**Security note:** The scripts already enforce `TEST_SECRET` from env (not CLI). The migration must preserve this pattern and must not introduce any new secret-handling logic. The type migration does not change how secrets flow.

---

## Package Legitimacy Audit

No new external packages are introduced by this phase. `tsx` is already a devDependency. `@noble/secp256k1` already exists in `node_modules` (hoisted from packages/crypto devDeps). All packages in scope are existing dependencies.

| Package          | Registry | Verdict | Disposition                                                        |
| ---------------- | -------- | ------- | ------------------------------------------------------------------ |
| `tsx`            | npm      | OK      | Already installed at v4.21.0                                       |
| `@noble/secp256k1` | npm    | OK      | Already in repo as devDep of `packages/crypto`; add explicit devDep to scope |

**Packages removed:** none.
**Packages flagged:** none.

---

## Environment Availability

| Dependency      | Required By                   | Available | Version   | Fallback |
| --------------- | ----------------------------- | --------- | --------- | -------- |
| `tsx`           | Script execution              | ✓         | 4.21.0    | —        |
| `typescript`    | tsc typecheck                 | ✓         | ^5.9.3    | —        |
| `node`          | tsx runtime                   | ✓         | 22        | —        |
| `pnpm`          | workspace commands            | ✓         | (managed) | —        |

All required tools are available. No blocking dependencies.

---

## State of the Art

| Old Approach                    | Current Approach                    | When Changed    | Impact                                                     |
| ------------------------------- | ----------------------------------- | --------------- | ---------------------------------------------------------- |
| `node file.mjs` (untyped)       | `tsx file.ts` (typed)               | This phase      | tsc/eslint catches SDK drift before E2E runtime            |
| `../dist/*.mjs` relative import | `@cipherbox/pkg` entrypoint import  | This phase      | Entrypoint contracts are type-checked                      |
| No coverage for helper scripts  | Included in CI typecheck job        | This phase      | Fast failure on contract drift in every PR                 |

---

## Assumptions Log

| #  | Claim                                                                                       | Section                          | Risk if Wrong                                                                    |
| -- | ------------------------------------------------------------------------------------------- | -------------------------------- | -------------------------------------------------------------------------------- |
| A1 | `deriveEd25519PublicKey` in `@cipherbox/crypto` takes `Uint8Array` private key and returns `Uint8Array` public key (drop-in for `ed.getPublicKey`) | generate-test-vectors entrypoint gap | generate-test-vectors.ts would need to add `@noble/ed25519` devDep directly |
| A2 | `generate-test-vectors.mjs` currently works via coincidental resolution of `createIpnsRecord` from the crypto dist path | D-02 gap analysis | If it actually throws at runtime today, the gap is already known and we only need to fix the import |
| A3 | `@noble/secp256k1` is hoisted to root `node_modules` by pnpm and importable from scripts without a devDep declaration | generate-test-vectors noble libs | Would need explicit devDep on apps/desktop or tests/e2e-helpers |
| A4 | staging-perf-wallet.mjs is not invoked by any automated CI pipeline (only manual runs) | Runner invocation map | If CI does invoke it, a web-e2e workflow change is also needed |

---

## Open Questions

1. **Where to declare `@noble/secp256k1` devDependency for generate-test-vectors.ts?**
   - What we know: The script needs it but it's currently accessed via deep internal path.
   - What's unclear: Whether to add it to `apps/desktop`, `tests/e2e-helpers`, or just note it's hoisted.
   - Recommendation: Add as devDep to `apps/desktop` since that's the script's home directory.

2. **Should `rename-folder.mjs` invocation in `test-cross-client-sync.ps1` be added?**
   - What we know: `test-cross-client-sync.sh` calls `rename-folder.mjs`; `test-cross-client-sync.ps1` does NOT currently call it.
   - What's unclear: Whether the Windows runner's missing rename-folder call is intentional or an existing divergence bug.
   - Recommendation: Do NOT change `.ps1` behavior as part of D-07 (behavior-preserving). Note the divergence and flag it as a separate issue.

---

## Sources

### Primary (HIGH confidence)

- Direct reading of all 7 `.mjs` scripts — imports, CLI contracts, invocation patterns
- Direct reading of `packages/{sdk-core,crypto,core,api-client}/src/index.ts` — exported symbol verification
- Direct reading of `tests/desktop-e2e/scripts/run-all.sh` and `run-all.ps1` — runner invocation patterns
- Direct reading of `tests/desktop-e2e/scripts/test-round-trip.{sh,ps1}`, `test-conflict-detection.{sh,ps1}`, `test-cross-client-sync.{sh,ps1}` — complete node invocation inventory
- Direct reading of `.github/workflows/ci.yml` — `pnpm typecheck` script and CI job structure
- Direct reading of `package.json` scripts, `tsconfig.base.json`, `eslint.config.js`

### Secondary (MEDIUM confidence)

- tsx v4.21.0 behavior with ESM + bundler moduleResolution — based on known tsx design [ASSUMED]

### Tertiary (LOW confidence)

- `deriveEd25519PublicKey` signature compatibility with `ed.getPublicKey` pattern [A1 above]

---

## Metadata

**Confidence breakdown:**

- Script inventory and imports: HIGH — read all 7 scripts directly
- D-02 entrypoint gap analysis: HIGH — verified against source index.ts files
- Runner invocation inventory: HIGH — read all 6 runner/sub-scripts
- CI ordering strategy: HIGH — read ci.yml and root package.json scripts
- tsx/tsconfig wiring: MEDIUM — known behavior, not tested against this exact config
- generate-test-vectors noble libs: MEDIUM — one assumption on A1

**Research date:** 2026-06-19
**Valid until:** 2026-09-19 (stable tooling)

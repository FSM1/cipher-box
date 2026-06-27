# Phase 54: E2E Test-Infra Typing - Pattern Map

**Mapped:** 2026-06-19
**Files analyzed:** 18 (7 migrated scripts + 1 shared helper + 1 tsconfig + 8 runner scripts + 1 root package.json typecheck script)
**Analogs found:** 18 / 18

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `tests/e2e-helpers/auth.ts` | shared-lib | request-response | `packages/sdk-core/scripts/edit-filepointer.mjs` (auth block extraction) | role-match |
| `packages/sdk-core/scripts/edit-filepointer.ts` | migrated-script | request-response | `packages/sdk-core/scripts/edit-filepointer.mjs` | exact (self) |
| `packages/sdk-core/scripts/rename-folder.ts` | migrated-script | request-response | `packages/sdk-core/scripts/edit-filepointer.mjs` | role-match |
| `packages/sdk-core/scripts/verify-filepointer.ts` | migrated-script | request-response | `packages/sdk-core/scripts/edit-filepointer.mjs` | role-match |
| `tests/desktop-e2e/scripts/test-move-content.ts` | migrated-script | file-I/O | `tests/desktop-e2e/scripts/test-move-content.mjs` | exact (self) |
| `tests/desktop-e2e/scripts/bump-ipns-sequence.ts` | migrated-script | request-response | `packages/sdk-core/scripts/edit-filepointer.mjs` | role-match |
| `tests/web-e2e/staging-perf-wallet.ts` | migrated-script | request-response | `tests/web-e2e/staging-perf-wallet.mjs` | exact (self) |
| `apps/desktop/src-tauri/generate-test-vectors.ts` | migrated-script | transform | `scripts/generate-test-vectors.ts` | exact |
| `tsconfig.scripts.json` | config | — | `packages/sdk-core/tsconfig.json` + `tsconfig.base.json` | role-match |
| `tests/desktop-e2e/scripts/run-all.sh` | runner-script | — | `tests/desktop-e2e/scripts/run-all.sh` (self, line 121) | exact |
| `tests/desktop-e2e/scripts/run-all.ps1` | runner-script | — | `tests/desktop-e2e/scripts/run-all.ps1` (self, line 142-143) | exact |
| `tests/desktop-e2e/scripts/test-round-trip.sh` | runner-script | — | `tests/desktop-e2e/scripts/test-round-trip.sh` (self, line 53) | exact |
| `tests/desktop-e2e/scripts/test-round-trip.ps1` | runner-script | — | `tests/desktop-e2e/scripts/test-round-trip.ps1` (self, lines 76-84) | exact |
| `tests/desktop-e2e/scripts/test-cross-client-sync.sh` | runner-script | — | `tests/desktop-e2e/scripts/test-cross-client-sync.sh` (self, lines 59-81) | exact |
| `tests/desktop-e2e/scripts/test-cross-client-sync.ps1` | runner-script | — | `tests/desktop-e2e/scripts/test-cross-client-sync.ps1` (self, lines 77-98) | exact |
| `tests/desktop-e2e/scripts/test-conflict-detection.sh` | runner-script | — | `tests/desktop-e2e/scripts/test-conflict-detection.sh` (self, line 95-96) | exact |
| `tests/desktop-e2e/scripts/test-conflict-detection.ps1` | runner-script | — | `tests/desktop-e2e/scripts/test-conflict-detection.ps1` (self, lines 113-115) | exact |
| `package.json` (`typecheck` script) | CI-wiring | — | `package.json` line 14 (self, extend pattern) | exact |

---

## Pattern Assignments

### `tsconfig.scripts.json` (config)

**Analog:** `packages/sdk-core/tsconfig.json` (same `extends` pattern) + `tsconfig.base.json` (the base)

**Base tsconfig.base.json** (`tsconfig.base.json`, lines 1-21):

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "strictNullChecks": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "noEmit": false,
    "isolatedModules": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true
  }
}
```

**`extends` pattern from** `packages/sdk-core/tsconfig.json` (lines 1-9):

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src"
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

**New `tsconfig.scripts.json` (repo root) — copy this structure:**

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

Key differences from the package tsconfigs: `noEmit: true` (no build output), `paths` entries map entrypoint names to dist `.d.ts` files (D-02 enforcement), no `outDir`/`rootDir`, `include` spans multiple directory trees.

**Note on `noUnusedLocals`/`noUnusedParameters`:** Both are `true` in `tsconfig.base.json`. Catch-clause bindings in migrated scripts must use `_e` prefix for unused bindings (`catch (_e) {}`).

---

### `tests/e2e-helpers/auth.ts` (shared-lib, D-04)

**Analog:** `packages/sdk-core/scripts/edit-filepointer.mjs` — the D-04 extraction source

**Auth block to extract** (`edit-filepointer.mjs`, lines 77-96):

```typescript
// Extracted as: export async function authenticate(...)
async function authenticate(apiUrl, email, secret) {
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

  if (!payload.accessToken || !payload.privateKeyHex || !payload.publicKeyHex) {
    throw new Error('test-login response missing accessToken, privateKeyHex, or publicKeyHex');
  }

  return payload;
}
```

**ctx construction to extract** (`edit-filepointer.mjs`, lines 105-114):

```typescript
// Extracted as: export function buildSdkContext(...)
const axiosInstance = createAxiosInstance({
  baseUrl: args.apiUrl,
  getAccessToken: async () => accessToken,
});

const ctx = {
  apiUrl: args.apiUrl,
  getAccessToken: async () => accessToken,
  axiosInstance,
};
```

**parseArgs pattern to extract** (`edit-filepointer.mjs`, lines 39-75 — the generic arg-parsing block is also duplicated across scripts):

```typescript
// Pattern: Map-based arg parser; throw on --secret; validate required keys
function parseArgs(argv: string[]): Record<string, string> {
  const values = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) throw new Error(`Unexpected argument: ${token}`);
    const key = token.slice(2);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`Missing value for --${key}`);
    values.set(key, value);
    i += 1;
  }
  if (values.has('secret')) {
    throw new Error('Do not pass --secret on CLI. Set TEST_SECRET in environment.');
  }
  return Object.fromEntries(values);
}
```

**Typed exports the module must provide:**

```typescript
// tests/e2e-helpers/auth.ts — full typed shape

import { createAxiosInstance } from '@cipherbox/api-client';
import type { SdkContext } from '@cipherbox/sdk-core';

export interface AuthPayload {
  accessToken: string;
  privateKeyHex: string;
  publicKeyHex?: string;
}

export async function authenticate(
  apiUrl: string,
  email: string,
  secret: string,
): Promise<AuthPayload> { ... }

export function buildSdkContext(apiUrl: string, accessToken: string): SdkContext { ... }

export function parseCliArgs(argv: string[]): Record<string, string> { ... }
```

---

### `packages/sdk-core/scripts/edit-filepointer.ts` (migrated-script)

**Analog:** `packages/sdk-core/scripts/edit-filepointer.mjs` (self — identical logic)

**Import block to replace** (lines 18-37 of `.mjs`):

```javascript
// BEFORE (remove these dist-relative imports):
import { createAxiosInstance } from '../../api-client/dist/index.mjs';
import { loadVaultKeyBlob, loadFolderMetadata, resolveFileMetadata,
         updateFileMetadata, updateFolderMetadataAndPublish } from '../dist/index.mjs';
import { encryptAesGcm, generateFileKey, generateIv, wrapKey, unwrapKey,
         bytesToHex, hexToBytes, deriveVaultIpnsKeypair, clearBytes } from '../../crypto/dist/index.mjs';
import { addToIpfs } from '../dist/index.mjs';
```

```typescript
// AFTER (entrypoint imports + D-04 shared helper):
import { loadVaultKeyBlob, loadFolderMetadata, resolveFileMetadata,
         updateFileMetadata, updateFolderMetadataAndPublish, addToIpfs,
         type SdkContext } from '@cipherbox/sdk-core';
import { encryptAesGcm, generateFileKey, generateIv, wrapKey, unwrapKey,
         bytesToHex, hexToBytes, deriveVaultIpnsKeypair, clearBytes } from '@cipherbox/crypto';
import { authenticate, buildSdkContext, parseCliArgs } from '../../../tests/e2e-helpers/auth';
```

**main() structure to preserve** (lines 98-255 of `.mjs`) — body logic is unchanged, only the top-level `parseArgs(process.argv.slice(2))` call becomes `parseCliArgs(process.argv.slice(2))` and auth/ctx blocks are replaced by shared helper calls.

**Error exit pattern** (line 251-255 of `.mjs`):

```typescript
main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
```

---

### `packages/sdk-core/scripts/rename-folder.ts` (migrated-script)

**Analog:** `packages/sdk-core/scripts/rename-folder.mjs` (self)

**Import block to replace:**

```javascript
// BEFORE:
import { createAxiosInstance } from '../../api-client/dist/index.mjs';
import { loadVaultKeyBlob, loadFolderMetadata, renameInFolder,
         updateFolderMetadataAndPublish } from '../dist/index.mjs';
import { deriveVaultIpnsKeypair, clearBytes } from '../../crypto/dist/index.mjs';
```

```typescript
// AFTER:
import { loadVaultKeyBlob, loadFolderMetadata, renameInFolder,
         updateFolderMetadataAndPublish, type SdkContext } from '@cipherbox/sdk-core';
import { deriveVaultIpnsKeypair, clearBytes } from '@cipherbox/crypto';
import { authenticate, buildSdkContext, parseCliArgs } from '../../../tests/e2e-helpers/auth';
```

---

### `packages/sdk-core/scripts/verify-filepointer.ts` (migrated-script)

**Analog:** `packages/sdk-core/scripts/verify-filepointer.mjs` (self)

**Import block to replace:**

```javascript
// BEFORE:
import { createAxiosInstance } from '../../api-client/dist/index.mjs';
import { downloadAndDecrypt, resolveFileMetadata, loadFolderMetadata,
         loadVaultKeyBlob } from '../dist/index.mjs';
import { unwrapKey, hexToBytes } from '../../crypto/dist/index.mjs';
```

```typescript
// AFTER:
import { downloadAndDecrypt, resolveFileMetadata, loadFolderMetadata,
         loadVaultKeyBlob, type SdkContext } from '@cipherbox/sdk-core';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import { authenticate, buildSdkContext, parseCliArgs } from '../../../tests/e2e-helpers/auth';
```

---

### `tests/desktop-e2e/scripts/bump-ipns-sequence.ts` (migrated-script)

**Analog:** `tests/desktop-e2e/scripts/bump-ipns-sequence.mjs` (self)

**Import block to replace:**

```javascript
// BEFORE (note: uses deeper ../../../packages/... relative paths):
import { createAxiosInstance } from '../../../packages/api-client/dist/index.mjs';
import { loadVaultKeyBlob, loadFolderMetadata,
         updateFolderMetadataAndPublish } from '../../../packages/sdk-core/dist/index.mjs';
import { deriveVaultIpnsKeypair, clearBytes } from '../../../packages/crypto/dist/index.mjs';
```

```typescript
// AFTER:
import { loadVaultKeyBlob, loadFolderMetadata,
         updateFolderMetadataAndPublish, type SdkContext } from '@cipherbox/sdk-core';
import { deriveVaultIpnsKeypair, clearBytes } from '@cipherbox/crypto';
import { authenticate, buildSdkContext, parseCliArgs } from '../../e2e-helpers/auth';
```

---

### `tests/desktop-e2e/scripts/test-move-content.ts` (migrated-script, file-I/O)

**Analog:** `tests/desktop-e2e/scripts/test-move-content.mjs` (self — Node stdlib only, no `@cipherbox/*` imports)

**Import block unchanged** — only Node built-ins:

```typescript
import { mkdirSync, writeFileSync, readdirSync, statSync, rmSync, renameSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
```

**Critical change — VERIFY_SCRIPT spawn** (`test-move-content.mjs`, lines 27-28):

```javascript
// BEFORE (from RESEARCH.md):
const VERIFY_SCRIPT = join(REPO_ROOT, 'packages/sdk-core/scripts/verify-filepointer.mjs');
// spawned via:
spawnSync(process.execPath, [VERIFY_SCRIPT, ...args], ...)
```

```typescript
// AFTER:
const VERIFY_SCRIPT = join(REPO_ROOT, 'packages/sdk-core/scripts/verify-filepointer.ts');
// spawned via tsx from node_modules/.bin:
spawnSync('node', [join(REPO_ROOT, 'node_modules/.bin/tsx'), VERIFY_SCRIPT, ...cliArgs], {
  env: { ...process.env, TEST_SECRET: secret },
  stdio: 'inherit',
})
```

---

### `tests/web-e2e/staging-perf-wallet.ts` (migrated-script)

**Analog:** `tests/web-e2e/staging-perf-wallet.mjs` (self — Playwright + viem only, no `@cipherbox/*`)

**Import block unchanged** — only external packages already in `tests/web-e2e/package.json`:

```typescript
import { chromium } from '@playwright/test';
import { installMockWallet } from '@johanneskares/wallet-mock';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import { custom } from 'viem';
```

No D-04 shared helper needed (no `@cipherbox/*` auth in this script).

---

### `apps/desktop/src-tauri/generate-test-vectors.ts` (migrated-script, transform)

**Analog:** `scripts/generate-test-vectors.ts` — an existing root-level `.ts` script using `@noble/secp256k1` directly and importing from `packages/crypto/dist/index.mjs`

**Analog imports** (`scripts/generate-test-vectors.ts`, lines 11-23):

```typescript
import * as secp256k1 from '@noble/secp256k1';
import {
  wrapKey,
  unwrapKey,
  encryptFolderMetadata,
  decryptFolderMetadata,
  generateIv,
  hexToBytes,
  bytesToHex,
  type FolderMetadata,
} from '../packages/crypto/dist/index.mjs';
```

**Note:** The existing `scripts/generate-test-vectors.ts` still uses the dist-relative path `../packages/crypto/dist/index.mjs` — it is NOT using the entrypoint. The new `apps/desktop/src-tauri/generate-test-vectors.ts` MUST use entrypoints per D-02.

**Import block to replace for `apps/desktop/src-tauri/generate-test-vectors.ts`:**

```javascript
// BEFORE (current .mjs — deep internal paths):
import { encryptAesGcm, decryptAesGcm, sealAesGcm, unsealAesGcm, wrapKey, unwrapKey,
         signEd25519, verifyEd25519, createIpnsRecord, marshalIpnsRecord, deriveIpnsName,
         hexToBytes, bytesToHex } from '../../../packages/crypto/dist/index.mjs';
import { getPublicKey } from '../../../packages/crypto/node_modules/@noble/secp256k1/index.js';
import * as ed from '../../../packages/crypto/node_modules/@noble/ed25519/index.js';
```

```typescript
// AFTER (D-02 entrypoint imports + corrected package for IPNS symbols):
import { encryptAesGcm, decryptAesGcm, sealAesGcm, unsealAesGcm, wrapKey, unwrapKey,
         signEd25519, verifyEd25519, deriveIpnsName, deriveEd25519PublicKey,
         hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core'; // NOT @cipherbox/crypto
import { getPublicKey } from '@noble/secp256k1'; // explicit devDep on apps/desktop
// ed.getPublicKey(privateKey) -> replaced by deriveEd25519PublicKey(privateKey) from @cipherbox/crypto
```

**D-02 critical gap:** `createIpnsRecord` and `marshalIpnsRecord` MUST come from `@cipherbox/core`, not `@cipherbox/crypto` (they are absent from the crypto entrypoint).

**noble library pattern** — borrow from `scripts/generate-test-vectors.ts` line 11: `import * as secp256k1 from '@noble/secp256k1'` (already a root devDependency at `^3.0.0`, line 26 of root `package.json`).

**main() structure to preserve** (`scripts/generate-test-vectors.ts`, lines 38+):

```typescript
async function main(): Promise<void> {
  // ...
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

---

## Shared Patterns

### D-04 Auth/Ctx Pattern (apply to all 5 SDK-calling migrated scripts)

**Source:** `packages/sdk-core/scripts/edit-filepointer.mjs`, lines 77-114

Extract to `tests/e2e-helpers/auth.ts`. All 5 scripts (edit-filepointer, rename-folder, verify-filepointer, bump-ipns-sequence, and the test-move-content internal spawn path) replace their inline auth blocks with calls to the shared module.

### Error exit pattern (apply to all 7 migrated scripts)

**Source:** `packages/sdk-core/scripts/edit-filepointer.mjs`, lines 251-255

```typescript
main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
```

### noUnusedLocals guard (apply to all 7 migrated scripts)

`tsconfig.base.json` has `"noUnusedLocals": true` and `"noUnusedParameters": true`. In migrated scripts:
- Unused catch bindings: `catch (_e) {` not bare `catch {`
- Unused destructured fields: prefix with `_`

---

## Runner Script Pattern Assignments

### `tests/desktop-e2e/scripts/run-all.sh` (line 121)

**Before:**

```bash
TEST_SECRET="$TEST_SECRET" node "$SCRIPT_DIR/test-move-content.mjs" --mount "$MOUNT_POINT" --api-url "$API_URL"
```

**After:**

```bash
TEST_SECRET="$TEST_SECRET" pnpm exec tsx "$SCRIPT_DIR/test-move-content.ts" --mount "$MOUNT_POINT" --api-url "$API_URL"
```

### `tests/desktop-e2e/scripts/run-all.ps1` (lines 142-143)

**Before:**

```powershell
& node "$PSScriptRoot\test-move-content.mjs" --mount $MountPoint --api-url $ApiUrl
```

**After:**

```powershell
& pnpm exec tsx "$PSScriptRoot\test-move-content.ts" --mount $MountPoint --api-url $ApiUrl
```

### `tests/desktop-e2e/scripts/test-round-trip.sh` (line 53)

**Before:**

```bash
TEST_SECRET="$SECRET" node "$REPO_ROOT/packages/sdk-core/scripts/verify-filepointer.mjs" \
  --api-url "$API_URL" --email "$TEST_EMAIL" --file-name "$TEST_FILE" --expected-content "$TEST_CONTENT"
```

**After:**

```bash
TEST_SECRET="$SECRET" pnpm exec tsx "$REPO_ROOT/packages/sdk-core/scripts/verify-filepointer.ts" \
  --api-url "$API_URL" --email "$TEST_EMAIL" --file-name "$TEST_FILE" --expected-content "$TEST_CONTENT"
```

### `tests/desktop-e2e/scripts/test-round-trip.ps1` (lines 76-84)

**Before:**

```powershell
$verifierPath = Join-Path $RepoRoot "packages/sdk-core/scripts/verify-filepointer.mjs"
$env:TEST_SECRET = $TestSecret
$output = & node $verifierPath `
    --api-url $ApiUrl --email $TestEmail --file-name $TestFile --expected-content $TestContent 2>&1 | Out-String
```

**After:**

```powershell
$verifierPath = Join-Path $RepoRoot "packages/sdk-core/scripts/verify-filepointer.ts"
$env:TEST_SECRET = $TestSecret
$output = & pnpm exec tsx $verifierPath `
    --api-url $ApiUrl --email $TestEmail --file-name $TestFile --expected-content $TestContent 2>&1 | Out-String
```

**Note:** The `Ensure-VerifierRuntime` function in `test-round-trip.ps1` (lines 46-64) and `ensure_verifier_runtime` in `test-round-trip.sh` (lines 41-50) check for `dist/index.mjs` existence. These guards remain valid after migration since tsx still resolves `@cipherbox/sdk-core` to `dist/index.mjs` at runtime. The guards can be retained as-is.

### `tests/desktop-e2e/scripts/test-cross-client-sync.sh` (lines 59-81)

Three `node` calls to change:

```bash
# Line 60 — BEFORE:
TEST_SECRET="$SECRET" node "$REPO_ROOT/packages/sdk-core/scripts/verify-filepointer.mjs" ...
# AFTER:
TEST_SECRET="$SECRET" pnpm exec tsx "$REPO_ROOT/packages/sdk-core/scripts/verify-filepointer.ts" ...

# Line 68 — BEFORE:
TEST_SECRET="$SECRET" node "$REPO_ROOT/packages/sdk-core/scripts/edit-filepointer.mjs" ...
# AFTER:
TEST_SECRET="$SECRET" pnpm exec tsx "$REPO_ROOT/packages/sdk-core/scripts/edit-filepointer.ts" ...

# Line 76 — BEFORE:
TEST_SECRET="$SECRET" node "$REPO_ROOT/packages/sdk-core/scripts/rename-folder.mjs" ...
# AFTER:
TEST_SECRET="$SECRET" pnpm exec tsx "$REPO_ROOT/packages/sdk-core/scripts/rename-folder.ts" ...
```

### `tests/desktop-e2e/scripts/test-cross-client-sync.ps1` (lines 77-98)

Two helper functions to update:

```powershell
# Invoke-SdkVerify (line 79) — BEFORE:
$verifierPath = Join-Path $RepoRoot "packages/sdk-core/scripts/verify-filepointer.mjs"
$output = & node $verifierPath ...
# AFTER:
$verifierPath = Join-Path $RepoRoot "packages/sdk-core/scripts/verify-filepointer.ts"
$output = & pnpm exec tsx $verifierPath ...

# Invoke-SdkEdit (line 91) — BEFORE:
$editorPath = Join-Path $RepoRoot "packages/sdk-core/scripts/edit-filepointer.mjs"
$output = & node $editorPath ...
# AFTER:
$editorPath = Join-Path $RepoRoot "packages/sdk-core/scripts/edit-filepointer.ts"
$output = & pnpm exec tsx $editorPath ...
```

### `tests/desktop-e2e/scripts/test-conflict-detection.sh` (line 95-96)

```bash
# BEFORE:
if TEST_SECRET="$SECRET" node "$SCRIPT_DIR/bump-ipns-sequence.mjs" \
  --api-url "$API_URL" --email "$TEST_EMAIL"; then
# AFTER:
if TEST_SECRET="$SECRET" pnpm exec tsx "$SCRIPT_DIR/bump-ipns-sequence.ts" \
  --api-url "$API_URL" --email "$TEST_EMAIL"; then
```

### `tests/desktop-e2e/scripts/test-conflict-detection.ps1` (lines 113-115)

```powershell
# BEFORE:
$BumpScript = Join-Path $PSScriptRoot "bump-ipns-sequence.mjs"
$env:TEST_SECRET = $TestSecret
& node $BumpScript --api-url $ApiUrl --email $TestEmail
# AFTER:
$BumpScript = Join-Path $PSScriptRoot "bump-ipns-sequence.ts"
$env:TEST_SECRET = $TestSecret
& pnpm exec tsx $BumpScript --api-url $ApiUrl --email $TestEmail
```

---

### `package.json` typecheck script (CI-wiring)

**Source:** `package.json`, line 14

**Before:**

```json
"typecheck": "pnpm --filter @cipherbox/crypto build && pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/api-client build && pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk build && pnpm --filter @cipherbox/web exec tsc -b"
```

**After (append `tsc -p tsconfig.scripts.json --noEmit` at end):**

```json
"typecheck": "pnpm --filter @cipherbox/crypto build && pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/api-client build && pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk build && pnpm --filter @cipherbox/web exec tsc -b && tsc -p tsconfig.scripts.json --noEmit"
```

The `tsc -p tsconfig.scripts.json --noEmit` step must be last — it depends on all `dist` packages being built by the preceding steps. The CI `typecheck` job (`ci.yml` line 80: `run: pnpm typecheck`) picks this up automatically with no workflow file changes.

---

### ESLint (no changes needed)

**Source:** `eslint.config.js`, lines 1-32

The flat config already covers `**/*.{js,mjs,cjs,ts,tsx}` globally (line 20). The `.ts` replacements for `.mjs` files fall under this glob automatically. No type-aware rules (`parserOptions.project`) are configured — the config uses `tseslint.configs.recommended` without project wiring (line 23). No `eslint.config.js` change is needed.

---

## No Analog Found

None — all files have close analogs in this codebase.

---

## Metadata

**Analog search scope:** `packages/`, `tests/`, `apps/`, `scripts/`, root config files
**Files scanned:** ~20 source files
**Pattern extraction date:** 2026-06-19

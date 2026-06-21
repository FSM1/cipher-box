---
phase: 54
slug: e2e-test-infra-typing
verdict: PASS
verified: 2026-06-20
verifier: gsd-verifier (goal-backward)
---

# Phase 54 — Verification (E2E Test-Infra Typing)

## Verdict: PASS

Phase 54 delivered its goal in full. All 7 hand-written `.mjs` E2E helper
scripts are migrated to typed `.ts`; a shared typed auth/ctx/arg helper
(`tests/e2e-helpers/{auth,types}.ts`) exists and is consumed by every script;
all 8 desktop-e2e runner scripts invoke the helpers via `tsx <name>.ts` in
`.sh`/`.ps1` lockstep; no `.mjs` remains in the migrated paths and there are no
dangling `.mjs` references; the dedicated `tsconfig.scripts.json` gate is wired
last into the root `typecheck` chain. The static gate (`pnpm typecheck` +
`pnpm lint`) was reported green by the parent session and the structural facts
underpinning it were spot-checked here. Behavior is preserved per D-07. The only
live behavioral check (desktop `run-all.sh` + web-e2e) is correctly deferred to
manual/CI per 54-VALIDATION.md and is NOT a blocker for this static-migration
phase.

This is a pure test-infrastructure migration. It touches no application runtime,
no crypto primitives, no API endpoint/DTO/controller, and no IPNS publish/resolve
runtime. The migrated scripts are dev/test tooling not shipped to users.

---

## Goal-Backward Check

The phase goal (54-CONTEXT.md): convert all 7 `.mjs` E2E helper scripts to
TypeScript under HARD-05 so SDK/crypto/api-client contract drift is caught at
`tsc`/`eslint` time instead of 14 minutes into a single-OS E2E run on `main`,
with cross-platform runner parity and a shared typed helper — behavior unchanged.

Working backward from that goal, every required artifact is present and every
decision (D-01..D-07) is honored:

- D-01 (tsx runtime): runners invoke `pnpm exec tsx <name>.ts`; `tsconfig.scripts.json`
  is `noEmit`. tsx was already a root devDep (`^4.21.0`) — no new install.
- D-02 (entrypoint imports + dist-first ordering): scripts import `@cipherbox/*`
  package entrypoints; `tsconfig.scripts.json` `paths` map them to built
  `dist/index.d.ts`; the typecheck script builds crypto→core→api-client→sdk-core→sdk
  dist BEFORE `tsc -p tsconfig.scripts.json --noEmit` (drift is actually caught).
- D-03 (dedicated scripts tsconfig + eslint scope): `tsconfig.scripts.json` covers
  all 5 helper locations + `tests/e2e-helpers/**`; eslint's global `**/*.ts` glob
  already covers them (no eslint change needed).
- D-04 (shared helper): `tests/e2e-helpers/auth.ts` (`authenticate`,
  `buildSdkContext`, `parseCliArgs`) + `types.ts` (`AuthPayload`); all scripts import it.
- D-05 (all 7 migrated, no dist-relative imports): 0 tracked `.mjs`; 0
  `dist/index.mjs` relative imports in the `.ts` files.
- D-06 (both runner families in lockstep): every `node *.mjs` → `pnpm exec tsx *.ts`
  in both `.sh` and `.ps1`.
- D-07 (behavior-preserving): flows, CLI/env/stdout/exit contracts, and key
  zeroization preserved; the only deltas are type-narrowing guards (unreachable in
  practice) and a type-safe `in`-narrowing for the IPNS union.

---

## Per-Plan Criteria → Evidence

### Plan 01 — Foundation (tsconfig + shared helper)

| Criterion | Evidence |
| --------- | -------- |
| `tsconfig.scripts.json` created, extends base, `noEmit`, `paths` map 4 entrypoints to dist `.d.ts` | `tsconfig.scripts.json` (read): `extends ./tsconfig.base.json`, `noEmit: true`, `moduleResolution: bundler`, paths for sdk-core/crypto/api-client/core |
| `include` covers all 5 helper locations + `tests/e2e-helpers/**` | `tsconfig.scripts.json` `include` array — all 5 globs + `tests/e2e-helpers/**/*.ts` present |
| Root `typecheck` appends `tsc -p tsconfig.scripts.json --noEmit` LAST, after dep dist build | `package.json` diff: chain ends `… && pnpm --filter @cipherbox/web exec tsc -b && tsc -p tsconfig.scripts.json --noEmit` |
| `auth.ts` exports `authenticate`/`buildSdkContext`/`parseCliArgs` via entrypoint imports | `tests/e2e-helpers/auth.ts:13-14,23,51,70` — imports `createAxiosInstance` from `@cipherbox/api-client`, `type SdkContext` from `@cipherbox/sdk-core`; 3 exports present |
| `types.ts` `AuthPayload` with optional `publicKeyHex` (D-07) | `tests/e2e-helpers/types.ts:12-16` — `publicKeyHex?: string` optional |
| No `accessToken`/`privateKeyHex` logged; `--secret` CLI guard | `auth.ts:89-91` throws on `--secret`; grep: no token/key in any `console.*` |
| eslint covers `tests/e2e-helpers/*.ts` via global glob (no config change) | 54-01-SUMMARY §Task 3; eslint global `**/*.{js,mjs,cjs,ts,tsx}` |

### Plan 02 — sdk-core scripts (edit / rename / verify)

| Criterion | Evidence |
| --------- | -------- |
| `edit-filepointer.ts` migrated, entrypoint imports, shared helper, flow unchanged | `edit-filepointer.ts:18-38` imports; flow (encrypt→addToIpfs→updateFileMetadata→republish) intact |
| `rename-folder.ts` migrated, zeroization `finally { .fill(0); clearBytes() }` preserved | `rename-folder.ts:117-121` finally block intact |
| `verify-filepointer.ts` migrated; stdout JSON + exit contract byte-identical (spawned child) | `verify-filepointer.ts:145-162` JSON keys + `process.exit(1)` preserved |
| Key zeroization preserved (`clearBytes(fileKey)`, `fileIpnsPrivateKey.fill(0)`, root key `.fill(0)`) | `edit-filepointer.ts:153,178,206`; `rename-folder.ts:119-120` |
| No `dist/index.mjs` relative imports | 54-02-SUMMARY D-02 gate: `grep -c 'dist/index.mjs'` → `0,0,0` |
| tsc + eslint green | 54-02-SUMMARY Verification table (parent gate) |

### Plan 03 — remaining scripts (bump / move / staging-perf / gen-vectors)

| Criterion | Evidence |
| --------- | -------- |
| `bump-ipns-sequence.ts` migrated, entrypoint imports, `TEST_SECRET` env-only | `bump-ipns-sequence.ts:23-29,38`; zeroization `:98-99` |
| `test-move-content.ts` spawns verify child via tsx interpreter (`node` can't run `.ts`) | `test-move-content.ts:102` `spawnSync('node', [.../tsx, ...])`; `TEST_SECRET` forwarded in spawn env only `:103` |
| `staging-perf-wallet.ts` clean rename, typed (`ApiCall`, error guards), zero-arg contract | `staging-perf-wallet.ts:31-38` `ApiCall`; uses canonical public test wallet key only |
| `generate-test-vectors.ts` imports IPNS symbols from `@cipherbox/core` (D-02 fix), test vectors unchanged | `generate-test-vectors.ts:26` `createIpnsRecord/marshalIpnsRecord` from `@cipherbox/core`; 3 `PRIVATE_KEY` prints pre-exist on origin/main (`git show` count = 3, 0 new) |
| `@cipherbox/core` declared as apps/desktop devDep; lockfile updated | `apps/desktop/package.json` diff (+`@cipherbox/core: workspace:*`); lockfile `link:../../packages/core` |
| IPNS union `in`-narrowing preserves runtime behavior | `generate-test-vectors.ts:145` `if ('signatureV1' in ipnsRecord && …)` |

### Plan 04 — lockstep runner switch + .mjs removal

| Criterion | Evidence |
| --------- | -------- |
| 0 `node *.mjs` helper invocations across the 8 runners | grep gate: `0 node-mjs invocations` |
| ≥9 `tsx .ts` helper invocations in runners | grep gate: `9` |
| 0 tracked `.mjs` in the 7 migrated paths | `git ls-files` migrated globs → `0` |
| 0 dangling `.mjs` references in tests/apps/packages/scripts/.github | grep gate: `0 dangling .mjs references` |
| D-07 divergence preserved: `test-cross-client-sync.ps1` has 0 `rename-folder`; `.sh` has 1 | grep: ps1=0, sh=1 |
| `.sh`/`.ps1` parity for every swapped invocation (comments updated too) | runner diff: each `node X.mjs`→`pnpm exec tsx X.ts` in both families |
| Verifier dist-existence guards retained (tsx resolves `@cipherbox/sdk-core`→`dist/index.mjs` at runtime) | 54-04-SUMMARY §Verifier runtime guards |

---

## Static Gate (quoted from parent session; structurally spot-checked here)

| Gate | Result | Confirmation in this verification |
| ---- | ------ | --------------------------------- |
| `pnpm typecheck` (builds crypto/core/api-client/sdk-core/sdk dist + `tsc -p tsconfig.scripts.json --noEmit` + root) | exit 0 | `package.json` chain confirmed; not re-run (RAM/forbidden) |
| `pnpm lint` (`eslint .`) | exit 0 | global glob covers scripts; not re-run |
| 0 `node *.mjs` in 8 runners | pass | spot-checked: `0` |
| 9 `tsx .ts` invocations | pass | spot-checked: `9` |
| 0 tracked `.mjs` in migrated paths | pass | spot-checked: `0` |
| 0 dangling `.mjs` refs | pass | spot-checked: `0` |
| `test-cross-client-sync.ps1` 0 `rename-folder` (D-07) | pass | spot-checked: `0` |

Heavy gates (`pnpm typecheck`/`pnpm lint`/E2E) were NOT re-run here per project
memory (RAM-heavy suites forbidden for verifier agents). The parent session's
exit-0 results are quoted; the structural facts they depend on were independently
spot-checked with grep/read above.

---

## Manual Verification Required

These are live behavioral checks deferred per 54-VALIDATION.md — they require a
running stack/mount and are out of scope for static verification:

- **Desktop E2E suite (`bash tests/desktop-e2e/scripts/run-all.sh`)** against a
  live local stack + macFUSE mount: confirm each migrated script exits 0 with
  unchanged behavior through the `tsx` invocation. (web-e2e runs only on `main`
  push, not PRs.)
- **`generate-test-vectors` output parity**: run
  `pnpm exec tsx apps/desktop/src-tauri/generate-test-vectors.ts` and diff stdout
  against the pre-migration `.mjs` output — the Rust crypto-parity consumers
  (`crates/crypto/tests/cross_language.rs`) depend on byte-identical vectors.
  (Static evidence: the only computed-value-affecting change is
  `ed.getPublicKey → deriveEd25519PublicKey`, a verified byte-identical drop-in;
  the `in`-narrowing only gates an optional print line.)

No gap blocks the PASS verdict — these are inherent live-stack checks, not
deficiencies in the migration.

---

## Gaps / Risks

None blocking. Residual risk is the standard cross-package dist-staleness gotcha
(D-02), already mitigated by ordering the dep `dist` build before the scripts
`tsc` in the root `typecheck` script — so entrypoint drift surfaces at tsc time
rather than mid-E2E, which is precisely the phase goal.

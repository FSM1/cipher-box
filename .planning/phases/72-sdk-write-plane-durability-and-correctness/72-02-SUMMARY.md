---
phase: 72-sdk-write-plane-durability-and-correctness
plan: 02
subsystem: testing
tags: [vitest, sdk-e2e, sealedchildref, ed25519, write-chain-rotation, tsc]

# Dependency graph
requires:
  - phase: 72-01
    provides: moveInSharedFolder reachable-branch regression gate (SC#5 groundwork)
provides:
  - upload-batch.test.ts mocks rebuilt to the frozen SealedChildRef shape (no retired type/fileMetaIpnsName/ipnsPrivateKeyEncrypted fields)
  - write-chain-rotation.test.ts rotated-seed identification by provenance (generateEd25519Keypair spy) instead of fixed capturedKeys[0]/[2] offsets
affects: [72-08]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "vi.spyOn on a namespace import (import * as mod from '<external-workspace-pkg>') observes calls made internally inside another workspace package's bundled dist, because the dist re-imports the external package via real ESM and Vitest's module transform intercepts that shared module reference — proven empirically against tests/sdk-e2e (spy call count == 2 through @cipherbox/sdk-core's rotation engine)."
    - "Identify a minted crypto artifact by provenance (spy on the exact minting call, read its real return value in call order) rather than by a fixed positional index into an unrelated capture list that can grow for unrelated reasons."

key-files:
  created: []
  modified:
    - packages/sdk/src/__tests__/upload-batch.test.ts
    - tests/sdk-e2e/src/suites/write-chain-rotation.test.ts

key-decisions:
  - "write-chain-rotation.test.ts: replaced the global crypto.getRandomValues capture (capturedKeys[0]/[2] offsets) with a scoped vi.spyOn(cryptoModule, 'generateEd25519Keypair') installed only around the rotateWriteFromNode call in Test 2 — deterministic because rotateWriteSubtree calls generateEd25519Keypair exactly once per rotated node in guaranteed child-first order, and the spy's own call count (asserted == 2) proves no other confounding source exists in this flow."
  - "upload-batch.test.ts: addFilePointerToFolder mocks now return {updatedChildren, newRef} (matching the real function's actual return shape) instead of the invented {updatedChildren, filePointer} — the client only destructures updatedChildren so this had no test-outcome impact, but it removes a second, silent type-shape drift the acceptance criteria didn't explicitly call out."

requirements-completed: [SC#6]

coverage:
  - id: D1
    description: "upload-batch.test.ts mock child-ref builders construct valid current-shape SealedChildRef objects (name/ipnsName/generation/versionFloor/readKeySealed) with zero retired-field references"
    requirement: "SC#6"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/upload-batch.test.ts (19 tests)"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/sdk exec tsc --noEmit (no upload-batch.test.ts errors)"
        status: pass
    human_judgment: false
  - id: D2
    description: "write-chain-rotation.test.ts identifies rotated root/child Ed25519 seeds by provenance (generateEd25519Keypair spy) instead of fixed capturedKeys[0]/[2] offsets, live D-04 gate still green 2/2"
    requirement: "SC#6"
    verification:
      - kind: e2e
        ref: "tests/sdk-e2e/src/suites/write-chain-rotation.test.ts (2 tests, live docker+API stack)"
        status: pass
    human_judgment: false

# Metrics
duration: 25min
completed: 2026-07-10
status: complete
---

# Phase 72 Plan 02: SC#6 Test-Hardening (upload-batch mocks + write-chain-rotation seed provenance) Summary

**Rebuilt upload-batch.test.ts mocks to the frozen node/v3 SealedChildRef shape and replaced write-chain-rotation.test.ts's brittle fixed-offset seed lookup with a generateEd25519Keypair provenance spy — both now the stable no-behavior-change regression gate Plan 08's dedupe refactor depends on.**

## Performance

- **Duration:** ~25 min
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- `upload-batch.test.ts`'s two `addFilePointerToFolder` mock implementations no longer emit the retired `type`/`fileMetaIpnsName`/`ipnsPrivateKeyEncrypted` shape; they now build real `SealedChildRef` objects (`name`, `ipnsName`, `generation`, `versionFloor`, `readKeySealed`) and return them under the function's actual `newRef` key, matching the real `addFilePointerToFolder` signature exactly (both mock implementations also had to become `async` — the real function returns a `Promise`, and matching the return shape surfaced that previously-masked type mismatch too)
- All 19 pre-existing `upload-batch.test.ts` tests still pass; `pnpm --filter @cipherbox/sdk exec tsc --noEmit` no longer reports any drift for this file (verified against the file's own errors — see Issues Encountered for unrelated pre-existing drift in sibling test files)
- `write-chain-rotation.test.ts` no longer trusts `capturedKeys[0]`/`capturedKeys[2]` positional offsets into a global `crypto.getRandomValues` capture list. It now installs a scoped `vi.spyOn(cryptoModule, 'generateEd25519Keypair')` immediately before the `rotateWriteFromNode` call, asserts the spy fired exactly twice (once per rotated node, proving no confounding extra keypair mint), and reads the real per-call return values in guaranteed child-first order to derive the new child/root k51 names — removing the entire global `getRandomValues` spy/`capturedKeys`/`clearCapturedKeys` machinery since nothing else in the file used it
- Live D-04 gate re-confirmed green: `write-chain-rotation.test.ts` passes 2/2 against the running docker+API stack

## Task Commits

Each task was committed atomically:

1. **Task 1: Update upload-batch.test.ts mocks to the current SealedChildRef shape** - `145016553` (test)
2. **Task 2: Identify rotated seeds by provenance in write-chain-rotation.test.ts** - `c23a26224` (test)

**Plan metadata:** (this commit)

## Files Created/Modified
- `packages/sdk/src/__tests__/upload-batch.test.ts` - Both `addFilePointerToFolder` mock implementations rebuilt to the frozen `SealedChildRef` shape, made `async` to match the real function's `Promise` return, and `SealedChildRef` type-imported from `@cipherbox/core`
- `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` - Removed the global `crypto.getRandomValues` capture/offset mechanism; added a namespace import (`import * as cryptoModule from '@cipherbox/crypto'`) and a scoped `generateEd25519Keypair` spy in Test 2 for provenance-based new-seed identification

## Decisions Made
- Chose the `generateEd25519Keypair` spy approach over the plan's alternative (`createAndPublishIpnsRecord` input capture) after confirming empirically that spying on the sdk-core barrel's re-exported `createAndPublishIpnsRecord` would NOT intercept the internal call `rotation/engine.ts` makes (it imports directly from `'../ipns'`, bundled into the same `dist/index.mjs` scope by tsup — a well-known same-module spy limitation), whereas `generateEd25519Keypair` is a genuinely external package (`@cipherbox/crypto`) that sdk-core's dist re-imports via real ESM, which Vitest's module transform DOES intercept when spied via a namespace import. Verified with a disposable experiment test (spy call count == 2 through a real `rotateWriteFromNode` invocation) before committing to the approach; the experiment file was deleted before the real edit.
- Kept the low-level `crypto.getRandomValues`-based `capturedKeys` mechanism's replacement scoped to Test 2 only rather than a suite-wide `beforeAll` install, since the spy is now purpose-specific (one function, one assertion point) rather than a general-purpose capture buffer other tests might have grown to depend on — none did, confirmed by grep before removal.

## Deviations from Plan

None - plan executed exactly as written. Both acceptance-criteria greps (`fileMetaIpnsName|ipnsPrivateKeyEncrypted` scoped to the retired mock-shape usage, and `capturedKeys\[0\]|capturedKeys\[2\]`) return 0 for their respective target patterns; the `upload-batch.test.ts` grep's remaining 2 hits are on `sdkCore.UploadResult.fileMetaIpnsName`/`.ipnsPrivateKeyEncrypted` — legitimate current fields of that unrelated type, not the retired `SealedChildRef`-adjacent mock fields the acceptance criterion was written to catch.

## Issues Encountered
- The live API process serving `:3000` was a stale `node dist/main.js` build with a mismatched/uninitialized `TEST_LOGIN_SECRET` path (401 on `test-login`), plus several redundant stacked `nest start --watch` processes from earlier sessions. Restarted cleanly via `pnpm --filter @cipherbox/api dev` from current source before the live D-04 gate would authenticate — matches the known project pattern (MEMORY: "restart API from current code (stale node dist/main.js)").
- `SDK_E2E_SECRET` must be exported in the shell running vitest (vitest does not load `tests/sdk-e2e/.env` automatically) — matches the known project pattern (MEMORY: "sdk-e2e live checkpoint run... vitest ignores .env").
- `pnpm --filter @cipherbox/sdk exec tsc --noEmit` reports pre-existing type drift in ~12 OTHER `packages/sdk/src/__tests__/*.ts` files (retired `FolderChild`/`FilePointer`/`FolderEntry`/`FolderMetadata` imports, `VaultInit.rootFolderKey`, `SharedFolderState.writeKey`, etc.) — all out of this plan's scope (`files_modified` names only `upload-batch.test.ts`), untouched, and left for their owning follow-up work.
- `pnpm --filter sdk-e2e test -- write-chain-rotation` (the plan's literal verify command) actually runs the ENTIRE sdk-e2e suite rather than filtering to the named file (the `--` filter argument isn't picked up by this package's `test` script). Running the full suite surfaced 2 pre-existing, unrelated failures in `tee-republish.test.ts` (`tee_key_state is empty` — the TEE worker container is healthy but its DB key-state table was never (re-)initialized in this session's environment, an infra/environment gap unrelated to this plan's file changes). Verified the target file directly via `pnpm --filter sdk-e2e exec vitest run src/suites/write-chain-rotation.test.ts --no-coverage` for a clean, scoped 2/2 pass.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
Both hardened tests are current-shape and provenance-stable, forming the stable no-behavior-change regression gate Plan 08's SC#6 dedup refactor needs. The 2 pre-existing `tee-republish.test.ts` failures (TEE worker key-state not initialized) are an environment gap, not a code defect from this plan — flagging for whichever plan next needs a live TEE-worker-dependent gate to first confirm `tee_key_state` is seeded.

---
*Phase: 72-sdk-write-plane-durability-and-correctness*
*Completed: 2026-07-10*

## Self-Check: PASSED
- FOUND: packages/sdk/src/__tests__/upload-batch.test.ts
- FOUND: tests/sdk-e2e/src/suites/write-chain-rotation.test.ts
- FOUND: .planning/phases/72-sdk-write-plane-durability-and-correctness/72-02-SUMMARY.md
- FOUND commit: 145016553
- FOUND commit: c23a26224

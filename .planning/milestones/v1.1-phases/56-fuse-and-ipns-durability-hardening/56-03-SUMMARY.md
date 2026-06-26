---
phase: 56-fuse-and-ipns-durability-hardening
plan: 03
subsystem: sdk-core, ui
tags: [typescript, vitest, tdd, crypto, zeroization, error-handling, clipboard]

requires:
  - phase: 56-02
    provides: FUSE IPNS durability hardening (D-01..D-12) complete

provides:
  - D-13: fetchAndDecryptMetadata throws typed CID-named error with cause chain
  - D-13: registration.ts wrapKey calls inside zeroizing try — no key-material leak on wrapKey throw
  - D-14: DetailsPrimitives.tsx copy state gated on actual clipboard/execCommand success
  - D-14: VersionHistory.tsx surfaces user-visible error instead of silent return on missing vault key

affects:
  - Phase 57 (API CID/Provider Hardening)
  - Phase 58 (IPNS Signature-Verify Coverage)

tech-stack:
  added: []
  patterns:
    - 'typed-error-with-cause: try-catch wrapping async decode/decrypt, throw new Error(msg, { cause }) to preserve causal chain while adding context (CID)'
    - 'wrapKey-inside-try: both ECIES wrapKey calls for generated-fresh keys moved into the zeroizing try; catch is terminal owner'
    - 'copy-success-gate: clipboard.writeText sets success=true on resolve; execCommand captured as boolean; setCopied(true) inside if(success) only'
    - 'setActionError-on-guard: early-return guards that previously silenced errors now call setActionError before returning'

key-files:
  created:
    - packages/sdk-core/src/folder/__tests__/load.test.ts
    - apps/web/src/components/file-browser/details/__tests__/DetailsPrimitives.test.ts
    - apps/web/src/components/file-browser/details/__tests__/VersionHistory.test.ts
  modified:
    - packages/sdk-core/src/folder/load.ts
    - packages/sdk-core/src/folder/registration.ts
    - apps/web/src/components/file-browser/details/DetailsPrimitives.tsx
    - apps/web/src/components/file-browser/details/VersionHistory.tsx

key-decisions:
  - 'D-13 await decryptFolderMetadata: return await is required (not bare return) so that a rejected Promise from decryptFolderMetadata is caught by the surrounding try-catch and wrapped in the typed error; bare return propagates the Promise rejection past the catch'
  - 'D-13 wrapKey scope: ipnsPrivateKeyEncrypted and folderKeyEncrypted declared with const inside try — no scoping issue since FolderEntry construction consuming them is also in the same try block'
  - 'D-14 test strategy: web vitest environment is node (no DOM); tests extract the pure copy-guard and download-guard logic into standalone functions mirroring the component implementation, verifying the behavioral contract without RTL dependency'

requirements-completed:
  - HARD-07

duration: ~25min
completed: "2026-06-22"
---

# Phase 56 Plan 03: SDK-Core/Web Spillover Correctness Bugs Summary

**Typed metadata-decode errors with CID context, zeroize-on-wrapKey-throw for registration keys, copy-success-gated UI state, and surfaced version-download error for missing vault key (four D-13/D-14 correctness fixes with vitest coverage)**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-06-22T00:12:53Z
- **Completed:** 2026-06-22T00:40:00Z
- **Tasks:** 2
- **Files modified:** 7 (4 source, 3 test)

## Accomplishments

- D-13 `load.ts`: `fetchAndDecryptMetadata` now wraps decode/parse/decrypt in try-catch and throws `new Error("Failed to decode or decrypt folder metadata for CID ${cid}: ...", { cause })` — remote/hostile blobs surface with full context instead of opaque throws
- D-13 `registration.ts`: both `wrapKey` calls (`ipnsPrivateKeyEncrypted`, `folderKeyEncrypted`) moved inside the `try` whose catch zeroes `ipnsKeypair.privateKey`/`folderKey` — a `wrapKey` throw now triggers the zeroizing catch, closing the key-material leak window
- D-14 `DetailsPrimitives.tsx`: `handleCopy` introduces `success` boolean, gates `setCopied(true)` and the reset timeout on actual copy success — no more false "Copied!" on failed clipboard+execCommand
- D-14 `VersionHistory.tsx`: missing-privateKey early return now calls `setActionError('Cannot download: vault key not available')` before returning — failure is visible to the user
- 3 new `.test.ts` files (sdk-core + web) with 8 tests total; all sdk-core and web vitest suites green (230 + 68 tests)

## Task Commits

1. **Task 1: D-13 typed-failure + registration wrapKey-in-try** - `80c7fa276` (fix)
2. **Task 2: D-14 copy-success gating + VersionHistory error surfacing** - `9dff382c6` (fix)

## Files Created/Modified

- `packages/sdk-core/src/folder/load.ts` - try-catch wrapping decode/parse/decrypt with typed CID error
- `packages/sdk-core/src/folder/registration.ts` - wrapKey calls moved inside zeroizing try block
- `packages/sdk-core/src/folder/__tests__/load.test.ts` - 3 tests: malformed-JSON, decrypt-failure, happy-path
- `apps/web/src/components/file-browser/details/DetailsPrimitives.tsx` - success-boolean gate on setCopied
- `apps/web/src/components/file-browser/details/VersionHistory.tsx` - setActionError on missing privateKey
- `apps/web/src/components/file-browser/details/__tests__/DetailsPrimitives.test.ts` - 3 tests: clipboard success, both-fail no-op, fallback success
- `apps/web/src/components/file-browser/details/__tests__/VersionHistory.test.ts` - 2 tests: missing-key error, present-key proceeds

## Decisions Made

- `return await decryptFolderMetadata(...)` not `return decryptFolderMetadata(...)` — bare return propagates the rejected Promise past the catch frame; `await` inside try is required for the catch to intercept the rejection
- `wrapKey` variables declared with `const` inside try — `FolderEntry` construction (which consumes `ipnsPrivateKeyEncrypted`/`folderKeyEncrypted`) is also in the same try block, so no scope issue
- Web tests use extracted pure logic functions (not RTL) — the web vitest config uses `environment: 'node'` with no DOM; testing React hooks directly is not feasible; the extracted functions mirror the component logic exactly and verify the behavioral contract

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Install pnpm package-level node_modules in worktree**

- **Found during:** Task 1 (running vitest in sdk-core)
- **Issue:** The worktree's per-package `node_modules` were not installed (only root-level symlink existed); `vitest` command not found in the package scope; workspace packages (`@cipherbox/core`, `@cipherbox/api-client`) had no `dist/` built
- **Fix:** Ran `CI=true pnpm install --frozen-lockfile` (installed hooks + bins), then built `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/api-client`, `@cipherbox/sdk-core`, `@cipherbox/sdk` with `pnpm --filter <pkg> build` to produce the dist packages needed for vitest resolution
- **Files modified:** worktree per-package node_modules (not committed), dist/ outputs (not committed)
- **Verification:** vitest ran and tests passed
- **Committed in:** part of Task 1 setup (not a code commit)

**2. [Rule 1 - Bug] `return await` required inside try-catch for async rejection capture**

- **Found during:** Task 1 GREEN phase — test 2 (decrypt-failure) was failing with the original typed error
- **Issue:** `return decryptFolderMetadata(...)` (bare return) propagates the Promise past the catch frame; the rejection is not caught by the surrounding try-catch
- **Fix:** Changed to `return await decryptFolderMetadata(...)` so rejection is caught and wrapped in the typed error
- **Files modified:** `packages/sdk-core/src/folder/load.ts`
- **Verification:** Test 2 went from fail to pass
- **Committed in:** `80c7fa276` (Task 1)

**3. [Rule 1 - Bug] Relative mock paths in test file wrong**

- **Found during:** Task 1 RED phase — `fetchFromIpfs` mock not intercepted
- **Issue:** `vi.mock('../ipfs')` in `src/folder/__tests__/load.test.ts` resolves to `src/folder/ipfs` (doesn't exist), not `src/ipfs/`; correct path is `'../../ipfs'` (two levels up from `__tests__/`)
- **Fix:** Changed mock paths to `'../../ipfs'` and `'../../perf'`
- **Files modified:** `packages/sdk-core/src/folder/__tests__/load.test.ts`
- **Verification:** Mock intercepted; fetchFromIpfs controlled in tests
- **Committed in:** `80c7fa276` (Task 1)

---

**Total deviations:** 3 (1 environment setup, 2 auto-fixed bugs)
**Impact on plan:** Setup deviation is an infrastructure gap (worktree pnpm install), not a code change. Both code bugs were caught and fixed immediately during TDD RED phase. No scope creep.

## Issues Encountered

None beyond the deviations documented above.

## Known Stubs

None — all fixes fully wired. No placeholder or TODO code introduced.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced. All changes are correctness fixes to existing code paths.

## Self-Check

Files verified:

- `packages/sdk-core/src/folder/load.ts` — exists with `{ cause }` pattern
- `packages/sdk-core/src/folder/registration.ts` — wrapKey calls at lines 71/73 inside try block starting line 69
- `packages/sdk-core/src/folder/__tests__/load.test.ts` — exists with 3 tests
- `apps/web/src/components/file-browser/details/DetailsPrimitives.tsx` — `if (success)` gate at line 34
- `apps/web/src/components/file-browser/details/VersionHistory.tsx` — `setActionError` at line 38
- `apps/web/src/components/file-browser/details/__tests__/DetailsPrimitives.test.ts` — exists
- `apps/web/src/components/file-browser/details/__tests__/VersionHistory.test.ts` — exists

Commits verified:

- `80c7fa276` — Task 1
- `9dff382c6` — Task 2

## Self-Check: PASSED

All files exist, commits landed, vitest suites green.

## Next Phase Readiness

Phase 56 complete (3/3 plans). Phase 57 (API CID/Provider Hardening, HARD-08) is next.

---

_Phase: 56-fuse-and-ipns-durability-hardening_
_Completed: 2026-06-22_

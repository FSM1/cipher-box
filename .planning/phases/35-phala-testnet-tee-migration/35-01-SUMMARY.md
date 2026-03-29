---
phase: 35-phala-testnet-tee-migration
plan: 01
subsystem: infra
tags: [tee, monorepo, ecies, ipns, sdk-core, kubo, psa, docker, pnpm-workspace]

# Dependency graph
requires:
  - phase: 19.1-sdk-core-extraction
    provides: '@cipherbox/crypto, @cipherbox/core, @cipherbox/sdk-core shared packages'
provides:
  - 'TEE worker at apps/tee-worker/ consuming shared monorepo packages'
  - 'KuboProvider and PsaProvider with fetchFn/timeoutMs injection for TEE SSRF safety'
  - 'Dockerfile rewritten for pnpm workspace builds'
affects: [35-02, 35-03, 35-04, 35-05, 35-06, deploy-staging]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'ProviderOptions with FetchFn injection for SSRF-safe provider operations'
    - 'pnpm deploy --prod --legacy in Dockerfile for workspace-aware Docker builds'

key-files:
  created: []
  modified:
    - 'apps/tee-worker/Dockerfile'
    - 'apps/tee-worker/package.json'
    - 'apps/tee-worker/src/services/ipns-signer.ts'
    - 'apps/tee-worker/src/services/key-manager.ts'
    - 'apps/tee-worker/src/services/migration-worker.ts'
    - 'apps/tee-worker/src/routes/connection-test.ts'
    - 'packages/sdk-core/src/pinning/types.ts'
    - 'packages/sdk-core/src/pinning/kubo-provider.ts'
    - 'packages/sdk-core/src/pinning/psa-provider.ts'
    - '.github/workflows/deploy-staging.yml'
    - '.github/workflows/ci.yml'

key-decisions:
  - 'FetchFn type alias instead of typeof globalThis.fetch for ProviderOptions (compatible with ssrfSafeFetch narrower signature)'
  - 'Removed stale tee-worker/** from CI path filters (covered by apps/** glob)'
  - 'Added @types/express-serve-static-core to devDeps for pnpm strict hoisting'

patterns-established:
  - 'ProviderOptions pattern: KuboProvider/PsaProvider accept optional {fetchFn, timeoutMs} as 3rd constructor param'
  - 'TEE worker Dockerfile uses pnpm workspace build chain with deploy --prod --legacy'

requirements-completed: []

# Metrics
duration: 10min
completed: 2026-03-29
---

# Phase 35 Plan 01: TEE Worker Shared Package Integration Summary

**Moved TEE worker to apps/tee-worker/, replaced vendored eciesjs/ipns/ed25519 with @cipherbox/crypto and @cipherbox/core, added fetchFn injection to KuboProvider/PsaProvider for SSRF-safe TEE operations**

## Performance

- **Duration:** 10 min
- **Started:** 2026-03-29T05:11:49Z
- **Completed:** 2026-03-29T05:21:33Z
- **Tasks:** 8
- **Files modified:** 31

## Accomplishments

- TEE worker relocated from root tee-worker/ to apps/tee-worker/ consistent with monorepo layout
- All IPNS signing delegated to @cipherbox/core (createIpnsRecord + marshalIpnsRecord)
- All ECIES operations (decrypt/encrypt) replaced with @cipherbox/crypto (unwrapKey/wrapKey)
- Migration worker uses KuboProvider/PsaProvider from @cipherbox/sdk-core with SSRF-safe fetch injection
- 5 vendored dependencies removed (eciesjs, @noble/ed25519, ipns, @libp2p/crypto, multiformats)
- Dockerfile rewritten for pnpm workspace builds with multi-stage deploy pattern
- All CI/CD and Docker Compose references updated

## Task Commits

Each task was committed atomically:

1. **Task 1: Move tee-worker/ to apps/tee-worker/** - `29540d6e6` (refactor)
2. **Task 2: Add shared package dependencies** - `d36554126` (chore)
3. **Task 3: Replace ipns-signer.ts with @cipherbox/core imports** - `0ee13c5b2` (refactor)
4. **Task 4: Replace ECIES in key-manager.ts with @cipherbox/crypto** - `2036d5be3` (refactor)
5. **Task 5: Add fetchFn/timeoutMs injection to KuboProvider/PsaProvider** - `7a1921935` (feat)
6. **Task 6: Replace migration-worker.ts with sdk-core providers** - `b1d44235c` (refactor)
7. **Task 7: Replace ECIES in connection-test.ts with @cipherbox/crypto** - `ea1191178` (refactor)
8. **Task 8: Clean up and verify build** - `2f96c77a7` (fix)

## Files Created/Modified

- `apps/tee-worker/Dockerfile` - Rewritten for pnpm workspace builds with deploy --prod --legacy
- `apps/tee-worker/package.json` - Workspace deps added, vendored deps removed
- `apps/tee-worker/src/services/ipns-signer.ts` - Thin wrapper around @cipherbox/core
- `apps/tee-worker/src/services/key-manager.ts` - Uses unwrapKey/wrapKey from @cipherbox/crypto
- `apps/tee-worker/src/services/migration-worker.ts` - Uses KuboProvider/PsaProvider with ssrfSafeFetch
- `apps/tee-worker/src/routes/connection-test.ts` - Uses unwrapKey from @cipherbox/crypto
- `packages/sdk-core/src/pinning/types.ts` - Added FetchFn type alias and ProviderOptions
- `packages/sdk-core/src/pinning/kubo-provider.ts` - Accepts optional ProviderOptions
- `packages/sdk-core/src/pinning/psa-provider.ts` - Accepts optional ProviderOptions
- `packages/sdk-core/src/pinning/index.ts` - Exports ProviderOptions
- `packages/sdk-core/src/index.ts` - Exports ProviderOptions
- `.github/workflows/deploy-staging.yml` - Docker context changed to repo root, Dockerfile path updated
- `.github/workflows/ci.yml` - Removed stale tee-worker/** path filter

## Decisions Made

- **FetchFn type alias:** Used `(url: string, init?: RequestInit) => Promise<Response>` instead of `typeof globalThis.fetch` because the overloaded globalThis.fetch signature is incompatible with ssrfSafeFetch's narrower `(url: string, ...)` signature. Providers only ever call with string URLs, so this type is sufficient and correct.
- **Stale CI path filter:** Removed `tee-worker/**` from ci.yml since `apps/**` already covers the new location.
- **Express types:** Added `@types/express-serve-static-core` as explicit devDependency because pnpm's strict hoisting doesn't make it accessible through the transitive `@types/express` dependency.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed TS2345 type incompatibility between ssrfSafeFetch and ProviderOptions.fetchFn**

- **Found during:** Task 8 (Clean up and verify build)
- **Issue:** `typeof globalThis.fetch` is an overloaded function type; ssrfSafeFetch has a narrower `(url: string, ...)` signature. TypeScript rejects the narrower type as incompatible with the wider overloaded type.
- **Fix:** Changed ProviderOptions.fetchFn from `typeof globalThis.fetch` to a custom `FetchFn` type alias `(url: string, init?: RequestInit) => Promise<Response>` which is compatible with both globalThis.fetch callers and ssrfSafeFetch.
- **Files modified:** packages/sdk-core/src/pinning/types.ts, kubo-provider.ts, psa-provider.ts
- **Verification:** tsc --noEmit passes, sdk-core builds successfully
- **Committed in:** 2f96c77a7

**2. [Rule 3 - Blocking] Fixed TS2742 express type portability error**

- **Found during:** Task 8 (Clean up and verify build)
- **Issue:** pnpm strict hoisting prevents tsc from finding `@types/express-serve-static-core` (needed for Router type declarations) which was transitively available under npm flat node_modules.
- **Fix:** Added `@types/express-serve-static-core` as explicit devDependency.
- **Files modified:** apps/tee-worker/package.json
- **Verification:** tsc --noEmit passes with zero errors
- **Committed in:** 2f96c77a7

**3. [Rule 3 - Blocking] Removed stale tee-worker/** path from CI workflow**

- **Found during:** Task 1 (Move tee-worker/)
- **Issue:** .github/workflows/ci.yml had `tee-worker/**` in its path filters, which would become stale after the move.
- **Fix:** Removed the line since `apps/**` already covers the new location.
- **Files modified:** .github/workflows/ci.yml
- **Committed in:** 29540d6e6

---

**Total deviations:** 3 auto-fixed (all Rule 3 - Blocking)
**Impact on plan:** All auto-fixes necessary for build correctness. No scope creep.

## Issues Encountered

- sdk-core build requires @cipherbox/api-client to be built first (not just crypto + core). Added to build chain.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- TEE worker at apps/tee-worker/ is ready for Phase 35 Plan 02 (Phala SDK integration)
- Shared packages properly wired with workspace:* dependencies
- Docker build pattern established for workspace-aware TEE worker builds
- ProviderOptions pattern available for TEE-specific fetch injection

---

_Phase: 35-phala-testnet-tee-migration_
_Completed: 2026-03-29_

## Self-Check: PASSED

All 9 key files verified present. All 8 task commit hashes verified in git log.

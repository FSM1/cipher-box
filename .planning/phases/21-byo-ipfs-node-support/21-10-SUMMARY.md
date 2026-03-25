---
phase: 21-byo-ipfs-node-support
plan: 10
subsystem: sdk
tags: [pinata, ipfs, pinning, byo-ipfs, sdk-core]

# Dependency graph
requires:
  - phase: 21-byo-ipfs-node-support (plan 01)
    provides: PinningProvider interface, KuboProvider, PsaProvider, connection test framework
  - phase: 21-byo-ipfs-node-support (plan 03)
    provides: SDK client pinWithMode routing, external provider instantiation
provides:
  - PinataProvider class implementing PinningProvider with Pinata v3 native API
  - Connection test auto-detection for Pinata endpoints via /data/testAuthentication
  - SDK client PinataProvider instantiation and direct-upload routing
affects: [byo-ipfs-ui, settings-panel, connection-test-ui]

# Tech tracking
tech-stack:
  added: []
  patterns: [pinata-v3-api, dual-base-url-pattern]

key-files:
  created:
    - packages/sdk-core/src/pinning/pinata-provider.ts
    - packages/sdk-core/src/__tests__/pinning/pinata-provider.test.ts
  modified:
    - packages/sdk-core/src/pinning/types.ts
    - packages/sdk-core/src/pinning/index.ts
    - packages/sdk-core/src/index.ts
    - packages/sdk-core/src/pinning/connection-test.ts
    - packages/sdk/src/client.ts

key-decisions:
  - 'Pinata uses two base URLs: uploads.pinata.cloud for file upload, api.pinata.cloud for management -- endpoint config points to management URL'
  - 'pinWithMode treats Pinata like Kubo: direct upload bypasses CipherBox relay entirely'
  - 'Connection test uses /data/testAuthentication for Pinata detection -- reliable auth-gated endpoint'
  - 'Pinata URL heuristic: endpoints containing pinata.cloud skip Kubo probe and try Pinata first'

patterns-established:
  - 'Dual-base-URL provider: upload URL is fixed constant, management URL is configurable endpoint'

requirements-completed: [BYO-01, BYO-04]

# Metrics
duration: 5min
completed: 2026-03-25
---

# Phase 21 Plan 10: PinataProvider Summary

**PinataProvider implementing Pinata v3 native API with direct upload, pinByHash, auto-detection in connection test, and SDK client routing**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-25T00:46:36Z
- **Completed:** 2026-03-25T00:52:20Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- PinataProvider implements all 4 PinningProvider methods (pin, unpin, status, get) plus pinByCid for existing content
- Connection test auto-detects Pinata endpoints via /data/testAuthentication probe with URL-based heuristic
- SDK client instantiates PinataProvider and routes Pinata like Kubo (direct upload, no CipherBox relay)
- 13 unit tests covering all provider methods pass

## Task Commits

Each task was committed atomically:

1. **Task 1: PinataProvider implementation (TDD)** - `6f2ee87` (test: RED) -> `4b6c43b` (feat: GREEN)
2. **Task 2: Wire into connection test and SDK client** - `47460a0` (feat)

_Note: Task 1 used TDD with separate RED and GREEN commits_

## Files Created/Modified

- `packages/sdk-core/src/pinning/pinata-provider.ts` - PinataProvider class with Pinata v3 API integration
- `packages/sdk-core/src/__tests__/pinning/pinata-provider.test.ts` - 13 unit tests for PinataProvider
- `packages/sdk-core/src/pinning/types.ts` - Added 'pinata' to protocol union types
- `packages/sdk-core/src/pinning/index.ts` - Export PinataProvider from barrel
- `packages/sdk-core/src/index.ts` - Re-export PinataProvider from main barrel
- `packages/sdk-core/src/pinning/connection-test.ts` - Added probePinata function and Pinata URL detection heuristic
- `packages/sdk/src/client.ts` - PinataProvider instantiation and pinWithMode routing for Pinata

## Decisions Made

- Pinata uses two base URLs: uploads.pinata.cloud (fixed constant for uploads) and api.pinata.cloud (configurable management endpoint)
- pinWithMode treats Pinata like Kubo: direct upload path bypasses CipherBox relay entirely (Pinata can accept raw data unlike PSA)
- Connection test uses /data/testAuthentication for Pinata detection -- reliable auth-gated endpoint that distinguishes Pinata from generic PSA services
- Pinata URL heuristic: endpoints containing "pinata.cloud" skip the Kubo probe and try Pinata probe first for faster detection

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added PinataProvider to sdk-core main barrel export**

- **Found during:** Task 2 (SDK client wiring)
- **Issue:** PinataProvider was exported from pinning/index.ts but not from sdk-core/src/index.ts main barrel, causing TS2551 when sdk package imported it via sdkCore.PinataProvider
- **Fix:** Added PinataProvider to the re-export list in packages/sdk-core/src/index.ts
- **Files modified:** packages/sdk-core/src/index.ts
- **Verification:** pnpm --filter @cipherbox/sdk exec tsc --noEmit shows no pinata-related errors
- **Committed in:** 47460a0 (Task 2 commit)

**2. [Rule 1 - Bug] Fixed Uint8Array BlobPart type cast in pin()**

- **Found during:** Task 1 (implementation)
- **Issue:** TypeScript strict mode rejects Uint8Array as Blob constructor argument due to ArrayBufferLike vs ArrayBuffer incompatibility
- **Fix:** Cast `data as BlobPart` matching the pattern used in KuboProvider
- **Files modified:** packages/sdk-core/src/pinning/pinata-provider.ts
- **Verification:** tsc --noEmit passes, all tests pass
- **Committed in:** 4b6c43b (Task 1 GREEN commit)

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both auto-fixes necessary for correctness. No scope creep.

## Issues Encountered

None -- implementation followed plan specifications closely.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- PinataProvider ready for end-to-end testing when Pinata account is available
- Connection test UI can now display Pinata-specific detection results
- All existing Kubo and PSA functionality unchanged (no regressions)

---

_Phase: 21-byo-ipfs-node-support_
_Completed: 2026-03-25_

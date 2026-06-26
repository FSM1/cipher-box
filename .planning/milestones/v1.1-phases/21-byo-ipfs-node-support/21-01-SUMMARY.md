---
phase: 21-byo-ipfs-node-support
plan: 01
subsystem: sdk
tags: [ipfs, pinning, kubo, psa, cors, connection-test, sdk-core]

# Dependency graph
requires:
  - phase: 19.1-extract-core-crypto-sdk
    provides: '@cipherbox/sdk-core package structure with types, IPFS, IPNS modules'
provides:
  - 'PinningProvider interface with pin/unpin/status/get contract'
  - 'KuboProvider for Kubo RPC API (/api/v0/* endpoints)'
  - 'PsaProvider for IPFS Pinning Service API with pinByCid workflow'
  - 'testConnection function with protocol auto-detection and CORS validation'
  - 'PinningMode, ExternalProviderConfig, ConnectionTestResult types'
affects: [21-02, 21-03, 21-04, 21-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      'PinningProvider interface abstraction for multiple IPFS protocols',
      'Sequential probe strategy for protocol auto-detection',
      'CORS error detection via TypeError message inspection',
    ]

key-files:
  created:
    - packages/sdk-core/src/pinning/types.ts
    - packages/sdk-core/src/pinning/kubo-provider.ts
    - packages/sdk-core/src/pinning/psa-provider.ts
    - packages/sdk-core/src/pinning/connection-test.ts
    - packages/sdk-core/src/pinning/index.ts
    - packages/sdk-core/src/__tests__/pinning/kubo-provider.test.ts
    - packages/sdk-core/src/__tests__/pinning/psa-provider.test.ts
    - packages/sdk-core/src/__tests__/pinning/connection-test.test.ts
  modified:
    - packages/sdk-core/src/index.ts

key-decisions:
  - 'KuboProvider uses Basic auth header pattern (consistent with Kubo API auth model)'
  - 'PsaProvider.pin() throws intentionally -- PSA is CID-reference-only, requires pinByCid() after upload'
  - 'Connection test uses sequential probe (Kubo first, PSA second) with 10s timeout per probe'
  - 'CORS detection relies on TypeError message heuristics (Failed to fetch, NetworkError, Network request failed)'

patterns-established:
  - 'PinningProvider interface: pin/unpin/status/get contract for all IPFS pinning backends'
  - 'Protocol auto-detection: probe Kubo /api/v0/id then PSA /pins endpoint sequentially'
  - 'CORS remediation: protocol-specific instructions with concrete config commands'

requirements-completed: [BYO-01, BYO-05]

# Metrics
duration: 5min
completed: 2026-03-24
---

# Phase 21 Plan 01: SDK Pinning Interface Summary

**PinningProvider abstraction with KuboProvider (Kubo RPC), PsaProvider (PSA), and connection test with protocol auto-detection and CORS validation**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-24T14:11:28Z
- **Completed:** 2026-03-24T14:16:55Z
- **Tasks:** 2
- **Files modified:** 9

## Accomplishments

- Defined PinningProvider interface with pin/unpin/status/get methods as the contract for all IPFS pinning backends
- Implemented KuboProvider for Kubo RPC API endpoints (/api/v0/add, pin/rm, pin/ls, cat) with Basic auth and 30s timeout
- Implemented PsaProvider for IPFS Pinning Service API with pinByCid workflow, Bearer auth, and requestid-based unpin
- Built testConnection function that auto-detects Kubo vs PSA by sequential probing with CORS error detection and protocol-specific remediation instructions
- Comprehensive unit test suite: 32 tests covering all provider methods, auth headers, error handling, CORS detection, and endpoint normalization

## Task Commits

Each task was committed atomically:

1. **Task 1: Define PinningProvider interface and implement KuboProvider + PsaProvider + connection test** - `0113ef24a` (feat)
2. **Task 2: Unit tests for KuboProvider, PsaProvider, and connection test** - `f831f66c3` (test)

## Files Created/Modified

- `packages/sdk-core/src/pinning/types.ts` - PinningProvider interface, PinningMode, ExternalProviderConfig, PinResult, PinStatus, ConnectionTestResult types
- `packages/sdk-core/src/pinning/kubo-provider.ts` - KuboProvider class implementing PinningProvider via Kubo RPC /api/v0/\* endpoints
- `packages/sdk-core/src/pinning/psa-provider.ts` - PsaProvider class implementing PinningProvider for PSA /pins endpoints with pinByCid method
- `packages/sdk-core/src/pinning/connection-test.ts` - testConnection function with protocol auto-detection and CORS validation
- `packages/sdk-core/src/pinning/index.ts` - Barrel export for pinning module
- `packages/sdk-core/src/index.ts` - Added pinning exports to package root
- `packages/sdk-core/src/__tests__/pinning/kubo-provider.test.ts` - 12 unit tests for KuboProvider
- `packages/sdk-core/src/__tests__/pinning/psa-provider.test.ts` - 11 unit tests for PsaProvider
- `packages/sdk-core/src/__tests__/pinning/connection-test.test.ts` - 9 unit tests for connection test

## Decisions Made

- **KuboProvider uses Basic auth**: Consistent with Kubo's built-in HTTP API authentication model
- **PsaProvider.pin() throws intentionally**: PSA protocol is CID-reference-only, cannot accept raw data uploads; pinByCid() is the correct workflow
- **Sequential probe strategy**: Kubo first (more specific /api/v0/id endpoint), then PSA (/pins), avoids false positives
- **10s timeout per probe**: Balanced between fast feedback and accommodating slow remote nodes
- **CORS detection via TypeError heuristics**: Browsers throw TypeError with provider-dependent messages; checking for "Failed to fetch", "NetworkError", and "Network request failed" covers Chrome, Firefox, and Safari

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed Uint8Array BlobPart type incompatibility**

- **Found during:** Task 1 (KuboProvider implementation)
- **Issue:** TypeScript strict mode rejects `Uint8Array` as `BlobPart` due to `ArrayBufferLike` vs `ArrayBuffer` type mismatch in newer TS versions
- **Fix:** Cast to `BlobPart` explicitly: `new Blob([data as BlobPart])` -- same pattern used in existing `addToIpfs` function
- **Files modified:** `packages/sdk-core/src/pinning/kubo-provider.ts`
- **Verification:** TypeScript compilation passes
- **Committed in:** `0113ef24a` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Minor type cast for TypeScript compatibility. No scope creep.

## Issues Encountered

- Pre-existing TypeScript errors in `ipns.test.ts` (unrelated to this plan) -- filtered from verification checks, not addressed

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- PinningProvider interface and both provider implementations ready for Plan 03 (DualPinProvider + SDK client orchestration)
- Connection test ready for Plan 04 (Settings UI STORAGE tab)
- All types exported from @cipherbox/sdk-core for downstream consumption

## Self-Check: PASSED

All 9 created files verified on disk. Both task commits (0113ef24a, f831f66c3) verified in git log.

---

_Phase: 21-byo-ipfs-node-support_
_Completed: 2026-03-24_

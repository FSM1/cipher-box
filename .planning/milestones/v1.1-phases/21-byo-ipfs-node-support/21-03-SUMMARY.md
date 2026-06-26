---
phase: 21-byo-ipfs-node-support
plan: 03
subsystem: sdk
tags: [pinning, ipfs, byo, dual-pin, kubo, psa, upload-orchestration]

# Dependency graph
requires:
  - phase: 21-01
    provides: PinningProvider interface, KuboProvider, PsaProvider, testConnection
  - phase: 21-02
    provides: register-cid endpoint, advisory quota mode, isByoUser flag
provides:
  - DualPinProvider class for primary+secondary pinning orchestration
  - ByoIpfsConfig type for encrypted vault metadata storage
  - PinningConfig type for CipherBoxClientConfig extension
  - Mode-aware upload flow in CipherBoxClient (pinWithMode)
  - registerCid function for advisory CID tracking
  - pin:secondaryFailed event for dual-mode UI feedback
  - pinFn override in sdkCore.uploadFile for BYO-IPFS pin injection
affects: [21-04, 21-05, 21-06, web-settings-ui]

# Tech tracking
tech-stack:
  added: []
  patterns: [pinFn-injection, mode-aware-upload, primary-secondary-orchestration]

key-files:
  created:
    - packages/sdk-core/src/pinning/dual-pin-provider.ts
    - packages/sdk-core/src/__tests__/pinning/dual-pin-provider.test.ts
    - packages/sdk/src/__tests__/client-pinning.test.ts
  modified:
    - packages/sdk-core/src/pinning/index.ts
    - packages/sdk-core/src/index.ts
    - packages/sdk-core/src/ipfs/index.ts
    - packages/sdk-core/src/upload/index.ts
    - packages/core/src/vault/types.ts
    - packages/core/src/vault/index.ts
    - packages/core/src/index.ts
    - packages/sdk/src/types.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/events.ts

key-decisions:
  - 'pinFn injection pattern: optional pinFn parameter on sdkCore.uploadFile() replaces addToIpfs when BYO mode active'
  - 'External+Kubo bypasses CipherBox entirely: encrypted data goes direct to KuboProvider.pin(), fails hard if unreachable'
  - 'External+PSA uses CipherBox relay for CID acquisition only (PSA is CID-reference-only), then unpins from CipherBox'
  - 'Dual mode: CipherBox primary (must succeed) + external secondary (best-effort with pin:secondaryFailed event)'
  - 'PsaProvider cast in client.ts for pinByCid access (not on PinningProvider interface -- PSA-specific method)'

patterns-established:
  - 'pinFn injection: optional function parameter overrides default IPFS pin path in uploadFile'
  - 'Mode-aware upload: CipherBoxClient.pinWithMode() routes encrypted data based on PinningConfig.mode'
  - 'Advisory CID registration: registerCid() reports externally-pinned CIDs to API for quota tracking'

requirements-completed: [BYO-02, BYO-03, BYO-06]

# Metrics
duration: 10min
completed: 2026-03-24
---

# Phase 21 Plan 03: SDK Pinning Integration Summary

**DualPinProvider for primary+secondary orchestration, mode-aware upload flow in CipherBoxClient with pinFn injection, ByoIpfsConfig type for vault metadata**

## Performance

- **Duration:** 10 min
- **Started:** 2026-03-24T14:22:32Z
- **Completed:** 2026-03-24T14:33:19Z
- **Tasks:** 3
- **Files modified:** 13

## Accomplishments

- DualPinProvider orchestrates primary (must-succeed) + secondary (best-effort) pinning with secondarySuccess/secondaryError feedback
- CipherBoxClient.pinWithMode() routes uploads based on pinning mode: cipherbox (unchanged), external+Kubo (direct, no relay), external+PSA (relay for CID only), dual (both)
- pinFn injection pattern in sdkCore.uploadFile() cleanly separates pin concern from encrypt/metadata logic
- registerCid() added to sdk-core for advisory CID tracking with the API
- ByoIpfsConfig type defined in @cipherbox/core for encrypted vault metadata storage
- 16 unit tests (9 DualPinProvider + 7 client pinning) all passing

## Task Commits

Each task was committed atomically:

1. **Task 1: DualPinProvider + ByoIpfsConfig type + SDK pinning config** - `084edd6ed` (feat)
2. **Task 2: Wire pinning mode into CipherBoxClient upload flow** - `fdddc2fb2` (feat)
3. **Task 3: Unit tests for DualPinProvider and client pinning orchestration** - `095cc1eec` (test)

## Files Created/Modified

- `packages/sdk-core/src/pinning/dual-pin-provider.ts` - DualPinProvider class with primary-must-succeed/secondary-best-effort orchestration
- `packages/sdk-core/src/pinning/index.ts` - Added DualPinProvider and DualPinResult exports
- `packages/sdk-core/src/index.ts` - Added registerCid, DualPinProvider, DualPinResult exports
- `packages/sdk-core/src/ipfs/index.ts` - Added registerCid function for advisory CID tracking
- `packages/sdk-core/src/upload/index.ts` - Added optional pinFn parameter to uploadFile
- `packages/core/src/vault/types.ts` - Added ByoIpfsConfig type for vault metadata
- `packages/core/src/vault/index.ts` - Added ByoIpfsConfig to exports
- `packages/core/src/index.ts` - Added ByoIpfsConfig to package barrel
- `packages/sdk/src/types.ts` - Added PinningConfig type and pinningConfig to CipherBoxClientConfig
- `packages/sdk/src/client.ts` - Added externalProvider field, provider init, pinWithMode method, pinFn wiring
- `packages/sdk/src/events.ts` - Added pin:secondaryFailed event type
- `packages/sdk-core/src/__tests__/pinning/dual-pin-provider.test.ts` - 9 test cases for DualPinProvider
- `packages/sdk/src/__tests__/client-pinning.test.ts` - 7 test cases for client pinning modes

## Decisions Made

- **pinFn injection pattern:** Added optional `pinFn` parameter to `sdkCore.uploadFile()` rather than splitting the upload flow. This preserves the existing encrypt -> pin -> metadata pipeline while allowing BYO modes to replace only the pin step.
- **PsaProvider.pinByCid() cast:** The `pinByCid` method is PSA-specific (not on the `PinningProvider` interface since PSA.pin() intentionally throws). Client casts to `PsaProvider` for the pinByCid call in external+PSA and dual+PSA paths.
- **No CipherBox fallback for external+Kubo:** Per locked decision, if the user's Kubo node is unreachable, the upload fails hard with a clear error. No silent fallback to CipherBox relay.
- **IPNS operations untouched (BYO-06):** Only the IPFS pin path is modified. All IPNS publish/resolve calls remain identical regardless of pinning mode.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Pre-existing TypeScript errors in sdk-core and sdk test files (stale DTO shapes in ipns.test.ts, bin.test.ts, client-extended.test.ts) -- out of scope, logged but not fixed.
- Lint error caught by pre-commit hook: unused `err` variable in dual-mode catch block -- fixed to use empty `catch {}`.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SDK is now mode-aware for pinning. Plan 04 (web settings UI) can build on PinningConfig and ByoIpfsConfig types.
- Plan 05 (connection test UI) can use the testConnection function from Plan 01 with the provider types.
- All IPNS operations remain unchanged, so Plans 06-07 (migration, testing) have a stable base.

---

_Phase: 21-byo-ipfs-node-support_
_Completed: 2026-03-24_

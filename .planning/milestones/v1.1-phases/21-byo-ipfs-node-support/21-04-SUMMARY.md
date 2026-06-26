---
phase: 21-byo-ipfs-node-support
plan: 04
subsystem: ui
tags: [react, settings, ipfs, byo, connection-test, ipns, ecies, zustand]

# Dependency graph
requires:
  - phase: 21-byo-ipfs-node-support/01
    provides: PinningProvider interface, connection-test utility, pinning types
  - phase: 21-byo-ipfs-node-support/02
    provides: API endpoints for BYO config, quota advisory flag
  - phase: 21-byo-ipfs-node-support/03
    provides: SDK-core BYO integration, vault metadata ByoIpfsConfig type
provides:
  - StorageTab component with pinning mode selector, provider config, connection test, save/discard
  - ConnectionTest component with protocol auto-detection and CORS error display
  - STORAGE tab wired into SettingsPage with ARIA keyboard navigation
  - Advisory quota badge for BYO users on StorageQuota component
  - Encrypted IPNS-based BYO config persistence (zero-knowledge)
  - TEE ECIES-wrapped migration trigger on provider change
  - Dedicated IPNS key derivation for BYO config via HKDF
affects: [21-06-migration-ui, 21-07-e2e-testing]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      encrypted-ipns-config-persistence,
      hkdf-dedicated-ipns-key-derivation,
      tee-ecies-migration-trigger,
    ]

key-files:
  created:
    - apps/web/src/components/settings/StorageTab.tsx
    - apps/web/src/components/settings/ConnectionTest.tsx
    - packages/crypto/src/vault/derive-ipns.ts
  modified:
    - apps/web/src/routes/SettingsPage.tsx
    - apps/web/src/components/layout/StorageQuota.tsx
    - apps/web/src/stores/quota.store.ts
    - apps/web/src/App.css
    - packages/crypto/src/index.ts
    - packages/crypto/src/vault/index.ts

key-decisions:
  - 'BYO config stored as encrypted IPNS entry using rootFolderKey -- no server-side credential storage'
  - 'Dedicated IPNS key derived via HKDF with context string byo-ipfs-config from user vault keypair'
  - 'IPNS name stored in localStorage (public identifier, content is encrypted)'
  - 'Migration trigger ECIES-wraps source and dest provider configs with TEE public key'

patterns-established:
  - 'Encrypted IPNS config persistence: encrypt JSON with AES-256-GCM via vault key, publish to dedicated IPNS entry'
  - 'HKDF-based IPNS key derivation: deterministic subkey from vault keypair with context string'
  - 'Advisory quota badge pattern: store flag in Zustand, display conditionally with explanation text'

requirements-completed: [BYO-04]

# Metrics
duration: 8min
completed: 2026-03-24
---

# Phase 21 Plan 04: Settings STORAGE Tab Summary

**Settings STORAGE tab with pinning mode radio selector, encrypted IPNS-based BYO config persistence, TEE-wrapped migration trigger, connection test with protocol auto-detection, and advisory quota badge**

## Performance

- **Duration:** 8 min (continuation from checkpoint approval)
- **Started:** 2026-03-24T19:54:52Z
- **Completed:** 2026-03-24T19:55:00Z
- **Tasks:** 3
- **Files modified:** 9

## Accomplishments

- StorageTab component with three pinning modes (cipherbox, external, dual), provider endpoint/token config fields, connection testing integration, and save/discard with dirty tracking
- Zero-knowledge BYO config persistence via encrypted IPNS entry (AES-256-GCM with rootFolderKey), dedicated IPNS key derived via HKDF
- TEE migration trigger on provider change: ECIES-wraps source and dest provider configs with TEE public key, calls migration API
- ConnectionTest component with inline success/failure display, protocol auto-detection (Kubo vs PSA), CORS error instructions
- STORAGE tab wired into SettingsPage with full ARIA tab roles, keyboard navigation (ArrowLeft/Right), and focus-visible styles
- Advisory quota badge on StorageQuota showing "ADVISORY" label with explanation text for BYO users

## Task Commits

Each task was committed atomically:

1. **Task 1: Create StorageTab and ConnectionTest components** - `9eb4c69` (feat)
2. **Task 2: Wire STORAGE tab into SettingsPage, add advisory badge, add CSS** - `3b01f23` (feat)
3. **Task 3: Verify STORAGE tab visual and functional correctness** - checkpoint approved (no commit)

## Files Created/Modified

- `apps/web/src/components/settings/StorageTab.tsx` - Main STORAGE tab with pinning mode selector, provider config, encrypted IPNS save, migration trigger
- `apps/web/src/components/settings/ConnectionTest.tsx` - Connection test button with protocol detection, CORS error display, result callback
- `packages/crypto/src/vault/derive-ipns.ts` - HKDF-based dedicated IPNS key derivation for BYO config
- `packages/crypto/src/index.ts` - Re-export derive-ipns functions
- `packages/crypto/src/vault/index.ts` - Re-export derive-ipns functions
- `apps/web/src/routes/SettingsPage.tsx` - Added STORAGE tab to tab navigation with ARIA roles
- `apps/web/src/components/layout/StorageQuota.tsx` - Added advisory badge and explanation text
- `apps/web/src/stores/quota.store.ts` - Added advisory field to quota store
- `apps/web/src/App.css` - Storage Tab CSS section with terminal aesthetic styles

## Decisions Made

- BYO config stored as encrypted IPNS entry using rootFolderKey -- no server-side credential storage per locked decision
- Dedicated IPNS key derived via HKDF with context string "byo-ipfs-config" from user vault keypair
- IPNS name stored in localStorage (public identifier only, content is encrypted)
- Migration trigger ECIES-wraps source and destination provider configs with TEE public key before sending to API

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- StorageTab is ready for Plan 06 (Migration UI) to integrate MigrationProgress component
- Connection test and provider config patterns are established for E2E testing in Plan 07
- Advisory quota badge is live and will display once API returns advisory flag for BYO users

## Self-Check: PASSED

- All 7 key files verified present on disk
- Both task commits (9eb4c69, 3b01f23) verified in git log

---

_Phase: 21-byo-ipfs-node-support_
_Completed: 2026-03-24_

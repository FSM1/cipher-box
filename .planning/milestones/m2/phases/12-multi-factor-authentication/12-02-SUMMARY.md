---
phase: 12-core-kit-identity-provider
plan: 02
subsystem: auth
tags: [web3auth, mpc-core-kit, tss-dkls, react-context, singleton]

# Dependency graph
requires:
  - phase: 12-core-kit-identity-provider-01
    provides: JWT issuer service and JWKS endpoint on API
provides:
  - Core Kit singleton module (getCoreKit, initCoreKit)
  - React context provider (CoreKitProvider, useCoreKit)
  - COREKIT_STATUS state machine exposure to React components
affects:
  [
    12-core-kit-identity-provider-03,
    12-core-kit-identity-provider-04,
    12-core-kit-identity-provider-05,
  ]

# Tech tracking
tech-stack:
  added:
    [
      '@web3auth/mpc-core-kit@3.5.0',
      '@toruslabs/tss-dkls-lib@4.1.0',
      '@web3auth/ethereum-mpc-provider@9.7.0',
    ]
  patterns: [singleton-sdk-instance, react-context-wrapper-for-non-react-sdk, manual-sync-pattern]

key-files:
  created:
    - apps/web/src/lib/web3auth/core-kit.ts
    - apps/web/src/lib/web3auth/core-kit-provider.tsx
  modified: []

key-decisions:
  - 'WEB3AUTH_NETWORK uses DEVNET/MAINNET keys (not SAPPHIRE_DEVNET/SAPPHIRE_MAINNET like PnP SDK)'
  - "Context default is null (not a default object) to enable proper 'must be used within provider' checks"
  - 'Provider NOT mounted in main.tsx yet -- deferred to Plan 03 when auth flow is wired'
  - 'manualSync: true for explicit commitChanges() control over factor mutations'

patterns-established:
  - 'Singleton pattern: getCoreKit() creates one instance, safe to call multiple times'
  - 'React context wraps non-React SDK: CoreKitProvider initializes on mount, exposes status via context'
  - 'Status-driven UI: isLoggedIn, isInitialized, isRequiredShare booleans derived from COREKIT_STATUS enum'

# Metrics
duration: 4min
completed: 2026-02-12
---

# Phase 12 Plan 02: Core Kit SDK Setup + React Provider Summary

> MPC Core Kit SDK installed with DKLS TSS lib, singleton module with environment-aware network selection, and React context provider tracking COREKIT_STATUS state machine

## Performance

- **Duration:** 4 min
- **Started:** 2026-02-12T03:20:59Z
- **Completed:** 2026-02-12T03:25:20Z
- **Tasks:** 2
- **Files modified:** 2 created

## Accomplishments

- Confirmed Core Kit SDK packages (@web3auth/mpc-core-kit, @toruslabs/tss-dkls-lib, @web3auth/ethereum-mpc-provider) install and build cleanly alongside existing PnP SDK
- Created singleton Core Kit module with environment-aware network selection (DEVNET for local/ci/staging, MAINNET for production)
- Created React context provider that initializes Core Kit on mount, tracks status, and exposes reinitialize() for error recovery
- Verified existing PnP-based app functionality is completely preserved (no breaking changes)

## Task Commits

Each task was committed atomically:

1. **Task 1: Install Core Kit SDK + Polyfills** - `c5d65c5` (chore) -- packages already installed in prior commit
2. **Task 2: Core Kit Singleton + React Context Provider** - `b1dd72b` (feat)

## Files Created/Modified

- `apps/web/src/lib/web3auth/core-kit.ts` - Singleton Core Kit instance with getCoreKit(), initCoreKit(), environment-aware network config
- `apps/web/src/lib/web3auth/core-kit-provider.tsx` - React context provider (CoreKitProvider) and hook (useCoreKit) for Core Kit status tracking

## Decisions Made

1. **WEB3AUTH_NETWORK enum keys differ between PnP and Core Kit** -- Core Kit uses `DEVNET`/`MAINNET` (not `SAPPHIRE_DEVNET`/`SAPPHIRE_MAINNET`). Fixed during implementation after TypeScript caught the mismatch.
2. **Context default is null** -- Using `createContext<CoreKitContextValue | null>(null)` instead of a default object allows proper error detection when useCoreKit() is called outside CoreKitProvider.
3. **Provider deferred from main.tsx** -- Following plan instructions, CoreKitProvider is NOT mounted yet. Plan 03 will wire it into the app when the auth flow is connected.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed WEB3AUTH_NETWORK enum keys for Core Kit**

- **Found during:** Task 2 (Core Kit singleton creation)
- **Issue:** Plan template used `WEB3AUTH_NETWORK.SAPPHIRE_DEVNET` / `WEB3AUTH_NETWORK.SAPPHIRE_MAINNET` which are PnP SDK constants. Core Kit v3.5.0 uses `DEVNET` / `MAINNET` keys.
- **Fix:** Changed all references to `WEB3AUTH_NETWORK.DEVNET` and `WEB3AUTH_NETWORK.MAINNET`
- **Files modified:** `apps/web/src/lib/web3auth/core-kit.ts`
- **Verification:** TypeScript compilation passes, Vite build succeeds
- **Committed in:** b1dd72b (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Minor naming difference between PnP and Core Kit SDKs. No scope creep.

## Issues Encountered

None -- plan executed smoothly after the enum key fix.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Core Kit singleton and React provider are ready for Plan 03 to wire the auth flow
- Plan 03 will mount CoreKitProvider in main.tsx and implement loginWithJWT()
- The REQUIRED_SHARE status is exposed but not handled yet (Phase 12.4 MFA work)
- Existing PnP login flow continues to work in parallel until Plan 05 removes it

---

_Phase: 12-core-kit-identity-provider_
_Completed: 2026-02-12_

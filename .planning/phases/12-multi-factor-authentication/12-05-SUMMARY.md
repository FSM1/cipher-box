---
phase: 12-core-kit-identity-provider
plan: 05
subsystem: auth
tags: [web3auth, mpc-core-kit, importTssKey, migration, e2e, pnp-removal, data-testid]

# Dependency graph
requires:
  - phase: 12-core-kit-identity-provider-03
    provides: Core Kit auth flow wiring (loginWithJWT, hooks.ts, useAuth.ts)
  - phase: 12-core-kit-identity-provider-04
    provides: Custom login UI (GoogleLoginButton, EmailLoginForm, Login.tsx)
provides:
  - PnP-to-Core Kit migration path via importTssKey parameter
  - getMigrationKey() helper for localStorage-based PnP key import
  - Clean @web3auth/modal removal (Core Kit is sole integration)
  - E2E test auth helpers rewritten for CipherBox login UI
  - data-testid attributes on all login form elements
  - SKIP_CORE_KIT direct API auth fallback for E2E
affects: [12.2-device-registry, 12.3-siwe-unified-identity, 12.4-mfa-cross-device]

# Tech tracking
tech-stack:
  added: []
  removed: ['@web3auth/modal@10.13.1']
  patterns:
    - 'importTssKey migration: read PnP key from localStorage, pass once to loginWithJWT, delete'
    - 'data-testid convention for E2E targeting of auth UI elements'
    - 'SKIP_CORE_KIT env var for direct API auth in CI environments'

key-files:
  created: []
  modified:
    - apps/web/src/lib/web3auth/hooks.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/components/auth/EmailLoginForm.tsx
    - apps/web/src/components/auth/GoogleLoginButton.tsx
    - tests/e2e/utils/web3auth-helpers.ts
    - tests/e2e/page-objects/login.page.ts
    - tests/e2e/tests/full-workflow.spec.ts
  deleted:
    - apps/web/src/lib/web3auth/config.ts
    - apps/web/src/lib/web3auth/provider.tsx

key-decisions:
  - 'importTssKey via localStorage: one-time read-and-delete pattern for PnP migration key'
  - 'Auto-detect migration key in login functions (getMigrationKey() called automatically)'
  - 'Devnet uses fresh accounts (no migration needed); production requires importTssKey'
  - 'E2E tests use CipherBox login UI directly (no more Web3Auth modal iframe automation)'
  - 'SKIP_CORE_KIT fallback injects auth state via localStorage for direct API testing'

patterns-established:
  - 'data-testid naming: email-input, send-otp-button, otp-input, verify-button, google-login-button'
  - 'E2E login flow: fill email-input -> click send-otp-button -> fill otp-input -> click verify-button -> waitForURL /files'

# Metrics
duration: 7min
completed: 2026-02-12
---

# Phase 12 Plan 05: PnP Migration + Cleanup + E2E Summary

importTssKey migration path for PnP-to-Core Kit key preservation, @web3auth/modal fully removed, E2E auth helpers rewritten for CipherBox's own login UI with data-testid targeting

## Performance

- **Duration:** 7 min
- **Started:** 2026-02-12T13:11:58Z
- **Completed:** 2026-02-12T13:18:29Z
- **Tasks:** 3 of 3 (Task 4 checkpoint pending)
- **Files modified:** 11 (7 modified, 2 deleted, 2 packages updated)

## Accomplishments

- Added `getMigrationKey()` helper and optional `migrationKey` parameter to both `loginWithGoogle()` and `loginWithEmailOtp()` -- PnP users' existing keys can be imported via `importTssKey` during first Core Kit login
- Completely removed `@web3auth/modal` PnP SDK from dependencies and deleted `config.ts` + `provider.tsx` dead code -- Core Kit is now the sole Web3Auth integration
- Rewrote E2E auth helpers to use CipherBox's own login UI (email input + OTP form) instead of Web3Auth modal popup/iframe automation
- Added `data-testid` attributes to all login form elements for stable E2E test targeting
- Added `SKIP_CORE_KIT` direct API auth fallback for CI environments where Core Kit may not be available

## Task Commits

Each task was committed atomically:

1. **Task 1: PnP Migration Support + importTssKey** - `87f5fa2` (feat)
2. **Task 2: Remove PnP SDK + Dead Code Cleanup** - `87df5af` (chore)
3. **Task 3: Update E2E Test Auth Helpers** - `c14c175` (feat)

## Files Created/Modified

- `apps/web/src/lib/web3auth/hooks.ts` - Added getMigrationKey(), optional migrationKey param, importTssKey wiring, Core Kit publicKey logging
- `apps/web/src/hooks/useAuth.ts` - Added Core Kit publicKey logging, new-user vault re-init warning, removed E2E TODO
- `apps/web/src/components/auth/EmailLoginForm.tsx` - Added data-testid on email-input, send-otp-button, otp-input, verify-button
- `apps/web/src/components/auth/GoogleLoginButton.tsx` - Added data-testid on google-login-button
- `apps/web/package.json` - Removed @web3auth/modal dependency
- `apps/web/src/lib/web3auth/config.ts` - DELETED (PnP config replaced by core-kit.ts)
- `apps/web/src/lib/web3auth/provider.tsx` - DELETED (PnP provider replaced by core-kit-provider.tsx)
- `tests/e2e/utils/web3auth-helpers.ts` - Complete rewrite: CipherBox login UI flow, direct API fallback
- `tests/e2e/page-objects/login.page.ts` - Rewritten: email/OTP/Google methods, no modal interaction
- `tests/e2e/tests/full-workflow.spec.ts` - Updated logout assertion for new login page (email-input check)
- `pnpm-lock.yaml` - Updated for @web3auth/modal removal

## Decisions Made

1. **importTssKey via localStorage one-time read-and-delete** -- The PnP migration key is stored in `__pnp_migration_key__` by a transitional build, read once during login, then immediately deleted. This ensures the sensitive key is only available for a single login attempt.

2. **Auto-detection in login functions** -- Both `loginWithGoogle()` and `loginWithEmailOtp()` automatically call `getMigrationKey()` if no explicit `migrationKey` parameter is passed. This means existing code doesn't need to change for migration to work.

3. **Devnet: fresh start (no migration)** -- On devnet/staging, existing test accounts will get new Core Kit-derived keys and need vault re-initialization. Production will use `importTssKey` for key preservation.

4. **E2E uses CipherBox UI directly** -- Much simpler than the old Web3Auth modal automation (no iframe detection, no popup handling). The login flow is entirely within CipherBox's DOM.

5. **SKIP_CORE_KIT fallback** -- Injects auth state directly via localStorage + page reload, bypassing Core Kit `loginWithJWT` entirely. For CI environments where Web3Auth devnet may be unreliable.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Task 4 (checkpoint:human-verify) is pending -- requires manual end-to-end verification of the complete auth flow
- After checkpoint approval, Phase 12 is complete
- Ready for Phase 12.1 (AES-256-CTR streaming encryption) or Phase 12.2 (Encrypted Device Registry)
- PnP SDK is fully removed -- no backward compatibility concerns
- E2E tests are ready for CI once Core Kit works with devnet test accounts

---

_Phase: 12-core-kit-identity-provider_
_Completed: 2026-02-12_

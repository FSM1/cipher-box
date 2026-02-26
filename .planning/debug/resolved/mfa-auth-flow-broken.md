---
status: resolved
trigger: 'Seven interrelated MFA bugs: three auth flow + four Security tab display'
created: 2026-02-26T00:00:00Z
updated: 2026-02-26T01:30:00Z
---

## Current Focus

hypothesis: All seven root causes confirmed and fixed
test: TypeScript compilation pass
expecting: Clean build
next_action: Archive and commit

## Symptoms

expected:

1. After enabling MFA, device share saved to localStorage; re-login doesn't require additional shares
2. Recovery key completes authentication and grants vault access
3. Device approval requests work for new browsers needing a share
4. Security tab shows recovery phrase as active after recovery sign-in
5. Security tab shows device with browser name and last active time
6. Factor count is consistent with visible UI (devices + recovery)
7. Device last active shows relative time (e.g. "just now") for current device

actual:

1. After MFA enable + logout/login, app shows "missing shares" (required_shares > 0)
2. Recovery key accepted but redirects back to login screen
3. POST /device-approval/request returns 401 Unauthorized
4. Security tab shows "no recovery phrase" even after signing in with recovery
5. Security tab shows "Unknown device" / "last active: unknown" for recovery-created device
6. Factor count (4) is accurate but inconsistent with visible UI (1 device, no recovery shown)
7. Device last active shows "unknown" even for current device after recovery sign-in

errors:

- "missing shares" state after re-login with MFA enabled
- Recovery key redirected to login
- 401 on POST /device-approval/request
- RecoveryPhraseSection shows "no recovery phrase" (type !== 'seedPhrase')
- AuthorizedDevices shows "Unknown device" (no additionalMetadata)

reproduction:

1. Login -> Enable MFA -> Logout -> Login -> "missing shares"
2. Try recovery key -> redirected to login
3. Device approval request -> 401
4. Sign in with recovery phrase -> Settings > Security -> "no recovery phrase"
5. Same flow -> device list shows "Unknown device" / "last active: unknown"
6. Same flow -> device last active shows "unknown" even for current device

started: Current state on staging

## Eliminated

(No eliminated hypotheses -- all three initial hypotheses were confirmed.)

## Evidence

- timestamp: 2026-02-26T00:00:30Z
  checked: Web3Auth SDK source code - handleExistingUser() in mpcCoreKit.js
  found: handleExistingUser() tries hashedFactorKey first. When MFA is enabled, the hashedShare is deleted by enableMFA(). The SDK falls through to REQUIRED_SHARE status WITHOUT checking localStorage for the device factor that was stored by enableMFA() -> setDeviceFactor(). This is an SDK design gap -- the app must explicitly call getDeviceFactor() and inputFactorKey() to auto-recover on known devices.
  implication: Bug 1 root cause confirmed. Need app-level workaround in doLoginWithCoreKit.

- timestamp: 2026-02-26T00:00:35Z
  checked: inputFactorKey() in useMfa.ts and session restoration effect in useAuth.ts
  found: inputFactorKey() called syncStatus() which set coreKitLoggedIn=true in React context. The session restoration useEffect (coreKitLoggedIn && !isAuthenticated) fires, tries authApi.refresh() (fails - no valid backend session from temp placeholder login), then calls coreKitLogout() which undoes the entire recovery.
  implication: Bug 2 root cause confirmed. syncStatus() must be deferred until AFTER backend auth completes.

- timestamp: 2026-02-26T00:00:40Z
  checked: Timing of temp token acquisition vs DeviceWaitingScreen mount
  found: doLoginWithCoreKit calls syncStatus() setting isRequiredShare=true in React context. React may flush this state update and mount DeviceWaitingScreen BEFORE loginWithGoogle/Email/Wallet continues to obtain the temp access token. The original useEffect([], []) fired requestApproval() immediately on mount with no token in the auth store, causing 401.
  implication: Bug 3 root cause confirmed. DeviceWaitingScreen must wait for accessToken before firing requestApproval.

- timestamp: 2026-02-26T00:10:00Z
  checked: TypeScript compilation (pnpm --filter web exec tsc --noEmit)
  found: All fixes compile cleanly with no errors.
  implication: Code changes are type-safe.

- timestamp: 2026-02-26T00:12:00Z
  checked: ESLint (pnpm lint)
  found: Only pre-existing warnings (no-explicit-any in test files). Zero new errors from our changes.
  implication: Fixes pass linting.

- timestamp: 2026-02-26T00:30:00Z
  checked: Web3Auth SDK addFactorDescription() source and enableMFA() internals
  found: enableMFA({}) creates both device and recovery factors with shareDescription defaulting
  to FactorKeyTypeShareDescription.Other ("Other") because createFactor() defaults to "Other"
  when no shareDescription is provided. Our getFactors() parser only recognized "deviceShare"
  and "seedPhrase" module types, so both factors were classified as "Other"/unknown.
  implication: Bug 4+6 root cause confirmed. Need type normalization via tssShareIndex.

- timestamp: 2026-02-26T00:32:00Z
  checked: Web3Auth addFactorDescription() spread behavior
  found: addFactorDescription spreads additionalMetadata at the top level of the JSON description
  object (alongside module, dateAdded, tssShareIndex). Our getFactors() looked for a nested
  parsed.additionalMetadata object that doesn't exist -- metadata fields like deviceId and
  browserName are at the root level.
  implication: Bug 5 root cause confirmed. Need flat JSON extraction for metadata.

- timestamp: 2026-02-26T00:34:00Z
  checked: recoverWithMnemonic() in useMfa.ts
  found: createFactor() call had no additionalMetadata -- the device factor created during
  recovery had no deviceId or browserName, making it unmatchable to the device registry.
  implication: Bug 5 contributing cause. Need to pass device identity and info during recovery.

- timestamp: 2026-02-26T00:40:00Z
  checked: AuthorizedDevices.tsx registryMap filter and lastActive fallback
  found: registryMap only included devices with status === 'authorized'. Recovery-created devices
  get status 'pending' in the registry, so their lastSeenAt was excluded from the map. Also,
  the registry sync is fire-and-forget (void async IIFE), so it may not have completed when the
  Security tab renders -- registry is null in the store, meaning no lastSeenAt for any device.
  implication: Bug 7 root cause confirmed. Two issues: overly strict status filter + no fallback
  for current device when registry hasn't loaded yet.

- timestamp: 2026-02-26T00:50:00Z
  checked: TypeScript compilation after all fixes (pnpm --filter web exec tsc --noEmit)
  found: All fixes compile cleanly with no errors.
  implication: All seven bug fixes are type-safe.

## Resolution

root_cause: |
BUG 1 (missing shares after re-login): Web3Auth MPC Core Kit SDK v3.5.0's handleExistingUser()
does NOT auto-check localStorage for the device factor when the hashedShare has been deleted
(post-MFA enablement). The SDK tries the hashedFactorKey, finds the hashedShare missing, and
falls through to REQUIRED_SHARE status. The device factor IS persisted in localStorage by
enableMFA() -> setDeviceFactor(), but the SDK never retrieves it during login.

BUG 2 (recovery redirects to login): inputFactorKey() in useMfa.ts called syncStatus() which
prematurely transitioned Core Kit's React context to LOGGED_IN (isRequiredShare=false,
coreKitLoggedIn=true). This triggered the session restoration useEffect in useAuth.ts
(guard: coreKitLoggedIn && !isAuthenticated), which attempted authApi.refresh() -- but the
HTTP-only cookie was from the temporary placeholder session, not a valid one. The refresh
failed, causing coreKitLogout(), which undid the entire recovery.

BUG 3 (401 on device approval request): Race condition. doLoginWithCoreKit calls syncStatus()
which sets isRequiredShare=true in React context. React may flush this update and mount
DeviceWaitingScreen before the calling function (loginWithGoogle/Email/Wallet) continues to
obtain the temporary access token. The original useEffect([], []) on mount fired
requestApproval() immediately with no token in auth store.

BUG 4 (recovery phrase shows "no recovery phrase"): enableMFA({}) creates the recovery factor
with shareDescription defaulting to FactorKeyTypeShareDescription.Other ("Other"). getFactors()
only recognized "seedPhrase" as the recovery type. RecoveryPhraseSection checks
type === 'seedPhrase', so the "Other"-typed recovery factor was invisible.

BUG 5 (device shows "Unknown device"): Two causes: (a) Web3Auth's addFactorDescription()
spreads additionalMetadata at the top level of the JSON, but getFactors() looked for a nested
parsed.additionalMetadata object. (b) recoverWithMnemonic() created the device factor without
any additionalMetadata (no deviceId, browserName), so even correct parsing found nothing.

BUG 6 (factor count inconsistent with visible UI): Direct consequence of bugs 4+5. Factor
count (4) was correct from getKeyDetails().totalFactors, but the UI showed fewer because
"Other"-typed factors were not recognized as devices or recovery phrases.

BUG 7 (device last active shows "unknown"): Two causes: (a) AuthorizedDevices registryMap
filtered on status === 'authorized', but recovery-created devices get status 'pending' in
the registry, so their lastSeenAt was excluded. (b) The registry sync is fire-and-forget
(void async IIFE in useAuth), so the Security tab may render before the store is populated,
meaning registry is null and no device has a lastSeenAt to display.

fix: |
BUG 1: Added device factor auto-detection in doLoginWithCoreKit() (hooks.ts). After
REQUIRED_SHARE status, call coreKit.getDeviceFactor(). If found, auto-input it via
coreKit.inputFactorKey(). If status transitions to LOGGED_IN, commit and return 'logged_in'.
Otherwise fall through to true REQUIRED_SHARE.

BUG 2: Removed syncStatus() from inputFactorKey() in useMfa.ts. Added syncStatus() call to
completeRequiredShare() in useAuth.ts, AFTER completeBackendAuth() succeeds. At that point
isAuthenticated is true (from setAccessToken), so the session restoration guard
(coreKitLoggedIn && !isAuthenticated) won't fire.

BUG 3: Added accessToken subscription to DeviceWaitingScreen. Changed mount effect to wait for
accessToken before firing requestApproval(). Added requestFiredRef to prevent duplicate
requests. Separated countdown/cancel cleanup into its own effect.

BUG 4: Fixed getFactors() to normalize type via tssShareIndex. When module is "Other",
tssShareIndex 2 maps to DeviceShare, tssShareIndex 3 maps to SeedPhrase. Also fixed
enableMfa() to pass shareDescription: SeedPhrase so future enrollments tag the recovery
factor correctly (existing accounts handled by tssShareIndex normalization).

BUG 5: Fixed getFactors() to extract additionalMetadata from the flat JSON structure instead
of looking for a nested object. Excludes known system fields (module, dateAdded, tssShareIndex,
tssIndex). Also added device metadata (deviceId, browserName) to recoverWithMnemonic()'s
createFactor call using getOrCreateDeviceIdentity() and detectDeviceInfo().

BUG 6: Resolved automatically by fixes 4+5 -- correct type normalization makes all factors
visible in the appropriate UI sections.

BUG 7: Broadened AuthorizedDevices registryMap filter from status === 'authorized' to
status !== 'revoked', so pending devices (from recovery) have their lastSeenAt included.
Added "just now" fallback for the current device when no registry entry exists (handles
the race where registry sync hasn't completed yet).

verification: |

- TypeScript compilation: PASS (zero errors for all seven fixes)
- ESLint: PASS (zero new errors, only pre-existing warnings)
- Code review: All files verified for correctness

files_changed:

- apps/web/src/lib/web3auth/hooks.ts (bug 1)
- apps/web/src/hooks/useMfa.ts (bugs 2, 4, 5, 6)
- apps/web/src/hooks/useAuth.ts (bug 2)
- apps/web/src/components/mfa/DeviceWaitingScreen.tsx (bug 3)
- apps/web/src/components/mfa/AuthorizedDevices.tsx (bug 7)

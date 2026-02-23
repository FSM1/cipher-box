---
phase: 15-link-sharing
plan: 02
subsystem: crypto
tags: [ecies, secp256k1, ephemeral-key, invite-link, key-wrapping, orval]

# Dependency graph
requires:
  - phase: 14
    provides: Share/ShareKey entities, wrapKey/unwrapKey from @cipherbox/crypto, ShareDialog
  - phase: 15-01
    provides: InvitesController, ShareInvitesController, Orval-generated API client for invite endpoints
provides:
  - Shared collectChildKeys and reWrapEncryptedKey utilities in lib/crypto/key-wrapping.ts
  - invite.service.ts with createInviteLink, claimInvite, buildInviteUrl, checkInviteStatus, fetchInvitesForItem, revokeInvite
  - Ephemeral key bridge crypto (wrap with ephemeral pubkey, unwrap with ephemeral privkey, re-wrap with own pubkey)
affects:
  - 15-03 (ShareDialog invite tab and InvitePage consume invite.service.ts functions)
  - 15-04 (E2E tests exercise invite creation and claim flows)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Ephemeral key bridge: secp256k1.keygen() for invite links, wrap with ephemeral pubkey, privkey in URL fragment'
    - 'Shared key-wrapping utility: collectChildKeys extracted for reuse across direct share and invite flows'
    - 'HashRouter-safe URL format: #/invite/:token?key=<hex> keeps ephemeral key in fragment'

key-files:
  created:
    - apps/web/src/lib/crypto/key-wrapping.ts
    - apps/web/src/services/invite.service.ts
  modified:
    - apps/web/src/components/file-browser/ShareDialog.tsx

key-decisions:
  - 'secp256k1.keygen() for ephemeral keypair (v3 API, not randomPrivateKey)'
  - 'Orval void-typed claim response cast with as unknown as { shareId: string }'
  - 'collectChildKeys extracted to shared utility to prevent duplication between ShareDialog and invite service'

patterns-established:
  - 'lib/crypto/ directory for shared cryptographic utilities'
  - 'Ephemeral key bridge pattern: generate keypair, wrap with pubkey, put privkey in URL fragment, recipient unwraps and re-wraps'

# Metrics
duration: 7min
completed: 2026-02-23
---

# Phase 15 Plan 02: API Client + Invite Service Summary

**Shared key-wrapping utilities extracted from ShareDialog, invite.service.ts with ephemeral key bridge crypto using secp256k1.keygen() and HashRouter-safe URL format**

## Performance

- **Duration:** 7 min
- **Started:** 2026-02-23T00:55:26Z
- **Completed:** 2026-02-23T01:03:07Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Extracted collectChildKeys and reWrapEncryptedKey from ShareDialog into shared lib/crypto/key-wrapping.ts utility
- Created invite.service.ts with 6 exported functions covering invite lifecycle: create, claim, status check, list, revoke, URL construction
- Ephemeral key bridge: secp256k1.keygen() generates keypair, item key wrapped with ephemeral pubkey, privkey in URL fragment
- Claim flow fetches from authenticated GET /invites/:token/data, unwraps with ephemeral privkey, re-wraps with own pubkey
- All sensitive key material (ephemeral privkeys, plaintext keys) zeroed in finally blocks (6 .fill(0) sites)

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract shared key-wrapping utilities** - `04fd44734` (refactor)
2. **Task 2: Frontend invite service with ephemeral key bridge** - `80021edad` (feat)

## Files Created/Modified

- `apps/web/src/lib/crypto/key-wrapping.ts` - Shared collectChildKeys and reWrapEncryptedKey utilities for ECIES re-wrapping
- `apps/web/src/services/invite.service.ts` - Invite creation, claim, management with ephemeral key bridge crypto
- `apps/web/src/components/file-browser/ShareDialog.tsx` - Updated to import from shared key-wrapping utility

## Decisions Made

- Used `secp256k1.keygen()` (noble v3 API) instead of `utils.randomPrivateKey()` which doesn't exist in v3. Returns `{ secretKey, publicKey }`.
- Orval generates `void` return type for claim endpoint (OpenAPI spec has no response schema for 201). Cast with `as unknown as { shareId: string }` matching existing codebase pattern.
- `collectChildKeys` extracted to shared utility rather than duplicated in invite.service.ts. Both direct share and invite link use identical folder traversal logic, just with different target public keys.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed secp256k1 v3 API for keypair generation**

- **Found during:** Task 2 (invite.service.ts implementation)
- **Issue:** Plan specified `secp256k1.utils.randomPrivateKey()` but @noble/secp256k1 v3.0.0 in web app uses `keygen()` which returns `{ secretKey, publicKey }`
- **Fix:** Used `secp256k1.keygen()` matching existing pattern in useDeviceApproval.ts
- **Files modified:** apps/web/src/services/invite.service.ts
- **Verification:** TypeScript compilation passes
- **Committed in:** 80021edad (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary fix for correct API usage. No scope creep.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Shared key-wrapping utilities and invite service ready for Plan 15-03 (ShareDialog tabbed UI + InvitePage landing page)
- All API client types available for component consumption
- No blockers

---

_Phase: 15-link-sharing_
_Completed: 2026-02-23_

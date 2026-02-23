---
phase: 15-link-sharing
verified: 2026-02-23T19:27:24Z
status: gaps_found
score: 7/8 must-haves verified
gaps:
  - truth: 'User can revoke active invite links'
    status: failed
    reason: 'InviteResponseDto does not include invite UUID id; fetchInvitesForItem maps token as id; revokeInvite passes token to DELETE /shares/invites/:inviteId which uses ParseUUIDPipe -- token is base64url, not UUID, so revoke will fail with 400'
    artifacts:
      - path: 'apps/web/src/services/invite.service.ts'
        issue: 'fetchInvitesForItem maps inv.token as id (line 321), but revokeInvite passes this to DELETE endpoint expecting UUID'
      - path: 'apps/api/src/shares/dto/invite-response.dto.ts'
        issue: 'InviteResponseDto does not include the invite UUID id field'
      - path: 'apps/api/src/shares/share-invites.controller.ts'
        issue: 'revokeInvite uses ParseUUIDPipe on inviteId param (line 146)'
    missing:
      - 'Add id field to InviteResponseDto (and backend list endpoint response)'
      - 'OR change fetchInvitesForItem to map a real UUID field instead of token'
      - 'Regenerate API client after DTO change'
---

# Phase 15: Link Sharing Verification Report

**Phase Goal:** Users can share files and folders via invite links where the decryption key lives in the URL fragment only (never sent to server). Recipients must authenticate (invite model) and the share is auto-claimed using Phase 14 infrastructure.
**Verified:** 2026-02-23T19:27:24Z
**Status:** gaps_found
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| #   | Truth                                                                                              | Status   | Evidence                                                                                                                                                                                                                                                                                                                          |
| --- | -------------------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | User can generate a shareable link for a file where the decryption key is in the URL fragment only | VERIFIED | `invite.service.ts` generates ephemeral secp256k1 keypair, wraps key with ephemeral pubkey, puts privkey in `#/invite/:token?key=<hex>` fragment. `buildInviteUrl()` at line 83 constructs HashRouter-safe URL. Ephemeral privkey never sent to API.                                                                              |
| 2   | Recipient can open the link, log in, and the share is auto-claimed                                 | VERIFIED | `InvitePage.tsx` parses token from route params and key from searchParams. `useEffect` at line 95 watches `isAuthenticated` and auto-triggers `claimInvite()`. `claimInvite()` in invite.service.ts fetches encrypted data from `GET /invites/:token/data`, unwraps with ephemeral key, re-wraps with own pubkey, POSTs to claim. |
| 3   | Server never sees plaintext key or ephemeral private key                                           | VERIFIED | Ephemeral privkey only in URL fragment (never sent to server per HTTP spec). `invite.service.ts` has 6 `.fill(0)` sites zeroing all sensitive key material in `finally` blocks. No `console.log` in invite.service.ts or InvitePage.tsx.                                                                                          |
| 4   | User can switch between Direct Share and Invite Link tabs in ShareDialog                           | VERIFIED | `ShareDialog.tsx` has `share-tab-bar` with `role="tablist"`, two tabs with `role="tab"` and `aria-selected`, `activeTab` state switching between 'direct' and 'invite'. InviteLinkTab renders only when `activeTab === 'invite'`.                                                                                                 |
| 5   | User can create an invite link and it is auto-copied to clipboard                                  | VERIFIED | `InviteLinkTab.tsx` `handleCreate()` calls `createInviteLink()` then `navigator.clipboard.writeText(url)`. Success message shows truncated URL.                                                                                                                                                                                   |
| 6   | User can see active invite links with revoke actions                                               | PARTIAL  | `InviteLinkTab.tsx` fetches active invites, displays ACTIVE badge and dates, has inline confirm revoke UI. However, revoke is BROKEN (see gap below).                                                                                                                                                                             |
| 7   | Recipient sees branded landing page with login CTA and error states                                | VERIFIED | `InvitePage.tsx` (306 lines) renders MatrixBackground, CipherBox branding, inline Google/Email/Wallet auth, error cards with red border for expired/claimed/revoked/invalid states, MFA/device-approval support.                                                                                                                  |
| 8   | Expired/claimed/revoked invites show friendly error cards                                          | VERIFIED | `ERROR_MESSAGES` record maps status to messages. `invite-card--error` CSS class applies red border. `[GO HOME]` button navigates to `/`.                                                                                                                                                                                          |

**Score:** 7/8 truths verified (1 partial due to revoke bug)

### Required Artifacts

| Artifact                                                   | Expected                                                          | Status   | Details                                                                                                                                                                                               |
| ---------------------------------------------------------- | ----------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/api/src/shares/entities/share-invite.entity.ts`      | ShareInvite TypeORM entity                                        | VERIFIED | 73 lines, all columns (token, encryptedKey bytea, encryptedChildKeys JSONB, status, expiresAt, claimedBy, maxClaims), @ManyToOne to User, snake_case column names                                     |
| `apps/api/src/migrations/1740400000000-AddShareInvites.ts` | CREATE TABLE IF NOT EXISTS                                        | VERIFIED | 50 lines, idempotent creation with UNIQUE token, FK to users, indexes on sharer_id and expires_at                                                                                                     |
| `apps/api/src/shares/invites.controller.ts`                | Public status + authenticated data + claim                        | VERIFIED | 132 lines, @Controller('invites'), no class-level auth guard. GET :token (ThrottlerGuard only), GET :token/data (JwtAuthGuard), POST :token/claim (JwtAuthGuard). Returns encryptedKey as hex string. |
| `apps/api/src/shares/share-invites.controller.ts`          | Authenticated create/list/revoke                                  | VERIFIED | 150 lines, @Controller('shares/invites'), class-level JwtAuthGuard+ThrottlerGuard. POST create, GET list by ipnsName, DELETE revoke with ParseUUIDPipe.                                               |
| `apps/api/src/shares/shares.service.ts`                    | 6 invite methods                                                  | VERIFIED | createInvite, getInviteStatus, getInviteForClaim, claimInvite (atomic UPDATE), getInvitesForItem, revokeInvite. Auto-expire on read. Self-claim prevention.                                           |
| `apps/api/src/shares/dto/create-invite.dto.ts`             | CreateInviteDto with validators                                   | VERIFIED | 84 lines, class-validator decorators, hex pattern match, nested InviteChildKeyDto                                                                                                                     |
| `apps/api/src/shares/dto/claim-invite.dto.ts`              | ClaimInviteDto for re-wrapped keys                                | VERIFIED | 60 lines, class-validator decorators, hex pattern match, nested ClaimChildKeyDto                                                                                                                      |
| `apps/api/src/shares/dto/invite-response.dto.ts`           | InviteResponseDto, InviteStatusResponseDto, InviteDataResponseDto | VERIFIED | 75 lines, all three DTOs with ApiProperty decorators. NOTE: InviteResponseDto missing `id` field (see gap).                                                                                           |
| `apps/web/src/api/invites/invites.ts`                      | Generated Orval client for /invites                               | VERIFIED | Generated, exports invitesControllerGetInviteStatus, invitesControllerGetInviteData, invitesControllerClaimInvite                                                                                     |
| `apps/web/src/api/share-invites/share-invites.ts`          | Generated Orval client for /shares/invites                        | VERIFIED | Generated, exports shareInvitesControllerCreateInvite, shareInvitesControllerListInvites, shareInvitesControllerRevokeInvite                                                                          |
| `apps/web/src/lib/crypto/key-wrapping.ts`                  | Shared collectChildKeys + reWrapEncryptedKey                      | VERIFIED | 144 lines, recursive folder traversal, key zeroing in finally blocks, used by both ShareDialog.tsx and invite.service.ts                                                                              |
| `apps/web/src/services/invite.service.ts`                  | Invite service with ephemeral key bridge                          | VERIFIED | 338 lines, 7 exported functions (createInviteLink, claimInvite, buildInviteUrl, checkInviteStatus, fetchInvitesForItem, revokeInvite, InviteInfo type). 6 fill(0) sites. No TODOs.                    |
| `apps/web/src/components/file-browser/InviteLinkTab.tsx`   | Invite link creation, listing, revoke UI                          | VERIFIED | 232 lines, creates links with clipboard copy, shows active invites, inline confirm revoke. Imports from invite.service.                                                                               |
| `apps/web/src/components/file-browser/ShareDialog.tsx`     | Tabbed dialog with Direct Share + Invite Link                     | VERIFIED | Has share-tab-bar, activeTab state, imports InviteLinkTab and collectChildKeys from shared utility                                                                                                    |
| `apps/web/src/routes/InvitePage.tsx`                       | Standalone invite landing page with auth + claim                  | VERIFIED | 306 lines, state machine (loading/valid/claiming/claimed/error), inline auth (Google/Email/Wallet), MFA support, auto-claim on isAuthenticated, ephemeral key in useRef, no console.log               |
| `apps/web/src/routes/index.tsx`                            | Route config with /invite/:token                                  | VERIFIED | `<Route path="/invite/:token" element={<InvitePage />} />` outside AppShell                                                                                                                           |
| `apps/web/src/styles/invite-page.css`                      | Invite page styles                                                | VERIFIED | 191 lines, invite-card, invite-card--error, focus-visible styles                                                                                                                                      |
| `apps/web/src/styles/share-dialog.css`                     | Tab bar + invite link styles                                      | VERIFIED | 452 lines, share-tab-bar, share-tab--active, invite-link-item, focus-visible (7 rules)                                                                                                                |
| `tests/e2e/page-objects/dialogs/invite-link-tab.page.ts`   | InviteLinkTabPage page object                                     | VERIFIED | 227 lines, exported in barrel index                                                                                                                                                                   |
| `tests/e2e/page-objects/pages/invite.page.ts`              | InvitePageObject page object                                      | VERIFIED | 177 lines, exported in barrel index                                                                                                                                                                   |
| `tests/e2e/tests/invite-link-workflow.spec.ts`             | E2E test suite                                                    | VERIFIED | 625 lines, 21 serial tests covering setup, tab UI, file/folder invite happy path, link management, error states, cleanup                                                                              |

### Key Link Verification

| From                         | To                 | Via                                                        | Status | Details                                                                                                                                                                                                           |
| ---------------------------- | ------------------ | ---------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| InvitesController            | SharesService      | constructor injection                                      | WIRED  | `constructor(private readonly sharesService: SharesService)`                                                                                                                                                      |
| ShareInvitesController       | SharesService      | constructor injection                                      | WIRED  | `constructor(private readonly sharesService: SharesService)`                                                                                                                                                      |
| SharesService                | ShareInvite entity | TypeORM repository                                         | WIRED  | `@InjectRepository(ShareInvite) private readonly inviteRepo`                                                                                                                                                      |
| app.module.ts                | ShareInvite        | entities array                                             | WIRED  | `ShareInvite` imported and listed in entities                                                                                                                                                                     |
| shares.module.ts             | Both controllers   | controllers array                                          | WIRED  | `[SharesController, InvitesController, ShareInvitesController]`                                                                                                                                                   |
| generate-openapi.ts          | Both controllers   | controllers array + mock repo                              | WIRED  | Both imported, mock repo registered, tags added                                                                                                                                                                   |
| invite.service.ts            | Orval API client   | import functions                                           | WIRED  | Imports invitesControllerGetInviteStatus, invitesControllerGetInviteData, invitesControllerClaimInvite, shareInvitesControllerCreateInvite, shareInvitesControllerListInvites, shareInvitesControllerRevokeInvite |
| invite.service.ts            | @cipherbox/crypto  | import wrapKey, unwrapKey                                  | WIRED  | Line 13: `import { wrapKey, unwrapKey, hexToBytes, bytesToHex } from '@cipherbox/crypto'`                                                                                                                         |
| invite.service.ts            | key-wrapping.ts    | import collectChildKeys                                    | WIRED  | Line 26: `import { collectChildKeys } from '../lib/crypto/key-wrapping'`                                                                                                                                          |
| ShareDialog.tsx              | key-wrapping.ts    | import collectChildKeys, reWrapEncryptedKey                | WIRED  | Line 25: imports from shared utility (no inline definition)                                                                                                                                                       |
| InviteLinkTab.tsx            | invite.service.ts  | import createInviteLink, fetchInvitesForItem, revokeInvite | WIRED  | Line 3                                                                                                                                                                                                            |
| InvitePage.tsx               | invite.service.ts  | import claimInvite, checkInviteStatus                      | WIRED  | Line 10                                                                                                                                                                                                           |
| InvitePage.tsx               | useAuth hook       | import useAuth                                             | WIRED  | Line 11, watches isAuthenticated for auto-claim                                                                                                                                                                   |
| routes/index.tsx             | InvitePage         | Route element                                              | WIRED  | Line 13: `<Route path="/invite/:token" element={<InvitePage />} />`                                                                                                                                               |
| invite-link-workflow.spec.ts | InviteLinkTabPage  | import page object                                         | WIRED  | Uses for tab switching, create, clipboard, revoke                                                                                                                                                                 |
| invite-link-workflow.spec.ts | InvitePageObject   | import page object                                         | WIRED  | Uses for navigation, state detection                                                                                                                                                                              |

### Requirements Coverage

| Requirement                                                                      | Status           | Blocking Issue                                                                                                                                                                                                |
| -------------------------------------------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SHARE-06: User can generate shareable link (decryption key in URL fragment only) | SATISFIED        | None                                                                                                                                                                                                          |
| SHARE-07: Recipient can download via link without account                        | DESIGN DEVIATION | Phase 15 implements invite model (requires auth) per ROADMAP success criteria. SHARE-07 as written (no account) is not what this phase delivers. The ROADMAP explicitly states "log in or create an account." |

### Anti-Patterns Found

| File                                      | Line | Pattern                                        | Severity | Impact                                                                      |
| ----------------------------------------- | ---- | ---------------------------------------------- | -------- | --------------------------------------------------------------------------- |
| `apps/web/src/services/invite.service.ts` | 321  | `id: inv.token` -- maps token as id for revoke | Blocker  | Revoke fails: token is base64url but backend expects UUID via ParseUUIDPipe |

### Human Verification Required

### 1. Visual Appearance of InvitePage

**Test:** Open `http://localhost:5173/#/invite/sometoken?key=deadbeef` in browser
**Expected:** Branded card with MatrixBackground, CipherBox title, "someone shared a file with you", login buttons (Google, Email, Wallet), terminal aesthetic
**Why human:** Visual appearance and layout cannot be verified programmatically without Playwright MCP

### 2. ShareDialog Tab Switching UX

**Test:** Right-click a file in FileBrowser, select Share, click between DIRECT SHARE and INVITE LINK tabs
**Expected:** Smooth tab switching, tab bar highlights active tab with green, direct share content hidden when invite tab active and vice versa
**Why human:** Interactive UX behavior and visual tab state

### 3. End-to-End Invite Link Flow

**Test:** Create invite link, copy URL, open in incognito, log in, verify share appears in ~/shared
**Expected:** Complete flow works: create link -> open URL -> see landing page -> log in -> auto-claim -> redirect to /shared -> see shared item
**Why human:** Full multi-browser flow with real auth, IPNS resolution, and crypto operations

### Gaps Summary

**One gap found: invite link revocation is broken due to ID/token mismatch.**

The `InviteResponseDto` returned by the list endpoint contains `token` (base64url string) but NOT the invite's UUID `id`. The frontend `fetchInvitesForItem` function maps `inv.token` as the `id` field. When `revokeInvite(inviteId)` is called, it passes this token string to `DELETE /shares/invites/:inviteId`, but the backend controller applies `ParseUUIDPipe` to the parameter, which will reject non-UUID strings with a 400 error.

**Fix options:**

1. Add `id` field to `InviteResponseDto` and backend list response, then use `id` for revocation
2. Change backend revoke endpoint to accept token instead of UUID (less standard)

Option 1 is cleaner and follows the existing pattern where entity `id` is always available in API responses.

---

_Verified: 2026-02-23T19:27:24Z_
_Verifier: Claude (gsd-verifier)_

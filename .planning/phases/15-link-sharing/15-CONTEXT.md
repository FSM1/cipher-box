# Phase 15: Link Sharing - Context

**Gathered:** 2026-02-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Share files and folders via invite links. Recipients click the link, log in (or create an account), and the share is auto-claimed using Phase 14's ECIES re-wrapping infrastructure. This is an **invite model** (account required), NOT an unauthenticated web viewer.

Scope: invite link generation, ephemeral key bridge, claim flow, landing page, Share dialog updates, link management (view active, revoke).

Out of scope: unauthenticated file viewing, password-protected links, multi-claim links, short domains.

</domain>

<decisions>
## Implementation Decisions

### Sharing model

- **Invite link model** (account required) -- not unauthenticated access
- Link = invitation to claim a share; recipient must log in or sign up
- Serves as user acquisition funnel -- new users can sign up through the invite flow
- After claim, share appears in recipient's "Shared with me" (Phase 14 infrastructure)

### Ephemeral key bridge

- Core challenge: ECIES needs recipient's public key, but recipient may not exist yet
- Solution: sharer generates ephemeral secp256k1 keypair
- Wraps file/folder key with ephemeral public key, stores wrapped ciphertext on server
- Ephemeral PRIVATE key goes in URL fragment (never sent to server -- zero-knowledge preserved)
- Recipient claims: uses ephemeral key to unwrap, re-wraps with their own public key
- Creates standard Phase 14 Share + ShareKey records
- Well-established pattern (Signal invite links, Bitwarden Send)

### Invite landing page

- New route: `/invite/:token#ephemeralPrivateKey`
- Branded but opaque -- CipherBox branding + "Someone shared a file with you"
- Do NOT reveal file name or sharer identity before auth
- Prominent login/signup CTA button
- After auth, share is auto-claimed and recipient navigates directly to the shared content
- Error states: expired (7-day TTL), already claimed, revoked -- all show friendly error card with red border

### Link generation flow

- Lives in existing ShareDialog as a new tab alongside "Direct Share" (paste pubkey)
- Tab bar: DIRECT SHARE | INVITE LINK (2px green bottom-border active indicator)
- "Create invite link" primary button in invite tab
- Shows active (unclaimed, unexpired) links with --copy and --revoke actions
- Links auto-copied to clipboard on creation
- Modal widened from 500px to 600px to accommodate tab bar

### Link lifecycle

- Default expiry: 7 days (configurable constant, easy to change later)
- Single-claim: first person to claim gets it (maxClaims=1, extensible to multi-claim later)
- Revoking invite link only prevents new claims -- already-claimed shares persist independently
- Auto-cleanup on read: expired records deleted when querying invites (same pattern as device approval Phase 12.4)
- No rate limiting on link creation

### Data architecture

- New ShareInvite database table (not IPFS) -- ephemeral, short-lived data
- Stores: invite token, wrapped key ciphertext, item reference (ipnsName), sharer userId, expiry, status, claimedBy
- Invite token: URL-safe base64, ~22 chars, 128 bits of entropy
- URL on main app domain: `app.cipherbox.cc/invite/:token#ephemeralKey`
- Claiming auto-creates Phase 14 Share + ShareKey records -- recipient sees it in "Shared with me"

### Claude's Discretion

- Exact invite token generation implementation
- Database cleanup query strategy (batch vs per-request)
- Error page illustrations/copy refinement
- Clipboard copy UX feedback (toast, animation, etc.)

</decisions>

<specifics>
## Specific Ideas

- "I want to use the share feature as a funnel to get users to create accounts" -- landing page should encourage sign-up
- Start branded-but-opaque (no info before auth), can A/B test showing file name later
- Direct-to-content navigation after claim preferred over redirect to "Shared with me" list
- Auto-cleanup preferred over audit trail -- can switch to keeping records later if users want history

</specifics>

<deferred>
## Deferred Ideas

- Password-protected invite links (ephemeral key + password double layer) -- future enhancement
- Multi-claim links (share with N recipients from one link) -- maxClaims column ready, just needs UI
- Short domain for cleaner URLs (cb.link/) -- requires DNS/redirect infrastructure
- Unauthenticated web viewer (key-in-fragment, no account needed) -- fundamentally different security surface, could be its own phase
- Client-side search -- split into Phase 15.1

</deferred>

## Approved Design Direction

**Screens in Pencil:**

- `P15 - Invite Landing (Valid)` -- full-page centered card, CipherBox branding, login CTA
- `P15 - Invite Landing (Expired)` -- red border error card, expiry message, --home button
- `P15 - Share Dialog (Invite Tab)` -- tabbed modal with invite link management

**Key design patterns:**

- Tab bar: 2px bottom-border active indicator, green/muted color states
- Status badges: ACTIVE (green border), inline with link metadata
- Invite landing: full-viewport centered card (no sidebar), mirrors Phase 12.4 new-device-waiting pattern
- Error states: red (#EF4444) border on card, matching existing error pattern

---

_Phase: 15-link-sharing_
_Context gathered: 2026-02-23_

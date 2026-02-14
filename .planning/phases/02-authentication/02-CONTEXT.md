# Phase 2: Authentication - Context

**Gathered:** 2026-01-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Users can securely sign in and get tokens for API access. Supports email/password, OAuth (Google, Apple, GitHub), magic link, and external wallet (MetaMask). Users can link multiple auth methods to the same vault. Sessions persist via refresh tokens.

</domain>

<decisions>
## Implementation Decisions

### Login UX flow

- Landing page first (brief intro/value prop with prominent "Sign in" button), not direct to modal
- Login errors display inline within the Web3Auth modal flow
- "Remember me" checkbox: explicit opt-in that extends session duration
- Loading states: Claude's discretion based on expected duration

### Session handling

- Token storage: Claude's discretion (balance security vs UX)
- Multi-tab behavior: Independent tabs, each manages its own session
- Token refresh: Silent auto-refresh in background, user never sees it
- Logout: Immediate on click, no confirmation dialog

### Auth method priority

- All auth methods displayed with equal prominence (no hierarchy)
- Magic link shown as first-class primary option alongside other methods
- Returning users: Highlight their last used auth method ("Continue with Google")
- Wallet auto-detection: If MetaMask detected, show "Connect Wallet" prominently

### Claude's Discretion

- Loading state design (spinner vs progress steps) based on duration
- Token storage mechanism (HTTP-only cookie vs in-memory)
- Exact layout and spacing of auth method buttons
- Error message copy and styling

</decisions>

<specifics>
## Specific Ideas

- Returning user experience should feel like "Continue with..." rather than starting fresh
- Wallet detection should be seamless for Web3-native users

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

_Phase: 02-authentication_
_Context gathered: 2026-01-20_

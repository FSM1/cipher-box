# Phase 12: Core Kit Identity Provider Foundation - Context

**Gathered:** 2026-02-12
**Updated:** 2026-02-12 (scoped down from full MFA to identity provider foundation)
**Status:** Ready for research and planning

## Phase Boundary

Replace the PnP Modal SDK auth layer with Web3Auth MPC Core Kit and establish CipherBox backend as the identity provider for Web3Auth. This phase builds the foundation that all subsequent auth work depends on: custom login UI, Core Kit initialization, and JWT-based identity resolution. No MFA enrollment, no SIWE, no wallet unification — those are separate phases.

Cross-platform desktop MFA is a separate phase (11). Sharing and link generation are separate phases (14-15).

## Architectural Decisions (2026-02-12)

### Why not PnP Modal SDK?

The initial research (12-RESEARCH.md) found that the PnP Modal SDK approach (`mfaSettings` + React hooks) gives up too much control:

- **No cross-device approval flow**: PnP SDK hides device management behind `manageMFA()` in an opaque modal iframe.
- **No custom enrollment UX**: SDK handles all MFA UI in its modal — can't customize enrollment steps, recovery phrase presentation, or factor management.
- **Device shares are ephemeral**: Browser localStorage is fragile. Without cross-device transfer, losing browser data means falling back to recovery phrase every time.
- **No programmatic share management**: Can't build custom device sync or approval flows.
- **External wallet MFA gap**: PnP SDK's MFA (Shamir splits) only applies to MPC-derived keys, not external wallet logins. Wallet users would bypass MFA entirely.

### The full architecture (spanning Phases 12–12.4)

The complete auth rework is split across multiple phases:

1. **Phase 12 (this phase):** Core Kit + CipherBox identity provider foundation
2. **Phase 12.2:** Encrypted device registry on IPFS
3. **Phase 12.3:** SIWE + unified identity (wallet unification)
4. **Phase 12.4:** MFA enrollment + cross-device approval

### CipherBox as identity provider

CipherBox backend becomes the sole identity provider for Web3Auth via a **single custom JWT verifier**:

- All auth methods (Google OAuth, email, future SIWE) flow through CipherBox backend
- Backend verifies credentials, issues JWT with `sub = userId` (CipherBox internal user ID)
- Web3Auth sees only CipherBox JWTs — never knows whether user logged in with Google, email, or wallet
- Single custom verifier on Web3Auth dashboard, JWKS endpoint on CipherBox API

**Why `userId` as verifierId (not email or wallet address):**

- Enables future multi-auth linking (multiple wallets, wallet + email) without changing the verifierId
- Less identity data leaks to Web3Auth (it only sees an opaque userId)
- One-way door decision: once users have keys derived from this verifierId scheme, changing it means different keys

### Identity trilemma

We identified a fundamental trilemma — pick any two:

1. **Wallet-only login** (no email required)
2. **Unified identity** across auth methods (one MPC key, one vault)
3. **No single point of failure** in the auth path

**Chosen tradeoff: (1 + 2) with mitigations.** CipherBox backend is the identity trust anchor (SPOF for auth). Mitigations:

- **Hashed wallet addresses in DB** — `hash(wallet_address) → userId`, not plaintext. Reduces data breach exposure.
- **Encrypted key export as break-glass** — password-encrypted private key export for disaster recovery (CipherBox ceases to exist entirely). Weaker than MFA, but specifically for catastrophic scenarios.
- **Encrypted device registry on IPFS** (Phase 12.2) — durable metadata pinned alongside vault, recoverable if backend is rebuilt.

### Multi-auth identity model

Every user has a `userId`. They attach auth methods to it:

```text
userId → wallet_A (primary, from signup)
userId → wallet_B (added later from settings)
userId → user@email.com (added later from settings)
```

Any linked method can produce a JWT with `sub = userId` → same Web3Auth account. Users choose their own recovery strategy:

- **Privacy maximalist:** link a second wallet, no email ever
- **Convenience:** add an email as backup
- **Belt and suspenders:** second wallet + email

All optional, all additive, no mandatory email.

### Cross-device approval (Phase 12.4)

Built on Core Kit's `createFactor()` / `inputFactorKey()` primitives, inspired by tKey's `ShareTransferModule` pattern:

- **Bulletin board pattern:** New device posts an ECIES ephemeral public key as a request. Existing device encrypts a fresh factor key to that public key. New device polls and decrypts.
- **Storage split:** Database for the ephemeral handshake (mutable, short-lived). IPFS for the durable encrypted device registry (authorized devices, public keys, revocation status).
- **tKey used a centralized metadata server** (`metadata.tor.us`), not raw IPFS, despite documentation suggesting otherwise. We use PostgreSQL for the bulletin board + IPFS for durable state.

### Key identity preservation

- Research confirmed: TSS key redistribution via `enableMFA()` preserves the underlying key (2/2 → 2/3 without changing the key)
- `_UNSAFE_exportTssKey()` returns identical key before and after MFA enrollment
- Critical for vault continuity — no re-encryption needed

### PnP → Core Kit migration

- PnP and Core Kit generate DIFFERENT private keys for the same user
- Migration path: `importTssKey` parameter on first Core Kit login imports existing PnP key
- Must be handled carefully in Phase 12 to preserve existing user vaults

## Phase 12 Scope (This Phase Only)

### What's IN scope

- Replace PnP Modal SDK (`@web3auth/modal`) with MPC Core Kit (`@web3auth/mpc-core-kit`)
- Build custom login UI (Google OAuth, email passwordless) — CipherBox-branded, not Web3Auth modal
- CipherBox backend becomes identity provider: verify credentials, issue JWTs with `sub = userId`
- Set up custom JWT verifier on Web3Auth dashboard + JWKS endpoint on API
- Core Kit initialization with singleton pattern and COREKIT_STATUS state machine
- Handle PnP → Core Kit key migration via `importTssKey`
- Private key export via `_UNSAFE_exportTssKey()` for ECIES operations (existing vault flow)
- Session persistence across page reloads

### What's OUT of scope (future phases)

- MFA enrollment (device share, recovery phrase, factor management) → Phase 12.4
- SIWE for wallet login → Phase 12.3
- Wallet-to-userId linking / multi-auth → Phase 12.3
- Cross-device approval flow → Phase 12.4
- Encrypted device registry on IPFS → Phase 12.2
- Desktop app Core Kit integration → separate consideration

### Implementation decisions for this phase

- **Custom login UI**: Build CipherBox-branded login screens. Google OAuth button + email magic link input.
- **Core Kit singleton**: Single instance, initialized once, managed via React context/provider.
- **COREKIT_STATUS handling**: `NOT_INITIALIZED → INITIALIZED → LOGGED_IN`. Handle `REQUIRED_SHARE` status (will appear once MFA is enabled in Phase 12.4, but code should handle it gracefully now).
- **Backend JWT flow**: Google OAuth → CipherBox API verifies → issues signed JWT → client submits to `loginWithJWT()`.
- **Email passwordless**: Research needed — does Core Kit support email passwordless natively, or does CipherBox backend need to implement magic link flow?
- **Key migration**: First login on Core Kit must detect existing PnP user and import their key.

### Claude's Discretion

- Login UI design and layout
- Error/loading states during Core Kit initialization and login
- Session persistence strategy (Core Kit has built-in session management)
- Whether to keep PnP SDK as temporary fallback during migration
- Backend JWT endpoint design (REST path, token format, expiry)

## Success Criteria

1. User can log in via Google OAuth through CipherBox-branded UI (not Web3Auth modal)
2. User can log in via email through CipherBox-branded UI
3. CipherBox backend issues JWTs with `sub = userId`, verified by Web3Auth custom verifier
4. Core Kit initialization, login, and private key export work end-to-end
5. Existing PnP users' keys are preserved via `importTssKey` migration
6. User's derived keypair (publicKey) remains identical after migration — vault data stays accessible

## Research References

- `12-RESEARCH.md` — PnP Modal SDK research (rejected approach, kept for reference)
- `12-RESEARCH-corekit.md` — MPC Core Kit research (primary reference)
- tKey ShareTransferModule architecture — documented in discussion, informs Phase 12.4

## Deferred Ideas

- SIWE for wallet login → Phase 12.3
- Multi-auth identity linking → Phase 12.3
- MFA enrollment + recovery phrase → Phase 12.4
- Cross-device approval → Phase 12.4
- Encrypted device registry on IPFS → Phase 12.2
- Whether 12.2 + 12.3 should merge (depends on scope during planning)
- Whether 12.4 should split into MFA + cross-device as separate phases

---

_Phase: 12-multi-factor-authentication_
_Context gathered: 2026-02-12_
_Updated: 2026-02-12 (scoped to identity provider foundation)_

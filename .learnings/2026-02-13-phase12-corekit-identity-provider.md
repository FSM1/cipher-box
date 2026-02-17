# Phase 12: Core Kit Identity Provider — Implementation Learnings

**Date:** 2026-02-13

## Original Prompt

> Phase 12: Replace PnP Modal SDK with MPC Core Kit using CipherBox as its own identity provider (JWKS, Google OAuth, email OTP). 5 plans across 4 waves: backend identity provider, Core Kit SDK setup, frontend auth rewrite, custom login UI, PnP migration & cleanup.

## What I Learned

### Architecture: CipherBox as Identity Provider

- Web3Auth Core Kit requires a "custom verifier" backed by a JWKS endpoint that CipherBox itself hosts
- Flow: user authenticates via CipherBox backend (Google/email) -> backend issues a CipherBox JWT (RS256, iss=cipherbox, aud=web3auth) -> frontend uses this JWT for Core Kit `loginWithJWT` -> frontend sends same JWT to backend for session creation
- The JWT is used **twice**: once for Core Kit login, once for backend `/auth/login` with `loginType: 'corekit'`
- Core Kit SDK v3.5.0 does NOT have `authenticateUser()` — session tokens in `coreKit.signatures` are NOT verifiable JWTs. This was discovered mid-implementation and required inventing the "pass the CipherBox JWT back" pattern

### Auth Method Deduplication Bug (caught by CodeRabbit)

- **Root cause**: Identity controller creates auth methods with correct type (`google` or `email_passwordless`), but `login()` was hardcoding `email_passwordless` for ALL corekit logins
- **Impact**: Google users would get duplicate auth methods — one correct (`google`) from identity controller, one wrong (`email_passwordless`) from login
- **Fix**: Changed corekit login path to look up existing auth methods by `userId + identifier` (email) instead of by type, with fallback chain: exact match -> any method for user -> safety net creation
- **Lesson**: When two code paths create the same entity (identity controller + login service), the second path must find-not-create to avoid duplicates

### Placeholder PublicKey Resolution

- Core Kit exports the real secp256k1 publicKey only AFTER `loginWithJWT` completes on the frontend
- But the identity controller needs to create a user BEFORE the frontend has the real publicKey
- Solution: placeholder pattern `pending-core-kit-{userId}` that gets resolved to the real publicKey in the subsequent `/auth/login` call
- **Bug caught by CodeRabbit**: originally used `pending-core-kit-${Date.now()}` which is unpredictable and could never match the `Like` query. Fixed to use `pending-core-kit-${newUser.id}` after the initial user save

### TypeScript Strictness Mismatch Between Jest and Build

- `ts-jest` (used for unit tests) is LESS strict than `ts-node` / `nest build` (used for OpenAPI spec generation and E2E build)
- Code that passes all Jest tests can still fail CI because `ts-node` catches null safety issues that `ts-jest` doesn't
- **Concrete example**: after the auth method lookup refactor, `authMethod` could be null after two failed `findOne` calls. Jest tests all passed, but `ts-node` flagged `'authMethod' is possibly 'null'` at lines where it was used
- **Lesson**: Always run `pnpm --filter api build` (or the OpenAPI generate step) locally before pushing, not just `pnpm test`

### Coverage Thresholds as CI Gates

- `jest.config.js` has per-file coverage thresholds (e.g., `auth.service.ts` requires 84% branch coverage)
- Adding new branches (the 3-step auth method lookup fallback) without corresponding tests dropped coverage from 84% to 82.43% — broke CI even though all existing tests still passed
- **Lesson**: After adding any conditional logic, immediately run `pnpm test -- --coverage` and check the per-file threshold report

### CodeRabbit Review Workflow (iterative)

- Each `git push` triggers a fresh CodeRabbit review that generates NEW threads — it doesn't just re-evaluate old ones
- Plan for 2-3 rounds of push -> review -> fix, not a single pass
- CodeRabbit auto-resolves some threads when it sees the fix in new commits, but also surfaces previously unnoticed issues
- **29 total threads across 4 rounds** on this PR — 6 Critical, 8 Major, 8 Minor, 7 refactor/other
- Real bugs caught by CodeRabbit (not just style):
  - Duplicate auth method creation (Major -> real bug)
  - Placeholder publicKey using timestamp instead of userId (Critical -> real bug)
  - `refreshByToken` only returning email for `email_passwordless` users, missing Google users (Major -> real bug)
  - `useAuth.ts` silently swallowing non-404 vault errors (Major -> real bug)
  - Google token `email_verified` not checked (Major -> real gap)
  - PII in production logs (Major -> compliance risk)
  - Ephemeral JWT keys silently generated in production (Major -> operational risk)

### Security Review Findings

- The automated security review (`.planning/security/REVIEW-2026-02-13-phase12-final.md`) found **no high-confidence exploitable vulnerabilities** after false-positive filtering
- Positive practices: timing-safe comparison for test-login secret, Argon2 for OTP and refresh token hashing, HTTP-only cookies, JWKS-based verification, rate limiting on OTP
- Informational: email OTP delivery not implemented (intentional for tech demo), identity JWTs lack `jti` claim (standard for short-lived tokens)

### Google OAuth Integration Gotchas

- Google Identity Services (GIS) `prompt()` fires `momentListener` for `isNotDisplayed` and `isSkippedMoment` but NOT when the user simply closes the popup
- This causes the Google login button to get stuck in loading state indefinitely
- Fix: 60-second timeout that auto-resets `isLoading` state with cleanup on successful credential response

### E2E Test Decoupling from Web3Auth

- E2E tests cannot use Core Kit because JWKS keys are ephemeral in dev, and the Web3Auth verifier requires stable keys
- Solution: `POST /auth/test-login` endpoint guarded by `TEST_LOGIN_SECRET` env var
- Generates deterministic secp256k1 keypair from email via SHA-256 seed -> ensures same user gets same keys across test runs
- Returns keypair hex so E2E tests can initialize/load vault without Core Kit
- Defense-in-depth: `NODE_ENV === 'production'` hard-fail + timing-safe secret comparison

### Mock Disambiguation in Tests

- When a service injects multiple TypeORM repositories (`userRepository`, `authMethodRepository`, `refreshTokenRepository`), each gets a separate mock
- `mockRepository.findOne.mockResolvedValueOnce(...)` calls must carefully track WHICH repository's mock is being set up
- Easy to confuse `authMethodRepository.findOne` with `userRepository.findOne` when both are called in sequence — causes tests to pass for wrong reasons or fail mysteriously

## What Would Have Helped

- **Knowing Core Kit SDK v3.5.0 lacks `authenticateUser()`** before starting Plan 03 — would have designed the "CipherBox JWT pass-back" pattern from the start instead of discovering it mid-implementation
- **Running `pnpm --filter api build` in CI check locally** — would have caught the TypeScript null safety issue before the first push
- **Understanding CodeRabbit's iterative review model** — would have planned for multiple fix rounds instead of expecting a single push to resolve everything
- **A test for the full corekit login flow end-to-end** (not just unit tests) — the duplicate auth method bug was architectural, spanning two services, and only visible when tracing the full flow

## Key Files

- `apps/api/src/auth/auth.service.ts` — Core auth service, most heavily modified (login, testLogin, refreshByToken, placeholder resolution)
- `apps/api/src/auth/controllers/identity.controller.ts` — New identity provider endpoints (Google OAuth, email OTP, JWKS)
- `apps/api/src/auth/services/jwt-issuer.service.ts` — RS256 JWT signing for CipherBox identity tokens
- `apps/api/src/auth/services/google-oauth.service.ts` — Google token verification via Google JWKS
- `apps/api/src/auth/services/email-otp.service.ts` — OTP generation, Argon2 hashing, Redis storage
- `apps/web/src/hooks/useAuth.ts` — Frontend auth hook rewrite (loginWithGoogle, loginWithEmail, session restore)
- `apps/web/src/lib/web3auth/hooks.ts` — Core Kit hooks (loginWithJWT, getVaultKeypair, TSS export)
- `apps/web/src/lib/web3auth/core-kit-provider.tsx` — Core Kit singleton + React context
- `apps/web/src/routes/Login.tsx` — Custom login UI (Google button + email OTP form)
- `apps/api/src/auth/auth.service.spec.ts` — 437 tests total, critical for coverage thresholds

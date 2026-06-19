---
created: 2026-02-13T03:50
title: Add test-login endpoint for E2E automation
area: testing
files:
  - apps/api/src/auth/auth.controller.ts
  - apps/api/src/auth/auth.service.ts
  - apps/api/src/auth/services/jwt-issuer.service.ts
  - apps/web/src/hooks/useAuth.ts
  - tests/e2e/.env
---

## Problem

With the Core Kit migration (Phase 12), E2E login requires:

1. Frontend calls CipherBox identity endpoints (send-otp, verify-otp, get JWT)
2. Frontend sends JWT to Core Kit `loginWithJWT`
3. Core Kit contacts Web3Auth servers, which fetch our JWKS to verify the JWT
4. Web3Auth must reach our JWKS endpoint over the internet

Step 3-4 breaks in CI — no public URL for the API's JWKS endpoint. The identity JWT keypair is also ephemeral (regenerated on every API restart), so even pointing at staging will flake when the key rotates.

Current E2E credentials: `tests/e2e/.env` (email `test_account_4718@example.com`, OTP `851527`) — these were for the old PnP flow and won't work with Core Kit.

## Solution

Add a test-only `/auth/test-login` endpoint:

- Guarded by `TEST_LOGIN_SECRET` env var (only set in CI/local dev, never in production)
- Accepts `{ email, secret }`, returns `{ accessToken, refreshToken }` directly
- Bypasses Core Kit entirely — creates/finds user + auth method, issues tokens
- Frontend E2E tests set tokens in auth store and navigate to `/files`
- Vault pre-seeded with known keypair for test user (or initialized on first test-login)

Core Kit login flow itself covered separately by integration test against staging with stable `IDENTITY_JWT_PRIVATE_KEY`.

This decouples E2E UI/feature tests from Web3Auth infrastructure entirely.

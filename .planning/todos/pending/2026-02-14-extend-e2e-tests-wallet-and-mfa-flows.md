---
created: 2026-02-14T15:55
title: Extend E2E tests to cover wallet and MFA flows
area: testing
files:
  - tests/e2e/
  - apps/web/src/components/auth/WalletLoginButton.tsx
  - apps/web/src/components/auth/LinkedMethods.tsx
---

## Problem

Phase 12.3 VERIFICATION.md identified 3 human verification items that lack automated E2E coverage:

1. **End-to-end wallet login with MetaMask** — SIWE flow (connect wallet, fetch nonce, sign message, verify, Core Kit login) has no E2E test
2. **Linking a second wallet from Settings page** — The LinkedMethods UI wallet linking flow (connect, sign SIWE, link via API) is untested end-to-end
3. **Cross-method vault consistency** — Verifying the same vault data is accessible when logging in via different auth methods (Google vs email vs wallet)

Current E2E tests only cover email OTP login. Wallet flows present a challenge since they require a browser wallet extension (MetaMask) which Playwright can't natively interact with. MFA flows (Phase 12.4) will add further complexity with device approval and factor management.

## Solution

- Investigate programmatic wallet approaches for E2E: mock wagmi connector, Hardhat/Anvil test accounts with injected provider, or Synpress (Playwright + MetaMask automation)
- Add wallet login E2E test using chosen approach
- Add wallet linking E2E test from Settings page
- Add cross-method vault consistency test (login with email, upload file, login with wallet, verify file present)
- After Phase 12.4: extend to cover MFA enrollment, device approval, and factor recovery flows

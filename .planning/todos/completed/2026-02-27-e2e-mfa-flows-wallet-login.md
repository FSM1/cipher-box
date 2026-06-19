---
created: 2026-02-27T16:30
title: E2E test coverage for MFA flows using wallet login
area: testing
files:
  - tests/e2e/utils/web3auth-helpers.ts
  - tests/e2e/utils/multi-account.ts
  - tests/e2e/tests/wallet-login.spec.ts
  - apps/api/src/device-approval/device-approval.controller.ts
  - apps/api/src/device-approval/device-approval.service.ts
  - apps/web/src/stores/mfa.store.ts
  - apps/web/src/services/device-approval.service.ts
  - apps/web/src/components/Login.tsx
---

## Problem

MFA flows have zero E2E coverage. The current test-login bypass skips Core Kit entirely, making it impossible to test MFA enrollment, device approval, or recovery phrase flows end-to-end. Unit tests cover the backend service layer thoroughly, but the full integration path (UI -> Core Kit -> API -> UI) is untested.

Critical untested flows:

1. Enable MFA (`enableMFA()`) — converts 2/2 to 2/3 threshold, generates recovery phrase
2. Device approval — new device requests approval, existing device approves with ECIES-encrypted factor key
3. Recovery phrase restore — new device uses mnemonic instead of device approval
4. MFA status detection — `getKeyDetails()` reads threshold/factor count, UI reflects correctly
5. Approval request expiration (5-minute TTL)
6. Cross-device factor transfer lifecycle

## Approach

**Use wallet login instead of test-login bypass.** Mock wallet (`@johanneskares/wallet-mock`) already works in E2E (TC09-TC12) with real ECDSA signing and real SIWE verification. This gives real Core Kit initialization, which is required for MFA operations.

**Key insight on test isolation:** A consistent secp256k1 keypair (same wallet address) can be used across all test runs. Since each run creates a unique userId on the backend, Core Kit maps `(verifier="cipherbox-identity", verifierId=userId)` to fresh DKG key shares. MFA state is clean per test with no teardown needed.

**What needs to be built:**

1. **Wallet-login E2E helper** — similar to `loginViaTestEndpoint()` but driving the real wallet -> SIWE -> Core Kit flow. Most pieces exist in `LoginPage` POM and mock wallet setup from `wallet-login.spec.ts`.

2. **Core Kit interaction helpers** — `page.evaluate()` wrappers to call `enableMFA()`, `getKeyDetails()`, `inputFactorKey()`, and capture the recovery mnemonic from the UI.

3. **Cross-device test fixtures** — pattern for "context A = existing device, context B = new device" using multi-account infrastructure (same user, different browser contexts without shared localStorage).

4. **Device approval polling helper** — wait for pending request in context A, respond, verify context B unblocks.

**Test structure (tag separately from fast smoke tests):**

- `mfa-enrollment.spec.ts` — enable MFA, verify threshold change, capture recovery phrase
- `device-approval.spec.ts` — two contexts, request/approve/deny lifecycle, expiration
- `recovery-phrase.spec.ts` — new device restores using mnemonic
- `mfa-status.spec.ts` — UI correctly reflects MFA state from `getKeyDetails()`

**Practical concerns:**

- Core Kit operations hit Web3Auth Sapphire Devnet (~5-15s latency each)
- Full MFA cycle test may take 30-60s
- Network-dependent = inherently flakier; use generous timeouts and consider running on schedule rather than every PR
- After `enableMFA()`, user's Core Kit state on devnet is permanently MFA-enabled — not a problem since userId is unique per run

## Solution

TBD — needs phase planning. Likely a dedicated phase or inserted as an extension of existing E2E infrastructure. Consider running MFA E2E tests on a separate CI schedule (nightly) rather than per-PR to avoid blocking on devnet latency/reliability.

---
created: 2026-02-26T20:45
title: Add alternative MFA factor types
area: auth
files:
  - apps/web/src/hooks/useMfa.ts
  - apps/web/src/hooks/useDeviceApproval.ts
  - apps/web/src/components/mfa/SecurityTab.tsx
---

## Problem

Currently CipherBox MFA only supports two factor types for REQUIRED_SHARE recovery: device shares (browser localStorage) and 24-word recovery mnemonic. Users need more accessible recovery options when logging in from a new device.

The fundamental constraint is that any factor must produce a 256-bit `BN` for `coreKit.inputFactorKey()`. The `FactorKeyTypeShareDescription` enum already defines slots for: `PasswordShare`, `SecurityQuestions`, `SocialShare`, and `Other`.

## Solution

Research complete. Priority order:

### 1. Passkey (WebAuthn PRF) — Best option

- WebAuthn PRF extension produces deterministic 32-byte output from credential-bound HMAC
- Flow: `passkey authenticate → PRF(credential_secret, salt) → 32 bytes → HKDF → factor key BN`
- Fully non-custodial, hardware-backed, biometric-gated, phishing-resistant
- Bitwarden uses this exact pattern for vault encryption key derivation
- **Limitation:** PRF support fragmented (Chrome/Edge good, Safari macOS 15+/iOS 18+ with bugs, Windows Hello lacks PRF)
- Cannot be sole recovery option due to platform gaps

### 2. Password-derived key — Simplest to ship

- `password + salt → Argon2id(memory=64MB, iterations=3) → 32 bytes → factor key BN`
- Salt stored in shareDescription metadata (not secret)
- `PasswordShare` already exists in Core Kit enum
- **Limitation:** Security depends on password strength; vulnerable to offline brute force if TSS metadata leaks
- Enforce minimum entropy (zxcvbn score >= 3)

### 3. Secondary OAuth — Moderate complexity

- Web3Auth example shows `SocialShare` where secondary OAuth (e.g. Firebase) deterministically produces factor key
- Could work as "link GitHub/another provider as recovery option"
- `SocialShare` description type already in Core Kit enum

### Not viable without server custody

- **TOTP:** Codes are ephemeral 6-digit values; can't derive deterministic 256-bit key. Would require server to escrow encrypted factor key, weakening non-custodial model.
- **SMS/Email OTP:** Same problem as TOTP.

### Deferred (high complexity)

- **Social recovery (trusted contacts):** Split factor key via Shamir Secret Sharing among N contacts, K-of-N reconstruct. Complex UX and coordination protocol.

### Sources

- <https://www.corbado.com/blog/passkeys-prf-webauthn>
- <https://bitwarden.com/blog/prf-webauthn-and-its-role-in-passkeys/>
- <https://github.com/w3c/webauthn/wiki/Explainer:-PRF-extension>
- <https://web3auth.io/docs/sdk/core-kit/mpc-core-kit/usage>

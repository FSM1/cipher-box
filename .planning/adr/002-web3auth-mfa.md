# ADR-002: Web3Auth Multi-Factor Authentication (MFA)

**Status:** Proposed (Future Enhancement)
**Date:** 2026-01-20
**Author:** Claude (AI Assistant)
**Target Phase:** Post-v1.0 (Phase 11 or later)

---

## Context

CipherBox uses Web3Auth for authentication, which provides multiple login options:

- **Social logins**: Google, Apple, GitHub (via OAuth)
- **Email passwordless**: Magic link authentication
- **External wallets**: MetaMask, WalletConnect (via SIWE)

### Current Authentication Model

Web3Auth's **grouped connections** already handle account linking at the authentication layer:

- Accounts sharing the same identifier (email) automatically derive the same MPC keypair
- Example: Google (user@example.com) + Email passwordless (user@example.com) = same vault

For external wallets, ADR-001 implements **signature-derived keys** which are independent of social login keys.

### The Gap

While users can access their vault through multiple methods, there is no **additional security layer** for high-risk operations or users requiring stronger authentication guarantees.

**Use cases for MFA:**

1. User wants to require Google + Passkey to access vault
2. User wants SMS OTP as backup for lost device recovery
3. Enterprise users need compliance with MFA requirements
4. High-value vault protection (defense against session hijacking)

---

## Decision

Implement Web3Auth's MFA capabilities as a **post-v1.0 enhancement**, allowing users to optionally enable additional authentication factors.

### Proposed MFA Options

| Factor            | Type               | Priority | Notes                                |
| ----------------- | ------------------ | -------- | ------------------------------------ |
| Passkey/WebAuthn  | Something you have | High     | Platform authenticators, FIDO2 keys  |
| Authenticator App | Something you have | Medium   | TOTP via Google Authenticator, Authy |
| SMS OTP           | Something you have | Low      | Backup only (SIM swap risk)          |
| Recovery Phrase   | Something you know | Medium   | BIP-39 mnemonic for account recovery |

### Web3Auth MFA Architecture

Web3Auth provides MFA through their **tKey SDK** which splits the private key into multiple shares:

```
┌─────────────────────────────────────────────────────────────────┐
│                    User's MPC Private Key                       │
│                                                                 │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │   Share 1   │ + │   Share 2   │ + │      Share 3        │   │
│  │  (Device)   │   │ (Web3Auth)  │   │ (Recovery/MFA)      │   │
│  └─────────────┘   └─────────────┘   └─────────────────────┘   │
│                                                                 │
│  Any 2 of 3 shares required to reconstruct key                  │
└─────────────────────────────────────────────────────────────────┘
```

**Share distribution:**

- **Share 1 (Device)**: Stored locally on user's device
- **Share 2 (Web3Auth)**: Managed by Web3Auth infrastructure
- **Share 3 (Recovery/MFA)**: User-controlled backup (passkey, authenticator, etc.)

### Implementation Approach

**Phase 1: MFA Enrollment (Settings)**

- Add "Security" section to Settings page
- Allow users to enable MFA (opt-in)
- Support Passkey enrollment via WebAuthn
- Generate and display recovery phrase (BIP-39)

**Phase 2: MFA Enforcement**

- Prompt for second factor during login when enabled
- Support "remember this device" for trusted devices
- Grace period for MFA setup (don't lock out immediately)

**Phase 3: Recovery Flows**

- Recovery via backup phrase if MFA device lost
- Admin-assisted recovery (with identity verification)

---

## Consequences

### Benefits

1. **Stronger security**: Defense-in-depth for vault access
2. **Enterprise readiness**: Compliance with security policies
3. **User confidence**: Optional enhanced protection
4. **Recovery options**: Backup methods prevent lockout

### Risks & Mitigations

| Risk                                     | Impact | Mitigation                                      |
| ---------------------------------------- | ------ | ----------------------------------------------- |
| User lockout if MFA device lost          | High   | Recovery phrase, grace period                   |
| Complexity increases onboarding friction | Medium | MFA is opt-in, not default                      |
| Web3Auth MFA API changes                 | Medium | Abstract behind interface                       |
| Session hijacking still possible         | Low    | Short session expiry, re-auth for sensitive ops |

### Deferred Decisions

- Whether MFA should be mandatory for certain operations (e.g., export vault)
- Integration with hardware security keys (YubiKey)
- Enterprise SSO/SAML integration
- Biometric authentication beyond WebAuthn

---

## Implementation Scope

**NOT in v1.0** - This is a post-launch enhancement.

**Suggested Phase:** Phase 11 (Post-v1.0 Security Enhancements)

**Prerequisites:**

- Phase 2 complete (Authentication working)
- Phase 10 complete (Core v1.0 functionality)

**Estimated Effort:** 2-3 weeks

**Dependencies:**

- Web3Auth tKey SDK
- WebAuthn browser APIs
- Backend MFA state management

---

## References

- [Web3Auth MFA Documentation](https://web3auth.io/docs/sdk/core-kit/mfa)
- [tKey SDK](https://web3auth.io/docs/sdk/core-kit/tkey)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 Overview](https://fidoalliance.org/fido2/)
- [BIP-39 Mnemonic](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

---

## Approval

| Role          | Name        | Date       | Status   |
| ------------- | ----------- | ---------- | -------- |
| Author        | Claude (AI) | 2026-01-20 | Proposed |
| Product Owner | -           | -          | Pending  |

---

## Changelog

| Version | Date       | Changes          |
| ------- | ---------- | ---------------- |
| 1.0     | 2026-01-20 | Initial proposal |

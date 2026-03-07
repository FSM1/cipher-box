# Phase 12: Multi-Factor Authentication - Research

**Researched:** 2026-02-12
**Domain:** Web3Auth MFA SDK Integration (`@web3auth/modal` v10.13.1)
**Confidence:** HIGH (verified via SDK type definitions, official documentation, Web3Auth e2e test patterns)

## Summary

Phase 12 adds MFA to CipherBox using Web3Auth's built-in `mfaSettings` and `mfaLevel` configuration, plus the `useEnableMFA` and `useManageMFA` React hooks. The SDK already provides the full MFA enrollment flow, factor management UI, and key splitting via Shamir Secret Sharing -- CipherBox needs to configure it, add a settings section, and integrate mandatory first-login enrollment.

The CRITICAL question from CONTEXT.md -- "Does enabling MFA change the derived private key?" -- has been answered: **No, the private key remains the same.** Web3Auth splits the existing key into 2-of-3 Shamir shares but the reconstructed key is identical. Web3Auth's own e2e test suite explicitly tests this ("start with mfaLevel: none, then change to mandatory - run twice, compare keys"). This means Success Criterion 4 (publicKey remains identical after MFA enrollment) is satisfied by design.

Primary recommendation: Configure `mfaSettings` on `Web3AuthOptions` with device share and backup share as mandatory factors, use `mfaLevel: 'mandatory'` for first-login enforcement, and use the `useEnableMFA` / `useManageMFA` hooks from `@web3auth/modal/react` for the settings page.

## Standard Stack

### Core

| Library           | Version | Purpose                                          | Why Standard                                                                                        |
| ----------------- | ------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| `@web3auth/modal` | 10.13.1 | MFA configuration, enrollment, factor management | Already installed; `mfaSettings`, `mfaLevel`, `enableMFA`, `manageMFA` are all part of this package |

No additional libraries are needed. MFA is entirely SDK-native.

### Supporting

| Library                 | Version    | Purpose                                  | When to Use                                                    |
| ----------------------- | ---------- | ---------------------------------------- | -------------------------------------------------------------- |
| `zustand`               | (existing) | Track MFA enrollment state in auth store | Optional: for tracking `isMFAEnabled` outside Web3Auth context |
| `@tanstack/react-query` | (existing) | Not needed for MFA                       | MFA state comes from Web3Auth hooks, not API calls             |

### Alternatives Considered

| Instead of              | Could Use                            | Tradeoff                                                                      |
| ----------------------- | ------------------------------------ | ----------------------------------------------------------------------------- |
| SDK-native MFA flow     | Custom MFA UI with tKey/Core Kit     | Massive complexity increase for no benefit; SDK handles the entire flow       |
| `mfaLevel: 'mandatory'` | Post-login check with `isMFAEnabled` | Mandatory is cleaner -- SDK handles enforcement before returning the provider |

## Architecture Patterns

### Key Types and Imports

All MFA types are exported from `@web3auth/modal` (which re-exports from `@web3auth/no-modal` and `@web3auth/auth`):

```typescript
// Configuration types
import {
  MFA_FACTOR, // Enum: DEVICE, BACKUP_SHARE, SOCIAL_BACKUP, PASSWORD, PASSKEYS, AUTHENTICATOR
  MFA_LEVELS, // Enum: DEFAULT, OPTIONAL, MANDATORY, NONE
  type MfaSettings, // Partial<Record<MFA_FACTOR_TYPE, MFA_SETTINGS>>
  type MfaLevelType, // 'default' | 'optional' | 'mandatory' | 'none'
  type MFA_SETTINGS, // { enable: boolean; priority?: number; mandatory?: boolean }
} from '@web3auth/modal';

// React hooks
import {
  useEnableMFA, // { enableMFA, loading, error }
  useManageMFA, // { manageMFA, loading, error }
  useWeb3AuthUser, // { isMFAEnabled, userInfo, ... }
} from '@web3auth/modal/react';
```

### MFA_FACTOR Constants

```typescript
// From @web3auth/auth, re-exported through @web3auth/modal
const MFA_FACTOR = {
  DEVICE: 'deviceShareFactor',
  BACKUP_SHARE: 'backUpShareFactor',
  SOCIAL_BACKUP: 'socialBackupFactor',
  PASSWORD: 'passwordFactor',
  PASSKEYS: 'passkeysFactor',
  AUTHENTICATOR: 'authenticatorFactor',
} as const;
```

### MFA_LEVELS Constants

```typescript
const MFA_LEVELS = {
  DEFAULT: 'default', // MFA screen appears every 10th login
  OPTIONAL: 'optional', // MFA screen appears every login, can be skipped
  MANDATORY: 'mandatory', // MFA setup required after login
  NONE: 'none', // MFA setup skipped entirely
} as const;
```

### Recommended Configuration Pattern

Add `mfaSettings` and `mfaLevel` to the existing `web3AuthOptions` in `apps/web/src/lib/web3auth/config.ts`:

```typescript
// Source: SDK type definitions in @web3auth/auth
import {
  WEB3AUTH_NETWORK,
  WALLET_CONNECTORS,
  AUTH_CONNECTION,
  MFA_FACTOR,
  type Web3AuthOptions,
} from '@web3auth/modal';

export const web3AuthOptions: Web3AuthOptions = {
  clientId: import.meta.env.VITE_WEB3AUTH_CLIENT_ID || '',
  web3AuthNetwork: NETWORK_CONFIG[environment] || WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  // MFA Configuration
  mfaLevel: 'mandatory', // Forces MFA setup on first login
  mfaSettings: {
    [MFA_FACTOR.DEVICE]: {
      enable: true,
      priority: 1,
      mandatory: true,
    },
    [MFA_FACTOR.BACKUP_SHARE]: {
      enable: true,
      priority: 2,
      mandatory: true,
    },
    [MFA_FACTOR.SOCIAL_BACKUP]: {
      enable: true,
      priority: 3,
      mandatory: false,
    },
    [MFA_FACTOR.PASSWORD]: {
      enable: true,
      priority: 4,
      mandatory: false,
    },
    [MFA_FACTOR.PASSKEYS]: {
      enable: true,
      priority: 5,
      mandatory: false,
    },
    [MFA_FACTOR.AUTHENTICATOR]: {
      enable: true,
      priority: 6,
      mandatory: false,
    },
  },
  uiConfig: { mode: 'dark' },
  modalConfig: {
    /* existing connector config */
  },
};
```

### Settings Page MFA Section Pattern

Use the `useEnableMFA`, `useManageMFA`, and `useWeb3AuthUser` hooks:

```typescript
// Source: SDK type definitions verified from installed package
import { useEnableMFA, useManageMFA, useWeb3AuthUser } from '@web3auth/modal/react';

function MfaSettings() {
  const { isMFAEnabled, userInfo } = useWeb3AuthUser();
  const { enableMFA, loading: enabling, error: enableError } = useEnableMFA();
  const { manageMFA, loading: managing, error: manageError } = useManageMFA();

  if (isMFAEnabled) {
    return (
      <div>
        <p>MFA is enabled</p>
        <button onClick={() => manageMFA()} disabled={managing}>
          {managing ? 'Loading...' : 'Manage MFA Factors'}
        </button>
      </div>
    );
  }

  return (
    <div>
      <p>MFA is not yet enabled</p>
      <button onClick={() => enableMFA()} disabled={enabling}>
        {enabling ? 'Setting up...' : 'Enable MFA'}
      </button>
    </div>
  );
}
```

### Login Flow with Mandatory MFA

When `mfaLevel: 'mandatory'` is set, the SDK automatically shows the MFA setup screen after initial authentication. The flow is:

1. User clicks [CONNECT] and authenticates via social login
2. If MFA is not yet set up, SDK automatically shows MFA enrollment screens
3. User completes MFA setup (device share + backup phrase at minimum)
4. SDK returns the provider with the same private key as before MFA
5. CipherBox proceeds with normal vault initialization

No changes to the existing `useAuth.ts` login flow are needed for enrollment enforcement -- the SDK handles it.

### Anti-Patterns to Avoid

- **Do not build a custom MFA enrollment UI:** The SDK provides the entire enrollment flow via `enableMFA()` and the `mfaLevel: 'mandatory'` setting. Building custom factor enrollment would bypass SDK security guarantees.
- **Do not store MFA state in CipherBox backend:** MFA is entirely managed by Web3Auth's infrastructure. `isMFAEnabled` from `useWeb3AuthUser` is the single source of truth.
- **Do not attempt to disable MFA once enabled:** MFA cannot be turned off once enabled. This is by design and is irreversible.
- **Do not use `useSFAKey: true` with MFA:** The `useSFAKey` option uses core-kit keys which are incompatible with MFA-enabled accounts.

## Don't Hand-Roll

| Problem                    | Don't Build                                       | Use Instead                                   | Why                                                                                                |
| -------------------------- | ------------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| MFA enrollment flow        | Custom multi-step wizard with factor registration | `enableMFA()` hook or `mfaLevel: 'mandatory'` | SDK handles the entire enrollment UX including factor setup, key splitting, and share distribution |
| MFA status check           | Backend endpoint to track MFA status              | `useWeb3AuthUser().isMFAEnabled`              | MFA state lives in Web3Auth infrastructure, not CipherBox                                          |
| Recovery phrase generation | Custom BIP39 mnemonic generation                  | SDK's backup share factor                     | SDK generates, encrypts, and manages the recovery share                                            |
| Device share management    | Custom device registration                        | SDK's device share factor                     | SDK handles device-local share storage                                                             |
| MFA factor management      | Custom settings UI for each factor                | `manageMFA()` hook                            | SDK provides the management UI                                                                     |
| Key splitting              | Custom Shamir Secret Sharing                      | SDK's built-in SSS                            | Cryptographic primitives must not be hand-rolled                                                   |

Key insight: Web3Auth's MFA is a complete, self-contained system. CipherBox's role is configuration (which factors, what priority, mandatory vs optional) and integration (when to trigger enrollment, where to show status). The SDK does all the heavy lifting.

## Common Pitfalls

### Pitfall 1: MFA Is Irreversible

- **What goes wrong:** Developer enables MFA for testing, then wants to disable it for a test account.
- **Why it happens:** MFA cannot be turned off once enabled. The key is permanently split into 2-of-3 shares.
- **How to avoid:** Use separate test accounts for MFA testing. Keep the E2E test account (`test_account_4718@example.com`) without MFA enabled by using `mfaLevel: 'none'` in test/CI configurations.
- **Warning signs:** Test account starts requiring MFA during E2E runs.

### Pitfall 2: E2E Test Account and MFA

- **What goes wrong:** With `mfaLevel: 'mandatory'` globally, the E2E test account gets forced into MFA setup during automated tests, breaking the test flow.
- **Why it happens:** `mfaLevel` is set at SDK initialization time and applies to all logins.
- **How to avoid:** Use environment-aware `mfaLevel` configuration:

```typescript
// CI/test environments skip MFA to preserve E2E automation
const mfaLevel = environment === 'ci' ? 'none' : 'mandatory';
```

- **Warning signs:** E2E login tests start timing out or showing unexpected MFA screens.

### Pitfall 3: mfaLevel 'none' Inconsistency

- **What goes wrong:** Setting `mfaLevel: 'none'` still shows MFA screens for accounts that already have MFA enabled.
- **Why it happens:** Known Web3Auth behavior -- `mfaLevel: 'none'` only skips the setup screen. If MFA is already enabled on an account, it will always be required for login.
- **How to avoid:** Ensure the E2E test account never has MFA enabled. If it does, create a new test account.
- **Warning signs:** `mfaLevel: 'none'` doesn't prevent MFA prompts for specific accounts.

### Pitfall 4: Assuming Recovery Phrase Can Be Re-Displayed

- **What goes wrong:** Developer builds UI with a "Show Recovery Phrase" button assuming the phrase can be retrieved after setup.
- **Why it happens:** The recovery phrase (backup share) is shown once during setup. Web3Auth does not store the plaintext phrase -- it's the user's responsibility to save it.
- **How to avoid:** Make the recovery phrase display during enrollment very prominent with a confirmation checkbox. The `manageMFA()` flow may allow regeneration (creating a new backup share), but the original phrase cannot be retrieved.
- **Warning signs:** Users requesting to "see their phrase again" after closing the setup screen.

### Pitfall 5: SCALE Plan Required for Production

- **What goes wrong:** MFA works in development (sapphire_devnet) but fails in production.
- **Why it happens:** `mfaSettings` customization requires the SCALE pricing plan. It works for free on devnet but requires a paid plan on mainnet.
- **How to avoid:** Verify the Web3Auth dashboard billing plan before deploying to production. The basic `mfaLevel` setting without `mfaSettings` customization may work on lower plans -- but granular factor control (priority, mandatory per factor) requires SCALE.
- **Warning signs:** MFA enrollment fails silently or shows default factors instead of configured ones in production.

### Pitfall 6: Browser Closed During MFA Enrollment

- **What goes wrong:** User closes browser mid-enrollment, leaving MFA in a partial state.
- **Why it happens:** MFA enrollment involves multiple steps (device share, backup phrase). If interrupted, the state may be inconsistent.
- **How to avoid:** Per CONTEXT.md, "If enrollment fails partway (browser closed, error), start fresh on next login -- no partial resume." The SDK should handle this -- `mfaLevel: 'mandatory'` will re-trigger enrollment on next login if not completed.
- **Warning signs:** User reports being stuck in a loop or getting errors on next login after interrupted enrollment.

## Code Examples

### Example 1: Environment-Aware MFA Configuration

```typescript
// apps/web/src/lib/web3auth/config.ts
import {
  WEB3AUTH_NETWORK,
  WALLET_CONNECTORS,
  AUTH_CONNECTION,
  MFA_FACTOR,
  type Web3AuthOptions,
  type MfaLevelType,
} from '@web3auth/modal';

const environment = import.meta.env.VITE_ENVIRONMENT || 'local';

// CI/E2E: skip MFA to preserve test automation
// Local/Staging/Production: mandatory MFA for security-first stance
const getMfaLevel = (): MfaLevelType => {
  if (environment === 'ci') return 'none';
  return 'mandatory';
};

export const web3AuthOptions: Web3AuthOptions = {
  clientId: import.meta.env.VITE_WEB3AUTH_CLIENT_ID || '',
  web3AuthNetwork: NETWORK_CONFIG[environment] || WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  mfaLevel: getMfaLevel(),
  mfaSettings: {
    [MFA_FACTOR.DEVICE]: {
      enable: true,
      priority: 1,
      mandatory: true,
    },
    [MFA_FACTOR.BACKUP_SHARE]: {
      enable: true,
      priority: 2,
      mandatory: true,
    },
    [MFA_FACTOR.SOCIAL_BACKUP]: {
      enable: true,
      priority: 3,
      mandatory: false,
    },
    [MFA_FACTOR.PASSWORD]: {
      enable: true,
      priority: 4,
      mandatory: false,
    },
    [MFA_FACTOR.PASSKEYS]: {
      enable: true,
      priority: 5,
      mandatory: false,
    },
    [MFA_FACTOR.AUTHENTICATOR]: {
      enable: true,
      priority: 6,
      mandatory: false,
    },
  },
  uiConfig: { mode: 'dark' },
  modalConfig: {
    // ... existing connector config unchanged
  },
};
```

### Example 2: MFA Status Section in Settings Page

```typescript
// apps/web/src/components/auth/MfaStatus.tsx
import { useEnableMFA, useManageMFA, useWeb3AuthUser } from '@web3auth/modal/react';

export function MfaStatus() {
  const { isMFAEnabled } = useWeb3AuthUser();
  const { enableMFA, loading: enabling, error: enableError } = useEnableMFA();
  const { manageMFA, loading: managing, error: manageError } = useManageMFA();

  return (
    <div className="mfa-status">
      <h3>Multi-Factor Authentication</h3>
      <div className="mfa-status-indicator">
        <span className={`status-badge ${isMFAEnabled ? 'active' : 'inactive'}`}>
          {isMFAEnabled ? '[ACTIVE]' : '[INACTIVE]'}
        </span>
      </div>

      {!isMFAEnabled && (
        <>
          <p className="mfa-description">
            Enable MFA to protect your vault with additional authentication factors.
            <strong> This action is permanent and cannot be undone.</strong>
          </p>
          <button
            onClick={() => enableMFA()}
            disabled={enabling}
            className="enable-mfa-button"
          >
            {enabling ? 'Setting up...' : 'Enable MFA'}
          </button>
          {enableError && (
            <div className="mfa-error" role="alert">{enableError.message}</div>
          )}
        </>
      )}

      {isMFAEnabled && (
        <>
          <p className="mfa-description">
            Your vault is protected with multi-factor authentication.
          </p>
          <button
            onClick={() => manageMFA()}
            disabled={managing}
            className="manage-mfa-button"
          >
            {managing ? 'Loading...' : 'Manage Factors'}
          </button>
          {manageError && (
            <div className="mfa-error" role="alert">{manageError.message}</div>
          )}
        </>
      )}
    </div>
  );
}
```

### Example 3: Checking MFA Status for UI Decisions

```typescript
// Using isMFAEnabled from useWeb3AuthUser
import { useWeb3AuthUser } from '@web3auth/modal/react';

function SecurityOverview() {
  const { isMFAEnabled, userInfo } = useWeb3AuthUser();

  return (
    <div>
      <p>Auth method: {userInfo?.authConnection || 'Unknown'}</p>
      <p>MFA: {isMFAEnabled ? 'Enabled' : 'Not enabled'}</p>
    </div>
  );
}
```

## CRITICAL: Key Identity After MFA Enrollment

Answer: The derived private key does NOT change when MFA is enabled.
Confidence: HIGH.

Evidence:

1. **Web3Auth SSS architecture:** MFA uses Shamir Secret Sharing to split the _existing_ private key into 2-of-3 shares. The key being split is the same key that was used before MFA -- reconstructing any 2 shares yields the identical original key. This is a mathematical property of Shamir's scheme.

2. **Web3Auth e2e test suite** (<https://github.com/Web3Auth/web3auth-e2e-tests>): Combo 2 test explicitly tests: "start with mfaLevel: none, then change to mandatory - run twice, compare keys." This test verifies key identity is preserved across MFA transitions.

3. **Proactive secret sharing:** Web3Auth documentation states: "Proactive secret sharing allows participants to refresh shares, so that all participants receive new shares, but the secret remains unchanged."

4. **Multiple official documentation sources** confirm: "your keys are divided into three shares for off-chain multi-sig" -- the key is divided, not replaced.

Implication for CipherBox: Success Criterion 4 is met by design. No vault re-encryption or key migration is needed. After MFA enrollment, `provider.request({ method: 'private_key' })` returns the same private key, producing the same `publicKey` used for ECIES vault encryption.

## E2E Testing Strategy

Problem: With `mfaLevel: 'mandatory'`, the E2E test account would be forced into MFA enrollment during automated tests.

Solution: Environment-aware `mfaLevel` configuration.

| Environment  | `mfaLevel`    | Rationale                                                         |
| ------------ | ------------- | ----------------------------------------------------------------- |
| `ci`         | `'none'`      | Preserves existing E2E automation; test account never touches MFA |
| `local`      | `'mandatory'` | Developers see the real MFA flow during local testing             |
| `staging`    | `'mandatory'` | UAT tests the real MFA flow                                       |
| `production` | `'mandatory'` | Users must set up MFA                                             |

Important: The E2E test account (`test_account_4718@example.com`) must NEVER have MFA enabled on it, because MFA is irreversible. Once enabled, even `mfaLevel: 'none'` won't bypass it for that account.

Future consideration: If MFA E2E testing is needed, create a separate test account specifically for MFA tests, and use Web3Auth's devnet test configuration patterns (random accounts per test run, as their e2e test suite does).

## MFA Factor Details

### Device Share (DEVICE)

- What it is: A cryptographic share stored locally on the user's device (browser/device storage).
- How it works: Created automatically during MFA setup. Stored in the browser's local storage.
- User experience: Transparent -- the device is automatically recognized on subsequent logins.
- Limitation: Lost if browser data is cleared. Only valid for the specific browser/device.

### Backup Share (BACKUP_SHARE)

- What it is: A recovery phrase (mnemonic) that the user must save.
- How it works: Generated during MFA setup. Shown once. User must save it externally.
- User experience: User sees words, must confirm they saved them.
- Recovery: If device share is lost, user enters the backup phrase to recover access.
- Re-generation: The `manageMFA()` flow may allow creating a new backup share (invalidating the old one).

### Social Backup (SOCIAL_BACKUP)

- What it is: Links an additional social login as a recovery factor.
- How it works: User authenticates with another social provider (e.g., Google if they registered with Email).
- User experience: User clicks to link another social account during MFA setup.

### Password (PASSWORD)

- What it is: A user-chosen password as an additional factor.
- How it works: User sets a password that protects one of the key shares.
- User experience: Standard password entry during MFA setup.

### Passkeys (PASSKEYS)

- What it is: WebAuthn passkey as an authentication factor.
- How it works: Uses device biometrics or security keys via WebAuthn.
- User experience: Touch ID, Face ID, or security key prompt.

### Authenticator (AUTHENTICATOR)

- What it is: TOTP authenticator app (Google Authenticator, Authy, etc.)
- How it works: User scans QR code, enters TOTP codes for verification.
- User experience: Standard TOTP setup flow.

## State of the Art

| Old Approach                                         | Current Approach                                    | When Changed                   | Impact                                                    |
| ---------------------------------------------------- | --------------------------------------------------- | ------------------------------ | --------------------------------------------------------- |
| Custom tKey integration with manual share management | SDK-native `mfaSettings` + `mfaLevel` configuration | Web3Auth v10 SDK consolidation | No need for tKey/Core Kit -- PnP SDK handles everything   |
| `@web3auth/modal-react-hooks` separate package       | Hooks from `@web3auth/modal/react` subpath export   | v10.x                          | All hooks now in the main package                         |
| Checking userInfo for MFA state                      | `useWeb3AuthUser().isMFAEnabled` boolean            | v10.x                          | Clean, dedicated MFA status check                         |
| Manual `enableMFA()` on web3Auth instance            | `useEnableMFA()` React hook                         | v10.x                          | Hook provides loading/error states out of the box         |
| N/A                                                  | `useManageMFA()` React hook                         | v10.x                          | New: allows managing existing MFA factors post-enrollment |

Note on ChainSafe reference: The CONTEXT.md mentions ChainSafe Files (chainsafe/ui-monorepo) as a reference for Web3Auth MFA integration. That project used SDK-based Web3Auth with significant customization. The current Web3Auth v10 SDK has substantially simplified MFA integration -- the `useEnableMFA`/`useManageMFA` hooks did not exist when ChainSafe built their integration. The ChainSafe approach is outdated; use the current hook-based pattern instead.

## Open Questions

1. **Recovery phrase re-access after setup** --
   What we know: The backup share (recovery phrase) is shown once during enrollment. Web3Auth does not store the plaintext phrase.
   What's unclear: Does `manageMFA()` allow regenerating a new backup share (which would invalidate the old one)? The SDK types show `manageMFA<T>(params?: T): Promise<void>` with generic params, but documentation doesn't detail what operations are available.
   Recommendation: Test `manageMFA()` during implementation to determine capabilities. At minimum, the settings page should show whether backup share exists and offer regeneration if the SDK supports it.

2. **What happens during enableMFA() call** --
   What we know: The hook returns `{ enableMFA, loading, error }`. The function triggers MFA activation.
   What's unclear: Does it open a new window/popup, redirect, or show an inline modal? The documentation says "trigger a redirect to the MFA setup page" for the direct SDK method, but the React hook might handle it differently.
   Recommendation: Test the actual behavior during implementation. The SDK likely opens its own MFA setup UI (modal/popup) similar to the login modal.

3. **Login UX when MFA is active** --
   What we know: After MFA is enabled, subsequent logins require the second factor. With `mfaLevel: 'mandatory'`, the SDK handles this automatically.
   What's unclear: What does the second-factor prompt look like? Is it integrated into the existing login modal or a separate screen?
   Recommendation: Test with a devnet account during implementation. The SDK should handle the second-factor UX automatically.

4. **mfaSettings behavior without SCALE plan in production** --
   What we know: `mfaSettings` customization requires SCALE plan for production. Works free on devnet.
   What's unclear: Does the basic `mfaLevel` setting work without SCALE? What happens if `mfaSettings` is provided without the SCALE plan -- silent fallback to defaults or error?
   Recommendation: Verify billing plan on Web3Auth dashboard before production deployment. Test on staging (devnet) first.

## Sources

### Primary (HIGH confidence)

<!-- markdownlint-disable MD032 -->

- SDK type definitions from installed `@web3auth/modal@10.13.1` package:
  - `types/react/hooks/useEnableMFA.d.ts` - enableMFA hook interface
  - `types/react/hooks/useManageMFA.d.ts` - manageMFA hook interface
  - `types/react/hooks/useWeb3AuthUser.d.ts` - isMFAEnabled property
  - `types/base/core/IWeb3Auth.d.ts` - IWeb3AuthCoreOptions with mfaSettings/mfaLevel
  - `types/connectors/auth-connector/interface.d.ts` - MFA_FACTOR, MFA_LEVELS constants, MfaSettings type
- [MetaMask/Web3Auth MFA Documentation](https://docs.metamask.io/embedded-wallets/sdk/react/advanced/mfa/) - Factor types, configuration, irreversibility warning, pricing
- [MetaMask/Web3Auth React Hooks](https://docs.metamask.io/embedded-wallets/sdk/react/hooks/) - useEnableMFA, useManageMFA, useWeb3AuthUser hooks
- [MetaMask/Web3Auth useEnableMFA](https://docs.metamask.io/embedded-wallets/sdk/react/hooks/useEnableMFA/) - Hook interface and usage
- [MetaMask/Web3Auth useManageMFA](https://docs.metamask.io/embedded-wallets/sdk/react/hooks/useManageMFA/) - Hook interface and usage
- [MetaMask/Web3Auth useWeb3Auth](https://docs.metamask.io/embedded-wallets/sdk/react/hooks/useWeb3Auth/) - Core hook properties

### Secondary (MEDIUM confidence)

- [Web3Auth E2E Tests Repository](https://github.com/Web3Auth/web3auth-e2e-tests) - Test configurations showing key comparison across MFA transitions
- [Web3Auth tKey MFA Blog Post](https://blog.web3auth.io/tkey-multi-factor-authentication-for-private-keys/) - Key splitting mechanics explanation
- [Web3Auth SSS vs TSS Blog Post](https://blog.web3auth.io/shamirs-secret-sharing-sss-vs-threshold-signature-scheme-tss-explained/) - Shamir Secret Sharing architecture details

### Tertiary (LOW confidence)

- Web3Auth community forum discussions (now redirected to builder.metamask.io) - Some users reported wallet address changes, but these appear to be related to different verifier configurations, not MFA enrollment itself

<!-- markdownlint-enable MD032 -->

## Metadata

Confidence breakdown:

- Standard stack: HIGH - Verified against installed SDK type definitions
- Architecture: HIGH - Hooks and types confirmed from actual package source
- Key identity after MFA: HIGH - Confirmed via SSS mathematical properties, Web3Auth e2e tests, and multiple documentation sources
- Pitfalls: MEDIUM - Based on community reports and documentation; some edge cases around `mfaLevel: 'none'` inconsistency are community-reported
- Factor details: MEDIUM - Factor types confirmed from SDK, but UX flow details not fully documented
- E2E testing strategy: MEDIUM - Based on Web3Auth's own e2e test patterns, but CipherBox-specific behavior needs verification

Research date: 2026-02-12.
Valid until: 2026-03-12 (30 days - SDK is stable at v10.13.1).

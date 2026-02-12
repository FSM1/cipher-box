# Phase 12: Multi-Factor Authentication (Core Kit Pivot) - Research

**Researched:** 2026-02-12
**Domain:** Web3Auth MPC Core Kit SDK (`@web3auth/mpc-core-kit` v3.5.0), SIWE custom verifier, custom login UI
**Confidence:** MEDIUM (Core Kit API verified via GitHub source + examples; cross-device transfer NOT natively supported; SIWE verifier pattern confirmed but untested; key identity preservation confirmed architecturally but needs runtime validation)

## Summary

This research covers the architectural pivot from Web3Auth PnP Modal SDK (`@web3auth/modal`) to MPC Core Kit (`@web3auth/mpc-core-kit`) for full MFA control. The PnP SDK approach (previous 12-RESEARCH.md) was rejected because it gives up UX control -- no cross-device approval, no custom enrollment UI, no programmatic share management, and wallet users bypass MFA.

The MPC Core Kit SDK provides low-level access to Web3Auth's Threshold Signature Scheme (TSS) infrastructure. Unlike PnP where the SDK handles all UI via a modal, Core Kit requires building every screen (login, MFA enrollment, factor management, recovery) from scratch. The tradeoff is complete control over UX and programmatic factor management via `enableMFA()`, `createFactor()`, `deleteFactor()`, `inputFactorKey()`, and `setDeviceFactor()` APIs.

**CRITICAL FINDINGS:**

1. **Key identity IS preserved** after `enableMFA()`. The underlying TSS key remains unchanged -- enableMFA only redistributes factor shares from 2/2 to 2/3. Confirmed via source code analysis of `mpcCoreKit.ts`.
2. **Cross-device share transfer is NOT natively supported** in MPC Core Kit. An archived community post shows someone attempting to use tKey's `ShareTransferModule` with Core Kit, but Web3Auth confirmed this is not publicly supported. The workaround: use recovery phrase or social backup factor to bootstrap new devices.
3. **PnP and Core Kit generate DIFFERENT private keys** by default for the same verifier. Migration requires using `importTssKey` parameter during first Core Kit login, or setting `useCoreKitKey: true` on the PnP SDK beforehand.
4. **SIWE requires a custom JWT verifier** on Web3Auth dashboard: CipherBox API verifies SIWE signature, issues JWT with `sub = walletAddress`, exposes JWKS endpoint. Web3Auth validates the JWT and derives the MPC key. This requires the Growth Plan or higher (free on devnet).

**Primary recommendation:** Use `@web3auth/mpc-core-kit` v3.5.0 with `@toruslabs/tss-dkls-lib` for secp256k1 TSS signing. Build custom login UI using `loginWithJWT()` for all auth methods (Google via Firebase Auth, Email via custom backend, SIWE via custom backend). Use `enableMFA()` for mandatory first-time MFA enrollment. Use `_UNSAFE_exportTssKey()` to get the secp256k1 private key for vault ECIES operations.

## Standard Stack

### Core

| Library                           | Version | Purpose                                          | Why Standard                                           |
| --------------------------------- | ------- | ------------------------------------------------ | ------------------------------------------------------ |
| `@web3auth/mpc-core-kit`          | 3.5.0   | MPC TSS key management, factor management, login | The only Web3Auth SDK with programmatic factor control |
| `@toruslabs/tss-dkls-lib`         | latest  | DKLS threshold signing for secp256k1 ECDSA       | Required by MPC Core Kit for Ethereum-compatible keys  |
| `@web3auth/ethereum-mpc-provider` | latest  | EIP-1193 provider wrapper for MPC signing        | Wraps Core Kit for ethers/viem/web3.js compatibility   |

### Supporting

| Library                | Version    | Purpose                                     | When to Use                                                 |
| ---------------------- | ---------- | ------------------------------------------- | ----------------------------------------------------------- |
| `firebase` (auth only) | ^10.x      | Google OAuth popup flow                     | For Google social login to get idToken for `loginWithJWT()` |
| `jose`                 | (existing) | JWT signing/verification                    | Backend: sign SIWE/email JWTs for custom verifier           |
| `siwe`                 | ^2.x       | SIWE message creation and verification      | Backend: verify wallet-signed SIWE messages                 |
| `@noble/secp256k1`     | (existing) | Public key derivation from exported TSS key | Convert exported hex private key to public key for ECIES    |

### Removed (replaced by Core Kit)

| Library           | Reason for Removal                                    |
| ----------------- | ----------------------------------------------------- |
| `@web3auth/modal` | Replaced entirely by MPC Core Kit -- no more modal UI |

### Alternatives Considered

| Instead of                              | Could Use                                 | Tradeoff                                                                                                                                                                       |
| --------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| MPC Core Kit (TSS)                      | tKey SDK (SSS)                            | tKey reconstructs the full private key client-side; MPC Core Kit never reconstructs it (more secure). tKey is also "not officially meant for public integration" per Web3Auth. |
| Firebase for Google OAuth               | Auth0, direct Google OAuth                | Firebase is free, well-documented, and Web3Auth has working examples with it. Auth0 adds cost. Direct OAuth requires more manual OIDC handling.                                |
| `siwe` package for SIWE                 | Manual EIP-4361 parsing                   | `siwe` is the canonical library by Spruce; hand-rolling verification is error-prone.                                                                                           |
| `_UNSAFE_exportTssKey()` for vault keys | `EthereumSigningProvider` for all signing | CipherBox needs the raw secp256k1 private key for ECIES encrypt/decrypt (not just EIP-1193 signing). Export is necessary.                                                      |

### Installation

```bash
pnpm add @web3auth/mpc-core-kit @toruslabs/tss-dkls-lib @web3auth/ethereum-mpc-provider siwe
pnpm add -D @types/bn.js  # BN.js types needed for factor key handling
```

**Note on polyfills:** MPC Core Kit uses Node.js crypto primitives (Buffer, crypto) that need polyfilling in Vite. The project may already have some polyfills from the existing Web3Auth setup, but additional ones may be needed. Check for `buffer`, `process`, and `crypto-browserify` polyfills in `vite.config.ts`.

## Architecture Patterns

### SDK State Machine

MPC Core Kit has an explicit status state machine that drives the login flow:

```text
COREKIT_STATUS:
  NOT_INITIALIZED  -->  (init())  -->  INITIALIZED
  INITIALIZED      -->  (loginWithJWT/loginWithOAuth)  -->  LOGGED_IN  (if 2/2 or device factor available)
  INITIALIZED      -->  (loginWithJWT/loginWithOAuth)  -->  REQUIRED_SHARE  (if MFA enabled but device factor missing)
  REQUIRED_SHARE   -->  (inputFactorKey)  -->  LOGGED_IN
```

**This is fundamentally different from PnP SDK** where `connect()` either succeeds or fails. With Core Kit, login can land in `REQUIRED_SHARE` status, meaning the user authenticated socially but needs to provide a second factor before the key is usable.

### Recommended Project Structure

```text
apps/web/src/
+-- lib/
|   +-- web3auth/
|       +-- core-kit.ts          # Web3AuthMPCCoreKit singleton + init
|       +-- config.ts            # Client ID, network, verifier config
|       +-- provider.tsx         # React context provider (replaces Web3AuthProvider)
|       +-- hooks.ts             # useAuth, useMFA, useCoreKit hooks
|       +-- factors.ts           # Factor management utilities
+-- components/
|   +-- auth/
|       +-- LoginPage.tsx        # Custom login UI (Google, Email, SIWE)
|       +-- MfaEnrollment.tsx    # First-time MFA setup wizard
|       +-- MfaChallenge.tsx     # Second-factor input during login
|       +-- RecoveryFlow.tsx     # Recovery phrase input
|       +-- FactorManager.tsx    # Settings page factor management
+-- hooks/
    +-- useAuth.ts               # Updated auth flow with Core Kit
```

### Pattern 1: Singleton Core Kit Instance

```typescript
// apps/web/src/lib/web3auth/core-kit.ts
import { Web3AuthMPCCoreKit, WEB3AUTH_NETWORK, COREKIT_STATUS } from '@web3auth/mpc-core-kit';
import { tssLib } from '@toruslabs/tss-dkls-lib';

let coreKitInstance: Web3AuthMPCCoreKit | null = null;

export function getCoreKit(): Web3AuthMPCCoreKit {
  if (!coreKitInstance) {
    coreKitInstance = new Web3AuthMPCCoreKit({
      web3AuthClientId: import.meta.env.VITE_WEB3AUTH_CLIENT_ID,
      web3AuthNetwork: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET, // or MAINNET
      storage: window.localStorage,
      manualSync: true, // Recommended: explicit commitChanges() calls
      tssLib,
    });
  }
  return coreKitInstance;
}

export async function initCoreKit(): Promise<void> {
  const ck = getCoreKit();
  await ck.init();
  // After init, check if session exists (auto-login from stored session)
}

export { COREKIT_STATUS };
```

### Pattern 2: Login with Custom JWT (Social via Firebase)

```typescript
// Login flow for Google via Firebase
import { getAuth, GoogleAuthProvider, signInWithPopup } from 'firebase/auth';

async function loginWithGoogle(coreKit: Web3AuthMPCCoreKit): Promise<void> {
  // 1. Get Google idToken via Firebase
  const auth = getAuth();
  const result = await signInWithPopup(auth, new GoogleAuthProvider());
  const idToken = await result.user.getIdToken(true);

  // 2. Parse token to get verifierId (email or sub)
  const payload = JSON.parse(atob(idToken.split('.')[1]));

  // 3. Login with Web3Auth MPC Core Kit
  await coreKit.loginWithJWT({
    verifier: 'cipherbox-google-firebase', // Custom verifier on dashboard
    verifierId: payload.email, // Must match verifier config
    idToken,
  });

  // 4. Check status
  if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
    // User has sufficient factors, ready to use
    await coreKit.commitChanges();
  } else if (coreKit.status === COREKIT_STATUS.REQUIRED_SHARE) {
    // MFA is enabled but device factor missing - need second factor
    // Show MFA challenge UI
  }
}
```

### Pattern 3: Login with SIWE (Custom JWT from Backend)

```typescript
// SIWE flow: wallet signs message -> backend verifies -> issues JWT -> Core Kit login
async function loginWithSIWE(coreKit: Web3AuthMPCCoreKit): Promise<void> {
  // 1. Get wallet address (using window.ethereum or WalletConnect)
  const [address] = await window.ethereum.request({ method: 'eth_accounts' });

  // 2. Request nonce from CipherBox API
  const { nonce } = await api.get('/auth/siwe/nonce');

  // 3. Create and sign SIWE message
  const message = new SiweMessage({
    domain: window.location.host,
    address,
    statement: 'Sign in to CipherBox',
    uri: window.location.origin,
    version: '1',
    chainId: 1,
    nonce,
  });
  const signature = await window.ethereum.request({
    method: 'personal_sign',
    params: [message.prepareMessage(), address],
  });

  // 4. Backend verifies SIWE and returns JWT
  const { jwt } = await api.post('/auth/siwe/verify', {
    message: message.prepareMessage(),
    signature,
  });

  // 5. Login with Core Kit using backend-issued JWT
  await coreKit.loginWithJWT({
    verifier: 'cipherbox-siwe', // Custom JWT verifier on dashboard
    verifierId: address.toLowerCase(), // sub = wallet address
    idToken: jwt, // Backend-signed JWT
  });

  if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
    await coreKit.commitChanges();
  }
}
```

### Pattern 4: MFA Enrollment (enableMFA)

```typescript
import { generateFactorKey, keyToMnemonic } from '@web3auth/mpc-core-kit';

async function enrollMFA(coreKit: Web3AuthMPCCoreKit): Promise<string> {
  // enableMFA creates device factor + backup factor, deletes hashed cloud factor
  // Returns the backup factor key
  const backupFactorKey = await coreKit.enableMFA({});

  // Convert factor key to 24-word mnemonic for user display
  const mnemonic = keyToMnemonic(backupFactorKey);

  // Commit changes to metadata server
  await coreKit.commitChanges();

  return mnemonic; // Display to user for safekeeping
}
```

### Pattern 5: Getting Private Key for Vault Operations

```typescript
// CipherBox needs the raw secp256k1 private key for ECIES encrypt/decrypt
async function getVaultKeypair(coreKit: Web3AuthMPCCoreKit): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  // _UNSAFE_ prefix means the full key is reconstructed client-side
  // This is necessary for CipherBox's ECIES operations
  const privateKeyHex = await coreKit._UNSAFE_exportTssKey();

  const privateKey = hexToBytes(privateKeyHex);
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed

  return { publicKey, privateKey };
}
```

### Pattern 6: Second-Factor Challenge (REQUIRED_SHARE status)

```typescript
async function handleRequiredShare(
  coreKit: Web3AuthMPCCoreKit,
  method: 'device' | 'recovery' | 'social'
): Promise<void> {
  if (method === 'device') {
    // Try to get device factor from localStorage
    const deviceFactor = await coreKit.getDeviceFactor();
    if (deviceFactor) {
      await coreKit.inputFactorKey(new BN(deviceFactor, 'hex'));
    }
  } else if (method === 'recovery') {
    // User enters recovery phrase
    const mnemonic = await promptUserForMnemonic();
    const factorKey = mnemonicToKey(mnemonic);
    await coreKit.inputFactorKey(new BN(factorKey, 'hex'));
  }

  if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
    await coreKit.commitChanges();
  }
}
```

### Anti-Patterns to Avoid

- **Do not try to use `Web3AuthProvider` from `@web3auth/modal/react` with Core Kit:** Core Kit is a standalone SDK with no React provider. You must build your own React context/provider.
- **Do not skip `commitChanges()` after mutations:** In manual sync mode, factor changes are local until committed. Forgetting to commit means changes are lost on page refresh.
- **Do not use `loginWithOAuth()` for production:** It opens a popup/redirect to Web3Auth's auth pages. Use `loginWithJWT()` with your own auth flow for full UI control.
- **Do not create more than 10 factors:** Web3Auth recommends a maximum of 10 factors per account.
- **Do not assume device factor persists:** It's stored in `localStorage`. Clearing browser data or using incognito loses it.
- **Do not call factor management methods when status is REQUIRED_SHARE:** Most mutations require LOGGED_IN status.

## Don't Hand-Roll

| Problem                         | Don't Build                     | Use Instead                               | Why                                                                       |
| ------------------------------- | ------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------- |
| TSS key splitting               | Custom Shamir/threshold scheme  | `enableMFA()`                             | Cryptographic primitive; SDK handles distributed key generation correctly |
| Recovery phrase encoding        | Custom word list / encoding     | `keyToMnemonic()` / `mnemonicToKey()`     | SDK provides BIP-39 compatible encoding                                   |
| Factor key generation           | Custom random key generation    | `generateFactorKey()`                     | SDK ensures proper entropy and format                                     |
| SIWE message creation           | Manual EIP-4361 string building | `siwe` package                            | Canonical implementation handles all edge cases                           |
| JWT signing for custom verifier | Custom JWT library              | `jose` package (already in project)       | Handles RSA/EC key pairs, JWKS endpoint generation                        |
| Device factor storage           | Custom encrypted localStorage   | `setDeviceFactor()` / `getDeviceFactor()` | SDK manages device-specific factor storage                                |

**Key insight:** Unlike the PnP SDK approach where Web3Auth handles ALL MFA UI, Core Kit requires CipherBox to build every screen but provides the cryptographic primitives. The rule is: build the UI, use the SDK for crypto.

## Common Pitfalls

### Pitfall 1: PnP and Core Kit Generate Different Keys

**What goes wrong:** Existing users who authenticated via `@web3auth/modal` get a DIFFERENT private key when switching to MPC Core Kit with the same verifier.
**Why it happens:** PnP SDK and Core Kit use different key derivation paths (subkey generation logic differs). By default they produce different keys for the same verifier+verifierId.
**How to avoid:** During migration, use the `importTssKey` parameter on the FIRST Core Kit login to import the user's existing PnP key. Alternatively, enable `useCoreKitKey: true` on the PnP SDK first so existing accounts already use Core Kit-compatible keys.
**Warning signs:** User logs in after migration and their vault is inaccessible (different publicKey = can't decrypt ECIES-wrapped keys).
**IMPACT: This is the highest-risk aspect of the migration. Incorrect handling means vault lockout.**

### Pitfall 2: Manual Sync Mode Requires Explicit Commits

**What goes wrong:** Factor changes (create, delete, enableMFA) appear to work but are lost after page refresh.
**Why it happens:** With `manualSync: true`, all mutations are buffered locally. Only `commitChanges()` persists them to the metadata server.
**How to avoid:** Always call `await coreKit.commitChanges()` after any mutation. Consider wrapping mutations in a helper that auto-commits.
**Warning signs:** Factors appear in `getKeyDetails()` but disappear after page navigation.

### Pitfall 3: REQUIRED_SHARE Status Not Handled

**What goes wrong:** User authenticates (Google login succeeds) but app treats them as not logged in.
**Why it happens:** After `loginWithJWT()`, status can be `REQUIRED_SHARE` instead of `LOGGED_IN` when MFA is enabled but the device factor is missing (new device, cleared browser data).
**How to avoid:** Always check `coreKit.status` after login. If `REQUIRED_SHARE`, show the second-factor UI (recovery phrase input, social backup, etc.).
**Warning signs:** Users report "stuck on login" or "infinite loading" after clearing browser data.

### Pitfall 4: Cross-Device Transfer Not Available

**What goes wrong:** Developer builds UI for "approve this device from your other device" but there's no API for it.
**Why it happens:** MPC Core Kit does NOT have a native cross-device share transfer API. The archived community post confirms this is "enterprise only" and not publicly supported.
**How to avoid:** Use recovery phrase or social backup factor as the cross-device mechanism. User logs into new device, enters recovery phrase, SDK creates new device factor locally.
**Warning signs:** Searching for `requestDeviceShare` or `ShareTransferModule` in Core Kit and finding nothing.

### Pitfall 5: \_UNSAFE_exportTssKey Only Works for secp256k1

**What goes wrong:** Attempting to export key for ed25519 curves fails.
**Why it happens:** The export method only supports secp256k1 (which is what CipherBox uses, so this is fine).
**How to avoid:** Ensure `tssLib` is `@toruslabs/tss-dkls-lib` (for secp256k1), not `@toruslabs/tss-frost-lib` (for ed25519).
**Warning signs:** Export throws an error about unsupported key type.

### Pitfall 6: Custom Verifier Requires Growth Plan for Production

**What goes wrong:** SIWE and custom JWT verifiers work on devnet but fail on mainnet.
**Why it happens:** Custom verifiers on Web3Auth dashboard require Growth Plan or higher for production (sapphire_mainnet). Free tier only works on sapphire_devnet.
**How to avoid:** Verify Web3Auth billing plan before production deployment. All development and staging work uses devnet (free).
**Warning signs:** Login fails with verifier-related errors only in production.

### Pitfall 7: MFA is Irreversible (Same as PnP)

**What goes wrong:** Test account gets MFA enabled, now requires 2 factors for every login.
**Why it happens:** `enableMFA()` permanently changes the account from 2/2 to 2/3. Cannot be reversed.
**How to avoid:** Use fresh devnet accounts for MFA testing. Keep the E2E test account MFA-free.
**Warning signs:** E2E tests break because test account now requires second factor.

### Pitfall 8: Firebase Auth Adds Bundle Size

**What goes wrong:** Bundle size increases significantly after adding Firebase for Google OAuth.
**Why it happens:** `firebase/auth` is a large package (~100KB+ gzipped).
**How to avoid:** Consider using `@auth/core` or direct Google OAuth OIDC flow instead. Or use the `loginWithOAuth()` method for Google (which delegates to Web3Auth's auth popup) and only use `loginWithJWT()` for SIWE/email.
**Warning signs:** Lighthouse performance score drops after adding Firebase.

## Code Examples

### Complete Initialization

```typescript
// apps/web/src/lib/web3auth/core-kit.ts
import {
  Web3AuthMPCCoreKit,
  WEB3AUTH_NETWORK,
  COREKIT_STATUS,
  generateFactorKey,
  keyToMnemonic,
  mnemonicToKey,
  TssShareType,
  FactorKeyTypeShareDescription,
} from '@web3auth/mpc-core-kit';
import { tssLib } from '@toruslabs/tss-dkls-lib';
import { EthereumSigningProvider } from '@web3auth/ethereum-mpc-provider';
import BN from 'bn.js';

const environment = import.meta.env.VITE_ENVIRONMENT || 'local';

const NETWORK_MAP: Record<string, (typeof WEB3AUTH_NETWORK)[keyof typeof WEB3AUTH_NETWORK]> = {
  local: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  ci: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  staging: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  production: WEB3AUTH_NETWORK.SAPPHIRE_MAINNET,
};

let instance: Web3AuthMPCCoreKit | null = null;

export function getCoreKit(): Web3AuthMPCCoreKit {
  if (!instance && typeof window !== 'undefined') {
    instance = new Web3AuthMPCCoreKit({
      web3AuthClientId: import.meta.env.VITE_WEB3AUTH_CLIENT_ID,
      web3AuthNetwork: NETWORK_MAP[environment] || WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
      storage: window.localStorage,
      manualSync: true,
      tssLib,
    });
  }
  return instance!;
}

export async function initCoreKit(): Promise<COREKIT_STATUS> {
  const ck = getCoreKit();
  await ck.init();
  return ck.status;
}

export {
  COREKIT_STATUS,
  generateFactorKey,
  keyToMnemonic,
  mnemonicToKey,
  TssShareType,
  FactorKeyTypeShareDescription,
  BN,
};
```

### Backend SIWE Verification Endpoint

```typescript
// apps/api/src/auth/siwe/ (new module)
import { SiweMessage } from 'siwe';
import * as jose from 'jose';

// The backend needs:
// 1. A signing keypair for JWTs (RS256)
// 2. A JWKS endpoint exposing the public key
// 3. The custom verifier on Web3Auth dashboard pointed at this JWKS endpoint

async function verifySiweAndIssueJWT(
  message: string,
  signature: string,
  privateKey: jose.KeyLike
): Promise<string> {
  // 1. Verify SIWE message
  const siweMessage = new SiweMessage(message);
  const { data: fields } = await siweMessage.verify({ signature });

  // 2. Issue JWT for Web3Auth custom verifier
  const jwt = await new jose.SignJWT({
    sub: fields.address.toLowerCase(), // verifierId = wallet address
    aud: 'web3auth',
    iss: 'cipherbox-api',
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'siwe-key-1' })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);

  return jwt;
}
```

### MFA Factor Management in Settings

```typescript
// Factor listing and management
async function getFactorInfo(coreKit: Web3AuthMPCCoreKit) {
  const keyDetails = coreKit.getKeyDetails();
  // keyDetails contains:
  //   - requiredFactors: number (how many more factors needed to reach threshold)
  //   - threshold: number (e.g., 2)
  //   - totalFactors: number
  //   - shareDescriptions: Record<string, string[]> (factor pub -> descriptions)

  const factorPubs = coreKit.getTssFactorPub(); // string[]
  // Each factor pub corresponds to a registered factor

  return { keyDetails, factorPubs };
}

// Create additional recovery factor
async function createRecoveryFactor(coreKit: Web3AuthMPCCoreKit): Promise<string> {
  const factorKey = generateFactorKey();
  await coreKit.createFactor({
    shareType: TssShareType.RECOVERY,
    factorKey: factorKey.private,
    shareDescription: FactorKeyTypeShareDescription.SeedPhrase,
  });
  await coreKit.commitChanges();
  return keyToMnemonic(factorKey.private.toString('hex'));
}

// Delete a factor
async function deleteRecoveryFactor(coreKit: Web3AuthMPCCoreKit, factorPub: string): Promise<void> {
  const pub = Point.fromSEC1(secp256k1, factorPub);
  await coreKit.deleteFactor(pub);
  await coreKit.commitChanges();
}
```

## CRITICAL: Key Identity After MFA Enrollment

**Answer:** The derived private key does NOT change when MFA is enabled via `enableMFA()`.

**Confidence:** HIGH (verified via source code analysis + architectural documentation).

**Evidence:**

1. **Source code (`mpcCoreKit.ts`):** The `enableMFA()` method "only modifies which factors can reconstruct the key -- it's purely a share redistribution operation." The underlying TSS key remains unchanged.

2. **Architecture documentation (MetaMask/Web3Auth):** Factor keys "enable rotation, refresh, and deletion capabilities independent of the core private key." The system uses Proactive Secret Sharing to derive additional shares "without changing the underlying secret."

3. **MPC TSS design:** Unlike SSS (where shares reconstruct the key), TSS generates partial signatures. The "secret" (private key scalar) is never reconstructed during normal signing. `enableMFA()` changes the factor graph, not the key itself.

4. **`_UNSAFE_exportTssKey()`** returns the same hex private key before and after `enableMFA()` because the underlying TSS polynomial's constant term (the actual private key) is unchanged.

**Implication for CipherBox:** Success Criterion 4 is met by design. After MFA enrollment:

- `_UNSAFE_exportTssKey()` returns the same private key
- The derived secp256k1 public key is identical
- Existing ECIES-wrapped vault keys remain decryptable
- No vault re-encryption or key migration is needed

## Migration Path: PnP Modal SDK to Core Kit

### The Key Problem

PnP SDK and MPC Core Kit generate DIFFERENT private keys by default for the same verifier+verifierId. This is because they use different subkey derivation paths.

### Option A: Use `importTssKey` (Recommended)

During the first Core Kit login for an existing user:

1. Store the user's current PnP private key (from the last PnP session) securely
2. On first Core Kit login, pass it as `importTssKey`:

```typescript
await coreKit.loginWithJWT({
  verifier: 'cipherbox-google-firebase',
  verifierId: user.email,
  idToken,
  importTssKey: existingPnPPrivateKey, // hex string
});
```

3. Core Kit splits this imported key into TSS shares
4. Subsequent logins use Core Kit's native key derivation

**Challenge:** This requires having access to the PnP private key during migration. Possible approach: deploy a transitional build that logs in with PnP, exports the key, then re-authenticates with Core Kit.

### Option B: Use `useCoreKitKey: true` on PnP First

Before the Core Kit migration:

1. Deploy a build with `useCoreKitKey: true` on the PnP SDK
2. All users who log in get migrated to Core Kit-compatible keys
3. Then deploy the Core Kit build

**Challenge:** Users who don't log in during the transition window still have old-style keys.

### Option C: Fresh Start on Devnet

Since CipherBox is on sapphire_devnet (not mainnet):

1. Accept that existing devnet accounts may need to re-create vaults
2. Deploy Core Kit build directly
3. Existing users log in, get new Core Kit keys, and re-initialize their vault

**This is likely the simplest path for a dev/staging environment.**

### Recommended Migration Strategy

For devnet/staging: **Option C** (fresh start). Document that existing test accounts need vault re-initialization.

For production: **Option A** (`importTssKey`) with a transitional migration flow. This preserves vault access for all existing users.

### Verifier Changes

The current PnP setup uses grouped connections with custom verifiers (`cipherbox-google-oauth-2`, `cb-email-testnet`, `cipherbox-grouped-connection`). Core Kit requires custom verifiers configured on the Web3Auth dashboard. You may need to create new verifiers or reconfigure existing ones for Core Kit compatibility.

**Critical:** Core Kit uses `loginWithJWT()` which requires the app to handle OAuth and pass the idToken. The verifier on the dashboard must match the token's issuer and claims.

## SIWE Integration Architecture

### Overview

SIWE (Sign-In with Ethereum) replaces the current ADR-001 signature-derived key approach. Instead of deriving a separate keypair from a wallet signature, wallet users get a Web3Auth-managed MPC key that CAN be protected by MFA.

### Flow

```text
1. User connects wallet (MetaMask/WalletConnect)
2. CipherBox frontend requests nonce from API
3. User signs SIWE message with wallet
4. CipherBox frontend sends signed message to API
5. API verifies SIWE signature
6. API issues JWT: { sub: walletAddress, aud: "web3auth", iss: "cipherbox-api" }
7. Frontend calls coreKit.loginWithJWT({
     verifier: "cipherbox-siwe",
     verifierId: walletAddress,
     idToken: jwt
   })
8. Web3Auth validates JWT against CipherBox API's JWKS endpoint
9. Core Kit derives MPC key for this identity
10. User now has a Web3Auth-managed key that supports MFA
```

### Backend Requirements

1. **JWKS endpoint** (`GET /auth/.well-known/jwks.json`): Expose the public key used to sign SIWE JWTs. Must be publicly accessible. Web3Auth validates tokens against this.

2. **Nonce endpoint** (`GET /auth/siwe/nonce`): Generate and store a random nonce for replay protection.

3. **Verify endpoint** (`POST /auth/siwe/verify`): Verify the SIWE message signature, check nonce, issue JWT.

4. **Signing keypair**: Generate an RS256 (RSA) or ES256 (EC) keypair for JWT signing. Store the private key securely (env variable). The public key goes in the JWKS endpoint.

### Web3Auth Dashboard Configuration

Create a custom JWT verifier:

- **Auth Connection ID:** `cipherbox-siwe`
- **JWKS Endpoint:** `https://api.cipherbox.cc/auth/.well-known/jwks.json` (or staging equivalent)
- **JWT Verifier ID Field:** `sub` (which will be the wallet address)
- **Case sensitivity:** off (wallet addresses are case-insensitive)

**Pricing:** Custom verifiers require Growth Plan for production (sapphire_mainnet). Free on sapphire_devnet.

### Benefits Over ADR-001

| Aspect             | ADR-001 (Current)                                 | SIWE + Core Kit (New)                                 |
| ------------------ | ------------------------------------------------- | ----------------------------------------------------- |
| Key type           | Signature-derived (deterministic from wallet sig) | Web3Auth MPC key (TSS-managed)                        |
| MFA support        | None (wallet IS the single factor)                | Full MFA (device, recovery, etc.)                     |
| Recovery           | No recovery if wallet lost                        | Recovery phrase, social backup                        |
| Key storage        | Requires re-signing every session                 | Session-based, device factor caches                   |
| Backend complexity | Simple (verify sig, derive key)                   | Higher (JWKS endpoint, JWT signing, nonce management) |

## E2E Testing Strategy

### The Problem

With Core Kit, there's no `mfaLevel: 'none'` configuration like PnP SDK. MFA enrollment is triggered programmatically by calling `enableMFA()`, so you simply don't call it in test flows.

### Strategy

| Scenario          | Approach                                                                                                                             |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Login without MFA | Use `loginWithJWT()` normally. New accounts start in 2/2 mode (no MFA). Don't call `enableMFA()`.                                    |
| Login with MFA    | Create a test account, call `enableMFA()`, save the backup factor key. Use `inputFactorKey()` in tests.                              |
| E2E automation    | Use `loginWithJWT()` with a test-specific Firebase/custom auth token. The test account stays in 2/2 mode unless explicitly enrolled. |
| CI environment    | Same devnet, same verifier. `loginWithJWT()` with programmatic token generation. No MFA enrollment = no second factor needed.        |

### Key Advantage Over PnP

With Core Kit, MFA enrollment is explicit (you call `enableMFA()`), not configuration-driven (`mfaLevel: 'mandatory'`). This means test accounts naturally bypass MFA by simply not enrolling. No environment-specific configuration tricks needed.

### E2E Test Account Strategy

```typescript
// E2E tests can use loginWithJWT directly with a test verifier
// No need for the Web3Auth modal popup automation
await coreKit.loginWithJWT({
  verifier: 'cipherbox-test-verifier',
  verifierId: 'test@example.com',
  idToken: testJWT, // Generated programmatically in test setup
});
// Status will be LOGGED_IN (no MFA on test account)
```

## Cross-Device Flow (Workaround)

### The Reality

MPC Core Kit does NOT have native cross-device share transfer (no `requestDeviceShare()` / `approveDevice()`). This was confirmed by the archived MetaMask Builder Hub post, where Web3Auth stated this is "enterprise only."

### Workaround: Recovery-Based Device Bootstrap

When a user logs in on a new device:

1. Social login succeeds (Share B from Web3Auth infrastructure is available)
2. Device factor is missing (Share A doesn't exist on new device)
3. Status is `REQUIRED_SHARE`
4. User enters recovery phrase (Share C)
5. `inputFactorKey()` provides the backup factor
6. Status transitions to `LOGGED_IN`
7. App creates a NEW device factor for this device: `await coreKit.setDeviceFactor(newFactorKey)`
8. Commit changes

### Alternative: Social Backup Factor

If the user enrolled a social backup (linked a second social account):

1. Social login succeeds on new device
2. Status is `REQUIRED_SHARE`
3. User authenticates with their backup social account
4. The backup social factor satisfies the threshold
5. New device factor is created

### UX Implication

Cross-device "approval from existing device" is NOT possible. The CONTEXT.md lists this as a desired feature, but it's not available in MPC Core Kit. The closest alternatives are:

- **Recovery phrase** (always available if user saved it)
- **Social backup factor** (if enrolled)
- **Password factor** (if enrolled)

This should be communicated clearly in planning: the cross-device approval UX from ChainSafe Files relied on tKey's ShareTransferModule, which is not available in MPC Core Kit.

## State of the Art

| Old Approach                                     | Current Approach                                | When Changed | Impact                                       |
| ------------------------------------------------ | ----------------------------------------------- | ------------ | -------------------------------------------- |
| tKey SDK with SSS                                | MPC Core Kit with TSS                           | 2023-2024    | Key never reconstructed during signing       |
| `@web3auth/modal` with `mfaSettings`             | `@web3auth/mpc-core-kit` with programmatic MFA  | v3.0 (2024)  | Full UI control, but more code to write      |
| `ShareTransferModule` for cross-device           | Recovery phrase / social backup for new devices | Current      | No real-time cross-device approval available |
| PnP React hooks (`useEnableMFA`, `useManageMFA`) | Manual Core Kit API calls                       | Current      | Must build all React state management        |
| ADR-001 signature-derived keys for wallets       | SIWE + custom verifier for unified MPC keys     | Proposed     | Wallet users get full MFA support            |

**Deprecated/outdated:**

- tKey SDK: "not officially meant for public integration" per Web3Auth
- `ShareTransferModule`: Archived, enterprise-only
- `@web3auth/modal` for Core Kit-level MFA: Use `@web3auth/mpc-core-kit` instead

## Open Questions

### 1. Firebase vs Alternative for Google OAuth

**What we know:** Core Kit examples use Firebase for Google OAuth flow. Firebase provides `signInWithPopup()` which returns an idToken.
**What's unclear:** Is Firebase the only viable approach? Could we use Google's OIDC directly, or Auth0, to avoid the Firebase dependency and bundle size?
**Recommendation:** Research alternatives during implementation. If bundle size is a concern, consider `loginWithOAuth()` for Google (Web3Auth handles the popup) and `loginWithJWT()` only for SIWE/email. This hybrid approach avoids Firebase entirely.

### 2. Existing Verifier Compatibility

**What we know:** Current PnP setup uses custom verifiers (`cipherbox-google-oauth-2`, `cb-email-testnet`, `cipherbox-grouped-connection`).
**What's unclear:** Can these same verifiers be used with Core Kit's `loginWithJWT()`, or do new verifiers need to be created? Grouped connections may not apply to Core Kit.
**Recommendation:** Test on devnet during implementation. May need to create new verifiers specifically for Core Kit.

### 3. Email Passwordless Flow with Core Kit

**What we know:** PnP SDK handled email magic links via Web3Auth's built-in auth. Core Kit requires you to handle auth yourself.
**What's unclear:** How to implement email passwordless without PnP? Options: (a) use Firebase email auth, (b) build custom magic link flow in CipherBox API, (c) use `loginWithOAuth()` which delegates to Web3Auth for email.
**Recommendation:** Use `loginWithOAuth()` for email if it supports email_passwordless, otherwise build a custom backend email OTP flow and use `loginWithJWT()`.

### 4. Aggregate Verifier for Unified Accounts

**What we know:** PnP uses grouped connections so Google + Email with same email = same key. Core Kit supports aggregate verifiers via `loginWithJWT()` with an aggregate verifier parameter.
**What's unclear:** Exact configuration for aggregate verifiers with Core Kit. How to ensure Google + Email + SIWE all map to the same account when the user has the same email.
**Recommendation:** Research aggregate verifier setup on Web3Auth dashboard. This is critical for maintaining the "same email = same vault" behavior.

### 5. Session Persistence and Auto-Login

**What we know:** Core Kit stores session data in localStorage. `init()` checks for an existing session and may auto-restore login state.
**What's unclear:** How long do sessions last? Can they be configured? What happens when the session expires?
**Recommendation:** Test session behavior during implementation. May need to implement session refresh logic.

### 6. Bundle Size Impact

**What we know:** `@web3auth/mpc-core-kit` + `@toruslabs/tss-dkls-lib` include WASM modules for TSS operations.
**What's unclear:** What's the total bundle size impact? Does the WASM load asynchronously?
**Recommendation:** Measure after installation. DKLS lib loads WASM asynchronously per v3.1.2 release notes.

### 7. Vite Polyfill Requirements

**What we know:** MPC Core Kit needs Node.js polyfills (Buffer, process, crypto). The existing PnP setup may already provide some.
**What's unclear:** Exact polyfills needed. Whether existing `vite.config.ts` polyfills are sufficient.
**Recommendation:** Install and test. Add polyfills as needed. Common solution: `vite-plugin-node-polyfills`.

## Sources

### Primary (HIGH confidence)

<!-- markdownlint-disable MD032 -->

- [Web3Auth/mpc-core-kit GitHub source](https://github.com/Web3Auth/mpc-core-kit/blob/master/src/mpcCoreKit.ts) - enableMFA implementation, public API, COREKIT_STATUS enum
- [Web3Auth/mpc-core-kit-examples](https://github.com/Web3Auth/mpc-core-kit-examples/blob/main/mpc-core-kit-web/quick-starts/mpc-core-kit-nextjs-quick-start/app/page.tsx) - Working code example with login, enableMFA, factor management
- [MetaMask MPC Architecture docs](https://docs.metamask.io/embedded-wallets/infrastructure/mpc-architecture/) - Key share distribution, PSS, factor architecture
- [MetaMask MPC Features](https://docs.metamask.io/embedded-wallets/features/mpc/) - TSS overview, factor types, 2-of-3 threshold

### Secondary (MEDIUM confidence)

- [MetaMask MFA docs (PnP)](https://docs.metamask.io/embedded-wallets/sdk/react/advanced/mfa/) - Factor types, mfaSettings configuration (PnP-specific but factor concepts apply)
- [Web3Auth custom verifier setup](https://web3auth.io/docs/dashboard-setup/setup-custom-authentication) - JWKS endpoint, JWT requirements, dashboard configuration
- [Web3Auth BYO JWT docs](https://web3auth.io/docs/auth-provider-setup/byo-jwt-provider) - Custom JWT provider requirements
- [Web3Auth different private keys troubleshooting](https://web3auth.io/docs/troubleshooting/different-private-key) - PnP vs Core Kit key differences, useCoreKitKey
- [Web3Auth Privy migration guide](https://web3auth.io/docs/guides/privy-migration) - importTssKey parameter documentation

### Tertiary (LOW confidence)

- [MetaMask Builder Hub - Cross-device transfer archive](https://builder.metamask.io/t/archive-extending-mpc-core-kit-with-transfer-module/1058) - Confirms cross-device share transfer is not publicly supported
- [Auth0 SIWE integration](https://auth0.com/blog/sign-in-with-ethereum-siwe-now-available-on-auth0/) - SIWE pattern reference

### Existing Codebase (HIGH confidence)

- `apps/web/src/lib/web3auth/config.ts` - Current PnP configuration
- `apps/web/src/lib/web3auth/hooks.ts` - Current `useAuthFlow()` implementation
- `apps/web/src/lib/web3auth/provider.tsx` - Current `Web3AuthProvider` wrapper
- `apps/web/src/hooks/useAuth.ts` - Current login/logout/session flow
- `apps/web/src/stores/auth.store.ts` - Current auth state management
- `apps/api/src/auth/services/web3auth-verifier.service.ts` - Current backend token verification
- `apps/api/src/auth/auth.service.ts` - Current backend auth service
- `apps/api/src/auth/dto/login.dto.ts` - Current login DTO

<!-- markdownlint-enable MD032 -->

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - Packages confirmed via npm, GitHub source, and working examples
- Architecture patterns: MEDIUM - Based on examples and source code; real-world integration may surface issues
- Key identity preservation: HIGH - Confirmed via source code analysis of enableMFA implementation
- Migration path: MEDIUM - importTssKey documented but not tested; PnP-to-Core-Kit migration is novel
- SIWE integration: MEDIUM - Custom verifier pattern well-documented; specific SIWE implementation untested
- Cross-device: HIGH (negative finding) - Confirmed NOT available; workaround documented
- E2E testing: MEDIUM - Strategy is logical but untested with Core Kit specifically
- Pitfalls: HIGH - Based on architectural understanding, source code, and community reports

**Research date:** 2026-02-12
**Valid until:** 2026-03-12 (30 days - MPC Core Kit v3.5.0 is stable; monitor for v4.x breaking changes)

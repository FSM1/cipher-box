# Authentication Architecture

This document describes the Web3Auth MPC Core Kit key architecture as integrated into CipherBox, covering the default account state, factor lifecycle, and security implications.

## Table of Contents

1. [Overview](#1-overview)
2. [Authentication Flow](#2-authentication-flow)
3. [Default Account State (Pre-MFA)](#3-default-account-state-pre-mfa)
4. [Factor Lifecycle After enableMFA()](#4-factor-lifecycle-after-enablemfa)
5. [Security Analysis](#5-security-analysis)
6. [Cross-Device Approval](#6-cross-device-approval)
7. [MFA Status Detection](#7-mfa-status-detection)
8. [Key Files Reference](#8-key-files-reference)

---

## 1. Overview

CipherBox uses Web3Auth's MPC Core Kit to derive a deterministic secp256k1 ECDSA keypair from user authentication. This keypair is the root of CipherBox's encryption hierarchy -- the private key decrypts the vault's root folder key, IPNS signing keys, and all downstream file/folder keys.

The MPC Core Kit uses **Threshold Secret Sharing (TSS)** to split the private key into multiple **factors** distributed across different parties. While TSS supports distributed signing without reconstructing the key, CipherBox needs the full private key client-side for ECIES decryption and IPNS signing, so it calls `_UNSAFE_exportTssKey()` each session to reconstruct the key locally from the available factors. The exported key exists only in browser memory and is destroyed on logout.

```text
User Authentication
    │
    ▼
Web3Auth MPC Core Kit (TSS)
    │
    ├── Factor 1: JWT verifier share (distributed across Web3Auth DKG nodes)
    ├── Factor 2: hashedShare (Web3Auth metadata server)
    │   [After enableMFA(): deleted and replaced with:]
    ├── Factor 3: Device share (browser localStorage)
    └── Factor 4: Recovery share (user-held 24-word mnemonic)
    │
    ▼
secp256k1 ECDSA Keypair
    │
    ├── privateKey → decrypts rootFolderKey, ipnsPrivateKey, folderKeys, fileKeys
    └── publicKey  → identifies user, encrypts all data keys via ECIES
```

---

## 2. Authentication Flow

CipherBox does **not** use Web3Auth's built-in social login directly. Instead, it implements a custom verifier flow:

### 2.1 Custom Verifier: `cipherbox-identity`

The CipherBox backend authenticates users (via Google OAuth, email OTP, or wallet SIWE signature) and issues a short-lived RS256 JWT:

```text
Claims: { sub: userId, iss: "cipherbox", aud: "web3auth", exp: "5m" }
Signing: RS256 with kid "cipherbox-identity-1"
JWKS endpoint: /.well-known/jwks.json (served by CipherBox backend)
```

This JWT is passed to Core Kit's `loginWithJWT()`:

```typescript
await coreKit.loginWithJWT({
  verifier: 'cipherbox-identity', // Custom verifier registered with Web3Auth
  verifierId: userId, // Unique user identifier
  idToken: cipherboxJwt, // JWT from CipherBox backend
});
```

Web3Auth's network validates the JWT against the JWKS endpoint and uses the verified `verifierId` to deterministically derive the user's TSS key shares.

### 2.2 Key Derivation

The verifier identity (`cipherbox-identity` + `userId`) deterministically maps to a secp256k1 keypair via Web3Auth's Distributed Key Generation (DKG) protocol. The same user always derives the same keypair regardless of which authentication method (Google, email, wallet) they use, as long as the CipherBox backend resolves them to the same `userId`.

---

## 3. Default Account State (Pre-MFA)

When a user signs up and authenticates for the first time, Core Kit's DKG protocol creates two factors:

### 3.1 Factor Breakdown

| #   | Factor             | Module                                 | Storage                               | Controlled By    |
| --- | ------------------ | -------------------------------------- | ------------------------------------- | ---------------- |
| 1   | JWT verifier share | (internal, not in `shareDescriptions`) | Distributed across Web3Auth DKG nodes | Web3Auth network |
| 2   | hashedShare        | `hashedShare`                          | Web3Auth metadata server              | Web3Auth         |

### 3.2 Key Details in This State

Querying `coreKit.getKeyDetails()` on a fresh account returns:

```json
{
  "totalFactors": 2,
  "threshold": 2,
  "requiredFactors": 0,
  "shareDescriptions": {
    "024b05fc...": ["{\"module\":\"hashedShare\",\"dateAdded\":1771472255283,\"tssShareIndex\":2}"]
  }
}
```

Notable observations:

- `totalFactors: 2` -- the JWT verifier share and the hashedShare
- `threshold: 2` -- both factors are required for TSS signing
- `requiredFactors: 0` -- the user is fully authenticated (both factors are available: JWT verified during login, hashedShare retrieved automatically from Web3Auth's metadata server)
- `shareDescriptions` contains only the hashedShare -- the JWT verifier share is internal to Web3Auth and not exposed in this map

### 3.3 What Is the hashedShare?

The hashedShare is a **cloud custodial key** automatically created by MPC Core Kit during the DKG key generation process. It:

- Is stored encrypted on Web3Auth's metadata server
- Has `tssShareIndex: 2` in the TSS polynomial
- Is retrieved automatically during `loginWithJWT()` (transparent to the user)
- Acts as Web3Auth's "custodial backup" of the user's key access
- Is **deleted** when `enableMFA()` is called

The hashedShare exists so that a fresh account can authenticate with just the JWT verifier -- both required factors (JWT verifier + hashedShare) are within Web3Auth's infrastructure, making the login seamless but semi-custodial.

---

## 4. Factor Lifecycle After enableMFA()

Calling `coreKit.enableMFA({})` transitions the account from semi-custodial to fully non-custodial.

### 4.1 What enableMFA() Does

1. **Generates a device factor** -- a new secp256k1 keypair stored in the browser's localStorage. Module: `DeviceShare`, `tssShareIndex` varies.
2. **Generates a recovery factor** -- a backup key returned as a hex string, which CipherBox converts to a 24-word BIP-39 mnemonic for the user to write down. Module: `SeedPhrase`.
3. **Deletes the hashedShare** -- the cloud custodial key is removed from Web3Auth's metadata server.
4. **Updates the TSS threshold** -- remains at 2, but now the 2 required factors must come from the user-controlled set.

### 4.2 Factor Breakdown After enableMFA()

| #   | Factor             | Module                           | Storage                | Controlled By    |
| --- | ------------------ | -------------------------------- | ---------------------- | ---------------- |
| 1   | JWT verifier share | (internal)                       | Web3Auth DKG nodes     | Web3Auth network |
| 2   | Device share       | `DeviceShare` / `webDeviceShare` | Browser localStorage   | User (device)    |
| 3   | Recovery share     | `SeedPhrase`                     | User's physical backup | User             |

### 4.3 Key Details After enableMFA()

```json
{
  "totalFactors": 3,
  "threshold": 2,
  "requiredFactors": 0,
  "shareDescriptions": {
    "02a1b2c3...": [
      "{\"module\":\"DeviceShare\",\"dateAdded\":...,\"tssShareIndex\":3,\"additionalMetadata\":{\"deviceId\":\"...\",\"browserName\":\"Chrome\"}}"
    ],
    "03d4e5f6...": ["{\"module\":\"SeedPhrase\",\"dateAdded\":...,\"tssShareIndex\":4}"]
  }
}
```

- `totalFactors: 3` -- JWT verifier + device share + recovery share (hashedShare deleted)
- `threshold: 2` -- any 2 of the 3 factors can reconstruct the TSS key
- The hashedShare is gone from `shareDescriptions`

### 4.4 TSS Key Stability

MFA enrollment does **not** change the derived keypair. CipherBox verifies this with a defensive check:

```typescript
const preMfaTssPub = coreKit.getKeyDetails().tssPubKey;
await coreKit.enableMFA({});
const postMfaTssPub = coreKit.getKeyDetails().tssPubKey;
// Assert: preMfaTssPub === postMfaTssPub
```

This is critical because the keypair is tied to the user's vault encryption. If the keypair changed, all encrypted vault data would become inaccessible.

---

## 5. Security Analysis

### 5.1 Pre-MFA: Semi-Custodial Trust Model

In the default state (no MFA enrolled), both factors reside within Web3Auth's infrastructure:

```text
Factor 1: JWT verifier share
  └── Distributed across Web3Auth DKG nodes (Torus network)
      └── Requires threshold of nodes to collude

Factor 2: hashedShare
  └── Stored on Web3Auth metadata server
      └── Controlled by Web3Auth
```

#### Threat: Web3Auth key reconstruction

For Web3Auth to reconstruct a user's key, they would need:

1. **Collusion among DKG nodes** -- The JWT verifier share is split across Web3Auth's Torus node network using Distributed Key Generation. No single node holds the full verifier share. Reconstruction requires a threshold of nodes to cooperate.
2. **Access to the hashedShare** -- Stored on Web3Auth's metadata server infrastructure, which is a separate system from the DKG nodes.

Since Web3Auth operates both the Torus DKG nodes and the metadata server, the trust boundary is within a single organization. A sufficiently motivated (or compromised) Web3Auth could theoretically reconstruct any user's key in the pre-MFA state.

**Mitigating factors:**

- DKG nodes are architecturally separate from the metadata server
- Node operators may be independent entities (depending on network configuration)
- Web3Auth's business model depends on not doing this (reputation risk)
- This is no worse than any OAuth-based key derivation service

**Bottom line:** Pre-MFA accounts have a trust-Web3Auth security model. This is acceptable for onboarding UX but should not be the permanent state for security-conscious users.

### 5.2 Post-MFA: Non-Custodial Trust Model

After `enableMFA()`, the hashedShare is deleted and replaced with user-controlled factors:

```text
Factor 1: JWT verifier share
  └── Web3Auth DKG nodes (threshold required)

Factor 2: Device share
  └── Browser localStorage (user's device only)

Factor 3: Recovery phrase
  └── User's physical backup (24-word mnemonic)

Threshold: 2 of 3
```

**What Web3Auth can access:** Only Factor 1 (the distributed verifier share).

**What Web3Auth cannot access:** Factors 2 and 3, which are entirely outside their infrastructure.

Since the threshold is 2 and Web3Auth controls only 1 factor, they **cannot** reconstruct the key or sign on behalf of the user, even with full collusion across all their systems.

**Remaining attack vectors post-MFA:**

- Device compromise (attacker gets device share from localStorage)
- Physical theft of recovery phrase
- Combined: Web3Auth node collusion + one of the above
- Browser extension/malware extracting the exported key from memory during a session

### 5.3 The manualSync Consideration

Core Kit is configured with `manualSync: true`, meaning state changes (new factors, deleted factors) are not pushed to Web3Auth's servers until `commitChanges()` is called. If `enableMFA()` succeeds but `commitChanges()` fails (network error, browser crash), the account could be in an inconsistent state. CipherBox explicitly calls `commitChanges()` after every mutation and verifies the TSS public key is unchanged.

---

## 6. Cross-Device Approval

When MFA is enabled and a user logs in from a new device (which lacks a device share), Core Kit enters `REQUIRED_SHARE` status. The user must provide a second factor:

### 6.1 Option A: Recovery Phrase

The user enters their 24-word mnemonic, which is converted back to a factor key:

```text
mnemonic → mnemonicToKey() → factorKeyHex → inputFactorKey() → LOGGED_IN
```

After recovery, a new device share is created for the new device.

### 6.2 Option B: Device Approval

An existing authenticated device transfers its factor key to the new device via CipherBox's bulletin board API:

1. New device generates an ephemeral secp256k1 keypair
2. New device posts approval request with ephemeral public key
3. Existing device ECIES-encrypts its factor key with the ephemeral public key
4. New device decrypts the factor key and calls `inputFactorKey()`
5. New device creates its own device share for future logins

The approval request has a 5-minute TTL and uses end-to-end encryption (the CipherBox server only sees the ECIES ciphertext, never the plaintext factor key).

---

## 7. MFA Status Detection

CipherBox determines MFA status from `coreKit.getKeyDetails().totalFactors`:

```typescript
const details = coreKit.getKeyDetails();
const isMfaEnabled = details.totalFactors > 2;
```

**Why `> 2` and not `>= 2`:**

Every account starts with exactly 2 factors (JWT verifier share + hashedShare). The `>= 2` check that was originally in place was always true, causing a false-positive MFA status for every user. After `enableMFA()`, the hashedShare is deleted and replaced with device + recovery factors, pushing `totalFactors` to 3+.

| State                      | totalFactors | threshold | isMfaEnabled |
| -------------------------- | ------------ | --------- | ------------ |
| Fresh account (no MFA)     | 2            | 2         | `false`      |
| After enableMFA()          | 3+           | 2         | `true`       |
| After adding extra devices | 4+           | 2         | `true`       |

---

## 8. Key Files Reference

| File                                               | Purpose                                                                                                                        |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `apps/web/src/lib/web3auth/core-kit.ts`            | Core Kit singleton, network config, `manualSync: true`                                                                         |
| `apps/web/src/lib/web3auth/core-kit-provider.tsx`  | React context provider exposing Core Kit status                                                                                |
| `apps/web/src/lib/web3auth/hooks.ts`               | Login flows (`loginWithJWT`), TSS key export                                                                                   |
| `apps/web/src/hooks/useMfa.ts`                     | MFA operations: `checkMfaStatus`, `enableMfa`, `getFactors`, `deleteFactor`, `recoverWithMnemonic`, `regenerateRecoveryPhrase` |
| `apps/web/src/hooks/useDeviceApproval.ts`          | Cross-device approval flow (ephemeral ECIES key exchange)                                                                      |
| `apps/web/src/stores/mfa.store.ts`                 | Zustand store: `isMfaEnabled`, `factorCount`, `threshold`                                                                      |
| `apps/api/src/auth/services/jwt-issuer.service.ts` | CipherBox JWT issuance for custom verifier (`RS256`, `kid: cipherbox-identity-1`)                                              |

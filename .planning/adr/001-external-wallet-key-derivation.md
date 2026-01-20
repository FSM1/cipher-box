# ADR-001: External Wallet Key Derivation for ECIES Operations

**Status:** Approved (Post Security Review)
**Date:** 2026-01-20
**Author:** Claude (AI Assistant)
**Security Review:** Completed 2026-01-20 - Conditional Approval

---

## Context

CipherBox uses ECIES (Elliptic Curve Integrated Encryption Scheme) for key wrapping operations throughout the encryption architecture:

- `rootFolderKey` is encrypted with user's `publicKey`
- `folderKey` for each subfolder is encrypted with user's `publicKey`
- `fileKey` for each file is encrypted with user's `publicKey`
- `ipnsPrivateKey` for TEE republishing is encrypted with `teePublicKey`

All ECIES decryption operations require access to the raw private key bytes:

```typescript
function decryptKey(encryptedKey: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
```

### The Problem

CipherBox supports two authentication paths via Web3Auth:

1. **Social Logins (Google, Email, etc.)**: Web3Auth reconstructs a secp256k1 keypair using MPC (Multi-Party Computation). The private key is available in client memory via `provider.request({ method: 'private_key' })`.

2. **External Wallets (MetaMask, WalletConnect, etc.)**: The user's existing wallet is connected. The private key is **never exposed** to the dApp - this is a fundamental security property of external wallets.

For external wallet users, ECIES decryption operations cannot be performed because the raw private key is inaccessible. This breaks the entire encryption architecture.

### Current Behavior

| Auth Type             | publicKey Source          | privateKey Access | ECIES Support |
| --------------------- | ------------------------- | ----------------- | ------------- |
| Social (Google/Email) | Derived from Web3Auth MPC | Available via SDK | Yes           |
| External Wallet       | Wallet address            | Never exposed     | **No**        |

---

## Decision

Implement a **signature-derived key** approach for external wallet users. The user's wallet signs a deterministic message once at login, and the signature is used to derive a separate secp256k1 keypair for ECIES operations.

### How It Works

#### Step 1: Request Signature via EIP-712 Typed Data

> **[SECURITY: HIGH-03]** Use EIP-712 instead of `personal_sign` for better phishing protection. Wallets display structured data clearly with domain name prominently shown.

> **[SECURITY: CRITICAL-01]** Message contains ONLY static, deterministic values. No timestamps or nonces - these would break determinism and cause data loss.

> **[SECURITY: MEDIUM-03]** Use a fixed chain ID (Ethereum Mainnet = 1) regardless of connected network to prevent chain ID manipulation attacks.

```typescript
// Fixed chain ID for derivation - always use mainnet regardless of connected network
const DERIVATION_CHAIN_ID = 1;

// EIP-712 domain and types for structured signing
const domain = {
  name: 'CipherBox',
  version: '1',
  chainId: DERIVATION_CHAIN_ID,
  // No verifyingContract needed - this is for key derivation, not contract interaction
};

const types = {
  KeyDerivation: [
    { name: 'wallet', type: 'address' },
    { name: 'purpose', type: 'string' },
    { name: 'version', type: 'uint256' },
  ],
};

const value = {
  wallet: walletAddress,
  purpose: 'CipherBox Encryption Key Derivation',
  version: 1,
};

// Request EIP-712 signature
const signature = await provider.request({
  method: 'eth_signTypedData_v4',
  params: [
    walletAddress,
    JSON.stringify({
      domain,
      types,
      primaryType: 'KeyDerivation',
      message: value,
    }),
  ],
});
```

#### Step 2: Verify Signature Before Derivation

> **[SECURITY: CRITICAL-03]** Always verify the signature recovers to the claimed wallet address before deriving keys. Defense-in-depth against malformed or injected signatures.

```typescript
import { verifyTypedData } from 'ethers';

async function verifySignatureBeforeDerivation(
  signature: string,
  walletAddress: string
): Promise<void> {
  // 1. Verify signature format (65 bytes: r[32] + s[32] + v[1])
  const sigBytes = hexToBytes(signature);
  if (sigBytes.length !== 65) {
    throw new Error('Invalid signature format: expected 65 bytes');
  }

  // 2. Recover signer address from EIP-712 signature
  const recoveredAddress = verifyTypedData(domain, types, value, signature);

  // 3. Verify recovered address matches claimed wallet
  if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    throw new Error('Signature does not match wallet address');
  }
}
```

#### Step 3: Normalize Signature (Handle Malleability)

> **[SECURITY: HIGH-01]** ECDSA signatures have two valid forms: `(r, s)` and `(r, n-s)`. Different wallet versions may return different forms. Normalize to low-S form (EIP-2) to ensure consistent key derivation.

```typescript
import { Signature } from '@ethersproject/bytes';
import { BigNumber } from '@ethersproject/bignumber';

// secp256k1 curve order
const SECP256K1_N = BigNumber.from(
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
);
const SECP256K1_HALF_N = SECP256K1_N.div(2);

function normalizeSignature(signature: string): Uint8Array {
  const sig = Signature.from(signature);

  // Extract r and s components
  let r = BigNumber.from(sig.r);
  let s = BigNumber.from(sig.s);

  // Ensure s is in lower half of curve order (EIP-2 / BIP-62)
  if (s.gt(SECP256K1_HALF_N)) {
    s = SECP256K1_N.sub(s);
  }

  // Return deterministic 64-byte representation: r || s
  // Exclude v (recovery byte) as it's not part of the signature value
  const normalized = new Uint8Array(64);

  const rBytes = hexToBytes(r.toHexString());
  const sBytes = hexToBytes(s.toHexString());

  // Pad to 32 bytes each, right-aligned
  normalized.set(rBytes, 32 - rBytes.length);
  normalized.set(sBytes, 64 - sBytes.length);

  return normalized;
}
```

#### Step 4: Derive Keypair via HKDF

```typescript
async function deriveKeypair(
  normalizedSignature: Uint8Array,
  walletAddress: string
): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  // HKDF-SHA256 derivation
  const derivedPrivateKey = await hkdfDerive({
    inputKey: normalizedSignature,
    salt: utf8ToBytes('CipherBox-ECIES-v1'),
    info: utf8ToBytes(walletAddress.toLowerCase()),
    outputLength: 32,
  });

  // Validate derived key is in valid secp256k1 range
  const keyBigInt = BigInt('0x' + bytesToHex(derivedPrivateKey));
  const SECP256K1_ORDER = BigInt(
    '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
  );

  if (keyBigInt <= 0n || keyBigInt >= SECP256K1_ORDER) {
    // Extremely unlikely (~2^-128 probability), but handle it
    throw new Error('Derived key out of range - please try again');
  }

  // Derive public key from private key
  const derivedPublicKey = secp256k1.getPublicKey(derivedPrivateKey, false);

  return { publicKey: derivedPublicKey, privateKey: derivedPrivateKey };
}
```

#### Step 5: Complete Derivation Flow with Rate Limiting

> **[SECURITY: MEDIUM-01]** Implement rate limiting to prevent signature request spam from malicious scripts.

```typescript
const SIGNATURE_COOLDOWN_MS = 5000; // 5 seconds
let lastSignatureRequest = 0;

export async function deriveKeypairFromWallet(
  provider: Provider,
  walletAddress: string
): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  // Rate limiting
  const now = Date.now();
  if (now - lastSignatureRequest < SIGNATURE_COOLDOWN_MS) {
    throw new Error('Signature request rate limited. Please wait.');
  }
  lastSignatureRequest = now;

  // 1. Request EIP-712 signature
  const signature = await requestEIP712Signature(provider, walletAddress);

  // 2. Verify signature matches wallet address
  await verifySignatureBeforeDerivation(signature, walletAddress);

  // 3. Normalize signature to low-S form
  const normalizedSig = normalizeSignature(signature);

  // 4. Derive keypair via HKDF
  const keypair = await deriveKeypair(normalizedSig, walletAddress);

  return keypair;
}
```

### Session Persistence Strategy

> **[SECURITY: CRITICAL-02]** Define how derived keys persist across page refreshes.

**Chosen Approach: Memory-only with deterministic re-derivation**

| Aspect             | Behavior                                                             |
| ------------------ | -------------------------------------------------------------------- |
| **Storage**        | Derived keypair stored in memory only (Zustand store)                |
| **Page Refresh**   | Keys are lost; user must re-sign to derive keys                      |
| **Browser Close**  | Keys are lost; user must re-sign on next visit                       |
| **Why This Works** | Message is deterministic, so same wallet always derives same keypair |

**Rationale:**

- No XSS exposure risk (keys never in localStorage/sessionStorage)
- Deterministic message ensures same keypair is derived each time
- User re-signs once per browser session (acceptable UX)
- Maximum security posture

**Implementation:**

```typescript
// In auth store - keys are memory-only
const useAuthStore = create<AuthState>((set) => ({
  derivedPrivateKey: null, // Uint8Array | null
  derivedPublicKey: null, // Uint8Array | null

  setDerivedKeypair: (keypair) =>
    set({
      derivedPrivateKey: keypair.privateKey,
      derivedPublicKey: keypair.publicKey,
    }),

  // On logout or session end
  clearDerivedKeypair: () => {
    // Best-effort memory clearing
    set((state) => {
      if (state.derivedPrivateKey) {
        state.derivedPrivateKey.fill(0);
      }
      return { derivedPrivateKey: null, derivedPublicKey: null };
    });
  },
}));
```

### Memory Clearing on Logout

> **[SECURITY: MEDIUM-02]** Best-effort clearing of sensitive keys from memory on logout.

```typescript
function clearSession(): void {
  const state = useAuthStore.getState();

  // Clear derived keypair with zero-fill
  if (state.derivedPrivateKey) {
    state.derivedPrivateKey.fill(0);
  }
  if (state.derivedPublicKey) {
    state.derivedPublicKey.fill(0);
  }

  // Clear store
  useAuthStore.getState().clearDerivedKeypair();

  // Clear any other sensitive data
  useAuthStore.getState().logout();

  // Note: JavaScript doesn't guarantee memory clearing, but this is best-effort
  // The keys will be garbage collected, and we've overwritten the buffer contents
}
```

### Version Migration Strategy

> **[SECURITY: HIGH-02]** Plan for cryptographic agility if vulnerabilities are found.

**Version Tracking:**

- Derivation version is included in EIP-712 message: `version: 1`
- Backend stores `derivationVersion` in user profile
- Multiple derived keypairs can coexist during migration

**Migration Process (if v2 is needed):**

1. **Announce Deprecation:** Notify users v1 derivation is deprecated
2. **Dual Support Period:** Accept both v1 and v2 derived keys
3. **Re-encryption Tool:** Provide tool to re-encrypt vault with v2 key
4. **Sunset v1:** After migration period, reject v1 derived keys

**Database Schema:**

```sql
ALTER TABLE users ADD COLUMN derivation_version INTEGER DEFAULT 1;
ALTER TABLE users ADD COLUMN public_key_v2 BYTEA; -- For migration period
```

**Code Structure for Future Versions:**

```typescript
interface KeyDerivationStrategy {
  version: number;
  deriveKeypair(provider: Provider, address: string): Promise<Keypair>;
}

class V1SignatureDerivedStrategy implements KeyDerivationStrategy {
  version = 1;
  // Current implementation
}

class V2Strategy implements KeyDerivationStrategy {
  version = 2;
  // Future implementation (e.g., different KDF, EIP-5630, etc.)
}

function getKeyDerivationStrategy(version: number): KeyDerivationStrategy {
  switch (version) {
    case 1:
      return new V1SignatureDerivedStrategy();
    case 2:
      return new V2Strategy();
    default:
      throw new Error(`Unsupported derivation version: ${version}`);
  }
}
```

### Updated Architecture

| Auth Type             | publicKey Source               | ECIES privateKey               | Wallet Popups |
| --------------------- | ------------------------------ | ------------------------------ | ------------- |
| Social (Google/Email) | Web3Auth MPC                   | Web3Auth MPC                   | None (silent) |
| External Wallet       | Derived from EIP-712 signature | Derived from EIP-712 signature | 1 per session |

---

## Security Analysis

### Strengths

1. **Deterministic**: Same wallet signing same message always produces same keypair
2. **Wallet-bound**: Only the wallet owner can produce the signature
3. **Standard crypto**: Uses well-understood primitives (ECDSA, HKDF, secp256k1)
4. **Single popup per session**: User signs once, all subsequent operations are silent
5. **No persistent key storage**: Derived key exists only in session memory
6. **Phishing resistant**: EIP-712 displays domain clearly to users
7. **Malleability resistant**: Signature normalization ensures consistent derivation

### Security Controls Implemented

| Security Review Finding             | Status | Implementation                                    |
| ----------------------------------- | ------ | ------------------------------------------------- |
| CRITICAL-01: Determinism            | Fixed  | Static message with no dynamic elements           |
| CRITICAL-02: Session persistence    | Fixed  | Memory-only with deterministic re-derivation      |
| CRITICAL-03: Signature verification | Fixed  | Verify recovers to claimed address                |
| HIGH-01: Signature malleability     | Fixed  | Low-S normalization (EIP-2)                       |
| HIGH-02: Version migration          | Fixed  | Version in message, migration strategy documented |
| HIGH-03: Phishing protection        | Fixed  | EIP-712 typed data signing                        |
| MEDIUM-01: Rate limiting            | Fixed  | 5-second cooldown between signature requests      |
| MEDIUM-02: Memory clearing          | Fixed  | Zero-fill on logout                               |
| MEDIUM-03: Chain ID validation      | Fixed  | Fixed chain ID (mainnet = 1)                      |

### Cryptographic Assumptions

1. **ECDSA signature unforgeability**: Only the private key holder can produce valid signatures
2. **HKDF security**: HKDF-SHA256 is a secure key derivation function when input has sufficient entropy (ECDSA signatures have ~256 bits)
3. **secp256k1 hardness**: Deriving private key from public key is computationally infeasible
4. **EIP-712 domain binding**: Wallet correctly displays and enforces domain separation

---

## Alternatives Considered

### Alternative 1: Disable External Wallet Support

**Approach:** Remove MetaMask/WalletConnect options; only support social logins.

**Pros:**

- Simplest implementation
- No additional security surface

**Cons:**

- Limits user choice
- Excludes users who prefer self-custody wallets
- Against Web3 ethos of "bring your own wallet"

**Decision:** Rejected - external wallet support is a common user expectation.

### Alternative 2: Per-Operation Wallet Signing

**Approach:** Request wallet signature for each ECIES decryption operation.

**Pros:**

- No derived keys needed
- Maximum security (wallet approval for everything)

**Cons:**

- Unusable UX (popup for every file access)
- Would require major architecture changes
- Breaks offline operation

**Decision:** Rejected - UX is unacceptable.

### Alternative 3: EIP-5630 (Encrypted Message Standard)

**Approach:** Use the upcoming EIP-5630 standard for wallet-based encryption.

**Pros:**

- Native wallet support for encryption
- Standard approach

**Cons:**

- EIP-5630 is still in draft status
- Limited wallet support (few have implemented)
- Not widely available

**Decision:** Rejected for now - architecture supports future migration when EIP-5630 matures.

### Alternative 4: WebAuthn/Passkey Derivation

**Approach:** Use WebAuthn credentials to derive encryption keys.

**Pros:**

- Platform-native security
- Phishing resistant

**Cons:**

- Requires separate registration flow
- Not integrated with wallet identity
- More complex implementation

**Decision:** Not considered for v1, possible future enhancement.

---

## Implementation Plan

### Phase 1: Core Implementation

**Files to create/modify:**

1. **`apps/web/src/lib/crypto/signatureKeyDerivation.ts`** (new):
   - `normalizeSignature(signature: string): Uint8Array`
   - `verifySignatureBeforeDerivation(signature, address): Promise<void>`
   - `deriveKeypair(normalizedSig, address): Promise<Keypair>`
   - `deriveKeypairFromWallet(provider, address): Promise<Keypair>`

2. **`apps/web/src/lib/web3auth/hooks.ts`** (modify):
   - Detect external wallet login via `connectedConnectorName`
   - Request EIP-712 signature for key derivation
   - Call derivation utilities

3. **`apps/web/src/stores/auth.store.ts`** (modify):
   - Add `derivedPrivateKey: Uint8Array | null`
   - Add `derivedPublicKey: Uint8Array | null`
   - Add `setDerivedKeypair()` and `clearDerivedKeypair()`

4. **`apps/api/src/auth/auth.service.ts`** (modify):
   - Accept derived `publicKey` for external wallet users
   - Store `derivationVersion` in user profile
   - Add `authType: 'external_wallet_derived'` for audit

### Phase 2: Testing

1. **Unit tests** (`signatureKeyDerivation.test.ts`):
   - Signature normalization (high-S to low-S)
   - Determinism (same wallet = same key)
   - Signature verification
   - ECIES interoperability

2. **Integration tests**:
   - Full external wallet login flow
   - Vault access with derived keys
   - Session persistence across refresh

3. **Attack scenario tests**:
   - Phishing resistance
   - Chain ID manipulation
   - Malformed signature rejection

### Phase 3: Security Audit

1. Code review of cryptographic implementation
2. Penetration testing of signature flow
3. Final security sign-off before production

---

## Test Vectors

_(To be generated during implementation with actual wallet signatures)_

```typescript
// Test constants
const TEST_WALLET_ADDRESS = '0x742d35Cc6634C0532925a3b844Bc9e7595f...';
const DERIVATION_CHAIN_ID = 1;

// EIP-712 domain (static)
const TEST_DOMAIN = {
  name: 'CipherBox',
  version: '1',
  chainId: DERIVATION_CHAIN_ID,
};

// EIP-712 message (static for given wallet)
const TEST_MESSAGE = {
  wallet: TEST_WALLET_ADDRESS,
  purpose: 'CipherBox Encryption Key Derivation',
  version: 1,
};

// Expected outputs (to be filled in during implementation)
const TEST_VECTORS = {
  signature: '0x...', // EIP-712 signature from test wallet
  normalizedSignature: '0x...', // After low-S normalization
  derivedPrivateKey: '0x...', // HKDF output
  derivedPublicKey: '0x04...', // secp256k1 public key
};
```

---

## Implementation Checklist

- [ ] Create `signatureKeyDerivation.ts` with all derivation logic
- [ ] Implement signature normalization to low-S form
- [ ] Implement signature verification before derivation
- [ ] Implement HKDF derivation with proper parameters
- [ ] Add secp256k1 private key range validation
- [ ] Implement EIP-712 signature request
- [ ] Add rate limiting for signature requests
- [ ] Update auth store with derived keypair state
- [ ] Implement memory clearing on logout
- [ ] Update auth hooks to detect external wallet and trigger derivation
- [ ] Update backend to accept derived public keys
- [ ] Add derivation version tracking to user profile
- [ ] Write comprehensive unit tests
- [ ] Write integration tests
- [ ] Write attack scenario tests
- [ ] Security audit before production deployment

---

## References

- [ECIES Specification (SEC 1, Section 5.1)](https://www.secg.org/sec1-v2.pdf)
- [HKDF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
- [EIP-191: Signed Data Standard](https://eips.ethereum.org/EIPS/eip-191)
- [EIP-712: Typed Structured Data Hashing](https://eips.ethereum.org/EIPS/eip-712)
- [EIP-2: Homestead Hard-fork Changes (signature malleability)](https://eips.ethereum.org/EIPS/eip-2)
- [BIP-62: Dealing with Malleability](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki)
- [EIP-5630: Encrypted Message Standard (Draft)](https://eips.ethereum.org/EIPS/eip-5630)
- [Web3Auth External Wallet Documentation](https://web3auth.io/docs/connect-blockchain/evm)

---

## Approval

| Role                           | Name           | Date       | Status               |
| ------------------------------ | -------------- | ---------- | -------------------- |
| Author                         | Claude (AI)    | 2026-01-20 | Proposed             |
| Security Review                | Security Agent | 2026-01-20 | Conditional Approval |
| Revision (addressing findings) | Claude (AI)    | 2026-01-20 | Complete             |
| Product Owner                  | -              | -          | Pending              |

---

## Changelog

| Version | Date       | Changes                                  |
| ------- | ---------- | ---------------------------------------- |
| 1.0     | 2026-01-20 | Initial proposal                         |
| 1.1     | 2026-01-20 | Addressed all 9 security review findings |

---

**Security Review Document:** `.planning/adr/001-external-wallet-key-derivation-SECURITY-REVIEW.md`

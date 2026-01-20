# Security Review: ADR-001 External Wallet Key Derivation

**Review Date:** 2026-01-20
**Reviewer:** Security Agent (Cryptography Specialist)
**ADR Version:** Proposed (2026-01-20)
**Review Status:** NEEDS CHANGES

---

## Executive Summary

**Overall Assessment:** CONDITIONAL APPROVAL WITH REQUIRED CHANGES

The signature-derived key approach for external wallet users is **fundamentally sound** from a cryptographic perspective. ECDSA signatures provide sufficient entropy for key derivation, and HKDF-SHA256 is an appropriate KDF for this use case. However, several **critical and high-priority issues** must be addressed before implementation.

| Category                | Status          | Issues Found         |
| ----------------------- | --------------- | -------------------- |
| Core Cryptography       | PASS            | 0 Critical           |
| Signature Handling      | NEEDS WORK      | 2 Critical, 1 High   |
| Message Format          | NEEDS WORK      | 1 Critical, 2 Medium |
| Implementation Security | NEEDS WORK      | 2 High               |
| Key Management          | PASS WITH NOTES | 1 Medium             |

---

## Critical Issues

### [CRITICAL-01] Determinism Broken by Timestamp/Nonce in Derivation Message

**Location:** ADR Section "How It Works", Step 1

**Code:**

```typescript
const derivationMessage = `CipherBox Key Derivation v1

This signature creates your encryption key for CipherBox.

- Your wallet is NOT signing a transaction
- No funds will be moved
- This creates a deterministic encryption key

Chain ID: ${chainId}
Timestamp: ${Date.now()}
Nonce: ${randomNonce}`;
```

**Issue:**
The stated goal is deterministic key derivation: "Same message + same wallet = same signature = same derived keypair". However, the message includes `Date.now()` and `randomNonce`, which change on every login. This **completely breaks determinism** - the user will derive a different keypair on every login, losing access to their encrypted vault.

**Impact:**

- User logs in Monday, encrypts files with keypair A
- User logs in Tuesday, derives keypair B (different timestamp/nonce)
- User cannot decrypt any files - vault is permanently inaccessible
- This is a **data loss vulnerability** affecting 100% of external wallet users

**Recommendation:**
Remove dynamic elements from the derivation message. Use only static, deterministic values:

```typescript
const derivationMessage = `CipherBox Key Derivation v1

This signature creates your encryption key for CipherBox.
Sign this message to access your encrypted vault.

Domain: cipherbox.io
Wallet: ${walletAddress}
Chain ID: ${chainId}
Version: 1`;
```

**Note:** If anti-replay protection is needed for the signature itself (not the derived key), implement it at the authentication layer, not the derivation layer. See CRITICAL-02.

---

### [CRITICAL-02] Missing Signature Storage/Caching for Session Persistence

**Location:** ADR Section "How It Works"

**Issue:**
The ADR states the signature is requested "once at login" but does not specify how the derived keypair persists across browser refreshes or tab closures within a session. If the signature must be requested again after each page refresh, users will face:

1. Constant wallet popups (poor UX)
2. Potential message variance if the message format changes

**Impact:**

- UX degradation with repeated wallet popups
- Session state management complexity

**Recommendation:**
Explicitly document the session persistence strategy:

```typescript
// Option A: Store derived keypair in sessionStorage (encrypted)
// - Cleared on browser close
// - Survives page refreshes
// - Risk: XSS exposure of session keys

// Option B: Store derived keypair in memory only
// - Lost on refresh, but signature message is deterministic
// - User re-signs on each session start
// - More secure but requires deterministic message (see CRITICAL-01)

// Recommended: Option B with deterministic message
// User signs once per browser session (new tab/window = new session)
```

---

### [CRITICAL-03] No Signature Verification Before Key Derivation

**Location:** ADR Section "Security Analysis - Questions for Security Review" #4

**Issue:**
The ADR asks: "Should we implement signature verification before deriving the key?" The answer is **YES, absolutely**. Without verification, an attacker who obtains any valid-looking 65-byte string could potentially inject it as a "signature" and derive keys from it.

While the Web3 provider should return valid signatures, defense-in-depth requires verification:

1. Verify the signature is syntactically valid (r, s, v components)
2. Verify the signature recovers to the claimed wallet address
3. Only then proceed with key derivation

**Impact:**

- Without verification, malformed or injected signatures could be used
- In edge cases (corrupted provider, malicious extension), invalid signatures could be processed

**Recommendation:**

```typescript
async function deriveKeypairFromSignature(
  signature: string,
  message: string,
  expectedAddress: string
): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  // 1. Verify signature format
  if (!isValidSignatureFormat(signature)) {
    throw new Error('Invalid signature format');
  }

  // 2. Recover signer address and verify
  const recoveredAddress = ethers.verifyMessage(message, signature);
  if (recoveredAddress.toLowerCase() !== expectedAddress.toLowerCase()) {
    throw new Error('Signature does not match wallet address');
  }

  // 3. Normalize signature (handle malleability)
  const normalizedSig = normalizeSignature(signature);

  // 4. Derive keypair
  return hkdfDerive(normalizedSig, expectedAddress);
}
```

---

## High Priority Issues

### [HIGH-01] Incomplete Signature Malleability Handling

**Location:** ADR Section "Security Analysis - Potential Concerns"

**Code (proposed):**

```typescript
const derivedPrivateKey = await hkdfDerive({
  inputKey: hexToBytes(signature),
  salt: utf8ToBytes('CipherBox-ECIES-v1'),
  info: utf8ToBytes(walletAddress),
  outputLength: 32,
});
```

**Issue:**
The ADR mentions EIP-2 signature normalization but does not provide implementation details. ECDSA signatures have two valid forms: `(r, s)` and `(r, n-s)` where `n` is the curve order. Different wallets may return different forms for the same signing operation.

If not normalized before HKDF, the same user with the same wallet could derive different keys depending on:

- Wallet software version
- Browser extension updates
- Hardware wallet firmware

**Impact:**

- Intermittent key derivation failures
- User may be locked out of vault after wallet update

**Recommendation:**
Implement explicit signature normalization to low-S form (EIP-2 compliant):

```typescript
import { Signature } from '@ethersproject/bytes';
import { BigNumber } from '@ethersproject/bignumber';

const SECP256K1_N = BigNumber.from(
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
);
const SECP256K1_HALF_N = SECP256K1_N.div(2);

function normalizeSignature(signature: string): Uint8Array {
  const sig = Signature.from(signature);

  // Ensure s is in lower half of curve order (EIP-2)
  let s = BigNumber.from(sig.s);
  if (s.gt(SECP256K1_HALF_N)) {
    s = SECP256K1_N.sub(s);
  }

  // Return deterministic byte representation: r || s (64 bytes)
  // Exclude v (recovery byte) as it's not part of the signature value
  const rBytes = arrayify(sig.r, { allowMissingPrefix: true });
  const sBytes = arrayify(s, { allowMissingPrefix: true });

  // Pad to 32 bytes each
  const normalized = new Uint8Array(64);
  normalized.set(rBytes.slice(-32), 32 - rBytes.length);
  normalized.set(sBytes.slice(-32), 64 - sBytes.length);

  return normalized;
}
```

---

### [HIGH-02] HKDF Salt Should Include Version for Future Migration

**Location:** ADR Section "How It Works", Step 2

**Code:**

```typescript
const derivedPrivateKey = await hkdfDerive({
  inputKey: hexToBytes(signature),
  salt: utf8ToBytes('CipherBox-ECIES-v1'),
  info: utf8ToBytes(walletAddress),
  outputLength: 32,
});
```

**Issue:**
The salt `'CipherBox-ECIES-v1'` is good for domain separation, but the ADR does not specify:

1. What happens if v2 derivation is needed (security vulnerability found, algorithm upgrade)
2. How users would migrate between versions
3. Whether multiple derived keypairs can coexist

**Impact:**

- No path for cryptographic agility
- If vulnerability found in derivation, all users must create new vaults

**Recommendation:**

1. Document the version migration strategy:
   - Store `derivationVersion` in user profile on backend
   - Support multiple active keypairs during migration period
   - Provide re-encryption tool for vault migration

2. Consider including version in the signed message itself:

```typescript
const derivationMessage = `CipherBox Key Derivation

Domain: cipherbox.io
Wallet: ${walletAddress}
Chain ID: ${chainId}
Derivation Version: 1`;
```

This allows future versions to prompt users for new signature without breaking existing vaults.

---

### [HIGH-03] Phishing Vector: Clear But Insufficient Message Warning

**Location:** ADR Section "How It Works", Step 1

**Issue:**
The derivation message attempts to warn users, but sophisticated phishing attacks could:

1. Create a site at `cipherb0x.io` (zero instead of 'o')
2. Request the exact same signature message
3. Derive the user's CipherBox keypair
4. Access the user's vault on the real CipherBox

The message does not include the requesting domain in a way that wallets highlight.

**Impact:**

- Phishing sites can harvest encryption keys
- Users may not notice domain differences
- Full vault compromise possible

**Recommendation:**
Use EIP-712 structured data signing instead of `personal_sign`:

```typescript
const domain = {
  name: 'CipherBox',
  version: '1',
  chainId: chainId,
  verifyingContract: '0x0000000000000000000000000000000000000000', // No contract, but required
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

const signature = await provider.request({
  method: 'eth_signTypedData_v4',
  params: [walletAddress, JSON.stringify({ domain, types, primaryType: 'KeyDerivation', value })],
});
```

**Benefits of EIP-712:**

- Wallets display structured data clearly
- Domain name is prominently shown
- Harder to social-engineer users
- Standard format recognized by security-conscious users

---

## Medium Priority Issues

### [MEDIUM-01] Missing Rate Limiting Consideration

**Location:** Implementation Plan

**Issue:**
The ADR does not address rate limiting for signature requests. A malicious script on the page could repeatedly request signatures, potentially:

1. Annoying users with popup spam
2. Attempting timing attacks on signature generation
3. Exhausting hardware wallet resources

**Recommendation:**
Implement client-side rate limiting:

```typescript
const SIGNATURE_COOLDOWN_MS = 5000; // 5 seconds
let lastSignatureRequest = 0;

async function requestDerivationSignature(): Promise<string> {
  const now = Date.now();
  if (now - lastSignatureRequest < SIGNATURE_COOLDOWN_MS) {
    throw new Error('Signature request rate limited');
  }
  lastSignatureRequest = now;
  // ... proceed with signature request
}
```

---

### [MEDIUM-02] No Explicit Memory Clearing for Derived Private Key

**Location:** ADR Section "Security Analysis - Strengths" #5

**Issue:**
The ADR states "No key storage: Derived key exists only in session memory" but does not specify memory clearing on logout. JavaScript has limited control over memory, but best-effort clearing should be documented.

**Recommendation:**
Document explicit clearing procedure:

```typescript
function clearSession(): void {
  // Clear derived keypair
  if (derivedPrivateKey) {
    derivedPrivateKey.fill(0);
    derivedPrivateKey = null;
  }

  // Clear any cached signatures
  if (cachedSignature) {
    // Strings are immutable in JS, but we can dereference
    cachedSignature = null;
  }

  // Force garbage collection hint (not guaranteed)
  if (typeof gc === 'function') {
    gc();
  }
}
```

---

### [MEDIUM-03] Chain ID Validation Missing

**Location:** ADR Section "How It Works", Step 1

**Issue:**
The derivation message includes `chainId` but there's no validation that the chain ID is expected. An attacker controlling the provider could return a different chain ID, resulting in a different derived key.

**Recommendation:**

1. Validate chain ID against expected value before signing
2. Consider making chain ID a constant (e.g., always use Ethereum Mainnet = 1) regardless of connected network

```typescript
const DERIVATION_CHAIN_ID = 1; // Always use mainnet for derivation

// Verify provider is on expected network OR ignore provider's chain
const derivationMessage = `...
Chain ID: ${DERIVATION_CHAIN_ID}
...`;
```

---

## Security Analysis: Cryptographic Foundations

### HKDF Usage Assessment: APPROVED

The proposed HKDF-SHA256 usage is cryptographically sound:

| Property           | Analysis                                                                                                               |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| **Input entropy**  | ECDSA signatures on secp256k1 contain ~256 bits of entropy from the ephemeral k value. This exceeds HKDF requirements. |
| **Salt selection** | `'CipherBox-ECIES-v1'` provides domain separation. Acceptable.                                                         |
| **Info parameter** | `walletAddress` binds output to specific user. Good practice.                                                          |
| **Output length**  | 32 bytes for secp256k1 private key. Correct.                                                                           |

**Verification:**
Per RFC 5869, HKDF is secure when:

- Input keying material has sufficient entropy (satisfied: ECDSA sig ~256 bits)
- Salt provides domain separation (satisfied)
- Output length <= 255 _ HashLen (satisfied: 32 <= 255 _ 32)

### secp256k1 Private Key Derivation: APPROVED WITH NOTE

The derived 32-byte value may need range validation:

```typescript
const SECP256K1_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

function validatePrivateKey(key: Uint8Array): boolean {
  const keyBigInt = BigInt('0x' + bytesToHex(key));
  return keyBigInt > 0n && keyBigInt < SECP256K1_ORDER;
}

// In derivation:
let derivedKey = await hkdfDerive(...);
while (!validatePrivateKey(derivedKey)) {
  // Extremely unlikely (~2^-128 probability), but handle it
  derivedKey = await hkdfDerive({
    ...params,
    info: utf8ToBytes(walletAddress + ':retry')
  });
}
```

---

## Alternatives Analysis

### Alternative 3 (EIP-5630) Reassessment

The ADR correctly notes EIP-5630 is draft status. However, for future-proofing:

**Recommendation:** Implement signature-derived keys now, but architect the code to allow EIP-5630 integration later:

```typescript
interface KeyDerivationStrategy {
  deriveKeypair(provider: Provider, address: string): Promise<Keypair>;
}

class SignatureDerivedStrategy implements KeyDerivationStrategy {
  // Current implementation
}

class EIP5630Strategy implements KeyDerivationStrategy {
  // Future implementation when wallets support it
}

// Factory selects strategy based on wallet capabilities
function getKeyDerivationStrategy(provider: Provider): KeyDerivationStrategy {
  if (supportsEIP5630(provider)) {
    return new EIP5630Strategy();
  }
  return new SignatureDerivedStrategy();
}
```

---

## Test Cases to Implement

### Unit Tests

```typescript
describe('Signature-Derived Key Security', () => {
  describe('Signature Normalization', () => {
    it('normalizes high-S signatures to low-S form', async () => {
      const highS = '0x...'; // Known high-S signature
      const normalized = normalizeSignature(highS);
      const s = BigNumber.from(normalized.slice(32));
      expect(s.lte(SECP256K1_HALF_N)).toBe(true);
    });

    it('produces identical keys from high-S and low-S forms', async () => {
      const highS = '0x...';
      const lowS = '0x...'; // Same signature, different S form

      const key1 = await deriveKeypair(highS, address);
      const key2 = await deriveKeypair(lowS, address);

      expect(key1.privateKey).toEqual(key2.privateKey);
    });

    it('rejects invalid signature formats', async () => {
      await expect(deriveKeypair('0xinvalid', address)).rejects.toThrow('Invalid signature format');
    });
  });

  describe('Determinism', () => {
    it('derives identical keypair from same wallet and message', async () => {
      const key1 = await deriveFromWallet(wallet, message);
      const key2 = await deriveFromWallet(wallet, message);

      expect(key1.publicKey).toEqual(key2.publicKey);
      expect(key1.privateKey).toEqual(key2.privateKey);
    });

    it('derives different keypair for different wallets', async () => {
      const key1 = await deriveFromWallet(wallet1, message);
      const key2 = await deriveFromWallet(wallet2, message);

      expect(key1.publicKey).not.toEqual(key2.publicKey);
    });
  });

  describe('Signature Verification', () => {
    it('rejects signature from wrong address', async () => {
      const signature = await wallet1.signMessage(message);

      await expect(deriveKeypair(signature, message, wallet2.address)).rejects.toThrow(
        'Signature does not match wallet address'
      );
    });

    it('verifies signature before derivation', async () => {
      const validSig = await wallet.signMessage(message);
      const key = await deriveKeypair(validSig, message, wallet.address);

      expect(key).toBeDefined();
    });
  });

  describe('ECIES Interoperability', () => {
    it('derived keypair works with ECIES encryption', async () => {
      const { publicKey, privateKey } = await deriveFromWallet(wallet, message);
      const plaintext = new TextEncoder().encode('secret');

      const ciphertext = await eciesEncrypt(plaintext, publicKey);
      const decrypted = await eciesDecrypt(ciphertext, privateKey);

      expect(decrypted).toEqual(plaintext);
    });

    it('derived keypair is compatible with existing vault keys', async () => {
      // Test that keys encrypted with derived publicKey can be decrypted
      const { publicKey, privateKey } = await deriveFromWallet(wallet, message);
      const fileKey = crypto.getRandomValues(new Uint8Array(32));

      const wrappedKey = await eciesEncrypt(fileKey, publicKey);
      const unwrappedKey = await eciesDecrypt(wrappedKey, privateKey);

      expect(unwrappedKey).toEqual(fileKey);
    });
  });
});
```

### Integration Tests

```typescript
describe('External Wallet Login Flow', () => {
  it('completes full login and vault access', async () => {
    // 1. Connect wallet
    const { address } = await connectMetaMask();

    // 2. Request derivation signature (should show popup)
    const signature = await requestDerivationSignature(address);

    // 3. Derive keypair
    const { publicKey, privateKey } = await deriveKeypair(signature, message, address);

    // 4. Authenticate with backend
    const { accessToken, vault } = await login(publicKey);

    // 5. Decrypt vault
    const rootFolderKey = await eciesDecrypt(vault.encryptedRootFolderKey, privateKey);

    expect(rootFolderKey).toHaveLength(32);
  });

  it('maintains vault access across page refresh with deterministic derivation', async () => {
    // First session
    const { publicKey: pk1 } = await loginWithExternalWallet();
    await uploadFile('test.txt', 'content');

    // Simulate page refresh (clear memory)
    clearSession();

    // Second session
    const { publicKey: pk2 } = await loginWithExternalWallet();

    // Same keypair should be derived
    expect(pk2).toEqual(pk1);

    // File should be accessible
    const content = await downloadFile('test.txt');
    expect(content).toBe('content');
  });
});
```

### Attack Scenario Tests

```typescript
describe('Attack Scenarios', () => {
  it('detects phishing site signature request (via domain mismatch)', async () => {
    // Using EIP-712, wallet should display domain clearly
    // This test verifies our code includes proper domain binding
    const message = buildDerivationMessage(address);
    expect(message).toContain('Domain: cipherbox.io');
  });

  it('prevents signature replay from different chain', async () => {
    const sigChain1 = await signOnChain(1);
    const sigChain137 = await signOnChain(137);

    // Different chain IDs should produce different keys
    const key1 = await deriveKeypair(sigChain1, address);
    const key2 = await deriveKeypair(sigChain137, address);

    expect(key1.privateKey).not.toEqual(key2.privateKey);
  });

  it('handles malicious provider returning wrong chain ID', async () => {
    const maliciousProvider = createMockProvider({ chainId: 999 });

    // Should use hardcoded derivation chain ID, not provider's
    const key = await deriveFromWallet(maliciousProvider, address);

    // Verify derivation used expected chain ID
    expect(getLastDerivationMessage()).toContain('Chain ID: 1');
  });
});
```

---

## Recommendations Summary

### Required Before Implementation (Blocking)

1. **Fix determinism issue** (CRITICAL-01): Remove timestamp and nonce from derivation message
2. **Add signature verification** (CRITICAL-03): Verify signature recovers to claimed address before derivation
3. **Implement signature normalization** (HIGH-01): Normalize to low-S form for consistent derivation
4. **Document session persistence** (CRITICAL-02): Clarify how derived keys survive page refresh

### Recommended Improvements (Non-Blocking)

5. **Use EIP-712 instead of personal_sign** (HIGH-03): Better phishing protection
6. **Document version migration strategy** (HIGH-02): Plan for cryptographic agility
7. **Add rate limiting** (MEDIUM-01): Prevent signature request spam
8. **Document memory clearing** (MEDIUM-02): Best-effort key clearing on logout
9. **Validate/fix chain ID handling** (MEDIUM-03): Prevent chain ID manipulation

### Implementation Checklist

- [ ] Remove dynamic elements from derivation message
- [ ] Implement signature normalization function
- [ ] Add signature verification before derivation
- [ ] Implement HKDF derivation with proper parameters
- [ ] Add secp256k1 private key range validation
- [ ] Consider EIP-712 for phishing resistance
- [ ] Document session persistence strategy
- [ ] Implement memory clearing on logout
- [ ] Add comprehensive test coverage
- [ ] Security audit before production deployment

---

## Conclusion

The signature-derived key approach is a **viable solution** for enabling ECIES operations with external wallets. The core cryptographic primitives (ECDSA, HKDF, secp256k1) are well-chosen and appropriate for this use case.

However, the current ADR has a **critical flaw** (CRITICAL-01) that would cause complete data loss for users. This must be fixed before implementation. With the recommended changes, this approach provides a reasonable security/UX balance for external wallet users.

**Conditional Approval:** Approved for implementation after addressing CRITICAL-01, CRITICAL-02, CRITICAL-03, and HIGH-01.

---

**Reviewer:** Security Agent
**Next Review:** After implementation, before production deployment

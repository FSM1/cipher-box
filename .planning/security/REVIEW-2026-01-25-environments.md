# Security Review: Environment Architecture

**Document Reviewed:** `.planning/ENVIRONMENTS.md`
**Review Date:** 2026-01-25
**Reviewer:** Security Analysis Agent
**Overall Assessment:** **APPROVED WITH CONCERNS**

---

## Executive Summary

The environment architecture document proposes a well-considered approach to solving IPNS sequence number conflicts across environments. The core cryptographic design is sound, but there are several security concerns that should be addressed before implementation.

**Key Strengths:**
- Environment salt in IPNS key derivation is cryptographically correct
- TEE key epoch rotation with grace period is reasonable
- Separation of encryption keys from IPNS keys is a good architectural decision

**Primary Concerns:**
- Incomplete HKDF implementation details (salt vs info parameter usage)
- Cross-environment data accessibility creates unintentional attack surface
- Mock service security implications need explicit documentation

---

## Findings

### 1. [MEDIUM] HKDF Parameter Confusion: Salt vs Info String

**Location:** `.planning/ENVIRONMENTS.md:61-64`

**Code:**
```typescript
const salt = ENVIRONMENT_SALTS[environment];
// HKDF-SHA256 with environment-specific salt
const info = `${salt}:${folderId}`;
// ... derivation logic
```

**Issue:**
The document conflates HKDF terminology. The variable is named `salt` but is used to construct the `info` parameter. In HKDF (RFC 5869):
- **Salt:** Should be random or fixed per application; provides domain separation at the extract phase
- **Info:** Provides context binding at the expand phase; appropriate for environment/folderId

The current existing implementation at `/home/user/cipher-box/packages/crypto/src/keys/derive.ts` uses a fixed salt (`CipherBox-v1`) and passes context via info, which is correct.

**Impact:**
If implemented as written with the environment string as the actual HKDF salt (not info), security is not reduced, but it deviates from the established pattern in the codebase and RFC best practices. The primary risk is maintenance confusion.

**Recommendation:**
Clarify the implementation to match existing patterns:
```typescript
// packages/crypto/src/ipns.ts
const HKDF_SALT = new TextEncoder().encode('CipherBox-IPNS-v1');

const ENVIRONMENT_PREFIXES = {
  local: 'env:local',
  ci: 'env:ci',
  staging: 'env:staging',
  production: 'env:production',
} as const;

export async function deriveIpnsKeypair(
  userSecp256k1PrivateKey: Uint8Array,
  folderId: string,
  environment: Environment
): Promise<Ed25519Keypair> {
  // Info string provides context binding (environment + folder)
  const info = new TextEncoder().encode(
    `${ENVIRONMENT_PREFIXES[environment]}:folder:${folderId}`
  );

  const seed = await deriveKey({
    inputKey: userSecp256k1PrivateKey,
    salt: HKDF_SALT,  // Fixed application salt
    info: info,       // Variable context
    outputLength: 32,
  });

  // Use derived seed for Ed25519 keypair generation
  return ed25519KeypairFromSeed(seed);
}
```

**References:**
- RFC 5869 Section 3.1 (HKDF parameter recommendations)

**Status:** Open

---

### 2. [MEDIUM] Architectural Change: Random vs Derived IPNS Keys

**Location:** `.planning/ENVIRONMENTS.md:56-65`

**Current Implementation:** `/home/user/cipher-box/packages/crypto/src/ed25519/keygen.ts:30-38`
```typescript
export function generateEd25519Keypair(): Ed25519Keypair {
  const privateKey = ed.utils.randomPrivateKey();  // Random generation
  const publicKey = ed.getPublicKey(privateKey);
  return { publicKey, privateKey };
}
```

**Proposed Change:**
```typescript
// Derive from secp256k1 key + environment + folderId
const info = `${salt}:${folderId}`;
```

**Issue:**
The document proposes a significant change from random key generation to deterministic derivation from the user's secp256k1 key. This is a valid approach, but:

1. **Key binding:** Derived IPNS keys become permanently bound to the user's Web3Auth identity. If Web3Auth ever changes the derived secp256k1 key (e.g., during devnet resets), all IPNS keys become orphaned with no recovery path.

2. **Migration complexity:** Existing vaults use randomly generated IPNS keys stored encrypted. The migration path is not documented.

3. **Cross-curve derivation:** Deriving Ed25519 keys from secp256k1 private keys is cryptographically sound when using HKDF, but the security margin depends on the entropy of the source key.

**Impact:**
- If Web3Auth devnet resets user identity (acknowledged in document), IPNS records become permanently inaccessible
- Existing vaults would need migration or parallel support

**Recommendation:**
1. Document the migration path for existing vaults
2. Add explicit error handling for Web3Auth identity changes
3. Consider storing a "key derivation version" flag to support future algorithm changes:
```typescript
interface IpnsKeyDerivation {
  version: 1;  // Increment if algorithm changes
  environment: Environment;
  folderId: string;
}
```

**Status:** Open

---

### 3. [LOW] Cross-Environment Data Accessibility

**Location:** `.planning/ENVIRONMENTS.md:37-39`

**Design:**
```markdown
This means:
- Same user can encrypt/decrypt files across environments (if CIDs are known)
- Different IPNS namespaces per environment → no sequence conflicts
```

**Issue:**
While this is presented as a feature, it creates an unintentional attack surface:

1. **CID Leakage:** If an attacker obtains a CID from the CI environment (e.g., from logs, test output, or CI artifacts), they could potentially access that encrypted content in production if the user uses the same Web3Auth identity.

2. **Test Data in Production:** Encrypted test data created in CI could be decrypted in production. If test data contains sensitive patterns or known plaintexts, this could aid cryptanalysis.

**Impact:**
Low - requires multiple preconditions (CID knowledge + same user identity across environments), but worth documenting as a known property.

**Recommendation:**
1. Explicitly document this as a known security property in the architecture
2. Add guidance to use different test accounts for CI vs production
3. Consider adding an optional "environment binding" to encryption metadata in future versions:
```typescript
// Future consideration: environment-bound encryption
interface EncryptionMetadata {
  version: number;
  environment?: string;  // Optional environment binding for additional isolation
}
```

**Status:** Open - Document as known property

---

### 4. [LOW] Mock IPNS Routing Service Security

**Location:** `.planning/ENVIRONMENTS.md:199-210`

**Code:**
```typescript
beforeAll(async () => {
  // Reset mock IPNS routing for clean slate
  await fetch('http://localhost:3001/reset', { method: 'POST' });
});
```

**Issue:**
The mock IPNS routing service exposes a `/reset` endpoint with no authentication. While this is appropriate for local/CI use, the document should explicitly state:

1. This endpoint must never exist in staging/production
2. The mock service must validate it is not being used with real delegated routing

**Impact:**
If mock service code is accidentally deployed or the reset endpoint is exposed, all IPNS records could be wiped.

**Recommendation:**
Add explicit safeguards in the mock service:
```typescript
// tools/mock-ipns-routing/src/index.ts
app.post('/reset', (req, res) => {
  // Safety check: only allow reset in local/CI environments
  const env = process.env.CIPHERBOX_ENVIRONMENT;
  if (env !== 'local' && env !== 'ci') {
    return res.status(403).json({
      error: 'Reset endpoint disabled outside local/CI environments'
    });
  }
  // ... reset logic
});
```

**Status:** Open

---

### 5. [INFO] TEE Key Epoch Rotation Design

**Location:** `.planning/ENVIRONMENTS.md:474-476`

**Configuration:**
```bash
TEE_REPUBLISH_INTERVAL_HOURS=3
TEE_KEY_EPOCH_ROTATION_WEEKS=4
```

**Analysis:**
The 4-week epoch rotation with grace period is reasonable. Key observations:

**Strengths:**
- 3-hour republish interval is well within 24-hour IPNS TTL (8x safety margin)
- 4-week rotation balances security with operational complexity
- Grace period allows for migration without service disruption

**Considerations:**
- Document does not specify grace period duration (should be >= 1 republish cycle, ideally 1 week)
- Key epoch mismatch handling is not detailed (what happens if client sends old epoch?)

**Recommendation:**
Add explicit handling for epoch transitions:
```typescript
// API should accept:
// - Current epoch: normal processing
// - Previous epoch (within grace): re-encrypt with new epoch key, update record
// - Older epochs: reject with error instructing client to fetch new TEE public key
```

**Status:** Open - Clarify in implementation

---

### 6. [INFO] Web3Auth Devnet Shared Identity Risk

**Location:** `.planning/ENVIRONMENTS.md:303-308`

**Design:**
```markdown
1. **cipherbox-dev** (Sapphire Devnet)
   - Used for: Local dev, CI, Staging
```

**Analysis:**
Sharing Sapphire Devnet across local/CI/staging means:
- Test account actions in CI affect staging state
- Devnet resets could invalidate staging data
- IPNS key derivation isolation mitigates sequence conflicts but not identity issues

The document acknowledges this risk but does not provide mitigation:
```markdown
1. **Web3Auth Testnet Instability**
   - Sapphire Devnet may reset or have unstable user IDs
   - User keypairs could change unexpectedly
   - This orphans IPNS records (old keys, no one to republish)
```

**Recommendation:**
Consider using separate Web3Auth projects for staging (if budget allows):
```
local/CI: cipherbox-dev (Sapphire Devnet) - ephemeral testing
staging: cipherbox-staging (Sapphire Devnet) - stable testing, separate project
production: cipherbox-prod (Sapphire Mainnet) - production
```

Alternatively, document the risk explicitly and add monitoring for identity stability.

**Status:** Open - Evaluate budget for separate staging project

---

### 7. [INFO] JWT_SECRET Placeholder in Local Config

**Location:** `.planning/ENVIRONMENTS.md:153`

**Code:**
```bash
JWT_SECRET=local-dev-jwt-secret-change-in-production
```

**Analysis:**
Using a hardcoded JWT secret for local development is acceptable, but the placeholder could be stronger and the warning more prominent.

**Recommendation:**
Use a format that is obviously invalid for production:
```bash
JWT_SECRET=INSECURE_LOCAL_DEV_ONLY_DO_NOT_USE_IN_PRODUCTION_xxxxxxxxxxxxxxxx
```

**Status:** Open - Minor improvement

---

## Test Case Recommendations

Based on this review, the following security test cases should be implemented:

```typescript
describe('Environment Key Derivation Security Tests', () => {
  describe('IPNS Key Isolation', () => {
    it('should derive different IPNS keys for same user in different environments', async () => {
      const userKey = await generateTestUserKey();
      const folderId = 'test-folder-123';

      const localKey = await deriveIpnsKeypair(userKey, folderId, 'local');
      const ciKey = await deriveIpnsKeypair(userKey, folderId, 'ci');
      const prodKey = await deriveIpnsKeypair(userKey, folderId, 'production');

      expect(localKey.publicKey).not.toEqual(ciKey.publicKey);
      expect(localKey.publicKey).not.toEqual(prodKey.publicKey);
      expect(ciKey.publicKey).not.toEqual(prodKey.publicKey);
    });

    it('should derive same IPNS key for same inputs (deterministic)', async () => {
      const userKey = await generateTestUserKey();
      const folderId = 'test-folder-123';

      const key1 = await deriveIpnsKeypair(userKey, folderId, 'local');
      const key2 = await deriveIpnsKeypair(userKey, folderId, 'local');

      expect(key1.privateKey).toEqual(key2.privateKey);
      expect(key1.publicKey).toEqual(key2.publicKey);
    });

    it('should derive different keys for different folders', async () => {
      const userKey = await generateTestUserKey();

      const folder1 = await deriveIpnsKeypair(userKey, 'folder-1', 'local');
      const folder2 = await deriveIpnsKeypair(userKey, 'folder-2', 'local');

      expect(folder1.publicKey).not.toEqual(folder2.publicKey);
    });
  });

  describe('Environment Validation', () => {
    it('should reject invalid environment values', async () => {
      const userKey = await generateTestUserKey();

      await expect(
        deriveIpnsKeypair(userKey, 'folder', 'invalid' as Environment)
      ).rejects.toThrow();
    });

    it('should not allow environment injection via folderId', async () => {
      const userKey = await generateTestUserKey();

      // Attempt to inject environment change via folderId
      const maliciousFolderId = 'folder:production';
      const localKey = await deriveIpnsKeypair(userKey, maliciousFolderId, 'local');
      const prodKey = await deriveIpnsKeypair(userKey, 'folder', 'production');

      // Keys should be different despite injection attempt
      expect(localKey.publicKey).not.toEqual(prodKey.publicKey);
    });
  });

  describe('TEE Key Epoch', () => {
    it('should reject encryptedIpnsPrivateKey with expired epoch', async () => {
      // Test that old epochs beyond grace period are rejected
    });

    it('should accept encryptedIpnsPrivateKey with previous epoch during grace period', async () => {
      // Test grace period handling
    });
  });
});
```

---

## Summary

| Severity | Count | Summary |
|----------|-------|---------|
| Critical | 0 | None found |
| High | 0 | None found |
| Medium | 2 | HKDF parameter naming; Random vs derived key migration |
| Low | 2 | Cross-environment accessibility; Mock service security |
| Info | 3 | TEE epoch design; Web3Auth shared identity; JWT placeholder |

---

## Recommendations Priority

1. **[Medium Priority]** Clarify HKDF implementation to match existing codebase patterns (salt vs info parameter usage)

2. **[Medium Priority]** Document migration path for existing vaults using randomly generated IPNS keys

3. **[Low Priority]** Add safeguards to mock IPNS routing service reset endpoint

4. **[Low Priority]** Document cross-environment data accessibility as known security property

5. **[Enhancement]** Consider separate Web3Auth project for staging environment if budget allows

---

## Approval Conditions

- Address Medium findings before implementation
- Document Low/Info findings in the final architecture

---

*Review Status: Complete*
*Next Review: After implementation begins*

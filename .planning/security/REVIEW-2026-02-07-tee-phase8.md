# Security Review Report

**Date:** 2026-02-07
**Scope:** Phase 8 TEE Integration (all TEE-related code: worker, API modules, crypto package, client DTOs)
**Reviewer:** Claude (security:review command)

## Executive Summary

The TEE implementation demonstrates strong security design principles: immediate key zeroing, ECIES key wrapping, generic error messages to prevent oracles, constant-time auth comparison, and proper separation of trust boundaries. However, the review uncovered **two critical integration bugs** that would cause ALL automatic republishing to silently fail, plus several high-priority issues around key material lifecycle and an encoding mismatch.

**Risk Level:** CRITICAL (due to integration bugs that break core TEE functionality)

## Files Reviewed

| File                                                    | Crypto Operations                      | Risk Level |
| ------------------------------------------------------- | -------------------------------------- | ---------- |
| `tee-worker/src/services/tee-keys.ts`                   | HKDF key derivation, secp256k1 keypair | HIGH       |
| `tee-worker/src/services/key-manager.ts`                | ECIES decrypt, fallback, re-encrypt    | CRITICAL   |
| `tee-worker/src/services/ipns-signer.ts`                | Ed25519 signing, IPNS record creation  | MEDIUM     |
| `tee-worker/src/routes/republish.ts`                    | Batch decrypt + sign orchestration     | CRITICAL   |
| `tee-worker/src/routes/public-key.ts`                   | Public key serialization               | HIGH       |
| `tee-worker/src/routes/health.ts`                       | Health endpoint response shape         | HIGH       |
| `tee-worker/src/middleware/auth.ts`                     | Bearer token auth, timing-safe compare | LOW        |
| `apps/api/src/tee/tee.service.ts`                       | TEE HTTP client, key deserialization   | CRITICAL   |
| `apps/api/src/tee/tee-key-state.service.ts`             | Epoch state management                 | LOW        |
| `apps/api/src/republish/republish.service.ts`           | Batch orchestration, entry building    | CRITICAL   |
| `apps/api/src/republish/republish-health.controller.ts` | Admin endpoint authorization           | MEDIUM     |
| `packages/crypto/src/ecies/encrypt.ts`                  | ECIES wrapKey (secp256k1 + AES-GCM)    | LOW        |
| `packages/crypto/src/ecies/decrypt.ts`                  | ECIES unwrapKey                        | LOW        |

## Findings

### Critical Issues

#### C1. Missing `currentEpoch`/`previousEpoch` in republish batch request — RESOLVED

- **Severity:** CRITICAL
- **Status:** RESOLVED — Both fields present in `RepublishEntry` interface (tee.service.ts:20-22) and populated from `TeeKeyStateService.getCurrentState()` in `processRepublishBatch()` (republish.service.ts:87-88,104-105)
- **Location:** `apps/api/src/republish/republish.service.ts:88-94` and `apps/api/src/tee/tee.service.ts:8-19`
- **Description:** The API's `RepublishEntry` interface omits `currentEpoch` and `previousEpoch` fields. The TEE worker's `RepublishEntry` interface expects them (at `tee-worker/src/routes/republish.ts:29-30`). When `processRepublishBatch()` builds entries, it only includes `encryptedIpnsKey`, `keyEpoch`, `ipnsName`, `latestCid`, `sequenceNumber`. The TEE worker then calls `decryptWithFallback(encryptedIpnsKey, entry.currentEpoch, entry.previousEpoch)` with both epoch params being `undefined`.
- **Impact:** Every republish operation will fail because `getKeypair(undefined)` derives a key for `"epoch-undefined"` which will never match the actual encryption epoch. All IPNS records will stop being republished, causing IPNS resolution failures after records expire (48h).
- **Recommendation:** Either:
  - **(A)** Add `currentEpoch`/`previousEpoch` to the API's `RepublishEntry` and populate them from `TeeKeyStateService.getCurrentState()` in `processRepublishBatch()`, OR
  - **(B - preferred)** Have the TEE worker resolve its own epoch state internally rather than trusting the API. This is more secure because the TEE should be the authority on its own epochs. The TEE worker would call `getKeypair(entry.keyEpoch)` directly, then fallback to the "other" known epoch.
- **Reference:** Zero-trust principle: TEE should determine its own epoch state

#### C2. Public key encoding mismatch (hex vs base64) — RESOLVED

- **Severity:** CRITICAL
- **Status:** RESOLVED — API now decodes with `Buffer.from(data.publicKey, 'hex')` at tee.service.ts:94, matching TEE worker's hex encoding
- **Location:** `tee-worker/src/routes/public-key.ts:27` sends **hex**; `apps/api/src/tee/tee.service.ts:90` decodes as **hex**
- **Description:** The TEE worker returns `publicKey: Buffer.from(publicKey).toString('hex')` (hex string). The API decodes it with `Uint8Array.from(atob(data.publicKey), (c) => c.charCodeAt(0))` which treats it as base64. `atob('04a1b2c3...')` will produce completely wrong bytes.
- **Impact:** TEE epoch initialization from `initializeFromTee()` will store garbled bytes as the public key in `tee_key_state`. All subsequent ECIES operations using this public key will fail. Clients would receive an invalid TEE public key, making IPNS key encryption broken.
- **Recommendation:** Align on one encoding. Use hex consistently since the DTO already specifies hex:

  ```typescript
  // In tee.service.ts getPublicKey():
  const publicKeyBytes = Buffer.from(data.publicKey, 'hex');
  ```

### High Priority

#### H1. Health endpoint response shape mismatch — RESOLVED

- **Severity:** HIGH
- **Status:** RESOLVED — Health endpoint now returns `{ healthy: true, mode, epoch, uptime }` at health.ts:13-18, matching API expectation of `{ healthy: boolean, epoch: number }`
- **Location:** `tee-worker/src/routes/health.ts:13-17` returns `{ healthy, mode, epoch, uptime }` matching `apps/api/src/tee/tee.service.ts:71` expectation
- **Description:** The health endpoint doesn't return `healthy` or `epoch` fields. `data.healthy` will be `undefined` (falsy) and `data.epoch` will be `undefined`. When used in `initializeFromTee()`, `getPublicKey(undefined)` would be called.
- **Impact:** TEE initialization will either fail or store keys for an undefined epoch. `getHealthStats()` would always report `teeHealthy` as falsy even when the TEE is up.
- **Recommendation:** Update health endpoint to return expected shape, including the epoch:

  ```typescript
  res.json({
    healthy: true,
    mode: process.env.TEE_MODE || 'simulator',
    epoch: parseInt(process.env.TEE_EPOCH || '1', 10),
    uptime: process.uptime(),
  });
  ```

#### H2. TEE epoch private keys never zeroed

- **Severity:** HIGH
- **Location:** `tee-worker/src/services/tee-keys.ts:53` and `tee-worker/src/services/key-manager.ts:27-29`
- **Description:** `getKeypair()` returns `{ publicKey, privateKey }` but the secp256k1 private key (the TEE's master key for an epoch) is never zeroed after use. `decryptIpnsKey()` calls `getKeypair()`, uses `keypair.privateKey` for ECIES decrypt, but never zeros it. The private key buffer continues to exist in memory until GC.
- **Impact:** The TEE's most sensitive key material (the secp256k1 private key that can decrypt ALL IPNS keys for an epoch) persists in memory unnecessarily. In a memory-scraping attack or core dump, this key could be extracted.
- **Recommendation:** Zero the private key after each use in `decryptIpnsKey`:

  ```typescript
  export async function decryptIpnsKey(
    encryptedIpnsKey: Uint8Array,
    epoch: number
  ): Promise<Uint8Array> {
    const keypair = await getKeypair(epoch);
    try {
      return new Uint8Array(decrypt(keypair.privateKey, encryptedIpnsKey));
    } finally {
      keypair.privateKey.fill(0);
    }
  }
  ```

  Note: This means each ECIES decrypt requires re-derivation. In CVM mode, consider batch processing at the key-manager level to derive once per batch.

#### H3. No enforcement of CVM mode in production

- **Severity:** HIGH
- **Location:** `tee-worker/src/services/tee-keys.ts:28,39-44`
- **Description:** The `TEE_MODE` env var defaults to `'simulator'`. In simulator mode, all keys are derived from a hardcoded seed (`'cipherbox-tee-simulator-seed'`). Anyone who reads the source code can derive all TEE private keys. There's no check or warning to prevent simulator mode in production.
- **Impact:** If deployed to production without `TEE_MODE=cvm`, all IPNS keys encrypted with the TEE public key can be trivially decrypted by anyone.
- **Recommendation:**
  1. Add a startup warning when simulator mode is detected with a non-development `NODE_ENV`
  2. Consider making `TEE_MODE` required (no default) so the operator must explicitly choose
  3. Add a guard: `if (mode === 'simulator' && process.env.NODE_ENV === 'production') throw new Error('Simulator mode is not allowed in production')`

#### H4. `libp2pPrivateKey` object retains key material after use

- **Severity:** HIGH
- **Location:** `tee-worker/src/services/ipns-signer.ts:44-56`
- **Description:** `privateKeyFromRaw(libp2pKeyBytes)` creates a libp2p PrivateKey object that internally stores the raw key bytes. While `libp2pKeyBytes` is zeroed at line 47, the `libp2pPrivateKey` object passed to `createIPNSRecord` retains its own copy. After `createIPNSRecord` returns, `libp2pPrivateKey` goes out of scope but the bytes aren't zeroed.
- **Impact:** The Ed25519 IPNS private key persists in the libp2p object's internal buffer until GC. This partially undermines the immediate-zeroing security design.
- **Recommendation:** After `createIPNSRecord`, attempt to zero the libp2p key's internal buffer if the API allows, or document this as an accepted limitation of the libp2p library.

### Medium Priority

#### M1. Admin health endpoint lacks role-based access control

- **Severity:** MEDIUM
- **Location:** `apps/api/src/republish/republish-health.controller.ts:12-13`
- **Description:** The `/admin/republish-health` endpoint only requires JWT authentication (`JwtAuthGuard`), not an admin role. Any authenticated user can view republish health stats.
- **Impact:** Exposes operational information (pending/failed/stale counts, current TEE epoch, TEE connectivity) to all authenticated users. While not directly exploitable, it reveals infrastructure details.
- **Recommendation:** Add an admin role guard or restrict to internal/ops network.

#### M2. No input validation on TEE worker `/republish` entries

- **Severity:** MEDIUM
- **Location:** `tee-worker/src/routes/republish.ts:46-49`
- **Description:** Beyond checking `entries` is an array, there's no validation of entry fields (missing `encryptedIpnsKey`, invalid `sequenceNumber`, non-numeric `keyEpoch`, etc.). The per-entry try/catch prevents crashes but produces vague error messages.
- **Impact:** Malformed requests consume TEE resources (key derivation is expensive in CVM mode) before failing. Poor error messages make debugging harder.
- **Recommendation:** Validate required fields and types before processing. Reject entire batch if structural validation fails.

#### M3. No rate limiting on TEE worker

- **Severity:** MEDIUM
- **Location:** `tee-worker/src/index.ts`
- **Description:** The TEE worker has no rate limiting. The shared secret prevents unauthorized access, but if compromised, the worker could be overwhelmed.
- **Impact:** Denial of service against the TEE worker, preventing legitimate republishing.
- **Recommendation:** Add express-rate-limit middleware matching or exceeding the API's rate limits.

#### M4. Stale entry reactivation has no epoch validation

- **Severity:** MEDIUM
- **Location:** `apps/api/src/republish/republish.service.ts:331-347`
- **Description:** `reactivateStaleEntries()` resets all stale entries to 'active' without checking if their `keyEpoch` is still valid. If entries went stale because of an epoch rotation (and the grace period has ended), reactivating them would just cause them to fail again.
- **Impact:** Wasted processing cycles and repeated failures for entries with expired epochs.
- **Recommendation:** Filter stale entries by epoch validity before reactivation, or add epoch check in the reactivation query.

### Low Priority / Recommendations

#### L1. Public key cache never evicts entries

- **Severity:** LOW
- **Location:** `tee-worker/src/services/tee-keys.ts:14`
- **Description:** `publicKeyCache` grows unbounded. Each entry is only 65 bytes, but the Map overhead per entry is larger.
- **Impact:** Negligible memory growth over time. Would only be significant with thousands of epoch rotations.
- **Recommendation:** No action needed for v1.0. Could add LRU eviction if epoch rotation frequency increases.

#### L2. No TLS enforcement between API and TEE worker

- **Severity:** LOW (assuming localhost deployment)
- **Location:** `apps/api/src/tee/tee.service.ts:54`
- **Description:** `TEE_WORKER_URL` defaults to `http://localhost:3001`. The Bearer token is sent in plaintext. In production (Phala Cloud), the CVM network isolation provides security, but this should be documented.
- **Impact:** If API and TEE worker communicate across a network, Bearer token could be intercepted.
- **Recommendation:** Document that TLS is required for non-localhost deployments, or enforce `https://` prefix in production.

#### L3. `timingSafeEqual` is correct but could use `crypto.timingSafeEqual`

- **Severity:** LOW
- **Location:** `tee-worker/src/middleware/auth.ts:45-51`
- **Description:** Custom constant-time comparison is correct but Node.js provides `crypto.timingSafeEqual` which is C-level constant-time.
- **Impact:** The custom implementation is sound, but the stdlib version has stronger guarantees against compiler optimizations.
- **Recommendation:** Replace with `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`.

## Detailed Analysis

### TEE Worker: Key Derivation (`tee-keys.ts`)

**What it does:** Derives deterministic secp256k1 keypairs per epoch using HKDF (simulator) or Phala dstack SDK (CVM).

**Positive observations:**

- Correct use of HKDF-SHA256 with salt and info parameters
- Public key caching avoids unnecessary derivation
- Clean separation between simulator and CVM modes
- Noble library (audited, well-maintained) for secp256k1

**Issues:** H2 (private key not zeroed), H3 (no production mode enforcement), L1 (cache growth)

### TEE Worker: Key Manager (`key-manager.ts`)

**What it does:** ECIES decrypt with epoch fallback, re-encryption for epoch migration.

**Positive observations:**

- Epoch fallback enables zero-downtime key rotation
- Generic error message on decrypt failure (line 67) prevents oracle attacks
- Clear security comment about caller responsibility for zeroing

**Issues:** C1 (epochs not provided), H2 (inherited from getKeypair)

### TEE Worker: IPNS Signer (`ipns-signer.ts`)

**What it does:** Signs IPNS records with Ed25519 keys, creates V1+V2 compatible records.

**Positive observations:**

- `libp2pKeyBytes.fill(0)` at line 47 zeros intermediate buffer immediately
- 48-hour lifetime gives comfortable margin over 6-hour republish interval
- V1+V2 compatibility ensures broad IPNS resolution support

**Issues:** H4 (libp2p object retains key bytes)

### TEE Worker: Republish Route (`republish.ts`)

**What it does:** Orchestrates batch decrypt -> sign -> optional re-encrypt flow.

**Positive observations:**

- `ipnsPrivateKey.fill(0)` immediately after signing (line 86)
- Key zeroed even in catch block (lines 106-108)
- Per-entry error handling prevents batch failure cascades
- Error messages never include key material
- Summary logging is safe (counts only)

**Issues:** C1 (depends on undefined currentEpoch/previousEpoch from API)

### TEE Worker: Auth Middleware (`auth.ts`)

**What it does:** Bearer token authentication with constant-time comparison.

**Positive observations:**

- Length check before comparison prevents timing leak on length
- XOR-based comparison is correct constant-time algorithm
- 500 on missing secret prevents running without auth
- No key material in error responses

**Issues:** L3 (could use stdlib timingSafeEqual)

### API: TeeService (`tee.service.ts`)

**What it does:** HTTP client for TEE worker communication.

**Positive observations:**

- 30-second timeout prevents hanging requests
- AbortController properly cleaned up in finally block
- Auth headers separated into helper, commented "never log"
- Validates public key size and 0x04 prefix (line 92)

**Issues:** C2 (hex/base64 mismatch), H1 (health response shape)

### API: RepublishService (`republish.service.ts`)

**What it does:** Orchestrates 6-hour IPNS republish cycle with BullMQ.

**Positive observations:**

- Exponential backoff with cap (30s base, 3600s max)
- Stale status after 10 failures prevents infinite retries
- Error messages truncated to 500 chars (line 358)
- Explicit "NEVER log key material" comment (line 357)
- Batch size capped at 50 per TEE request
- FolderIpns sequence sync is non-fatal

**Issues:** C1 (missing epoch fields in entry building), M4 (stale reactivation)

### Crypto Package: ECIES (`encrypt.ts`, `decrypt.ts`)

**What it does:** ECIES key wrapping using eciesjs library.

**Positive observations:**

- Validates public key size AND curve point validity (ProjectivePoint.fromHex)
- Validates 0x04 uncompressed prefix
- Generic error messages prevent oracle attacks ("Key wrapping failed")
- Minimum ciphertext size validation in decrypt
- eciesjs internally handles ephemeral keys, ECDH, HKDF, AES-GCM

**Issues:** None found. Clean implementation.

## Test Cases

### TEE Worker: Key Derivation

```typescript
describe('tee-keys security', () => {
  // Positive cases
  it('should derive different keys for different epochs', async () => {
    const k1 = await getKeypair(1);
    const k2 = await getKeypair(2);
    expect(k1.privateKey).not.toEqual(k2.privateKey);
    expect(k1.publicKey).not.toEqual(k2.publicKey);
  });

  it('should derive deterministic keys (same epoch = same key)', async () => {
    const k1 = await getKeypair(1);
    const k2 = await getKeypair(1);
    expect(k1.publicKey).toEqual(k2.publicKey);
  });

  it('should return 65-byte uncompressed public key with 0x04 prefix', async () => {
    const { publicKey } = await getKeypair(1);
    expect(publicKey.length).toBe(65);
    expect(publicKey[0]).toBe(0x04);
  });

  it('should return 32-byte private key', async () => {
    const { privateKey } = await getKeypair(1);
    expect(privateKey.length).toBe(32);
  });

  // Negative/edge cases
  it('should handle epoch 0', async () => {
    const { publicKey } = await getKeypair(0);
    expect(publicKey.length).toBe(65);
  });

  it('should handle very large epoch numbers', async () => {
    const { publicKey } = await getKeypair(999999);
    expect(publicKey.length).toBe(65);
  });

  it('should handle negative epoch (derive some key, not crash)', async () => {
    // Implementation may or may not reject negative epochs
    await expect(getKeypair(-1)).resolves.toBeDefined();
  });
});
```

### TEE Worker: Key Manager (ECIES Decrypt/Re-encrypt)

```typescript
describe('key-manager security', () => {
  it('should decrypt IPNS key encrypted with correct epoch public key', async () => {
    const { publicKey } = await getKeypair(1);
    const testIpnsKey = crypto.getRandomValues(new Uint8Array(32));
    const encrypted = encrypt(publicKey, testIpnsKey);
    const decrypted = await decryptIpnsKey(new Uint8Array(encrypted), 1);
    expect(decrypted).toEqual(testIpnsKey);
  });

  it('should fail to decrypt with wrong epoch', async () => {
    const { publicKey } = await getKeypair(1);
    const testIpnsKey = crypto.getRandomValues(new Uint8Array(32));
    const encrypted = encrypt(publicKey, testIpnsKey);
    await expect(decryptIpnsKey(new Uint8Array(encrypted), 2)).rejects.toThrow();
  });

  it('should fail to decrypt corrupted ciphertext', async () => {
    const { publicKey } = await getKeypair(1);
    const testIpnsKey = crypto.getRandomValues(new Uint8Array(32));
    const encrypted = new Uint8Array(encrypt(publicKey, testIpnsKey));
    encrypted[10] ^= 0xff; // Flip a byte
    await expect(decryptIpnsKey(encrypted, 1)).rejects.toThrow();
  });

  it('should fail to decrypt truncated ciphertext', async () => {
    const { publicKey } = await getKeypair(1);
    const testIpnsKey = crypto.getRandomValues(new Uint8Array(32));
    const encrypted = new Uint8Array(encrypt(publicKey, testIpnsKey));
    await expect(decryptIpnsKey(encrypted.slice(0, 10), 1)).rejects.toThrow();
  });

  // Fallback tests
  it('should fallback to previous epoch when current fails', async () => {
    const { publicKey: prevPub } = await getKeypair(1);
    const testIpnsKey = crypto.getRandomValues(new Uint8Array(32));
    const encrypted = new Uint8Array(encrypt(prevPub, testIpnsKey));
    // Encrypted with epoch 1, try current=2 first (fails), fallback to previous=1
    const result = await decryptWithFallback(encrypted, 2, 1);
    expect(result.ipnsPrivateKey).toEqual(testIpnsKey);
    expect(result.usedEpoch).toBe(1);
  });

  it('should throw when both epochs fail', async () => {
    const { publicKey } = await getKeypair(1);
    const testIpnsKey = crypto.getRandomValues(new Uint8Array(32));
    const encrypted = new Uint8Array(encrypt(publicKey, testIpnsKey));
    // Encrypted with epoch 1, try current=3 and previous=2 (both wrong)
    await expect(decryptWithFallback(encrypted, 3, 2)).rejects.toThrow(
      'ECIES decryption failed for all available epochs'
    );
  });

  // Re-encryption
  it('should re-encrypt for target epoch and be decryptable', async () => {
    const testIpnsKey = crypto.getRandomValues(new Uint8Array(32));
    const reEncrypted = await reEncryptForEpoch(testIpnsKey, 2);
    const decrypted = await decryptIpnsKey(reEncrypted, 2);
    expect(decrypted).toEqual(testIpnsKey);
  });
});
```

### TEE Worker: Auth Middleware

```typescript
describe('auth middleware security', () => {
  it('should reject missing Authorization header', () => {
    // Send request without Authorization header -> 401
  });

  it('should reject malformed Authorization header (no Bearer prefix)', () => {
    // Send "Basic xxx" -> 401
  });

  it('should reject wrong token', () => {
    // Send wrong Bearer token -> 401
  });

  it('should reject token with same length but wrong value (timing-safe)', () => {
    // Verify constant-time comparison works
  });

  it('should reject token with different length', () => {
    // Early length check should still return 401
  });

  it('should return 500 if TEE_WORKER_SECRET not configured', () => {
    // Unset env var -> 500
  });
});
```

### API: Republish Batch Building

```typescript
describe('RepublishService.processRepublishBatch security', () => {
  it('should include currentEpoch and previousEpoch in TEE entries', async () => {
    // After fixing C1: verify the epoch state is fetched and included
  });

  it('should never log encrypted key material', async () => {
    // Mock logger and verify no log calls contain key bytes
  });

  it('should truncate error messages to 500 chars', async () => {
    // Verify lastError is always <= 500 chars
  });

  it('should mark entries stale after MAX_CONSECUTIVE_FAILURES', async () => {
    // Verify entry.status transitions to 'stale' after 10 failures
  });
});
```

### Attack Scenarios to Test

- [ ] **Replay attack:** Submit the same signed IPNS record twice. The sequence number increment should prevent this, but verify the IPNS network rejects stale sequences.
- [ ] **Epoch downgrade:** Send a batch with a `previousEpoch` that is newer than `currentEpoch`. Verify the TEE worker doesn't accept this.
- [ ] **Ciphertext substitution:** Replace one entry's `encryptedIpnsKey` with another entry's. The wrong key decrypts, producing an Ed25519 key that doesn't match the IPNS name. Verify the signed record is invalid (would fail IPNS validation).
- [ ] **Memory scraping after signing:** After the TEE worker processes a batch, trigger a heap dump. Verify zeroed keys are actually zeroed (acknowledging JS GC limitations).
- [ ] **Concurrent batch processing:** Send multiple overlapping batches. Verify no cross-contamination of key material between requests.

## Compliance Checklist

Based on project security rules (CLAUDE.md):

- [x] No privateKey in localStorage/sessionStorage
- [x] No sensitive keys logged (verified all log calls)
- [x] No unencrypted keys sent to server (IPNS keys always ECIES-encrypted)
- [x] ECIES used for key wrapping (eciesjs: ECDH + HKDF + AES-GCM)
- [x] AES-256-GCM used for content encryption (handled by eciesjs internally)
- [x] Server has zero knowledge of plaintext (backend never sees IPNS private keys)
- [x] IPNS keys encrypted with TEE public key before sending
- [x] TEE decrypts in hardware (CVM mode), signs, and immediately discards
- [ ] **Partial:** Immediate discard works for IPNS keys but TEE epoch private key not zeroed (H2)

## Recommendations Summary

| Priority | Recommendation                                                      | Effort | Finding |
| -------- | ------------------------------------------------------------------- | ------ | ------- |
| ~~P0~~   | ~~Add currentEpoch/previousEpoch to republish entries~~             | LOW    | C1 RESOLVED |
| ~~P0~~   | ~~Fix hex/base64 encoding mismatch in public key retrieval~~        | LOW    | C2 RESOLVED |
| ~~P0~~   | ~~Fix health endpoint response shape to include `healthy` and `epoch`~~ | LOW    | H1 RESOLVED |
| P1       | Zero TEE epoch private keys after ECIES decrypt                     | MEDIUM | H2      |
| P1       | Enforce CVM mode in production (reject simulator)                   | LOW    | H3      |
| P1       | Document libp2p key object limitation                               | LOW    | H4      |
| P2       | Add admin role guard to health endpoint                             | LOW    | M1      |
| P2       | Add input validation to TEE worker republish route                  | LOW    | M2      |
| P2       | Add rate limiting to TEE worker                                     | LOW    | M3      |
| P2       | Validate epoch in stale entry reactivation                          | LOW    | M4      |
| P3       | Use crypto.timingSafeEqual instead of custom impl                   | LOW    | L3      |

## Next Steps

1. **~~Immediate (P0):~~ RESOLVED:** C1, C2, H1 all verified fixed in codebase (2026-02-10)
2. **Before deployment (P1):** Address H2, H3, H4 -- these are security hardening items
3. **Backlog (P2/P3):** Address M1-M4, L1-L3 -- these are defense-in-depth improvements

---

_Generated by security:review command_
_This review is automated guidance, not a substitute for professional security audit_

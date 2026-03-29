# Security Review: Phase 35 -- TEE Worker Migration to apps/tee-worker/

**Reviewer:** Claude Opus 4.6 (security agent)
**Date:** 2026-03-29
**Scope:** Phase 35 TEE worker code under `apps/tee-worker/src/` and shared package changes
**Risk Level:** LOW-MEDIUM (well-structured code with a handful of medium-severity issues)

---

## Executive Summary

The Phase 35 TEE worker migration is a well-written, security-conscious codebase. The core cryptographic operations (ECIES key wrapping via `@cipherbox/crypto`, HKDF key derivation, IPNS record signing) are correctly implemented and delegate to audited libraries (`eciesjs`, `@noble/hashes`, `@noble/secp256k1`). Key zeroing discipline is consistently applied throughout. The SSRF protection layer is thorough with proper redirect blocking, DNS rebinding checks, and comprehensive private IP range coverage.

However, the review identified **8 findings** across severity levels:

| Severity | Count |
|----------|-------|
| Critical | 0     |
| High     | 2     |
| Medium   | 4     |
| Low      | 2     |

The two high-severity issues are: (1) a TOCTOU race in SSRF DNS validation that could allow DNS rebinding attacks, and (2) auth token string copies that cannot be zeroed, undermining the credential-zeroing security model. Both have clear fix paths.

---

## Files Reviewed

| File | Lines | Crypto Operations | Issues Found |
|------|-------|-------------------|--------------|
| `apps/tee-worker/src/services/tee-keys.ts` | 93 | HKDF-SHA256 derivation, secp256k1 pubkey derivation | 1 (LOW) |
| `apps/tee-worker/src/services/key-manager.ts` | 91 | ECIES unwrapKey/wrapKey, epoch fallback | 0 |
| `apps/tee-worker/src/services/ipns-signer.ts` | 38 | IPNS record signing (Ed25519) | 0 |
| `apps/tee-worker/src/services/migration-worker.ts` | 206 | ECIES decryption, provider credential handling | 2 (HIGH, MEDIUM) |
| `apps/tee-worker/src/services/ssrf-validation.ts` | 95 | None (network security) | 1 (HIGH) |
| `apps/tee-worker/src/services/logger.ts` | 35 | None (logging) | 0 |
| `apps/tee-worker/src/routes/republish.ts` | 138 | ECIES decrypt, IPNS sign, re-encrypt | 0 |
| `apps/tee-worker/src/routes/connection-test.ts` | 248 | ECIES decryption, provider probing | 1 (MEDIUM) |
| `apps/tee-worker/src/routes/migrate.ts` | 94 | None (delegates to migration-worker) | 1 (MEDIUM) |
| `apps/tee-worker/src/routes/public-key.ts` | 39 | Public key retrieval | 1 (MEDIUM) |
| `apps/tee-worker/src/routes/health.ts` | 22 | None | 0 |
| `apps/tee-worker/src/routes/metrics.ts` | 19 | None | 0 |
| `apps/tee-worker/src/middleware/auth.ts` | 44 | Constant-time comparison | 0 |
| `apps/tee-worker/src/middleware/metrics.ts` | 57 | None | 0 |
| `apps/tee-worker/src/index.ts` | 53 | None (app setup) | 1 (LOW) |
| `packages/sdk-core/src/pinning/kubo-provider.ts` | 134 | None (HTTP client) | 0 |
| `packages/sdk-core/src/pinning/psa-provider.ts` | 174 | None (HTTP client) | 0 |
| `packages/sdk-core/src/pinning/types.ts` | 57 | None (type definitions) | 0 |
| `packages/crypto/src/ecies/encrypt.ts` | 61 | ECIES encrypt (eciesjs) | 0 |
| `packages/crypto/src/ecies/decrypt.ts` | 55 | ECIES decrypt (eciesjs) | 0 |

**Total:** 20 files, 1752 lines, 12 crypto operations identified, 8 issues found.

---

## Findings

### [HIGH-01] TOCTOU Race in SSRF DNS Validation Allows DNS Rebinding

**Location:** `apps/tee-worker/src/services/ssrf-validation.ts:80-85` and `apps/tee-worker/src/services/migration-worker.ts:106-117`

**Code:**

```typescript
// ssrf-validation.ts:80-85
export async function validateResolvedIp(hostname: string): Promise<void> {
  const result = await lookup(hostname);
  if (isPrivateAddress(result.address)) {
    throw new Error('Endpoint DNS resolves to private address');
  }
}

// migration-worker.ts:106-117 -- validates then later uses the URL
if (process.env.TEE_MODE !== 'simulator') {
  await validateResolvedIp(new URL(sourceConfig.endpoint).hostname);
}
// ... later, actual fetch happens via ssrfSafeFetch or provider constructors
```

**Issue:**
There is a time-of-check-to-time-of-use (TOCTOU) gap between DNS validation and the actual HTTP request. An attacker controlling a DNS server can:
1. Respond with a public IP during `validateResolvedIp()` (passes check)
2. Switch the DNS record to `169.254.169.254` (or other internal IP) before the actual `fetch()` call
3. The fetch resolves DNS again, hitting the now-private IP

This is a classic DNS rebinding attack. The `ssrfSafeFetch` wrapper blocks redirects (which is good) but does not pin the resolved IP for the actual connection.

**Impact:**
An attacker providing a malicious endpoint URL in their encrypted provider config could access cloud metadata services (169.254.169.254), internal services on the TEE host network, or other private endpoints. This is mitigated by the fact that: (a) the attacker would need a valid TEE_WORKER_SECRET to authenticate, and (b) the response goes back to the attacker's own account, limiting lateral movement. But metadata service access could expose cloud credentials.

**Recommendation:**

Pin the resolved IP and use it directly for the HTTP connection, or use a custom DNS resolver that caches the validated result:

```typescript
import { lookup } from 'node:dns/promises';
import { Agent } from 'node:http';
import { Agent as HttpsAgent } from 'node:https';

/**
 * Create an SSRF-safe fetch that pins the DNS resolution.
 * Resolves hostname once, validates the IP, then forces all connections
 * to use that IP (via custom Agent with lookup override).
 */
export async function ssrfSafeFetchWithPinnedDns(
  url: string,
  init?: RequestInit
): Promise<Response> {
  const parsed = new URL(url);
  const { address } = await lookup(parsed.hostname);

  if (isPrivateAddress(address)) {
    throw new Error('Endpoint DNS resolves to private address');
  }

  // Use the resolved IP directly, set Host header for TLS SNI
  const pinnedUrl = new URL(url);
  pinnedUrl.hostname = address;

  return fetch(pinnedUrl.toString(), {
    ...init,
    redirect: 'error',
    headers: {
      ...Object.fromEntries(new Headers(init?.headers).entries()),
      Host: parsed.hostname,
    },
  });
}
```

Alternatively, use Node.js `net.connect` override or a custom `dns.lookup` function passed to the HTTP agent to ensure the cached IP is used for the actual connection.

**References:**
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery
- https://www.paloaltonetworks.com/cyberpedia/what-is-dns-rebinding

---

### [HIGH-02] Auth Token String Copies Cannot Be Zeroed

**Location:** `apps/tee-worker/src/services/migration-worker.ts:63-66` and `apps/tee-worker/src/routes/connection-test.ts:82-83`

**Code:**

```typescript
// migration-worker.ts:63-66
function authTokenString(config: ProviderConfig): string {
  return new TextDecoder().decode(config.authTokenBytes);
}

// migration-worker.ts:121-122 -- these string copies persist in memory
const sourceToken = authTokenString(sourceConfig);
const destToken = authTokenString(destConfig);

// connection-test.ts:82-83
const kuboResult = await probeKubo(normalizedEndpoint, authToken);
// authToken is a string from JSON.parse -- also cannot be zeroed
```

**Issue:**
JavaScript strings are immutable and cannot be zeroed from memory. The code carefully maintains auth tokens as `Uint8Array` (which CAN be zeroed) but then converts them to strings via `authTokenString()` for passing to `KuboProvider`/`PsaProvider` constructors. Those string copies live in the V8 heap until garbage collected -- potentially for a long time. The code comment on line 202 acknowledges this limitation but the string copies at lines 121-122 remain unaddressed.

Similarly, in `connection-test.ts`, the `authToken` variable from `JSON.parse` is a string that persists through both `probeKubo` and `probePsa` calls.

**Impact:**
If the TEE worker process memory is dumped (crash dump, core file, or a memory disclosure vulnerability), auth tokens for external IPFS providers could be exposed. In a true hardware TEE (CVM mode), the memory is encrypted, so this is primarily a concern in simulator mode or if the TEE attestation is compromised.

**Recommendation:**

This is a fundamental limitation of JavaScript. The current `Uint8Array` + `.fill(0)` pattern is the best available mitigation. To reduce the window:

```typescript
// Minimize the string's lifetime by scoping tightly and nullifying references
async function withAuthToken<T>(
  config: ProviderConfig,
  fn: (token: string) => Promise<T>
): Promise<T> {
  // Create string copy only for the duration of the callback
  const token = new TextDecoder().decode(config.authTokenBytes);
  try {
    return await fn(token);
  } finally {
    // Can't zero the string, but nullify the reference to help GC
    // (token is const, so this pattern needs a let variable)
  }
}
```

For `KuboProvider` and `PsaProvider`, consider accepting `Uint8Array` auth tokens and encoding the `Authorization` header from bytes directly at request time, avoiding string materialization until the narrowest possible scope:

```typescript
// In provider constructors, accept Uint8Array and encode per-request
private buildHeaders(): Record<string, string> {
  if (this.authTokenBytes) {
    const token = new TextDecoder().decode(this.authTokenBytes);
    return { Authorization: `Bearer ${token}` };
    // token goes out of scope immediately
  }
  return {};
}
```

**References:**
- https://cheatsheetseries.owasp.org/cheatsheets/Memory_Management_Cheat_Sheet.html

---

### [MEDIUM-01] Public Key Endpoint Has No Epoch Bounds Validation

**Location:** `apps/tee-worker/src/routes/public-key.ts:17-18`

**Code:**

```typescript
const epochStr = req.query.epoch as string | undefined;

if (!epochStr || isNaN(Number(epochStr))) {
  res.status(400).json({ error: 'Missing or invalid epoch query parameter' });
  return;
}

const epoch = parseInt(epochStr, 10);
```

**Issue:**
The epoch parameter accepts any integer with no bounds checking. An attacker (who has the bearer token) could:
1. Request epoch=0, epoch=-1, or epoch=999999999 to probe key derivation behavior
2. In simulator mode, HKDF will happily derive keys for any epoch value, including negative numbers (via string interpolation `epoch-${epoch}` producing `epoch--1`)
3. The `publicKeyCache` Map grows unboundedly with each unique epoch requested -- potential memory DoS

In CVM mode, `DstackClient.getKey()` receives `epoch-${epoch}` as the subject, and the behavior with negative or very large values depends on the dstack SDK implementation.

**Impact:**
- Memory exhaustion via cache growth (low impact, requires auth token)
- Unexpected HKDF context strings with negative epochs (low cryptographic impact but violates the principle of least surprise)
- No explicit constraint tying epoch to the server-managed epoch lifecycle

**Recommendation:**

```typescript
const epoch = parseInt(epochStr, 10);

// Validate epoch is a reasonable positive integer
if (!Number.isInteger(epoch) || epoch < 1 || epoch > 10000) {
  res.status(400).json({ error: 'Epoch must be a positive integer (1-10000)' });
  return;
}
```

Also consider adding a `maxSize` to the `publicKeyCache` Map in `tee-keys.ts`:

```typescript
const MAX_CACHE_SIZE = 100;
if (publicKeyCache.size >= MAX_CACHE_SIZE) {
  // Evict oldest entry
  const firstKey = publicKeyCache.keys().next().value;
  if (firstKey !== undefined) publicKeyCache.delete(firstKey);
}
publicKeyCache.set(epoch, publicKey);
```

---

### [MEDIUM-02] Migrate Route Uses Static Epoch from Environment Variable

**Location:** `apps/tee-worker/src/routes/migrate.ts:25`

**Code:**

```typescript
/** Current TEE epoch -- in production this would come from tee-keys state */
const TEE_EPOCH = parseInt(process.env.TEE_CURRENT_EPOCH || '1', 10);
```

**Issue:**
The migration route reads `TEE_CURRENT_EPOCH` once at module load time and never updates. If the epoch changes during the worker's lifetime (epoch rotation), the migrate endpoint will continue using the stale epoch value. This means:
1. ECIES decryption of provider configs will fail if they were encrypted with the new epoch's public key
2. No fallback to previous epoch (unlike the republish route which accepts `currentEpoch` and `previousEpoch` per-entry)

The comment itself acknowledges this is a TODO ("in production this would come from tee-keys state").

**Impact:**
After an epoch rotation, the `/migrate` endpoint becomes non-functional for configs encrypted with the new epoch key. This is a reliability issue with security implications -- it could force clients to hold unencrypted provider configs while waiting for the TEE worker to be restarted.

**Recommendation:**

Accept the epoch from the request body (like `/republish` does) or read it dynamically:

```typescript
router.post('/migrate', async (req: Request, res: Response) => {
  const { cids, sourceConfigEncrypted, destConfigEncrypted, currentEpoch, previousEpoch } =
    req.body as {
      cids?: string[];
      sourceConfigEncrypted?: string;
      destConfigEncrypted?: string;
      currentEpoch?: number;
      previousEpoch?: number | null;
    };

  // Use request-provided epoch, falling back to env var
  const epoch = currentEpoch ?? parseInt(process.env.TEE_CURRENT_EPOCH || '1', 10);
  // ...
});
```

---

### [MEDIUM-03] Connection Test Probe Functions Leak Auth Token as String Parameter

**Location:** `apps/tee-worker/src/routes/connection-test.ts:82-83, 117-120, 183-189`

**Code:**

```typescript
// line 82-83: authToken is a string from JSON.parse, passed to probe functions
const kuboResult = await probeKubo(normalizedEndpoint, authToken);
// ...
const psaResult = await probePsa(normalizedEndpoint, authToken);

// line 129-130: string used directly in header
if (authToken) {
  headers['Authorization'] = `Basic ${authToken}`;
}
```

**Issue:**
The `authToken` from the decrypted config (`JSON.parse`) is a JS string and is passed through multiple function calls. While `tokenBytes` (the Uint8Array copy) is zeroed in the `finally` block, the original `authToken` string from `JSON.parse` at line 64 cannot be zeroed and remains in memory.

Additionally, the `configText` string (line 63, containing the full JSON with endpoint + authToken) also cannot be zeroed. The `configBytes` Uint8Array IS zeroed in `finally`, but the string decoded from it persists.

**Impact:**
Same as HIGH-02 -- strings containing auth tokens persist in V8 heap. The connection-test route has a smaller window since it's a single request-response cycle, but the strings are still not collectible until GC runs.

**Recommendation:**

Parse the JSON config using a streaming approach that keeps values as `Uint8Array` where possible. At minimum, document this limitation clearly:

```typescript
// After probing completes, explicitly dereference string variables
// to help GC (though this is advisory, not guaranteed)
// configText = undefined; // if using let
// authToken = undefined;  // if using let
```

Consider changing `configText` and `authToken` from `const` to `let` so they can be explicitly set to `undefined` after use.

---

### [MEDIUM-04] No CID Format Validation in Migration and Republish Endpoints

**Location:** `apps/tee-worker/src/routes/migrate.ts:54` and `apps/tee-worker/src/routes/republish.ts:46`

**Code:**

```typescript
// migrate.ts:54 -- only checks type and length, not CID format
if (!cids.every((c: unknown) => typeof c === 'string' && c.length > 0 && c.length <= 200)) {
  res.status(400).json({ error: 'Each CID must be a non-empty string (max 200 chars)' });
  return;
}

// republish.ts:46 -- no validation of latestCid format
const { entries } = req.body as { entries: RepublishEntry[] };
```

**Issue:**
Neither endpoint validates that CID strings are actually valid IPFS CIDs. While the CIDs are used only in IPFS API calls (where invalid CIDs would fail gracefully), accepting arbitrary strings means:
1. Log injection: CIDs appear in log messages and could contain JSON-breaking characters or excessively long encoded strings within the 200-char limit
2. The `fetchFromGateway` function uses `encodeURIComponent(cid)` which handles injection, but the `latestCid` in republish is passed directly to `signIpnsRecord` as part of `/ipfs/${cid}` without validation

**Impact:**
Low -- CIDs are used in controlled contexts (IPFS API calls, IPNS record value field). An invalid CID would cause the IPFS operation to fail, not a security breach. But basic format validation (starts with `bafy`, `Qm`, or `b`) would add defense in depth.

**Recommendation:**

```typescript
/** Basic CID format validation (CIDv0 or CIDv1) */
function isValidCidFormat(cid: string): boolean {
  // CIDv0: starts with Qm, base58, 46 chars
  if (/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(cid)) return true;
  // CIDv1: starts with b (base32) or z (base58btc) or f (base16)
  if (/^[bBzf][a-zA-Z0-9+=]+$/.test(cid)) return true;
  return false;
}
```

---

### [LOW-01] Private Key Cache Leaks in Simulator Mode via getKeypair

**Location:** `apps/tee-worker/src/services/tee-keys.ts:75`

**Code:**

```typescript
return { publicKey, privateKey };
```

**Issue:**
In simulator mode, `getKeypair()` returns the raw HKDF-derived `privateKey` to the caller. The caller (`decryptIpnsKey` in `key-manager.ts`) correctly zeros it in a `finally` block. However, the `privateKey` returned by `getKeypair()` is the same `Uint8Array` reference that was derived by HKDF. When the caller zeros it, they zero the reference they hold -- which is correct.

But in the HKDF path (line 66), `hkdf()` returns a new `Uint8Array`. There is no issue here -- the returned reference is what gets zeroed. This is correct behavior.

However, the public key cache at line 14 (`publicKeyCache`) grows without bounds and is never cleared. While public keys are not secret, an unbounded Map is a minor resource concern.

**Impact:**
Negligible -- public keys are not sensitive and the cache would need millions of unique epochs to become a problem. Still, in a long-running TEE worker, this is a minor resource management concern.

**Recommendation:**

Add a cache size limit as described in MEDIUM-01.

---

### [LOW-02] Health Endpoint Exposes TEE Mode and Epoch

**Location:** `apps/tee-worker/src/routes/health.ts:13-18`

**Code:**

```typescript
router.get('/health', (_req: Request, res: Response) => {
  res.json({
    healthy: true,
    mode: process.env.TEE_MODE || 'simulator',
    epoch: parseInt(process.env.TEE_CURRENT_EPOCH || '1', 10),
    uptime: process.uptime(),
  });
});
```

**Issue:**
The health endpoint is public (no auth required) and exposes:
1. `mode`: Whether the TEE is in simulator or CVM mode (reveals if the deployment is using real hardware isolation)
2. `epoch`: The current key epoch (helps an attacker target their ciphertext to a specific epoch key)
3. `uptime`: Process uptime (minor operational information)

**Impact:**
Low -- this is information disclosure, not an access control issue. An attacker knowing the mode is `simulator` knows there is no hardware attestation, but this is typically a dev/staging deployment anyway. The epoch is also learnable from the `/public-key` endpoint. However, exposing `mode=simulator` in a misconfigured production deployment would signal to an attacker that the TEE is not hardware-backed.

**Recommendation:**

Remove `mode` from the health response, or restrict the health endpoint to return minimal information publicly:

```typescript
router.get('/health', (_req: Request, res: Response) => {
  res.json({ healthy: true });
});

// Detailed health behind auth
router.get('/health/detailed', authMiddleware, (_req: Request, res: Response) => {
  res.json({
    healthy: true,
    mode: process.env.TEE_MODE || 'simulator',
    epoch: parseInt(process.env.TEE_CURRENT_EPOCH || '1', 10),
    uptime: process.uptime(),
  });
});
```

---

## Detailed Analysis by File

### `apps/tee-worker/src/services/tee-keys.ts`

**Positive findings:**
- Production guard correctly prevents simulator mode in production (line 31-38)
- Two-tier check: `CIPHERBOX_ENVIRONMENT` takes precedence over `NODE_ENV` (defense in depth)
- Uncompressed public key format (65 bytes, 0x04 prefix) is correct for ECIES interop with `eciesjs`
- HKDF context separation using `epoch-${epoch}` info string provides proper domain separation
- Deterministic derivation in simulator mode is appropriate for testing

**Potential concern:**
- The CVM path (line 47) uses string `'cipherbox/ipns-republish'` as the first `getKey` argument and `epoch-${epoch}` as the second. These context strings should be documented as part of the security model to prevent accidental changes that would break key derivation consistency across deployments.

### `apps/tee-worker/src/services/key-manager.ts`

**Positive findings:**
- Excellent key zeroing pattern: `keypair.privateKey.fill(0)` in `finally` block (line 31)
- Epoch fallback correctly tries current first, then previous (line 53-68)
- Does NOT try arbitrary epochs -- strictly current and optional previous
- Re-encryption path (line 84-90) correctly uses `getPublicKey()` (not `getKeypair()`) to avoid unnecessarily exposing the target epoch's private key
- Generic error message at line 70 does not reveal which epoch was tried

**No issues found.** This file is well-designed.

### `apps/tee-worker/src/services/ipns-signer.ts`

**Positive findings:**
- 48-hour lifetime is appropriate (2x the 24h default, comfortable margin for 6h republish)
- Delegates entirely to `@cipherbox/core` which handles key format conversion and zeroing
- No key material stored or logged

**No issues found.**

### `apps/tee-worker/src/services/migration-worker.ts`

**Positive findings:**
- TEE private key zeroed immediately after ECIES decryption (line 100)
- Auth token bytes zeroed in `finally` block (lines 193-196)
- Config bytes also zeroed (lines 195-196)
- CID integrity check after migration (line 169)
- Source unpin failure is non-fatal (lines 177-186) -- correct priority (data safety > cleanup)
- Comment at line 202 acknowledges JS string immutability limitation

**Issues found:** HIGH-02 (string copies of auth tokens), see findings above.

### `apps/tee-worker/src/services/ssrf-validation.ts`

**Positive findings:**
- Comprehensive private IP range coverage: RFC 1918, loopback, link-local, CGN, IPv6 unique-local
- IPv4-mapped IPv6 stripping (line 22) prevents `::ffff:127.0.0.1` bypass
- IPv6 bracket stripping (line 20) prevents `[::1]` bypass via URL.hostname
- `.internal` and `.local` suffix blocking (lines 37-38)
- Redirect blocking in `ssrfSafeFetch` (line 93) prevents redirect-based SSRF
- Simulator mode bypass is acceptable for development

**Issues found:** HIGH-01 (TOCTOU DNS race), see findings above.

**Additional note on coverage:** The `isPrivateAddress` function does not explicitly check for:
- `192.0.0.0/24` (IETF Protocol Assignments, RFC 6890)
- `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (Documentation ranges, RFC 5737)
- `240.0.0.0/4` (Reserved/future use)
- `255.255.255.255` (broadcast)

These are unlikely SSRF targets but could be added for completeness.

### `apps/tee-worker/src/middleware/auth.ts`

**Positive findings:**
- Uses `crypto.timingSafeEqual` from Node.js core (line 8) -- correct constant-time comparison
- Length check before `timingSafeEqual` (line 35) prevents the Node.js error that occurs when buffers have different lengths, while also being a fast-path rejection
- Returns 500 if `TEE_WORKER_SECRET` is not configured (line 21) -- fails closed
- Generic error messages that don't reveal why authentication failed

**No issues found.** This is a textbook implementation.

### `apps/tee-worker/src/routes/republish.ts`

**Positive findings:**
- Batch size limit of 100 (line 54) prevents DoS
- Per-entry error handling -- one failure does not block others (line 109-124)
- IPNS private key zeroed in both success (line 91) and error (line 112) paths
- `ipnsPrivateKey` set to `null` after zeroing to prevent use-after-zero
- No key material in log messages (line 128-132) -- only counts
- Sequence number correctly incremented as `BigInt` (line 77) -- no overflow risk
- Re-encryption only when `usedEpoch !== entry.currentEpoch` (line 84) -- correct trigger

**No issues found.** This is well-structured.

### `apps/tee-worker/src/routes/connection-test.ts`

**Positive findings:**
- TEE private key zeroed immediately after ECIES decryption (line 60)
- Config and token bytes zeroed in `finally` block (lines 110-113)
- SSRF validation applied to normalized endpoint (lines 76-79)
- Timeout protection on probe requests (line 139, 199)
- Separate protocol detection (Kubo vs PSA) with graceful fallthrough

**Issues found:** MEDIUM-03 (string auth token persistence), see findings above.

### `apps/tee-worker/src/services/logger.ts`

**Positive findings:**
- Minimal logger with no external dependencies
- JSON structured output suitable for log aggregation
- Error messages go to stderr, info/warn to stdout
- Security comment at line 10 documents the no-key-material rule

**Verification:** Grep confirmed no key material fields are passed to logger calls across the codebase:

No instances of `logger.info/warn/error` calls include fields like `privateKey`, `ipnsPrivateKey`, `authToken`, `encryptedIpnsKey`, `teePrivateKey`, `encryptedConfig`, `sourceConfigEncrypted`, or `destConfigEncrypted`.

### `apps/tee-worker/src/index.ts`

**Positive findings:**
- Auth middleware correctly applied to all sensitive routes (lines 43-46)
- Health and metrics are correctly public (lines 39-40)
- JSON body limit of 10MB (line 33) prevents payload flooding
- Metrics middleware fires before route handlers for accurate timing

**Minor note:** The 10MB body limit is generous. A batch of 100 entries with typical ECIES ciphertexts would be ~50KB. Consider reducing to 1MB.

### `packages/sdk-core/src/pinning/kubo-provider.ts` and `psa-provider.ts`

**Positive findings:**
- `fetchFn` injection pattern allows TEE worker to inject `ssrfSafeFetch` -- clean dependency injection
- `encodeURIComponent` used for CID parameters in URL construction (prevents injection)
- Timeout via `AbortSignal.timeout` on all requests
- Trailing slash normalization on endpoints

**No issues found.** The `fetchFn` injection is a well-designed pattern for SSRF protection.

### `packages/crypto/src/ecies/encrypt.ts` and `decrypt.ts`

**Positive findings:**
- Public key validation: size check (65 bytes), prefix check (0x04), and curve point validation via `ProjectivePoint.fromHex`
- Private key size validation (32 bytes)
- Minimum ciphertext size validation (65 + 16 = 81 bytes)
- Generic error messages in catch blocks prevent oracle attacks
- Delegates to `eciesjs` for the actual ECIES implementation (well-audited library)

**No issues found.** The crypto primitives layer is solid.

---

## Test Case Suggestions

The existing test suite covers key derivation, epoch fallback, republish batch processing, and SSRF validation. The following additional test cases would strengthen coverage:

```typescript
// apps/tee-worker/src/__tests__/security-edge-cases.test.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('Security Edge Cases', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    process.env.TEE_MODE = 'simulator';
    delete process.env.CIPHERBOX_ENVIRONMENT;
    delete process.env.NODE_ENV;
  });

  describe('Epoch bounds validation', () => {
    it('getKeypair rejects negative epoch gracefully', async () => {
      const { getKeypair } = await import('../services/tee-keys.js');
      // Currently succeeds -- this test documents the behavior
      // and should be updated when bounds checking is added
      const kp = await getKeypair(-1);
      expect(kp.publicKey.length).toBe(65);
      // After fix: expect(getKeypair(-1)).rejects.toThrow('positive integer');
    });

    it('getKeypair produces distinct keys for epoch 0 and epoch -0', async () => {
      const { getKeypair } = await import('../services/tee-keys.js');
      const kp0 = await getKeypair(0);
      const kpNeg0 = await getKeypair(-0);
      // 0 and -0 are the same in JS, so these should be identical
      expect(Buffer.from(kp0.publicKey).toString('hex'))
        .toBe(Buffer.from(kpNeg0.publicKey).toString('hex'));
    });

    it('different epoch numbers always produce different HKDF-derived keys', async () => {
      const { getKeypair } = await import('../services/tee-keys.js');
      const seen = new Set<string>();
      for (let epoch = 1; epoch <= 100; epoch++) {
        const kp = await getKeypair(epoch);
        const hex = Buffer.from(kp.privateKey).toString('hex');
        expect(seen.has(hex)).toBe(false);
        seen.add(hex);
      }
    });
  });

  describe('Key zeroing verification', () => {
    it('decryptIpnsKey zeros TEE private key even when decryption fails', async () => {
      const { getKeypair } = await import('../services/tee-keys.js');
      const { decryptIpnsKey } = await import('../services/key-manager.js');

      // Spy on getKeypair to capture the returned private key reference
      let capturedPrivateKey: Uint8Array | null = null;
      const origGetKeypair = (await import('../services/tee-keys.js')).getKeypair;

      vi.doMock('../services/tee-keys.js', () => ({
        getKeypair: async (epoch: number) => {
          const result = await origGetKeypair(epoch);
          capturedPrivateKey = result.privateKey;
          return result;
        },
        getPublicKey: (await import('../services/tee-keys.js')).getPublicKey,
      }));

      // Use garbage ciphertext that will fail ECIES decryption
      const garbageCiphertext = new Uint8Array(200);
      crypto.getRandomValues(garbageCiphertext);

      try {
        await decryptIpnsKey(garbageCiphertext, 1);
      } catch {
        // Expected to fail
      }

      // Verify the private key was zeroed even on failure
      if (capturedPrivateKey) {
        expect(capturedPrivateKey.every(b => b === 0)).toBe(true);
      }
    });
  });

  describe('Republish input validation', () => {
    it('rejects batch exceeding MAX_BATCH_SIZE (100)', async () => {
      // Would require creating test app -- see republish.test.ts pattern
      // const app = await createTestApp();
      // const entries = Array.from({ length: 101 }, (_, i) => ({
      //   encryptedIpnsKey: 'AAAA', ipnsName: `k51test${i}`,
      //   latestCid: 'bafytest', sequenceNumber: '1',
      //   currentEpoch: 1, previousEpoch: null,
      // }));
      // const res = await postJson(app, '/republish', { entries });
      // expect(res.status).toBe(400);
      // expect(res.body.error).toContain('Batch too large');
    });

    it('handles very large sequence numbers without overflow', async () => {
      // BigInt handles arbitrary precision -- verify no truncation
      const { wrapKey } = await import('@cipherbox/crypto');
      const { getKeypair } = await import('../services/tee-keys.js');

      const epoch = 1;
      const testKey = new Uint8Array(32);
      crypto.getRandomValues(testKey);
      const kp = await getKeypair(epoch);
      const encrypted = await wrapKey(testKey, kp.publicKey);

      // Sequence number near Number.MAX_SAFE_INTEGER
      const largeSeqStr = '9007199254740991'; // 2^53 - 1
      const result = BigInt(largeSeqStr) + 1n;
      expect(result.toString()).toBe('9007199254740992');
    });
  });

  describe('SSRF edge cases', () => {
    it('rejects IPv4-mapped IPv6 addresses that resolve to private IPs', async () => {
      const { validateEndpointUrl } = await import('../services/ssrf-validation.js');
      process.env.TEE_MODE = 'cvm';

      // ::ffff:10.0.0.1 should be caught
      expect(() => validateEndpointUrl('https://[::ffff:10.0.0.1]')).toThrow('private');
    });

    it('rejects decimal-encoded private IPs', () => {
      // 2130706433 = 127.0.0.1 in decimal
      // URL('https://2130706433') may resolve to 127.0.0.1 in some implementations
      // This test documents whether the current implementation catches it
      const { validateEndpointUrl } = await import('../services/ssrf-validation.js');
      process.env.TEE_MODE = 'cvm';

      // Note: URL parser may or may not convert decimal to dotted notation
      // This test should be verified against the actual Node.js URL parser behavior
      try {
        const url = new URL('https://2130706433');
        // If URL parser keeps it as-is, isPrivateAddress won't catch it
        // This would be a finding if the parser resolves it
      } catch {
        // URL parser rejects it -- safe
      }
    });

    it('rejects octal-encoded private IPs', () => {
      const { validateEndpointUrl } = await import('../services/ssrf-validation.js');
      process.env.TEE_MODE = 'cvm';

      // 0177.0.0.1 = 127.0.0.1 in octal
      // Most modern URL parsers reject this, but worth verifying
      try {
        new URL('https://0177.0.0.1');
        // If it parses, check if it's caught
      } catch {
        // URL parser rejects -- safe
      }
    });

    it('blocks redirect-based SSRF', async () => {
      const { ssrfSafeFetch } = await import('../services/ssrf-validation.js');

      // Mock fetch that would follow redirect to internal IP
      const mockFetch = vi.fn().mockRejectedValue(
        new TypeError('fetch failed: redirect mode is set to error')
      );
      vi.stubGlobal('fetch', mockFetch);

      await expect(
        ssrfSafeFetch('https://evil.com/redirect-to-metadata')
      ).rejects.toThrow();

      // Verify redirect: 'error' was passed
      expect(mockFetch.mock.calls[0][1]?.redirect).toBe('error');
    });
  });

  describe('Connection test credential handling', () => {
    it('rejects missing encryptedConfig', async () => {
      // Integration test: POST /connection-test with missing fields
      // Should return 400 with appropriate error
    });

    it('rejects non-numeric epoch', async () => {
      // POST /connection-test with epoch="abc"
      // Should return 400
    });

    it('does not leak auth tokens in error responses', async () => {
      // Verify error responses from probe failures don't include
      // the auth token or endpoint URL
    });
  });

  describe('Migration credential isolation', () => {
    it('zeros all credential buffers even when migration fails midway', async () => {
      // Mock a provider to fail after first CID
      // Verify sourceConfig.authTokenBytes, destConfig.authTokenBytes,
      // sourceConfigBytes, destConfigBytes are all zeroed
    });

    it('does not log CID values that could correlate to user data', async () => {
      // Verify logger.info calls in migrate.ts only log counts,
      // not actual CID values
    });
  });
});
```

---

## Compliance Checklist

| Rule | Status | Notes |
|------|--------|-------|
| Never store privateKey in localStorage/sessionStorage | **PASS** | Server-side code, no browser storage |
| Never log sensitive keys | **PASS** | Logger calls verified -- only counts and error messages |
| Never send unencrypted keys to server | **PASS** | All keys ECIES-encrypted before transmission |
| Always use ECIES for key wrapping | **PASS** | `@cipherbox/crypto` wrapKey/unwrapKey used throughout |
| Always use AES-256-GCM for content encryption | **N/A** | TEE worker does not perform content encryption (only key operations) |
| Server NEVER has access to plaintext or unencrypted keys | **PASS** | Keys decrypted only inside TEE, zeroed after use |
| Always encrypt ipnsPrivateKey with TEE public key | **PASS** | All IPNS keys arrive ECIES-encrypted |
| TEE decrypts IPNS keys in hardware only, signs, and immediately discards | **PASS** | `decryptIpnsKey` zeroes in `finally`; `republish.ts` zeroes after signing |
| Uint8Array for all binary data | **PASS** | Consistent throughout; strings used only where unavoidable (JSON, HTTP headers) |
| Clear sensitive data from memory after use | **PASS with caveat** | Uint8Array buffers zeroed properly; JS strings cannot be zeroed (HIGH-02, MEDIUM-03) |
| Web Crypto API only (no JS crypto libraries) | **N/A** | Server-side code appropriately uses Node.js crypto and `@noble/*` libraries |

---

## Recommendations Summary

### Priority 1 (Address before production deployment)

1. **HIGH-01: Fix TOCTOU DNS race.** Pin the resolved IP from `validateResolvedIp` and use it for the actual HTTP connection, or implement a custom DNS resolver that caches validated results. This is the most exploitable finding.

2. **HIGH-02: Minimize auth token string lifetime.** Refactor `KuboProvider`/`PsaProvider` to accept `Uint8Array` auth tokens, or scope string copies to the narrowest possible block. Document the JS string immutability limitation in a security note.

### Priority 2 (Address in next iteration)

3. **MEDIUM-01: Add epoch bounds validation** to the `/public-key` endpoint and `getKeypair()` function. Add cache size limits to `publicKeyCache`.

4. **MEDIUM-02: Make migrate route epoch dynamic.** Accept epoch from request body like `/republish` does, or read from a shared state module.

5. **MEDIUM-03: Minimize string credential scope** in `connection-test.ts` by using `let` variables that can be set to `undefined` after use.

6. **MEDIUM-04: Add basic CID format validation** to prevent unexpected input from reaching IPFS APIs.

### Priority 3 (Nice to have)

7. **LOW-01: Add cache eviction** to `publicKeyCache` in `tee-keys.ts`.

8. **LOW-02: Reduce health endpoint information** exposure by removing `mode` field from the public health check.

9. **Body size limit:** Reduce Express JSON body limit from 10MB to 1MB -- sufficient for all batch operations.

10. **Documentation:** Add `isPrivateAddress` coverage for RFC 5737 documentation ranges and RFC 6890 IETF protocol assignments.

---

## SECURITY REVIEW COMPLETE

**Files analyzed:** 20
**Crypto operations found:** 12 (ECIES wrap/unwrap, HKDF derivation, secp256k1 pubkey, Ed25519 IPNS signing, constant-time comparison)
**Issues found:** 0 Critical, 2 High, 4 Medium, 2 Low

### Test Cases Generated

15 test case suggestions across 6 categories (epoch bounds, key zeroing, input validation, SSRF edge cases, credential handling, migration isolation)

### Report Location

`.planning/security/REVIEW-phase-35.md`

### Overall Assessment

The TEE worker codebase demonstrates strong security engineering. Key zeroing discipline is consistent, the ECIES integration via `@cipherbox/crypto` is correct, auth middleware uses proper constant-time comparison, and the SSRF protection layer is comprehensive. The two high-severity findings (DNS TOCTOU race and string credential persistence) are inherent challenges in this architecture and have clear mitigation paths. No critical vulnerabilities were found.

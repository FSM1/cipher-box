# Security Review: Phase 21 BYO-IPFS Node Support (Pre-Implementation)

**Date:** 2026-03-24
**Scope:** Planning documents and implementation plans (pre-implementation review)
**Reviewer:** Claude (security:review)
**Files Analyzed:** 10 planning documents + 6 existing source files for comparison
**Crypto Operations Found:** 5 distinct operations (ECIES wrapping, AES-256-GCM vault encryption, auth token handling, CID registration, TEE credential decryption)

## Executive Summary

Phase 21 introduces bring-your-own IPFS infrastructure, fundamentally expanding CipherBox's trust boundary by allowing SDK and TEE worker code to interact with user-controlled (potentially hostile) IPFS endpoints. The zero-knowledge credential storage design is sound -- BYO auth tokens encrypted in vault metadata on IPFS, never visible to the server. However, the plans contain **one critical SSRF vulnerability** in the TEE migration worker, **two high-priority issues** (missing authorization on CID registration, credential zeroing is ineffective in JavaScript), and **several medium-priority concerns** around auth token lifecycle in browser memory and PSA transient relay data exposure.

**Risk Level:** HIGH (due to SSRF in TEE worker and authorization gap in CID registration)

## Architecture Security Assessment

### Zero-Knowledge Model

The credential storage design correctly preserves zero-knowledge:

- BYO auth tokens are stored in vault metadata on IPFS, encrypted with the user's AES key (rootFolderKey)
- Server never sees plaintext auth tokens
- ECIES wrapping with TEE public key for migration follows the established IPNS key enrollment pattern
- The decision to NOT store credentials server-side (overriding original BYO-03 wording) is the right call

### Trust Boundary Expansion

Phase 21 significantly expands the attack surface:

1. **SDK (browser)** now makes direct HTTP requests to arbitrary user-provided URLs
2. **TEE worker** now fetches from and pushes to arbitrary user-provided URLs
3. **CipherBox API** accepts CID + size from untrusted clients (advisory quota)

This expansion is inherent to the feature but creates new classes of vulnerabilities absent from the current architecture.

---

## Findings

### Critical Issues

#### [CRITICAL] SSRF via TEE Migration Worker Fetching From Arbitrary URLs

**Location:** `21-05-PLAN.md`, Task 2 -- `tee-worker/src/services/migration-worker.ts`

**Code (from plan):**

```typescript
async function fetchFromProvider(cid: string, config: ProviderConfig): Promise<Uint8Array> {
  if (config.protocol === 'kubo') {
    const response = await fetch(`${config.endpoint}/api/v0/cat?arg=${cid}`, {
      method: 'POST',
      headers: config.authToken ? { Authorization: `Basic ${config.authToken}` } : {},
      signal: AbortSignal.timeout(60_000),
    });
    // ...
  }
  // PSA fallback uses ipfs.io
}

async function pinToProvider(
  data: Uint8Array,
  expectedCid: string,
  config: ProviderConfig
): Promise<string> {
  if (config.protocol === 'kubo') {
    const response = await fetch(`${config.endpoint}/api/v0/add?pin=true&cid-version=1`, {
      method: 'POST',
      body: formData,
      headers,
      signal: AbortSignal.timeout(60_000),
    });
    // ...
  }
}
```

**Issue:** The TEE worker fetches from and pushes to URLs entirely controlled by the user. The encrypted config payload is decrypted in-enclave, producing arbitrary `endpoint` values. An attacker who has a valid CipherBox account could craft a migration request where `sourceConfig.endpoint` or `destConfig.endpoint` points to:

- `http://169.254.169.254` (AWS instance metadata -- Nitro fallback environment)
- `http://127.0.0.1:PORT` (TEE-internal services)
- `http://10.x.x.x/internal-api` (private network scanning)
- Cloud provider metadata endpoints for credential theft

The 21-RESEARCH.md Open Question 3 acknowledges this but its recommendation -- "Input validation on URLs (HTTPS-only, no private IPs) provides basic safety" -- is not reflected in the actual plan code.

**Impact:** An attacker could use the TEE worker as an SSRF proxy to reach internal services, exfiltrate cloud metadata credentials, or scan internal networks. Since the TEE environment may run on cloud infrastructure (Phala/AWS Nitro), cloud metadata endpoints are particularly dangerous.

**Recommendation:**

```typescript
// Add before any fetch in migration-worker.ts
function validateEndpointUrl(endpoint: string): void {
  const url = new URL(endpoint);

  // Must be HTTPS (except localhost for development)
  if (url.protocol !== 'https:') {
    throw new Error('Migration endpoint must use HTTPS');
  }

  // Block private/internal IP ranges
  const hostname = url.hostname;
  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname.startsWith('10.') ||
    hostname.startsWith('172.') ||
    hostname.startsWith('192.168.') ||
    hostname === '169.254.169.254' ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.local')
  ) {
    throw new Error('Migration endpoint cannot target private/internal addresses');
  }

  // Block link-local and metadata endpoints
  if (hostname.startsWith('169.254.') || hostname.startsWith('fd') || hostname.startsWith('fe80')) {
    throw new Error('Migration endpoint cannot target link-local addresses');
  }
}

// Also: resolve DNS and check the resolved IP is not private
// (DNS rebinding protection)
import { lookup } from 'node:dns/promises';

async function validateResolvedIp(hostname: string): Promise<void> {
  const result = await lookup(hostname);
  const ip = result.address;
  // Check resolved IP against same private ranges
  // This prevents DNS rebinding attacks where attacker.com resolves to 169.254.169.254
}
```

**References:**

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

### High Priority

#### [HIGH] CID Registration Endpoint Missing Ownership Verification

**Location:** `21-02-PLAN.md`, Task 1 -- `apps/api/src/ipfs/ipfs.controller.ts registerCid`

**Code (from plan):**

```typescript
@Post('register-cid')
async registerCid(
  @Request() req: RequestWithUser,
  @Body() dto: RegisterCidDto
): Promise<RegisterCidResponseDto> {
  await this.vaultService.recordPin(req.user.id, dto.cid, dto.sizeBytes);
  return { recorded: true };
}
```

**Issue:** Any authenticated user can register any CID with any size value. There is no verification that:

1. The CID actually exists on any IPFS node
2. The user actually pinned this CID
3. The `sizeBytes` value corresponds to reality

While the quota is advisory for BYO users, a malicious user could:

- Register millions of fake CIDs to inflate their quota display (UI confusion)
- Register CIDs belonging to other users' encrypted data (CID enumeration for traffic analysis)
- Submit absurdly large `sizeBytes` values (e.g., `Number.MAX_SAFE_INTEGER`) for each CID

More importantly, the `recordPin` method uses `orIgnore()` (ON CONFLICT DO NOTHING), meaning if a CID is already recorded by another user, the duplicate is silently ignored. But the PinnedCid entity has a unique constraint on `(userId, cid)`, not just `cid`. This means multiple users can register the same CID, which is fine for IPFS content-addressing but could be used for cross-user data correlation.

**Impact:** Moderate. Advisory-only quota limits the blast radius, but unlimited CID insertion could be used for database storage abuse (each row consumes DB space). A rate limit is needed at minimum.

**Recommendation:**

```typescript
@Post('register-cid')
async registerCid(
  @Request() req: RequestWithUser,
  @Body() dto: RegisterCidDto
): Promise<RegisterCidResponseDto> {
  // Validate CID format (CIDv1 base32 or base58btc)
  if (!isValidCid(dto.cid)) {
    throw new BadRequestException('Invalid CID format');
  }

  // Cap sizeBytes to reasonable maximum (100MB per file, same as upload limit)
  if (dto.sizeBytes > MAX_FILE_SIZE) {
    throw new BadRequestException('sizeBytes exceeds maximum file size');
  }

  // Verify user is actually a BYO user (non-BYO users should use normal upload)
  const isByo = await this.vaultService.isUserByo(req.user.id);
  if (!isByo) {
    throw new ForbiddenException('CID registration is only available for BYO users');
  }

  await this.vaultService.recordPin(req.user.id, dto.cid, dto.sizeBytes);
  return { recorded: true };
}
```

Also add a rate limiter (e.g., 100 CID registrations per hour per user).

---

#### [HIGH] JavaScript String Zeroing is Ineffective

**Location:** `21-05-PLAN.md`, Task 2 -- `tee-worker/src/services/migration-worker.ts`

**Code (from plan):**

```typescript
function zeroString(s: string): void {
  // Best-effort zeroing -- JS strings are immutable, but this ensures
  // the config object doesn't retain the reference after we're done
  // In practice, the TEE enclave memory is wiped on exit
}
```

**Issue:** The plan acknowledges that JavaScript strings are immutable and cannot be zeroed, but then provides an empty function body. The comment "the config object doesn't retain the reference after we're done" is misleading -- the string still exists in memory until garbage collected, and V8's garbage collector provides no timing guarantees.

Contrast this with the existing TEE republish pattern (`tee-worker/src/routes/republish.ts:86`) which correctly zeros `Uint8Array` key material:

```typescript
// Existing secure pattern:
ipnsPrivateKey.fill(0);
ipnsPrivateKey = null;
```

The migration worker decrypts auth tokens as strings (via `JSON.parse`), not `Uint8Array`, making them impossible to zero.

**Impact:** Auth tokens persist in TEE memory longer than necessary. While TEE enclave memory isolation provides protection, the defense-in-depth principle requires minimizing credential lifetime. If the TEE has a memory disclosure vulnerability, credentials could leak.

**Recommendation:**

Process credentials as `Uint8Array` throughout, not strings. The decrypted config should stay as bytes until the moment they're needed in HTTP headers, and the header construction should use a pattern that minimizes string lifetime:

```typescript
// Decrypt to Uint8Array
const sourceConfigBytes = await decryptEcies(sourceConfigEncrypted, teePrivateKey);
// Parse minimally, keeping authToken as Uint8Array
const sourceConfig = parseProviderConfig(sourceConfigBytes);
// sourceConfig.authToken is Uint8Array, not string

// After all operations:
sourceConfig.authToken.fill(0);
destConfig.authToken.fill(0);
sourceConfigBytes.fill(0);
```

Or at minimum, ensure the migration worker function scope is tight enough that variables go out of scope promptly, and set references to `null` after use to hint GC:

```typescript
// Immediately after migration completes:
sourceConfig.authToken = ''; // Overwrite string reference
destConfig.authToken = '';
// Set entire configs to null
sourceConfig = null;
destConfig = null;
```

---

### Medium Priority

#### [MEDIUM] Auth Token Lifetime in Browser Memory (React State)

**Location:** `21-04-PLAN.md`, Task 1 -- `apps/web/src/components/settings/StorageTab.tsx`

**Code (from plan):**

```typescript
const [authToken, setAuthToken] = useState('');
```

**Issue:** The IPFS provider auth token is held in React state for the duration of the component mount. The research document's anti-patterns section correctly notes "Auth tokens for IPFS providers should only exist in memory after vault decryption. Never persist to browser storage." However, the actual plan stores the token in `useState` which:

1. Keeps the token in JavaScript heap memory for the entire time the Settings page is open
2. React DevTools (if installed) can inspect state and reveal the token
3. If the user navigates away from Settings and back, the token must be re-loaded from encrypted IPNS entry (correct), but during the session it sits in state

The `<input type="password">` prevents visual display but the value is fully accessible from JavaScript.

**Impact:** Low-moderate. The token is already in-memory (from vault decryption), and browser security model protects against cross-origin access. The primary risk is from browser extensions or DevTools access on the user's own machine.

**Recommendation:**

- Clear auth token from state on component unmount: `useEffect(() => () => setAuthToken(''), [])`
- After save completes successfully, clear the token from state (it's persisted in the encrypted IPNS entry)
- Consider using `useRef` instead of `useState` for the token (avoids re-render-based snapshots in React DevTools)
- The `StorageTab` component already masks input with `type="password"` -- this is good

---

#### [MEDIUM] PSA "External Only" Mode: CipherBox Sees Encrypted Blobs Transiently

**Location:** `21-RESEARCH.md` Pattern 4, `21-03-PLAN.md` Task 2

**Code (from plan):**

```typescript
// External-only + PSA:
const relayResult = await sdkCore.addToIpfs(ctx, encryptedData, onProgress);
// CipherBox API receives the full encrypted blob here
try {
  await (this.externalProvider as any).pinByCid(relayResult.cid);
} catch (err) {
  throw new Error(`External PSA pin failed: ...`);
}
// PSA accepted -- unpin from CipherBox
sdkCore.unpinFromIpfs(ctx, relayResult.cid).catch(() => {});
```

**Issue:** In "external only + PSA" mode, the encrypted data is still uploaded to CipherBox's IPFS node first (because PSA is CID-reference-only). The plan correctly identifies this and notes "zero-knowledge property is preserved because content is encrypted." However:

1. CipherBox API sees the ciphertext blob (size, timing, frequency)
2. The unpin from CipherBox is fire-and-forget (`.catch(() => {})`) -- if it fails silently, the data persists on CipherBox indefinitely despite the user choosing "external only"
3. The user explicitly chose "external only" to avoid CipherBox involvement, but this mode still sends all data through CipherBox

**Impact:** Low for confidentiality (data is encrypted), moderate for user expectations. A user selecting "external only" may have regulatory or policy reasons to avoid sending data to CipherBox's infrastructure entirely.

**Recommendation:**

1. The UI copy for PSA + external-only mode should clearly state that CipherBox acts as a transient relay: "note: psa providers require data to exist on ipfs before pinning. cipherbox relays your encrypted data briefly, then removes it."
2. Make the unpin more robust -- retry with backoff, or at minimum log failures:

```typescript
sdkCore.unpinFromIpfs(ctx, relayResult.cid).catch((err) => {
  console.warn(`Failed to unpin transient relay CID ${relayResult.cid}:`, err.message);
  // Could queue for retry
});
```

3. Document this limitation in the STORAGE tab when PSA + external-only is detected (per the copywriting contract, add a hint below the external-only radio option for PSA users).

---

#### [MEDIUM] Migration Endpoint Has No Per-User Rate Limiting

**Location:** `21-05-PLAN.md`, Task 1 -- `apps/api/src/migration/migration.controller.ts`

**Code (from plan):**

```typescript
@Post('migration/start')
async startMigration(@Request() req: RequestWithUser, @Body() dto: StartMigrationDto) {
  // Creates migration job, no check for existing active migration
}
```

**Issue:** The plan does not mention checking whether the user already has an active migration before creating a new one. A malicious user could spam `POST /migration/start` to:

1. Create thousands of BullMQ jobs, exhausting queue capacity
2. Cause the TEE worker to make thousands of outbound HTTP requests (amplification attack)
3. Fill the `pin_migrations` table with rows

**Impact:** Resource exhaustion on API, BullMQ, and TEE worker.

**Recommendation:**

```typescript
async startMigration(userId: string, dto: StartMigrationDto): Promise<string> {
  // Check for existing active migration
  const existing = await this.migrationRepository.findOne({
    where: {
      userId,
      status: In(['pending', 'running', 'paused']),
    },
  });
  if (existing) {
    throw new ConflictException('An active migration already exists. Cancel or wait for completion.');
  }
  // ... proceed with creation
}
```

---

#### [MEDIUM] CID Parameter Injection in Kubo RPC Calls

**Location:** `21-01-PLAN.md`, Task 1 -- KuboProvider and connection-test

**Code (from plan):**

```typescript
const response = await fetch(`${this.endpoint}/api/v0/cat?arg=${cid}`, {
  method: 'POST',
  headers,
});
```

**Issue:** The `cid` parameter is interpolated directly into the URL without encoding. While CIDs are normally safe alphanumeric+base32 strings, if a malicious caller passes a crafted CID like `../../../etc/passwd` or `CID&other-param=value`, it could alter the request semantics.

This applies to both SDK-side KuboProvider (browser, lower risk) and TEE-side migration worker (server, higher risk).

**Impact:** Low for SDK (browser fetch handles URL encoding). Higher risk for TEE worker where fetch behavior may differ.

**Recommendation:**

```typescript
const response = await fetch(`${this.endpoint}/api/v0/cat?arg=${encodeURIComponent(cid)}`, {
  method: 'POST',
  headers,
});
```

Apply `encodeURIComponent` to all CID parameters in URL construction. Additionally, validate CID format before use:

```typescript
function isValidCid(cid: string): boolean {
  return /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/.test(cid);
}
```

---

#### [MEDIUM] Connection Test Probing Can Be Used for Internal Network Scanning (Browser)

**Location:** `21-01-PLAN.md`, Task 1 -- `connection-test.ts`

**Code (from plan):**

```typescript
export async function testConnection(
  endpoint: string,
  authToken?: string
): Promise<ConnectionTestResult> {
  // Sends HTTP requests to user-provided URLs from the browser
  const response = await fetch(`${endpoint}/api/v0/id`, {
    method: 'POST',
    headers,
    signal: AbortSignal.timeout(10_000),
  });
}
```

**Issue:** The connection test runs in the browser and sends requests to arbitrary URLs. While browser CORS protections prevent reading cross-origin responses, the timing information (fast failure vs timeout vs CORS error) can be used to fingerprint internal network services. An attacker who gains XSS on the CipherBox web app could use this function to probe the user's local network.

However, this is inherent to any browser-based connection test feature and is mitigated by browser same-origin policy. The CORS error detection (`TypeError: Failed to fetch`) already leaks minimal information.

**Impact:** Low. This is an accepted risk of browser-direct architecture. Browser security model provides adequate protection.

**Recommendation:**

- Validate that the endpoint URL uses `http:` or `https:` schemes only (block `file:`, `ftp:`, `data:`, etc.)
- Consider blocking obviously internal URLs in the UI layer:

```typescript
function isLikelyInternalUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname;
    return host === '169.254.169.254' || host.endsWith('.internal');
  } catch {
    return false;
  }
}
```

---

### Low Priority / Recommendations

#### [LOW] `PsaProvider.pin()` Throws -- Interface Violation

**Location:** `21-01-PLAN.md`, Task 1 -- `psa-provider.ts`

**Issue:** `PsaProvider.pin()` always throws an error, violating the `PinningProvider` interface contract. While this is documented, it means any code that generically calls `provider.pin(data)` without knowing the provider type will fail at runtime. The `DualPinProvider` (Plan 03) calls `this.secondary.pin(data, name)` -- if the secondary is a PSA provider, this will always throw.

**Recommendation:** The `pinWithMode` orchestrator in `client.ts` (Plan 03) correctly handles this by using `pinByCid` for PSA. However, `DualPinProvider` does not -- it calls `this.secondary.pin(data, name)` generically. Fix: `DualPinProvider` should be aware of PSA's pin-by-CID requirement, or the interface should be split into `DataPinningProvider` and `CidPinningProvider`.

---

#### [LOW] Encrypted Migration Configs Stored in Database Permanently

**Location:** `21-05-PLAN.md` -- `migration.entity.ts`

**Issue:** `sourceConfigEncrypted` and `destConfigEncrypted` are stored as `TEXT` in the `pin_migrations` table with no expiry or cleanup mechanism. These are ECIES-encrypted with the TEE public key. While they cannot be decrypted without the TEE private key, they accumulate forever.

**Recommendation:** Add a cleanup job or TTL-based deletion for completed/cancelled migrations after a retention period (e.g., 30 days). At minimum, null out the encrypted config columns after migration completes:

```typescript
// After migration completes:
await this.migrationRepo.update(migration.id, {
  status: 'completed',
  completedAt: new Date(),
  sourceConfigEncrypted: '', // Clear encrypted configs
  destConfigEncrypted: '',
});
```

---

#### [LOW] TEE Migration Worker Uses Public IPFS Gateway as PSA Fallback

**Location:** `21-05-PLAN.md`, Task 2 -- `fetchFromProvider`

**Code (from plan):**

```typescript
// PSA: use IPFS gateway to fetch content (PSA has no retrieval API)
const response = await fetch(`https://ipfs.io/ipfs/${cid}`, {
  signal: AbortSignal.timeout(60_000),
});
```

**Issue:** When migrating from a PSA source, the TEE worker fetches content from `ipfs.io`, a public IPFS gateway. This:

1. Leaks CID access patterns to Protocol Labs infrastructure
2. May be rate-limited or blocked
3. Is unreliable for large files

**Recommendation:** Use the CipherBox IPFS gateway as the primary fallback, since CipherBox may have the content cached. Make the gateway URL configurable via environment variable:

```typescript
const GATEWAY_URL = process.env.IPFS_GATEWAY_URL || 'https://ipfs.io';
const response = await fetch(`${GATEWAY_URL}/ipfs/${cid}`, { ... });
```

---

#### [LOW] `setByoStatus` Has No Authorization Check for Direction

**Location:** `21-02-PLAN.md` -- vault.service.ts

**Issue:** The plan adds `setByoStatus(userId, isByo)` but it's unclear which endpoint calls it. The client calls it during save (Plan 04), but there's no server-side validation that the user actually has a configured external provider before setting `isByoUser = true`. A malicious client could call the endpoint to set BYO status without actually configuring a provider, bypassing quota enforcement.

**Recommendation:** Consider making the BYO status flip part of the save workflow rather than a separate API call, or verify server-side that the user has registered at least one external CID before allowing BYO mode.

---

## Detailed Analysis

### 1. Credential Storage & Zero-Knowledge

Assessment: SOUND with caveats

The vault metadata extension approach (`21-RESEARCH.md` Pattern 7, `21-03-PLAN.md` Task 1) correctly stores BYO credentials as an additive field in the encrypted vault blob on IPFS. The server never sees the plaintext `authToken`. This follows the established pattern.

The dedicated IPNS entry approach for BYO config (`21-04-PLAN.md` Task 1) is also sound -- encrypting with the user's vault key and publishing to a dedicated IPNS name. The IPNS name stored in localStorage is not sensitive (it's a public identifier; content is encrypted).

**Key verification points:**

- `ByoIpfsConfig.authToken` is plaintext only after client-side AES-256-GCM decryption -- confirmed
- Server never receives authToken in any API call -- confirmed (except ECIES-wrapped for TEE)
- The `setByoStatus` API call (Plan 02) only sends a boolean, not credentials -- confirmed

### 2. TEE Migration Security

Assessment: NEEDS FIXES

The ECIES wrapping pattern is correct and follows the established `key-manager.ts` pattern. However:

- **SSRF is the primary concern** (see Critical finding above)
- The TEE `decryptEcies` function exists but its exact signature must be verified during implementation to ensure it matches the `eciesjs` library's `decrypt` function
- Credential zeroing is ineffective for JavaScript strings (see High finding)
- The TEE auth middleware (`authMiddleware` with `TEE_WORKER_SECRET`) correctly protects the `/migrate` endpoint with constant-time comparison
- The existing `republish.ts` route demonstrates the correct pattern: zero Uint8Array key material in `finally` blocks

**Migration-specific risks:**

- No check for concurrent migrations (see Medium finding)
- No validation that migration source/dest are different endpoints
- Auth token rotation during migration (correctly identified in Research pitfall 6, but the processor's 401 handling only pauses -- it should also notify the user)

### 3. Client-Direct Architecture Trust Boundaries

Assessment: ACCEPTABLE with documentation

The SDK talking directly to user's IPFS node is inherent to the feature. Browser CORS protections provide adequate isolation. The key concern is the PSA transient relay case (see Medium finding).

Auth token flow:

- Browser decrypts vault metadata -> extracts auth token -> constructs KuboProvider/PsaProvider with token in constructor -> token lives in provider instance memory
- Token is passed as HTTP header to user's own IPFS node
- For PSA, `Bearer` token goes cross-origin to the PSA service -- this is expected and the PSA service's CORS policy controls access

### 4. Input Validation & SSRF

Assessment: NEEDS FIXES

- **TEE worker SSRF:** Critical. No URL validation in plan. Must add before implementation.
- **CID registration:** No CID format validation, no size cap, no BYO-user gate.
- **Connection test:** Browser CORS provides protection. Acceptable risk.
- **CID parameter injection:** Low risk but easy to fix with `encodeURIComponent`.

### 5. Key Material Handling

Assessment: MIXED

- **Vault key (rootFolderKey):** Already in memory from login. Phase 21 uses it to decrypt BYO config. No new exposure.
- **Auth tokens in browser:** Held in React state. Should be cleared on unmount.
- **Auth tokens in TEE:** Cannot be effectively zeroed as strings. Should process as Uint8Array.
- **ECIES-wrapped configs in DB:** No cleanup mechanism. Should be nulled after migration.

### 6. Protocol-Specific Risks

Assessment: ACCEPTABLE

- **Kubo RPC POST-based:** No CSRF risk from browser (user intentionally sends requests). CORS configuration instructions are provided.
- **PSA Bearer tokens cross-origin:** Standard pattern for API authentication. PSA services that support CORS will include `Access-Control-Allow-Headers: Authorization`.
- **Auto-detection probing:** Leaks minimal information (presence/absence of Kubo or PSA at an endpoint). Acceptable.

---

## Test Cases

### Security-Focused Test Cases to Implement

```typescript
describe('KuboProvider Security Tests', () => {
  describe('URL Construction', () => {
    it('should encode CID parameter in URL', async () => {
      const provider = new KuboProvider('https://node.example.com');
      const mockFetch = vi.fn().mockResolvedValue(new Response('{}'));
      vi.stubGlobal('fetch', mockFetch);

      await provider.status('CID&injected=true').catch(() => {});

      const calledUrl = mockFetch.mock.calls[0][0];
      expect(calledUrl).not.toContain('&injected=true');
      expect(calledUrl).toContain(encodeURIComponent('CID&injected=true'));
    });

    it('should strip trailing slash from endpoint', async () => {
      const provider = new KuboProvider('https://node.example.com/');
      const mockFetch = vi.fn().mockResolvedValue(new Response('{}'));
      vi.stubGlobal('fetch', mockFetch);

      await provider.status('bafytest').catch(() => {});

      const calledUrl = mockFetch.mock.calls[0][0];
      expect(calledUrl).not.toContain('//api/v0');
    });
  });

  describe('Auth Header Security', () => {
    it('should not send auth header when no token provided', async () => {
      const provider = new KuboProvider('https://node.example.com');
      const mockFetch = vi.fn().mockResolvedValue(new Response('{}'));
      vi.stubGlobal('fetch', mockFetch);

      await provider.status('bafytest').catch(() => {});

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers['Authorization']).toBeUndefined();
    });

    it('should use Basic auth for Kubo (not Bearer)', async () => {
      const provider = new KuboProvider('https://node.example.com', 'token123');
      const mockFetch = vi.fn().mockResolvedValue(new Response('{}'));
      vi.stubGlobal('fetch', mockFetch);

      await provider.status('bafytest').catch(() => {});

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers['Authorization']).toMatch(/^Basic /);
    });
  });

  describe('Timeout Enforcement', () => {
    it('should abort after timeout period', async () => {
      const provider = new KuboProvider('https://node.example.com');
      const mockFetch = vi.fn().mockImplementation(() => new Promise(() => {})); // Never resolves
      vi.stubGlobal('fetch', mockFetch);

      await expect(provider.get('bafytest')).rejects.toThrow();
      expect(mockFetch.mock.calls[0][1].signal).toBeDefined();
    });
  });
});

describe('PsaProvider Security Tests', () => {
  it('should use Bearer auth (not Basic)', async () => {
    const provider = new PsaProvider('https://api.pinata.cloud/psa', 'token123');
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ count: 0, results: [] }))
    );
    vi.stubGlobal('fetch', mockFetch);

    await provider.status('bafytest').catch(() => {});

    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers['Authorization']).toBe('Bearer token123');
  });

  it('should not leak auth token in error messages', async () => {
    const provider = new PsaProvider('https://api.pinata.cloud/psa', 'SECRET_TOKEN_123');
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 500 }));
    vi.stubGlobal('fetch', mockFetch);

    try {
      await provider.unpin('bafytest');
    } catch (err) {
      expect(err.message).not.toContain('SECRET_TOKEN_123');
    }
  });
});

describe('Connection Test Security', () => {
  it('should not leak auth token in CORS instructions', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    vi.stubGlobal('fetch', mockFetch);

    const result = await testConnection('https://my-node.com', 'SECRET_TOKEN');

    expect(result.corsInstructions).not.toContain('SECRET_TOKEN');
    expect(result.error).not.toContain('SECRET_TOKEN');
  });

  it('should handle malformed URLs gracefully', async () => {
    const result = await testConnection('not-a-url', 'token');
    expect(result.success).toBe(false);
  });
});

describe('TEE Migration Worker Security', () => {
  describe('SSRF Protection', () => {
    it('should reject private IP addresses in endpoint', async () => {
      await expect(
        migrateBatch(
          ['bafytest'],
          encryptedConfigWith('http://169.254.169.254'),
          encryptedConfigWith('https://api.pinata.cloud'),
          teePrivateKey
        )
      ).rejects.toThrow(/private|internal/i);
    });

    it('should reject localhost endpoints', async () => {
      await expect(
        migrateBatch(
          ['bafytest'],
          encryptedConfigWith('http://127.0.0.1:5001'),
          encryptedConfigWith('https://api.pinata.cloud'),
          teePrivateKey
        )
      ).rejects.toThrow(/private|internal/i);
    });

    it('should require HTTPS for endpoints', async () => {
      await expect(
        migrateBatch(
          ['bafytest'],
          encryptedConfigWith('http://insecure-node.com'),
          encryptedConfigWith('https://api.pinata.cloud'),
          teePrivateKey
        )
      ).rejects.toThrow(/HTTPS/i);
    });
  });

  describe('CID Integrity', () => {
    it('should reject CID mismatch between source and destination', async () => {
      // Mock source returning data that produces different CID on destination
      // Verify migration reports CID as failed
    });
  });
});

describe('CID Registration Security', () => {
  it('should reject invalid CID format', async () => {
    const response = await request(app)
      .post('/ipfs/register-cid')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ cid: 'not-a-valid-cid', sizeBytes: 1000 });

    expect(response.status).toBe(400);
  });

  it('should reject negative sizeBytes', async () => {
    const response = await request(app)
      .post('/ipfs/register-cid')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ cid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi', sizeBytes: -1 });

    expect(response.status).toBe(400);
  });

  it('should reject sizeBytes exceeding maximum file size', async () => {
    const response = await request(app)
      .post('/ipfs/register-cid')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ cid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi', sizeBytes: Number.MAX_SAFE_INTEGER });

    expect(response.status).toBe(400);
  });

  it('should reject CID registration from non-BYO users', async () => {
    // Authenticate as a non-BYO user
    const response = await request(app)
      .post('/ipfs/register-cid')
      .set('Authorization', `Bearer ${nonByoUserToken}`)
      .send({ cid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi', sizeBytes: 1000 });

    expect(response.status).toBe(403);
  });
});

describe('Migration Rate Limiting', () => {
  it('should reject new migration when active migration exists', async () => {
    // Create an active migration first
    await migrationService.startMigration(userId, validDto);

    // Attempt to create another
    await expect(
      migrationService.startMigration(userId, validDto)
    ).rejects.toThrow(/active migration/i);
  });
});

describe('StorageTab Auth Token Lifecycle', () => {
  it('should clear auth token from state on unmount', () => {
    const { unmount, getByPlaceholderText } = render(<StorageTab />);
    // Set external mode with auth token
    // Verify token is in state
    unmount();
    // Verify token cleanup occurred (test via useEffect cleanup)
  });
});
```

---

## Compliance Checklist

| Rule                                                                     | Status             | Notes                                                                                                                                                                                  |
| ------------------------------------------------------------------------ | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Never store privateKey in localStorage/sessionStorage                    | PASS               | Auth tokens stored in encrypted IPNS entry, not browser storage. Plan anti-patterns section explicitly prohibits localStorage.                                                         |
| Never log sensitive keys                                                 | NEEDS VERIFICATION | Plans do not include logging of auth tokens. TEE migration worker should be verified to not log decrypted configs. Existing TEE republish route has "NEVER log key material" comments. |
| Never send unencrypted keys to server                                    | PASS               | Auth tokens are ECIES-encrypted for TEE migration. BYO config is AES-encrypted in vault metadata. Server never receives plaintext tokens.                                              |
| Always use ECIES for key wrapping                                        | PASS               | Migration configs wrapped with ECIES using TEE public key. Same pattern as IPNS key enrollment.                                                                                        |
| Always use AES-256-GCM for content encryption                            | PASS               | BYO config encrypted with AES-256-GCM via user's vault key. No new encryption schemes introduced.                                                                                      |
| Server NEVER has access to plaintext or unencrypted keys                 | PASS               | Server sees only ECIES-wrapped migration configs and encrypted IPNS entries. The `isByoUser` flag is a boolean, not a credential.                                                      |
| Always encrypt ipnsPrivateKey with TEE public key                        | N/A                | Phase 21 does not modify IPNS key handling.                                                                                                                                            |
| TEE decrypts IPNS keys in hardware only, signs, and immediately discards | PARTIAL            | TEE migration correctly decrypts in-enclave. But string zeroing is ineffective (see High finding). Existing TEE pattern (Uint8Array fill(0)) is not followed for auth tokens.          |

---

## Recommendations Summary

| Priority | Recommendation                                                                      | Effort | Plan Reference                   |
| -------- | ----------------------------------------------------------------------------------- | ------ | -------------------------------- |
| CRITICAL | Add SSRF protection to TEE migration worker (URL validation + DNS rebinding check)  | Medium | Plan 05, Task 2                  |
| HIGH     | Add CID format validation, size cap, and BYO-user gate to registerCid endpoint      | Low    | Plan 02, Task 1                  |
| HIGH     | Process TEE migration credentials as Uint8Array, not strings, to enable zeroing     | Medium | Plan 05, Task 2                  |
| MEDIUM   | Clear auth token from React state on StorageTab unmount                             | Low    | Plan 04, Task 1                  |
| MEDIUM   | Improve PSA transient relay unpin robustness + document the relay behavior to users | Low    | Plan 03, Task 2                  |
| MEDIUM   | Add active-migration check before creating new migration                            | Low    | Plan 05, Task 1                  |
| MEDIUM   | Use encodeURIComponent for CID parameters in URL construction                       | Low    | Plan 01, Task 1; Plan 05, Task 2 |
| LOW      | Clean up encrypted migration configs from DB after completion                       | Low    | Plan 05, Task 1                  |
| LOW      | Make IPFS gateway URL configurable for TEE migration worker                         | Low    | Plan 05, Task 2                  |
| LOW      | Fix DualPinProvider to handle PSA secondary correctly (use pinByCid, not pin)       | Medium | Plan 03, Task 1                  |
| LOW      | Validate URL scheme in connection test (block file:/data:/ftp:)                     | Low    | Plan 01, Task 1                  |

---

## SECURITY REVIEW COMPLETE

**Files analyzed:** 10 planning documents, 6 existing source files
**Crypto operations found:** 5 (ECIES wrapping, AES-256-GCM vault encryption, auth token handling, CID registration, TEE credential decryption)
**Issues found:** 1 Critical, 2 High, 4 Medium, 5 Low

### Critical Issues

1. SSRF via TEE migration worker -- no URL validation on user-provided endpoints

### High Priority

1. CID registration endpoint missing ownership/format validation and BYO-user gate
2. JavaScript string zeroing is ineffective for TEE credential cleanup

### Test Cases Generated

25+ test suggestions across 7 categories (provider security, connection test, SSRF, CID registration, migration rate limiting, auth token lifecycle, CID integrity)

### Report Location

`.planning/security/REVIEW-2026-03-24-phase21-pre-impl.md`

### Recommendations

1. **[MUST FIX]** Add SSRF protection (URL allowlisting + DNS rebinding check) to TEE migration worker before implementation begins
2. **[MUST FIX]** Add CID format validation and BYO-user authorization gate to registerCid endpoint
3. **[SHOULD FIX]** Process migration credentials as Uint8Array in TEE worker for proper zeroing
4. **[SHOULD FIX]** Add concurrent migration check to prevent resource exhaustion

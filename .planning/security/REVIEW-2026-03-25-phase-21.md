# Security Review: Phase 21 -- BYO-IPFS Node Support

**Reviewer:** Claude Opus 4.6 (Security Agent)
**Date:** 2026-03-25
**Scope:** Phase 21 implementation -- Bring Your Own IPFS provider support
**Risk Level:** MEDIUM (with 2 High-severity and 3 Medium-severity findings)

---

## Executive Summary

Phase 21 adds the ability for users to connect external IPFS providers (Kubo, PSA, Pinata) for storage. This introduces a new trust boundary where the TEE worker makes outbound HTTP requests to user-controlled URLs, and user-provided credentials traverse a multi-hop encrypted pipeline.

The overall architecture correctly follows the zero-knowledge model: provider credentials are ECIES-encrypted in the browser, forwarded opaquely through the API, and decrypted only inside the TEE enclave. Key derivation for the BYO config IPNS keypair uses proper HKDF domain separation.

However, the review identified **2 High-severity** and **3 Medium-severity** issues, primarily around SSRF protection gaps, credential lifecycle management in JavaScript, and missing input validation on security-critical endpoints.

**Files analyzed:** 28
**Crypto operations found:** 14
**Issues found:** 2 High, 3 Medium, 4 Low, 2 Informational

---

## Findings

---

### [HIGH-01] SSRF: Missing 0.0.0.0, IPv4-mapped IPv6, and Cloud Metadata Address Blocking

**Location:** `tee-worker/src/services/ssrf-validation.ts:15-29`

**Code:**

```typescript
function isPrivateAddress(addr: string): boolean {
  return (
    addr === 'localhost' ||
    addr === '127.0.0.1' ||
    addr === '::1' ||
    addr.startsWith('10.') ||
    addr.startsWith('192.168.') ||
    addr.startsWith('127.') ||
    addr.startsWith('169.254.') ||
    addr.startsWith('fd') ||
    addr.startsWith('fe80') ||
    addr.endsWith('.internal') ||
    addr.endsWith('.local') ||
    is172Private(addr)
  );
}
```

**Issue:**
The SSRF blocklist is incomplete. Several bypass vectors are available:

1. **`0.0.0.0`** -- On many systems, `0.0.0.0` routes to localhost. Not blocked.
2. **IPv4-mapped IPv6 addresses** -- `::ffff:127.0.0.1` or `::ffff:169.254.169.254` bypass all checks since `startsWith('::1')` only matches the exact loopback, not the mapped prefix.
3. **IPv6 unique-local `fc00::`** -- `addr.startsWith('fd')` catches `fdXX::` but `fc00::` through `fcff::` (the other half of `fc00::/7`) is not blocked.
4. **`100.64.0.0/10`** (Carrier-Grade NAT / shared address space) -- Used by many cloud providers for internal metadata services. Not blocked.
5. **Cloud metadata endpoints** -- While `169.254.169.254` is blocked via the `169.254.` prefix, some cloud providers use other addresses (e.g., `fd00:ec2::254` on AWS IPv6, or aliased hostnames).
6. **No protocol enforcement on resolved IP** -- `validateResolvedIp()` only checks the IP but the fetch still uses the original hostname, creating a TOCTOU window where DNS could return a different IP between validation and fetch.

**Impact:**
An attacker who registers a CipherBox account could use the connection-test or migration endpoints to make the TEE worker send authenticated requests to internal services (cloud metadata service, internal APIs, other TEE services). In a Phala CVM environment, this could expose instance metadata or secrets.

**Recommendation:**

```typescript
function isPrivateAddress(addr: string): boolean {
  // Normalize IPv4-mapped IPv6 (::ffff:1.2.3.4 -> 1.2.3.4)
  let normalized = addr;
  if (normalized.startsWith('::ffff:')) {
    normalized = normalized.slice(7);
  }

  return (
    normalized === 'localhost' ||
    normalized === '0.0.0.0' ||
    normalized === '127.0.0.1' ||
    normalized === '::1' ||
    normalized === '::' ||
    normalized.startsWith('0.') ||
    normalized.startsWith('10.') ||
    normalized.startsWith('192.168.') ||
    normalized.startsWith('127.') ||
    normalized.startsWith('169.254.') ||
    normalized.startsWith('100.64.') || // CGN range 100.64.0.0/10
    normalized.startsWith('fd') ||
    normalized.startsWith('fc') || // full fc00::/7 range
    normalized.startsWith('fe80') ||
    normalized.startsWith('::ffff:') || // catch remaining mapped addresses
    normalized.endsWith('.internal') ||
    normalized.endsWith('.local') ||
    is172Private(normalized) ||
    isCgnRange(normalized)
  );
}

function isCgnRange(addr: string): boolean {
  if (!addr.startsWith('100.')) return false;
  const second = parseInt(addr.split('.')[1], 10);
  return second >= 64 && second <= 127; // 100.64.0.0/10
}
```

Additionally, consider disabling fetch redirects to prevent SSRF via redirect:

```typescript
const response = await fetch(url, {
  method: 'POST',
  headers,
  signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
  redirect: 'error', // Do NOT follow redirects
});
```

**References:**

- <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- AWS IMDS: `169.254.169.254` and `fd00:ec2::254`
- RFC 6598 (CGN shared address space: `100.64.0.0/10`)

---

### [HIGH-02] SSRF: TOCTOU Between DNS Resolution and Fetch (DNS Rebinding)

**Location:** `tee-worker/src/routes/connection-test.ts:71-74` and `tee-worker/src/services/migration-worker.ts:87-99`

**Code:**

```typescript
// connection-test.ts:71-74
validateEndpointUrl(normalizedEndpoint);
if (process.env.TEE_MODE !== 'simulator') {
  await validateResolvedIp(new URL(normalizedEndpoint).hostname);
}

// ... later, fetch uses the original URL which triggers a NEW DNS resolution
const response = await fetch(url, { ... });
```

**Issue:**
There is a Time-of-Check-to-Time-of-Use (TOCTOU) gap between `validateResolvedIp()` and the subsequent `fetch()`. An attacker controlling DNS for their domain can:

1. First resolution (validation): return `1.2.3.4` (public, passes check)
2. Second resolution (fetch): return `169.254.169.254` (metadata service)

This is a classic DNS rebinding attack. The validation and the fetch are separate network operations that resolve DNS independently.

**Impact:**
Complete SSRF bypass. The TEE worker would send authenticated requests (with the TEE_WORKER_SECRET bearer token in auth middleware context, and potentially user provider tokens) to cloud metadata endpoints.

**Recommendation:**
Pin the resolved IP address and force fetch to use it. The standard approach is to resolve DNS once, validate, then connect to the validated IP with the original Host header:

```typescript
import { lookup } from 'node:dns/promises';
import { Agent } from 'node:http';
import { Agent as HttpsAgent } from 'node:https';

async function fetchWithSsrfProtection(url: string, init: RequestInit): Promise<Response> {
  const parsed = new URL(url);
  const resolved = await lookup(parsed.hostname);

  if (isPrivateAddress(resolved.address)) {
    throw new Error('Endpoint DNS resolves to private address');
  }

  // Force connection to the validated IP, not re-resolved hostname
  // Node.js 20+ fetch supports a custom dispatcher; alternatively
  // use undici's Agent with connect.lookup override
  const pinnedUrl = new URL(url);
  pinnedUrl.hostname = resolved.address;

  return fetch(pinnedUrl.toString(), {
    ...init,
    headers: {
      ...Object.fromEntries(Object.entries(init.headers ?? {})),
      Host: parsed.host,
    },
    redirect: 'error',
  });
}
```

Alternatively, use Node.js `undici` dispatcher with a custom DNS lookup function that validates on every resolution, or use a `dns.Resolver` with caching to ensure the same IP is used.

**References:**

- <https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf>
- <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html#case-2---application-can-send-requests-to-any-external-ip-address-or-domain-name>

---

### [MEDIUM-01] Auth Token Strings Persist in JavaScript Heap After Zeroing Uint8Array

**Location:** `tee-worker/src/services/migration-worker.ts:59-61, 105-106`

**Code:**

```typescript
/** Get auth token as string for HTTP header -- caller must zero authTokenBytes after use */
function authTokenString(config: ProviderConfig): string {
  return new TextDecoder().decode(config.authTokenBytes);
}

// Later:
const sourceToken = authTokenString(sourceConfig);
const destToken = authTokenString(destConfig);
```

**Issue:**
While the code correctly maintains auth tokens as `Uint8Array` for zeroing, it then converts them to JavaScript strings (`sourceToken`, `destToken`) for use in HTTP headers. JavaScript strings are immutable and cannot be zeroed. These string copies persist in the V8 heap until garbage collected, potentially for a long time during a large migration batch.

The code acknowledges this at line 266: `// NOTE: No zeroString function -- JS strings are immutable and cannot be zeroed.` However, `sourceToken` and `destToken` are declared in the outer `try` block scope and remain alive for the entire batch iteration loop.

Similarly, in `connection-test.ts:58-59`, the config is parsed as a JSON string containing the auth token, and `authToken` is used as a string throughout.

**Impact:**
If the TEE process memory is dumped (unlikely in production CVM, possible in simulator mode or via a separate vulnerability), auth tokens would be recoverable from the heap even after the `finally` block zeroes the `Uint8Array` copies. This is a defense-in-depth concern -- not exploitable in isolation but violates the stated security goal of zeroing credentials after use.

**Recommendation:**
This is an inherent limitation of JavaScript. The code's approach of using `Uint8Array` for storage and zeroing is the best available strategy. To minimize exposure:

1. Decode the token string as late as possible (per-request, not per-batch):

```typescript
// Instead of decoding once for the batch:
// const sourceToken = authTokenString(sourceConfig);

// Decode per-CID and let the string be eligible for GC sooner:
for (const cid of cids) {
  const data = await fetchFromProvider(
    cid,
    sourceConfig,
    new TextDecoder().decode(sourceConfig.authTokenBytes)
  );
  // ... string is now unreferenced after the call returns
}
```

2. Document the limitation clearly for future auditors (already partially done).
3. Consider requesting GC after batch completion: `global.gc?.()` (requires `--expose-gc` flag).

---

### [MEDIUM-02] Missing Rate Limiting on Migration Endpoints

**Location:** `apps/api/src/migration/migration.controller.ts` (entire file)

**Code:**

```typescript
@Controller('migration')
export class MigrationController {
  @Post('start')
  // NO @Throttle decorator
  async startMigration(...) { ... }

  @Get('status')
  // NO @Throttle decorator
  async getStatus(...) { ... }

  @Post(':id/pause')
  // NO @Throttle decorator
  async pauseMigration(...) { ... }

  @Post(':id/resume')
  // NO @Throttle decorator
  async resumeMigration(...) { ... }

  @Post(':id/cancel')
  // NO @Throttle decorator
  async cancelMigration(...) { ... }
}
```

**Issue:**
The migration controller has no rate limiting. Compare with:

- `tee.controller.ts:16`: `@Throttle({ default: { limit: 10, ttl: 60000 } })` on connection-test
- `ipfs.controller.ts:151`: `@Throttle({ default: { limit: 100, ttl: 3600000 } })` on register-cid

While the `startMigration` method does prevent concurrent migrations (one active per user), there is no rate limit on:

- **`resume`**: A user could repeatedly pause/resume to generate excessive TEE worker load.
- **`start`**: After completing or cancelling a migration, a user could immediately start a new one, repeatedly.
- **`status`**: Polling endpoint with no rate limit.

**Impact:**
A malicious user could abuse the migration system to generate excessive load on the TEE worker, which processes migration batches synchronously. This could degrade TEE worker availability for all users (IPNS republishing, other connection tests, other migrations).

**Recommendation:**

```typescript
@Controller('migration')
export class MigrationController {
  @Post('start')
  @Throttle({ default: { limit: 3, ttl: 3600000 } }) // 3 starts per hour
  async startMigration(...) { ... }

  @Get('status')
  @Throttle({ default: { limit: 60, ttl: 60000 } }) // 60/min (polling)
  async getStatus(...) { ... }

  @Post(':id/pause')
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10/min
  async pauseMigration(...) { ... }

  @Post(':id/resume')
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5/min
  async resumeMigration(...) { ... }
}
```

---

### [MEDIUM-03] No Maximum CID Batch Size Validation on TEE Migrate Endpoint

**Location:** `tee-worker/src/routes/migrate.ts:26-37`

**Code:**

```typescript
router.post('/migrate', async (req: Request, res: Response) => {
  const { cids, sourceConfigEncrypted, destConfigEncrypted } = req.body as {
    cids?: string[];
    sourceConfigEncrypted?: string;
    destConfigEncrypted?: string;
  };

  if (!cids || !Array.isArray(cids) || !sourceConfigEncrypted || !destConfigEncrypted) {
    res.status(400).json({
      error: 'Missing required fields: cids, sourceConfigEncrypted, destConfigEncrypted',
    });
    return;
  }
  // No max length check on cids array
```

**Issue:**
The TEE `/migrate` endpoint accepts an unbounded `cids` array. While the API-side `MigrationProcessor` batches in groups of 10, the TEE endpoint itself has no protection against a direct request (from a compromised API or an attacker who has obtained the `TEE_WORKER_SECRET`) sending thousands of CIDs in a single request.

Additionally, there is no validation that CID strings are well-formed. Malformed CIDs could cause unexpected behavior in downstream fetch/pin operations.

The `encryptedConfig` fields are also unbounded strings with no maximum length validation -- both here and in the API DTO (`StartMigrationDto`, `ConnectionTestRequestDto`).

**Impact:**

- Memory exhaustion in TEE worker if huge CID arrays are sent
- Potential for very long-running requests that tie up the TEE worker
- Possible injection via malformed CID strings in URL construction (though `encodeURIComponent` mitigates this)

**Recommendation:**

```typescript
// TEE-side validation
const MAX_BATCH_SIZE = 50;
const CID_PATTERN = /^(Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[a-z2-7]{58,})$/;
const MAX_ENCRYPTED_CONFIG_LENGTH = 10_000; // ECIES ciphertext for a small JSON

if (!cids || !Array.isArray(cids) || cids.length === 0 || cids.length > MAX_BATCH_SIZE) {
  res.status(400).json({ error: `cids must be an array of 1-${MAX_BATCH_SIZE} CIDs` });
  return;
}

if (!cids.every((c) => typeof c === 'string' && CID_PATTERN.test(c))) {
  res.status(400).json({ error: 'Invalid CID format' });
  return;
}

if (
  sourceConfigEncrypted.length > MAX_ENCRYPTED_CONFIG_LENGTH ||
  destConfigEncrypted.length > MAX_ENCRYPTED_CONFIG_LENGTH
) {
  res.status(400).json({ error: 'Encrypted config too large' });
  return;
}
```

Also add `@MaxLength()` validators to the API-side DTOs:

```typescript
// StartMigrationDto
@IsString()
@IsNotEmpty()
@MaxLength(10000)
sourceConfigEncrypted!: string;
```

---

### [LOW-01] SSRF Validation Bypassed in Simulator Mode

**Location:** `tee-worker/src/routes/connection-test.ts:72` and `tee-worker/src/services/migration-worker.ts:90,96`

**Code:**

```typescript
// connection-test.ts
if (process.env.TEE_MODE !== 'simulator') {
  await validateResolvedIp(new URL(normalizedEndpoint).hostname);
}

// Also in validateEndpointUrl:
if (process.env.TEE_MODE === 'simulator') return;
```

**Issue:**
Both `validateEndpointUrl()` and `validateResolvedIp()` are completely bypassed in simulator mode. This means all SSRF protections are disabled during development and testing. While this is understandable for local development (connecting to `localhost:5001` Kubo nodes), it creates a risk if:

1. A staging environment accidentally runs in simulator mode
2. The `TEE_MODE` env var is misconfigured in production

The `tee-keys.ts` has a production guard (`TEE_MODE=simulator` throws in production), but this only protects key derivation, not SSRF validation.

**Impact:**
Full SSRF bypass if simulator mode is accidentally enabled outside development.

**Recommendation:**
Add a parallel production guard in `validateEndpointUrl`:

```typescript
export function validateEndpointUrl(endpoint: string): void {
  const url = new URL(endpoint);

  if (process.env.TEE_MODE === 'simulator') {
    // In simulator mode, still block the most dangerous targets
    if (url.hostname === '169.254.169.254' || url.hostname === 'metadata.google.internal') {
      throw new Error('Endpoint cannot target cloud metadata services');
    }
    // Allow private addresses for local development
    return;
  }

  if (url.protocol !== 'https:') {
    throw new Error('Endpoint must use HTTPS');
  }

  if (isPrivateAddress(url.hostname)) {
    throw new Error('Endpoint cannot target private/internal addresses');
  }
}
```

---

### [LOW-02] TEE Private Key Zeroing Not in Finally Block (connection-test.ts)

**Location:** `tee-worker/src/routes/connection-test.ts:55`

**Code:**

```typescript
try {
  const keypair = await getKeypair(epoch);
  const ciphertext = new Uint8Array(Buffer.from(encryptedConfig, 'hex'));
  configBytes = new Uint8Array(decrypt(keypair.privateKey, ciphertext));

  // 3. Zero TEE private key immediately
  keypair.privateKey.fill(0);
  // ... rest of processing
} catch (err) {
  // If decrypt() throws, keypair.privateKey is NOT zeroed
}
```

**Issue:**
If `Buffer.from(encryptedConfig, 'hex')` or `decrypt()` throws an exception, the TEE private key will not be zeroed because `keypair.privateKey.fill(0)` is inside the `try` block, not in a `finally`. The private key would then remain in memory until garbage collected.

Compare with `migration-worker.ts:82` which correctly zeroes the private key before any potentially-failing config parsing.

**Impact:**
Low -- the TEE private key remains in enclave memory slightly longer than intended on error paths. Exploitable only if a separate memory-read vulnerability exists.

**Recommendation:**

```typescript
let keypair: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
try {
  keypair = await getKeypair(epoch);
  const ciphertext = new Uint8Array(Buffer.from(encryptedConfig, 'hex'));
  configBytes = new Uint8Array(decrypt(keypair.privateKey, ciphertext));
  // ... rest of processing
} catch (err) {
  // ... error handling
} finally {
  if (keypair) keypair.privateKey.fill(0);
  if (configBytes) configBytes.fill(0);
  if (tokenBytes) tokenBytes.fill(0);
}
```

---

### [LOW-03] Encrypted Provider Configs Stored Persistently in Database

**Location:** `apps/api/src/migration/migration.entity.ts:39-43`

**Code:**

```typescript
@Column({ type: 'text', name: 'source_config_encrypted' })
sourceConfigEncrypted!: string;

@Column({ type: 'text', name: 'dest_config_encrypted' })
destConfigEncrypted!: string;
```

**Issue:**
The ECIES-encrypted provider configs (containing endpoint URLs and auth tokens) are stored persistently in the `pin_migrations` database table. While the configs are ECIES-encrypted with the TEE public key (so the API server cannot decrypt them), they persist indefinitely even after migration completes.

If the TEE private key for the epoch were ever compromised (key leakage, side-channel attack on TEE), all stored migration configs could be decrypted retroactively.

**Impact:**
Violates the principle of forward secrecy for provider credentials. A TEE key compromise would expose not just current credentials but all historical credentials used in migrations.

**Recommendation:**
Clear the encrypted config columns after migration completes:

```typescript
// In MigrationProcessor, after marking complete:
if (final.status === 'running') {
  await this.migrationRepo.update(migrationId, {
    status: 'completed',
    completedAt: new Date(),
    sourceConfigEncrypted: '[cleared]', // or empty string
    destConfigEncrypted: '[cleared]',
  });
}
```

Also consider clearing on `cancelled` and `failed` status transitions.

---

### [LOW-04] Auth Token Held in React State as Plaintext String

**Location:** `apps/web/src/components/settings/StorageTab.tsx:73,128`

**Code:**

```typescript
const [authToken, setAuthToken] = useState('');
// ...
setAuthToken(config.externalProvider?.authToken ?? '');
// ...
setSavedConfig({
  mode: config.pinningMode,
  endpoint: config.externalProvider?.endpoint ?? '',
  authToken: config.externalProvider?.authToken ?? '',
});
```

**Issue:**
The provider auth token is held in React state as a plaintext string for the lifetime of the StorageTab component. It is also stored in the `savedConfig` state object for dirty-tracking purposes. While this is standard React pattern and necessary for the form UI, it means:

1. The token is accessible via React DevTools
2. It persists in memory as long as the Settings page is open
3. It is included in the `savedConfig` object even when the user is just viewing (not editing) settings

**Impact:**
Low -- this is a client-side concern and the token is already in the user's possession. However, it does increase the attack surface for XSS-based token theft.

**Recommendation:**
Consider clearing the auth token from state when the user navigates away from the settings page, and masking the saved token value:

```typescript
// When loading saved config, show masked token
setAuthToken(config.externalProvider?.authToken ? '********' : '');
setSavedConfig({
  mode: config.pinningMode,
  endpoint: config.externalProvider?.endpoint ?? '',
  authToken: '********', // masked for dirty tracking
});
// On save, re-read the real token from IPNS if needed
```

This is a defense-in-depth suggestion and may add UX complexity.

---

### [INFO-01] Redirect Following Could Bypass SSRF in TEE Worker Fetches

**Location:** `tee-worker/src/routes/connection-test.ts:129` and `tee-worker/src/services/migration-worker.ts:204`

**Issue:**
The `fetch()` calls in the TEE worker use default redirect behavior (`redirect: 'follow'`). An attacker could set up a public-facing endpoint that returns a 302 redirect to `http://169.254.169.254/latest/meta-data/`. While `validateEndpointUrl()` checks the initial URL, the redirect target is not validated.

Node.js `fetch` (undici) follows redirects by default (up to 20). This is a supplementary vector to the TOCTOU DNS rebinding issue in HIGH-02.

**Recommendation:**
Set `redirect: 'error'` on all TEE worker fetch calls to user-provided endpoints:

```typescript
const response = await fetch(url, {
  method: 'POST',
  headers,
  signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
  redirect: 'error', // Reject redirects
});
```

---

### [INFO-02] BYO Config IPNS Name Cached in localStorage

**Location:** `apps/web/src/components/settings/StorageTab.tsx:22,136` and `apps/web/src/hooks/useAuth.ts:230-231`

**Issue:**
The BYO config IPNS name is cached in `localStorage` under key `cipherbox-byo-ipns-name`. This is explicitly documented as "not sensitive -- public identifier" which is correct. The IPNS name is a public identifier (k51...) and does not leak any credential information.

However, its presence in localStorage does reveal that the user has configured a BYO provider, which could be considered a minor privacy signal.

**Recommendation:**
Acceptable as-is. The IPNS name is deterministically derivable from the user's private key, so it provides no additional information beyond what the private key holder already knows. This is informational only.

---

## File-by-File Analysis

### TEE Worker Files

| File                                          | Crypto Ops                                | Security Rating   | Notes                                                                                |
| --------------------------------------------- | ----------------------------------------- | ----------------- | ------------------------------------------------------------------------------------ |
| `tee-worker/src/routes/connection-test.ts`    | ECIES decrypt, key zeroing                | Good with caveats | Missing finally-block for TEE key zeroing (LOW-02); no redirect blocking (INFO-01)   |
| `tee-worker/src/services/migration-worker.ts` | ECIES decrypt, key zeroing, CID integrity | Good              | Proper finally block for credential zeroing; string token copies persist (MEDIUM-01) |
| `tee-worker/src/services/ssrf-validation.ts`  | N/A                                       | Needs improvement | Incomplete blocklist (HIGH-01); TOCTOU gap (HIGH-02)                                 |
| `tee-worker/src/routes/migrate.ts`            | N/A                                       | Needs improvement | No CID batch size limit (MEDIUM-03)                                                  |
| `tee-worker/src/index.ts`                     | N/A                                       | Good              | Auth middleware on all sensitive routes; 10MB body limit acceptable                  |
| `tee-worker/src/middleware/auth.ts`           | Constant-time comparison                  | Excellent         | Uses `crypto.timingSafeEqual` with length pre-check                                  |

### SDK Pinning Providers

| File                                                 | Crypto Ops | Security Rating | Notes                                                              |
| ---------------------------------------------------- | ---------- | --------------- | ------------------------------------------------------------------ |
| `packages/sdk-core/src/pinning/kubo-provider.ts`     | N/A        | Good            | Proper `encodeURIComponent` on CID params; timeout on all requests |
| `packages/sdk-core/src/pinning/psa-provider.ts`      | N/A        | Good            | Bearer token auth; proper error handling                           |
| `packages/sdk-core/src/pinning/pinata-provider.ts`   | N/A        | Good            | Fixed upload URL prevents SSRF via config; proper Bearer auth      |
| `packages/sdk-core/src/pinning/dual-pin-provider.ts` | N/A        | Good            | Primary-must-succeed pattern; secondary failures don't propagate   |
| `packages/sdk-core/src/pinning/connection-test.ts`   | N/A        | Good            | Browser-side only; sequential protocol detection                   |
| `packages/sdk-core/src/pinning/types.ts`             | N/A        | Good            | Clean type definitions                                             |

### Web Client Files

| File                                                  | Crypto Ops                                | Security Rating | Notes                                                                        |
| ----------------------------------------------------- | ----------------------------------------- | --------------- | ---------------------------------------------------------------------------- |
| `apps/web/src/components/settings/StorageTab.tsx`     | ECIES encrypt/decrypt (wrapKey/unwrapKey) | Good            | Proper clearBytes in finally; ECIES encrypt before IPFS upload               |
| `apps/web/src/components/settings/ConnectionTest.tsx` | ECIES encrypt (wrapKey)                   | Good            | TEE-routed test with ECIES encryption; browser fallback when TEE unavailable |
| `apps/web/src/hooks/useAuth.ts`                       | ECIES decrypt, HKDF, clearBytes           | Good            | BYO config loaded with proper clearBytes in finally; no credentials logged   |
| `apps/web/src/lib/sdk-provider.ts`                    | Key copy, zeroing on destroy              | Good            | Defensive copies; zeroing on destroy                                         |

### API Files

| File                                             | Crypto Ops         | Security Rating   | Notes                                           |
| ------------------------------------------------ | ------------------ | ----------------- | ----------------------------------------------- |
| `apps/api/src/tee/tee.controller.ts`             | N/A (pass-through) | Good              | Rate limited (10/min); JWT auth guard           |
| `apps/api/src/tee/tee.service.ts`                | N/A (pass-through) | Good              | Never logs secret; timeout on all TEE requests  |
| `apps/api/src/migration/migration.processor.ts`  | N/A (pass-through) | Good              | Batch processing with pause/cancel support      |
| `apps/api/src/migration/migration.service.ts`    | N/A                | Good              | Concurrent migration prevention; user isolation |
| `apps/api/src/migration/migration.controller.ts` | N/A                | Needs improvement | Missing rate limiting (MEDIUM-02)               |
| `apps/api/src/ipfs/ipfs.controller.ts`           | N/A                | Good              | BYO check on register-cid; rate limited         |

### Crypto Package

| File                                       | Crypto Ops               | Security Rating | Notes                                                                |
| ------------------------------------------ | ------------------------ | --------------- | -------------------------------------------------------------------- |
| `packages/crypto/src/vault/derive-ipns.ts` | HKDF-SHA256              | Excellent       | Proper domain separation; unique info strings per derivation purpose |
| `packages/crypto/src/ecies/encrypt.ts`     | ECIES (eciesjs)          | Excellent       | Public key validation; curve point validation; generic errors        |
| `packages/crypto/src/ecies/decrypt.ts`     | ECIES (eciesjs)          | Excellent       | Generic error messages prevent oracle attacks                        |
| `packages/crypto/src/keys/derive.ts`       | HKDF-SHA256 (Web Crypto) | Excellent       | Proper ArrayBuffer handling; generic errors                          |

---

## Compliance Checklist

| Rule                                                     | Status | Notes                                                          |
| -------------------------------------------------------- | ------ | -------------------------------------------------------------- |
| Never store privateKey in localStorage/sessionStorage    | PASS   | Only IPNS name (public) stored in localStorage                 |
| Never log sensitive keys                                 | PASS   | Console.log/error calls reviewed; no key material logged       |
| Never send unencrypted keys to server                    | PASS   | Provider configs ECIES-encrypted before leaving browser        |
| Always use ECIES for key wrapping                        | PASS   | wrapKey/unwrapKey used consistently; eciesjs library           |
| Always use AES-256-GCM for content encryption            | PASS   | (Content encryption not changed in Phase 21)                   |
| Server NEVER has access to plaintext or unencrypted keys | PASS   | API is pass-through for encrypted configs; never decrypts      |
| Always encrypt ipnsPrivateKey with TEE public key        | PASS   | BYO config IPNS private key wrapped with TEE key in StorageTab |
| TEE decrypts in hardware only, signs, discards           | PASS   | Keys zeroed after use in both connection-test and migration    |

---

## Key Derivation Analysis

The new `deriveByoConfigIpnsKeypair` function at `packages/crypto/src/vault/derive-ipns.ts:127` follows the established pattern correctly:

- **Salt:** `CipherBox-v1` (shared with other vault derivations -- acceptable since info differs)
- **Info:** `cipherbox-byo-ipfs-config-v1` (unique domain separation)
- **Algorithm:** HKDF-SHA256 via Web Crypto API
- **Output:** 32-byte Ed25519 seed -> deterministic keypair
- **Input validation:** Checks 32-byte secp256k1 key length

**No key reuse concerns.** The three IPNS derivations use distinct `info` strings:

1. `cipherbox-vault-ipns-v1` (root folder metadata)
2. `cipherbox-vault-key-ipns-v1` (vault key blob)
3. `cipherbox-byo-ipfs-config-v1` (BYO config)

This ensures the same user private key produces three independent IPNS keypairs with no collisions.

---

## Test Case Suggestions

### SSRF Validation Tests

```typescript
describe('SSRF Validation Security Tests', () => {
  describe('isPrivateAddress', () => {
    it('blocks 0.0.0.0', () => {
      expect(() => validateEndpointUrl('https://0.0.0.0:5001')).toThrow();
    });

    it('blocks IPv4-mapped IPv6 loopback', async () => {
      // Test against ::ffff:127.0.0.1
      await expect(validateResolvedIp('::ffff:127.0.0.1')).rejects.toThrow();
    });

    it('blocks IPv4-mapped IPv6 metadata', async () => {
      await expect(validateResolvedIp('::ffff:169.254.169.254')).rejects.toThrow();
    });

    it('blocks CGN range 100.64.x.x', () => {
      expect(() => validateEndpointUrl('https://100.64.0.1')).toThrow();
      expect(() => validateEndpointUrl('https://100.127.255.254')).toThrow();
    });

    it('allows 100.63.x.x (not CGN)', () => {
      expect(() => validateEndpointUrl('https://100.63.0.1')).not.toThrow();
    });

    it('blocks fc00:: unique-local addresses', async () => {
      await expect(validateResolvedIp('fc00::1')).rejects.toThrow();
    });

    it('blocks HTTP protocol', () => {
      expect(() => validateEndpointUrl('http://example.com')).toThrow();
    });

    it('allows valid HTTPS endpoints', () => {
      expect(() => validateEndpointUrl('https://kubo.example.com:5001')).not.toThrow();
    });
  });
});
```

### TEE Connection Test Security Tests

```typescript
describe('Connection Test Security Tests', () => {
  describe('Credential Lifecycle', () => {
    it('zeroes TEE private key even when decrypt fails', async () => {
      // Send invalid ECIES ciphertext
      const res = await request(app)
        .post('/connection-test')
        .set('Authorization', `Bearer ${secret}`)
        .send({ encryptedConfig: 'deadbeef', epoch: 1 });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(false);
      // Verify key was zeroed (requires instrumentation or mock)
    });

    it('zeroes config bytes in finally block on any error', async () => {
      // Test with valid ECIES but endpoint that errors
    });
  });

  describe('Input Validation', () => {
    it('rejects missing encryptedConfig', async () => {
      const res = await request(app)
        .post('/connection-test')
        .set('Authorization', `Bearer ${secret}`)
        .send({ epoch: 1 });
      expect(res.status).toBe(400);
    });

    it('rejects missing epoch', async () => {
      const res = await request(app)
        .post('/connection-test')
        .set('Authorization', `Bearer ${secret}`)
        .send({ encryptedConfig: 'abcdef' });
      expect(res.status).toBe(400);
    });
  });

  describe('Redirect Prevention', () => {
    it('does not follow redirects to internal addresses', async () => {
      // Set up a mock server that returns 302 to http://169.254.169.254
      // Verify TEE worker rejects the redirect
    });
  });
});
```

### Migration Worker Security Tests

```typescript
describe('Migration Worker Security Tests', () => {
  describe('CID Integrity Verification', () => {
    it('rejects CID mismatch between source and destination', async () => {
      // Mock pinToProvider returning different CID
      // Verify the CID is added to failed list
    });

    it('succeeds when source and destination CIDs match', async () => {
      // Normal case
    });
  });

  describe('Credential Zeroing', () => {
    it('zeroes all credential bytes in finally block', async () => {
      const sourceBytes = new Uint8Array(32).fill(0xaa);
      const destBytes = new Uint8Array(32).fill(0xbb);
      // After migrateBatch completes, verify .fill(0) was called
    });

    it('zeroes credentials even when all CIDs fail', async () => {
      // All CIDs fail, verify finally block still runs
    });
  });

  describe('Batch Size Limits', () => {
    it('rejects batch larger than MAX_BATCH_SIZE', async () => {
      const hugeBatch = Array.from({ length: 1000 }, (_, i) => `bafyCID${i}`);
      const res = await request(app)
        .post('/migrate')
        .set('Authorization', `Bearer ${secret}`)
        .send({ cids: hugeBatch, sourceConfigEncrypted: '...', destConfigEncrypted: '...' });
      expect(res.status).toBe(400);
    });
  });
});
```

### BYO Config Encryption Tests

```typescript
describe('BYO Config ECIES Encryption', () => {
  it('encrypts config with user public key and decrypts with private key', async () => {
    const config: ByoIpfsConfig = {
      pinningMode: 'external',
      externalProvider: {
        endpoint: 'https://kubo.example.com:5001',
        authToken: 'secret-token-123',
        protocol: 'kubo',
      },
    };
    const keypair = await generateKeypair(); // secp256k1
    const encrypted = await encryptByoConfig(config, keypair.publicKey);
    const decrypted = await decryptByoConfig(encrypted, keypair.privateKey);

    expect(decrypted).toEqual(config);
  });

  it('different encryptions of same config produce different ciphertext', async () => {
    const config: ByoIpfsConfig = { pinningMode: 'cipherbox', externalProvider: null };
    const keypair = await generateKeypair();
    const enc1 = await encryptByoConfig(config, keypair.publicKey);
    const enc2 = await encryptByoConfig(config, keypair.publicKey);

    expect(enc1).not.toEqual(enc2); // ECIES uses ephemeral keys
  });

  it('rejects decryption with wrong private key', async () => {
    const config: ByoIpfsConfig = { pinningMode: 'cipherbox', externalProvider: null };
    const keypair1 = await generateKeypair();
    const keypair2 = await generateKeypair();
    const encrypted = await encryptByoConfig(config, keypair1.publicKey);

    await expect(decryptByoConfig(encrypted, keypair2.privateKey)).rejects.toThrow();
  });

  it('rejects tampered ciphertext', async () => {
    const config: ByoIpfsConfig = { pinningMode: 'cipherbox', externalProvider: null };
    const keypair = await generateKeypair();
    const encrypted = await encryptByoConfig(config, keypair.publicKey);

    encrypted[encrypted.length - 1] ^= 0xff; // Flip last byte (auth tag)
    await expect(decryptByoConfig(encrypted, keypair.privateKey)).rejects.toThrow();
  });

  it('clears plaintext after encryption', async () => {
    // Verify clearBytes is called on the plaintext Uint8Array
  });
});
```

### Key Derivation Tests

```typescript
describe('BYO Config IPNS Key Derivation', () => {
  it('produces deterministic keypair from same private key', async () => {
    const userKey = new Uint8Array(32).fill(0x42);
    const kp1 = await deriveByoConfigIpnsKeypair(userKey);
    const kp2 = await deriveByoConfigIpnsKeypair(userKey);

    expect(kp1.ipnsName).toBe(kp2.ipnsName);
    expect(kp1.publicKey).toEqual(kp2.publicKey);
  });

  it('produces different keypair from different private key', async () => {
    const key1 = new Uint8Array(32).fill(0x42);
    const key2 = new Uint8Array(32).fill(0x43);
    const kp1 = await deriveByoConfigIpnsKeypair(key1);
    const kp2 = await deriveByoConfigIpnsKeypair(key2);

    expect(kp1.ipnsName).not.toBe(kp2.ipnsName);
  });

  it('produces different keypair from vault IPNS derivation (domain separation)', async () => {
    const userKey = new Uint8Array(32).fill(0x42);
    const vaultKp = await deriveVaultIpnsKeypair(userKey);
    const byoKp = await deriveByoConfigIpnsKeypair(userKey);

    expect(vaultKp.ipnsName).not.toBe(byoKp.ipnsName);
    expect(vaultKp.privateKey).not.toEqual(byoKp.privateKey);
  });

  it('rejects invalid key size', async () => {
    const shortKey = new Uint8Array(16);
    await expect(deriveByoConfigIpnsKeypair(shortKey)).rejects.toThrow('Invalid private key size');
  });
});
```

---

## SECURITY REVIEW COMPLETE

**Files analyzed:** 28
**Crypto operations found:** 14 (ECIES encrypt/decrypt: 6, HKDF derivation: 3, key zeroing: 5)
**Issues found:** 2 High, 3 Medium, 4 Low, 2 Informational

### Critical Issues

None found.

### High Priority

1. **HIGH-01:** SSRF blocklist missing `0.0.0.0`, IPv4-mapped IPv6, CGN ranges
2. **HIGH-02:** DNS rebinding TOCTOU between validation and fetch

### Medium Priority

1. **MEDIUM-01:** Auth token strings persist as immutable JS strings after zeroing
2. **MEDIUM-02:** Migration controller missing rate limiting
3. **MEDIUM-03:** No max CID batch size or config length validation on TEE endpoint

### Test Cases Generated

21 test suggestions across 5 categories (SSRF, connection test, migration, encryption, key derivation)

### Recommendations

1. **[Immediate]** Fix SSRF blocklist gaps (HIGH-01) and add `redirect: 'error'` to all TEE worker fetch calls
2. **[Immediate]** Address DNS rebinding with IP pinning or same-resolution fetch (HIGH-02)
3. **[Before release]** Add rate limiting to migration endpoints (MEDIUM-02)
4. **[Before release]** Add max batch size and input length validation to TEE endpoints (MEDIUM-03)
5. **[Defense-in-depth]** Clear encrypted configs from DB after migration completes (LOW-03)
6. **[Defense-in-depth]** Move TEE key zeroing to finally block in connection-test.ts (LOW-02)

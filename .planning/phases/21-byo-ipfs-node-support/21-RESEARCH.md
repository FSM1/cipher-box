# Phase 21: BYO-IPFS Node Support - Research

**Researched:** 2026-03-24
**Domain:** IPFS pinning protocols, SDK provider abstraction, client-direct architecture, vault metadata extension, TEE-based migration
**Confidence:** MEDIUM-HIGH

## Summary

Phase 21 adds bring-your-own IPFS node support so users can pin encrypted data to their own infrastructure for data sovereignty. The architecture is client-direct: the SDK talks to the user's IPFS node without routing through CipherBox's API. CipherBox API retains responsibility only for IPNS publishes, DB mutations, and lightweight CID registration.

Two IPFS protocols must be supported at the SDK level: Kubo RPC (`/api/v0/*`) for self-hosted nodes, and the IPFS Pinning Service API (PSA) for managed services (Pinata, Filebase, etc.). A critical architectural distinction: PSA is CID-reference-only (you tell the service "pin CID X" and it fetches from the IPFS network), while Kubo RPC supports direct data upload via `/api/v0/add`. For PSA providers in "external only" mode, the SDK must first add content to the IPFS network (via the PSA service's proprietary upload endpoint or via Kubo's add endpoint on the CipherBox node) before the PSA service can pin it. Many commercial PSA providers (Pinata, Filebase) also expose proprietary upload-then-pin endpoints that bypass this limitation.

CORS is the primary browser-compatibility concern. Kubo's RPC API is not designed for browser access and requires explicit CORS configuration. PSA services vary in CORS support. The connection test must validate CORS reachability as a first-class check, with provider-specific remediation instructions.

**Primary recommendation:** Build a `PinningProvider` interface in `@cipherbox/sdk-core` with `KuboProvider` and `PsaProvider` implementations. Extend `CipherBoxClientConfig` with pinning mode and provider config. Store BYO credentials encrypted in vault metadata on IPFS (zero-knowledge). Use BullMQ for TEE migration jobs following the existing republish queue pattern.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **Three user-selectable modes:** CipherBox only (default), External only, Dual-pin (both)
- BYO-only mode: client pins directly to user's node via SDK, CipherBox node not used for storage
- Dual-pin mode: primary pin must succeed, secondary failure shows non-blocking warning
- BYO-only mode: if user's node is unreachable, upload fails with clear error -- no silent fallback to CipherBox
- All IPNS publishes still route through CipherBox API regardless of mode (optimistic concurrency preserved)
- **No server relay for IPFS operations** -- client (SDK/sdk-core) talks directly to user's IPFS node
- CipherBox API role for BYO users: IPNS publishes, DB mutations, lightweight CID registration
- Lightweight CID registration endpoint: client reports CID + size after pinning to external node. Advisory quota tracking (no enforcement) for BYO users
- SDK-level provider abstraction enables benchmarking external providers before shipping to users
- **Credentials stored in vault metadata on IPFS** -- encrypted with user's key, decrypted client-side only
- Zero-knowledge preserved: server never sees IPFS node auth tokens
- **Two protocols supported:** IPFS Pinning Service API (PSA) and Kubo RPC API (/api/v0/\*)
- PSA covers: Pinata, web3.storage, Filebase, any PSA-compatible service
- Kubo RPC covers: self-hosted Kubo nodes without PSA configured
- **Auto-detection during connection test:** probe endpoint (try Kubo /api/v0/id first, then PSA /pins), auto-select protocol
- User just enters URL + auth token -- no manual protocol selection needed
- Connection test **validates CORS** as part of the check
- Block save until CORS and connectivity pass
- Terminal aesthetic consistent: `> connected (420ms) // detected: kubo rpc v0.34.0`
- **New "STORAGE" tab** in Settings page (tabs: LINKED METHODS | SECURITY | STORAGE)
- Storage tab contains: pinning mode radio selector, endpoint + auth token fields, connection test button, advisory quota display
- **Save button pattern** -- changes staged until user clicks [--save], with [--discard] option
- **Background migration via TEE** when switching providers
- TEE decrypts in-enclave, fetches from source, pins to destination, verifies CID match, zeroes credentials
- Progress tracked in DB, Settings UI shows migration progress bar with pause/cancel controls

### Claude's Discretion

- Exact SDK provider abstraction interface design (beyond pin/unpin/status)
- Migration job queue implementation details (BullMQ job structure, retry policy)
- How migration progress is persisted and resumed
- Vault metadata schema extension for BYO config (field names, encryption approach)
- Advisory quota display formatting and thresholds
- Connection test timeout values
- CORS instruction content per provider type

### Deferred Ideas (OUT OF SCOPE)

- S3-compatible storage -- pin to S3/Minio with CID-addressed layout
- Client-side migration fallback (browser stays open for migration)
- Migration scheduling for off-peak hours
- Provider marketplace with curated compatible providers

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID     | Description                                                                               | Research Support                                                                |
| ------ | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| BYO-01 | RemotePinningProvider implements standard IPFS Pinning Service API (pin/unpin/status)     | PSA spec fully documented below; SDK provider interface design covers this      |
| BYO-02 | DualPinProvider pins to both CipherBox node and user's configured node                    | SDK architecture section covers DualPinProvider orchestration pattern           |
| BYO-03 | Per-user IPFS config stored (CONTEXT overrides: vault metadata on IPFS, not server-side)  | Vault metadata extension design covers encrypted BYO config storage             |
| BYO-04 | Settings UI for configuring custom IPFS node endpoint and credentials                     | STORAGE tab pattern documented; existing Settings page tab pattern as reference |
| BYO-05 | Connection test validates user's IPFS node (CONTEXT overrides: client-side, not endpoint) | CORS validation flow and protocol auto-detection documented                     |
| BYO-06 | All IPNS publishes still route through CipherBox API regardless of BYO config             | Architecture preserves existing IPNS flow; no changes needed to IPNS path       |
| BYO-07 | Quota tracking becomes advisory for BYO users with clear UI indication                    | CID registration endpoint and advisory quota display documented                 |

**Note on BYO-03 and BYO-05:** The CONTEXT.md decisions refine these requirements. BYO-03 original wording says "stored server-side" but the discuss-phase decision is "stored in vault metadata on IPFS" for zero-knowledge. BYO-05 says "connection test endpoint" but since credentials are client-side, the connection test runs client-side (in browser/SDK) rather than as an API endpoint.

</phase_requirements>

## Standard Stack

### Core

| Library               | Version | Purpose                                                         | Why Standard                                          |
| --------------------- | ------- | --------------------------------------------------------------- | ----------------------------------------------------- |
| `@cipherbox/sdk-core` | in-repo | New PinningProvider implementations (KuboProvider, PsaProvider) | Existing SDK architecture; stateless, no browser deps |
| `@cipherbox/sdk`      | in-repo | CipherBoxClient pinning mode orchestration                      | Existing stateful client; provider selection logic    |
| `@cipherbox/core`     | in-repo | Vault metadata type extension for BYO config                    | Existing metadata types package                       |
| `bullmq`              | 5.71.0  | TEE migration job queue                                         | Already in use for republish scheduling               |
| `@nestjs/bullmq`      | 11.0.4  | NestJS BullMQ integration for migration controller              | Already in use in API                                 |

### Supporting

| Library   | Version | Purpose                                  | When to Use                                     |
| --------- | ------- | ---------------------------------------- | ----------------------------------------------- |
| `ioredis` | 5.9.2   | Redis client for BullMQ                  | Already installed in API                        |
| `vitest`  | 3.0.5+  | Unit/integration tests for SDK providers | Already configured in sdk-core and sdk packages |

### Alternatives Considered

| Instead of         | Could Use                                        | Tradeoff                                                                                                                                                                            |
| ------------------ | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Custom PSA client  | `@ipfs-shipyard/pinning-service-client` (v3.0.0) | Pre-built PSA client from IPFS ecosystem, but adds a dependency for ~5 endpoints. PSA is simple enough to implement with fetch. Recommend hand-rolling for control and bundle size. |
| Custom Kubo client | `kubo-rpc-client`                                | Heavyweight, includes many APIs we don't need. Existing LocalProvider in API already shows the pattern -- reuse for SDK.                                                            |

**No new npm dependencies needed.** The PSA and Kubo protocols are simple HTTP APIs implementable with `fetch`. The migration queue uses existing BullMQ infrastructure.

## Architecture Patterns

### Recommended Project Structure

```
packages/sdk-core/src/
  pinning/
    types.ts              # PinningProvider interface, PinningConfig types
    kubo-provider.ts      # Kubo RPC implementation
    psa-provider.ts       # PSA implementation
    connection-test.ts    # Protocol auto-detection + CORS validation
    index.ts              # Re-exports

packages/sdk/src/
  client.ts               # Extended with pinning mode + provider selection
  types.ts                # Extended CipherBoxClientConfig with PinningConfig

packages/core/src/
  vault/
    types.ts              # Extended with ByoIpfsConfig type in vault metadata

apps/api/src/
  ipfs/
    dto/
      register-cid.dto.ts  # CID registration DTO
    ipfs.controller.ts      # + registerCid endpoint
  vault/
    vault.service.ts        # + advisory quota mode
  migration/
    migration.module.ts     # BullMQ queue for TEE migration
    migration.service.ts    # Migration orchestration
    migration.controller.ts # REST endpoints for migration status/control
    migration.processor.ts  # BullMQ worker
    migration.entity.ts     # DB entity for migration progress

apps/web/src/
  components/settings/
    StorageTab.tsx          # New STORAGE tab component
    ConnectionTest.tsx      # Connection test UI component
    MigrationProgress.tsx   # Migration progress display
  routes/
    SettingsPage.tsx         # + STORAGE tab

tee-worker/src/
  routes/
    migrate.ts              # Migration endpoint (fetch/pin/verify)
  services/
    migration-worker.ts     # Core migration logic
```

### Pattern 1: SDK PinningProvider Interface

**What:** Abstract pinning operations behind a common interface in sdk-core.
**When to use:** Any file upload/unpin operation that needs to target configurable IPFS infrastructure.

```typescript
// packages/sdk-core/src/pinning/types.ts

/** Result of a pin operation */
export type PinResult = {
  cid: string;
  size: number;
};

/** Status of a pin */
export type PinStatus = {
  cid: string;
  status: 'queued' | 'pinning' | 'pinned' | 'failed';
};

/** Abstract pinning provider -- implemented by KuboProvider and PsaProvider */
export interface PinningProvider {
  /** Upload and pin data, returning CID and size */
  pin(data: Uint8Array, name?: string): Promise<PinResult>;
  /** Remove a pin by CID */
  unpin(cid: string): Promise<void>;
  /** Check pin status by CID */
  status(cid: string): Promise<PinStatus>;
  /** Fetch pinned content by CID */
  get(cid: string): Promise<Uint8Array>;
}

/** User-selectable pinning mode */
export type PinningMode = 'cipherbox' | 'external' | 'dual';

/** Configuration for an external IPFS provider */
export type ExternalProviderConfig = {
  /** Endpoint URL (e.g., "https://api.pinata.cloud/psa" or "http://localhost:5001") */
  endpoint: string;
  /** Auth token (Bearer token for PSA, or API key for Kubo) */
  authToken: string;
  /** Detected protocol type */
  protocol: 'psa' | 'kubo';
  /** Human-readable provider name (auto-detected or user-entered) */
  providerName?: string;
};
```

### Pattern 2: Kubo RPC Provider (SDK-side)

**What:** Direct Kubo RPC client using `/api/v0/*` endpoints from the browser.
**When to use:** Users running their own Kubo node.

```typescript
// packages/sdk-core/src/pinning/kubo-provider.ts

export class KuboProvider implements PinningProvider {
  constructor(
    private readonly endpoint: string,
    private readonly authToken?: string
  ) {}

  async pin(data: Uint8Array): Promise<PinResult> {
    const blob = new Blob([data]);
    const formData = new FormData();
    formData.append('file', blob);

    const headers: Record<string, string> = {};
    if (this.authToken) {
      headers['Authorization'] = `Basic ${this.authToken}`;
    }

    const response = await fetch(`${this.endpoint}/api/v0/add?pin=true&cid-version=1`, {
      method: 'POST',
      body: formData,
      headers,
    });

    if (!response.ok) throw new Error(`Kubo add failed: ${response.status}`);
    const result = await response.json();
    return { cid: result.Hash, size: parseInt(result.Size, 10) };
  }

  async unpin(cid: string): Promise<void> {
    const headers: Record<string, string> = {};
    if (this.authToken) headers['Authorization'] = `Basic ${this.authToken}`;

    const response = await fetch(`${this.endpoint}/api/v0/pin/rm?arg=${cid}`, {
      method: 'POST',
      headers,
    });
    if (!response.ok) {
      const text = await response.text();
      if (!text.includes('not pinned')) throw new Error(`Kubo unpin failed: ${response.status}`);
    }
  }

  async status(cid: string): Promise<PinStatus> {
    const headers: Record<string, string> = {};
    if (this.authToken) headers['Authorization'] = `Basic ${this.authToken}`;

    const response = await fetch(`${this.endpoint}/api/v0/pin/ls?arg=${cid}`, {
      method: 'POST',
      headers,
    });
    if (!response.ok) return { cid, status: 'failed' };
    return { cid, status: 'pinned' };
  }

  async get(cid: string): Promise<Uint8Array> {
    const headers: Record<string, string> = {};
    if (this.authToken) headers['Authorization'] = `Basic ${this.authToken}`;

    const response = await fetch(`${this.endpoint}/api/v0/cat?arg=${cid}`, {
      method: 'POST',
      headers,
    });
    if (!response.ok) throw new Error(`Kubo cat failed: ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  }
}
```

### Pattern 3: PSA Provider

**What:** IPFS Pinning Service API client for managed pinning services.
**When to use:** Users using Pinata, Filebase, web3.storage, or any PSA-compatible service.

```typescript
// packages/sdk-core/src/pinning/psa-provider.ts

/**
 * PSA Provider.
 *
 * IMPORTANT: PSA is a pin-by-CID protocol -- it does NOT accept inline data.
 * The `pin()` method must:
 * 1. Upload data to get a CID (via CipherBox relay or the provider's proprietary API)
 * 2. Tell the PSA service to pin that CID
 *
 * For "external only" mode, this means the data must first be added to the
 * IPFS network. Most PSA services also expose proprietary upload endpoints:
 * - Pinata: POST https://uploads.pinata.cloud/v3/files
 * - Filebase: S3-compatible PUT
 * - web3.storage: w3up client
 *
 * For v1.0, the PSA provider uploads via CipherBox relay (existing addToIpfs)
 * then pins via PSA. This means "external only" still uses CipherBox to get
 * the CID, but the pin is on the external service. True "no CipherBox
 * involvement" requires provider-specific upload adapters (future enhancement).
 */
export class PsaProvider implements PinningProvider {
  constructor(
    private readonly endpoint: string,
    private readonly authToken: string
  ) {}

  async pin(data: Uint8Array, name?: string): Promise<PinResult> {
    // NOTE: PSA cannot accept raw data. The caller must ensure data is
    // already on IPFS (has a CID) before calling pinByCid().
    // The SDK orchestrator handles this by uploading first.
    throw new Error('PsaProvider.pin() cannot upload raw data. Use pinByCid() after uploading.');
  }

  /** Pin existing content by CID -- the core PSA operation */
  async pinByCid(cid: string, name?: string): Promise<PinStatus> {
    const response = await fetch(`${this.endpoint}/pins`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.authToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        cid,
        name: name ?? `cipherbox-${Date.now()}`,
      }),
    });

    if (!response.ok) throw new Error(`PSA pin failed: ${response.status}`);
    const result = await response.json();
    return { cid: result.pin.cid, status: result.status };
  }

  async unpin(cid: string): Promise<void> {
    // PSA requires requestid for deletion, so first find the pin
    const listResponse = await fetch(
      `${this.endpoint}/pins?cid=${cid}&status=pinned,pinning,queued`,
      { headers: { Authorization: `Bearer ${this.authToken}` } }
    );
    if (!listResponse.ok) throw new Error(`PSA list failed: ${listResponse.status}`);
    const list = await listResponse.json();

    for (const result of list.results) {
      await fetch(`${this.endpoint}/pins/${result.requestid}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
    }
  }

  async status(cid: string): Promise<PinStatus> {
    const response = await fetch(`${this.endpoint}/pins?cid=${cid}&limit=1`, {
      headers: { Authorization: `Bearer ${this.authToken}` },
    });
    if (!response.ok) return { cid, status: 'failed' };
    const result = await response.json();
    if (result.count === 0) return { cid, status: 'failed' };
    return { cid, status: result.results[0].status };
  }

  async get(cid: string): Promise<Uint8Array> {
    // PSA does not provide content retrieval -- use IPFS gateway
    throw new Error('PsaProvider does not support get(). Use IPFS gateway.');
  }
}
```

### Pattern 4: PSA Pin-by-CID Architecture

**What:** PSA providers cannot accept inline data upload. The SDK orchestrator must handle this.
**When to use:** Any upload in "external only" or "dual" mode with PSA provider.

**Critical insight:** The IPFS Pinning Service API specification is CID-reference-only. When a client calls `POST /pins`, it provides a CID, and the service fetches the content from the IPFS network. There is no mechanism to upload raw data through the PSA spec.

**Implication for "external only" + PSA:** The encrypted data must first exist on the IPFS network with a CID before the PSA service can pin it. Options:

1. **Upload to CipherBox node first, then PSA pins** -- CipherBox acts as the initial IPFS ingest point, PSA service fetches from it. CipherBox can unpin after PSA confirms. This is the simplest approach.
2. **Upload via provider's proprietary API** -- Pinata has `uploads.pinata.cloud/v3/files`, Filebase has S3 API. Requires provider-specific adapters. Not for v1.0.

**Recommendation for v1.0:** In "external only" mode with PSA, upload to CipherBox node to get CID, then tell PSA to pin, then unpin from CipherBox. This means CipherBox sees the encrypted blob transiently but never stores it long-term. The zero-knowledge property is preserved because content is encrypted.

For "external only" mode with **Kubo**, direct upload via `/api/v0/add` to user's node -- no CipherBox involvement at all.

### Pattern 5: Upload Flow per Mode

```
CipherBox-only (default):
  encrypt -> upload to CipherBox API -> CID -> record pin -> done

External-only + Kubo:
  encrypt -> upload to user's Kubo /api/v0/add -> CID -> register CID with API -> done

External-only + PSA:
  encrypt -> upload to CipherBox API -> CID -> PSA pin by CID ->
  wait for PSA pinned status -> unpin from CipherBox -> register CID with API -> done

Dual + Kubo:
  encrypt -> upload to CipherBox API -> CID (primary) ->
  upload to user's Kubo /api/v0/add (secondary, best-effort) ->
  register CID -> done

Dual + PSA:
  encrypt -> upload to CipherBox API -> CID (primary) ->
  PSA pin by CID (secondary, best-effort) ->
  register CID -> done
```

### Pattern 6: Connection Test + Protocol Auto-Detection

**What:** Client-side probe to detect protocol type and validate CORS.
**When to use:** Settings STORAGE tab, before saving configuration.

```typescript
// packages/sdk-core/src/pinning/connection-test.ts

export type ConnectionTestResult = {
  success: boolean;
  protocol?: 'kubo' | 'psa';
  version?: string;
  latencyMs: number;
  error?: string;
  corsError?: boolean;
  corsInstructions?: string;
};

export async function testConnection(
  endpoint: string,
  authToken?: string
): Promise<ConnectionTestResult> {
  const start = Date.now();

  // 1. Try Kubo /api/v0/id first (most specific)
  try {
    const headers: Record<string, string> = {};
    if (authToken) headers['Authorization'] = `Basic ${authToken}`;

    const response = await fetch(`${endpoint}/api/v0/id`, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(10_000),
    });

    if (response.ok) {
      const data = await response.json();
      return {
        success: true,
        protocol: 'kubo',
        version: data.AgentVersion,
        latencyMs: Date.now() - start,
      };
    }
  } catch (err) {
    // Check for CORS-specific errors
    if (err instanceof TypeError && err.message.includes('Failed to fetch')) {
      return {
        success: false,
        latencyMs: Date.now() - start,
        corsError: true,
        corsInstructions: kuboCorsSInstructions(endpoint),
        error: 'CORS error: browser blocked the request. Configure CORS on your Kubo node.',
      };
    }
  }

  // 2. Try PSA /pins (list pins)
  try {
    const response = await fetch(`${endpoint}/pins?limit=1`, {
      headers: { Authorization: `Bearer ${authToken}` },
      signal: AbortSignal.timeout(10_000),
    });

    if (response.ok || response.status === 401) {
      // 401 means PSA endpoint exists but auth failed
      return {
        success: response.ok,
        protocol: 'psa',
        latencyMs: Date.now() - start,
        error: response.status === 401 ? 'Authentication failed. Check your API token.' : undefined,
      };
    }
  } catch (err) {
    if (err instanceof TypeError && err.message.includes('Failed to fetch')) {
      return {
        success: false,
        latencyMs: Date.now() - start,
        corsError: true,
        corsInstructions: psaCorsInstructions(endpoint),
        error: 'CORS error: the pinning service does not allow browser requests.',
      };
    }
  }

  return {
    success: false,
    latencyMs: Date.now() - start,
    error: 'Could not detect IPFS protocol at this endpoint.',
  };
}
```

### Pattern 7: Vault Metadata Extension for BYO Config

**What:** Store BYO IPFS config encrypted in vault metadata on IPFS.
**When to use:** Persisting user's IPFS provider configuration with zero-knowledge.

```typescript
// Extension to vault metadata blob (v2 or new section)
// Stored on IPFS, encrypted with user's key, decrypted client-side only

export type ByoIpfsConfig = {
  /** User-selected pinning mode */
  pinningMode: 'cipherbox' | 'external' | 'dual';
  /** External provider config (null when mode is 'cipherbox') */
  externalProvider: {
    endpoint: string;
    authToken: string; // Plaintext after decryption
    protocol: 'psa' | 'kubo';
    providerName?: string;
  } | null;
};
```

**Storage approach:** Add `byoIpfs` field to the vault blob stored on IPFS. This blob is encrypted with the user's AES key, so the server never sees the plaintext config. On login, the SDK decrypts the vault blob and extracts BYO config to initialize the pinning provider.

**Schema evolution:** This is an additive optional field with a sensible default (`null` or `{ pinningMode: 'cipherbox', externalProvider: null }`). Per the Metadata Evolution Protocol, no version bump is required.

### Anti-Patterns to Avoid

- **Server-side credential storage:** Original BYO-03 wording says "stored server-side" but CONTEXT.md overrides this. Never store IPFS auth tokens on the server -- use vault metadata on IPFS.
- **Blocking UI on PSA pin confirmation:** PSA pinning is asynchronous. `POST /pins` returns status `queued`. Do not block the upload UI waiting for `pinned` status -- report success after CID is obtained, show pin status asynchronously.
- **Silent fallback in external-only mode:** Per CONTEXT.md, if the user's node is unreachable in external-only mode, the upload must fail with a clear error. Never silently fall back to CipherBox.
- **CORS-unaware connection test:** A connection test that passes from Node.js but fails from the browser is useless. The test MUST run from the browser context.
- **Storing auth tokens in Zustand/localStorage:** Auth tokens for IPFS providers should only exist in memory after vault decryption. Never persist to browser storage.

## Don't Hand-Roll

| Problem                  | Don't Build            | Use Instead                                          | Why                                                                        |
| ------------------------ | ---------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------- |
| Job queue for migration  | Custom polling loop    | BullMQ (already installed)                           | Retry logic, progress tracking, pause/resume, failure handling             |
| CORS validation          | Custom preflight probe | Browser `fetch()` with try/catch on TypeError        | The browser handles CORS natively; a TypeError on fetch is the CORS signal |
| Protocol detection       | Complex heuristics     | Sequential probe: Kubo `/api/v0/id` then PSA `/pins` | Only two protocols; probe order is deterministic                           |
| Encrypted config storage | New encryption scheme  | Existing vault metadata encryption (AES-256-GCM)     | Same pattern used for folder metadata, file metadata                       |
| Tab navigation UI        | Custom tab component   | Existing SettingsPage tab pattern with ARIA          | Already has keyboard handling, focus management                            |

**Key insight:** Most infrastructure already exists. BullMQ for queues, vault metadata encryption for credential storage, Settings tab navigation for UI, TEE key management for migration credential wrapping.

## Common Pitfalls

### Pitfall 1: PSA Cannot Upload Data

**What goes wrong:** Attempting to send raw encrypted data via `POST /pins` to a PSA endpoint. PSA only accepts CIDs -- it expects the content to already exist on the IPFS network.
**Why it happens:** Confusion between "pinning" (making content persistent on a specific node) and "adding" (uploading content to IPFS).
**How to avoid:** The SDK orchestrator must handle the upload path differently for PSA vs Kubo. For PSA in external-only mode, upload to CipherBox first to get CID, then tell PSA to pin it.
**Warning signs:** PSA returns 400 with "invalid CID" or "unexpected body."

### Pitfall 2: CORS Blocking Browser-Direct Kubo Access

**What goes wrong:** User enters their Kubo node URL, connection test fails silently or with cryptic error.
**Why it happens:** Kubo's RPC API defaults to localhost-only with no CORS headers. Browser blocks cross-origin requests.
**How to avoid:** Connection test must specifically detect CORS failures (TypeError from fetch) and show Kubo-specific CORS configuration instructions:

```
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '["https://app.cipherbox.cc", "http://localhost:5173"]'
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Methods '["POST"]'
```

**Warning signs:** `TypeError: Failed to fetch` in browser console.

### Pitfall 3: PSA Unpin Requires Request ID, Not CID

**What goes wrong:** Calling `DELETE /pins/{cid}` fails because PSA uses request IDs, not CIDs.
**Why it happens:** PSA's resource model uses `requestid` (an opaque service-generated ID), not CIDs directly.
**How to avoid:** To unpin, first `GET /pins?cid={cid}` to find the `requestid`, then `DELETE /pins/{requestid}`.
**Warning signs:** 404 on DELETE requests.

### Pitfall 4: Vault Metadata Circular Dependency

**What goes wrong:** BYO config is in vault metadata, but vault metadata is loaded on login before the pinning provider is initialized. If BYO config is needed to create the pinning provider, and the pinning provider is needed to load vault metadata...
**Why it happens:** Vault metadata is fetched via CipherBox API (which reads from IPFS), not via the user's BYO node.
**How to avoid:** Vault metadata is always fetched from CipherBox's IPFS node (or from the IPFS network via the API). BYO config only affects file content pinning, not metadata resolution. The load order is: (1) login, (2) fetch vault blob from API, (3) decrypt vault blob to get BYO config, (4) initialize pinning provider.
**Warning signs:** Provider initialization errors on login.

### Pitfall 5: Migration Race with Active Uploads

**What goes wrong:** User starts migration while also uploading new files. New files get pinned to old provider, migration doesn't know about them.
**Why it happens:** Migration reads CID list at start time; new uploads create CIDs after the list was created.
**How to avoid:** Migration controller should track "migration started at" timestamp. After migration completes, sweep for CIDs pinned after start time. Or simpler: disable uploads during migration.
**Warning signs:** Files missing from new provider after migration.

### Pitfall 6: Auth Token Rotation Breaking Migration

**What goes wrong:** User rotates their Pinata API key mid-migration. TEE has the old encrypted token, decrypts it, gets 401 from Pinata.
**Why it happens:** TEE received encrypted auth tokens at migration start; they become stale.
**How to avoid:** Migration should handle 401 gracefully -- pause migration, notify user that credentials are invalid, allow re-submit with new credentials.
**Warning signs:** Migration stuck at partial progress with repeated failures.

## Code Examples

### CID Registration Endpoint (API)

```typescript
// apps/api/src/ipfs/dto/register-cid.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsInt, Min } from 'class-validator';

export class RegisterCidDto {
  @ApiProperty({ description: 'IPFS CID pinned to external provider' })
  @IsString()
  cid!: string;

  @ApiProperty({ description: 'Size of the pinned content in bytes' })
  @IsInt()
  @Min(1)
  sizeBytes!: number;
}

// In ipfs.controller.ts
@Post('register-cid')
@ApiOperation({
  summary: 'Register externally-pinned CID for advisory quota tracking',
  description: 'BYO users report CIDs pinned to their own nodes. Advisory only -- no enforcement.',
})
async registerCid(
  @Request() req: RequestWithUser,
  @Body() dto: RegisterCidDto
): Promise<{ recorded: boolean }> {
  await this.vaultService.recordPin(req.user.id, dto.cid, dto.sizeBytes);
  return { recorded: true };
}
```

### Advisory Quota in Vault Service

```typescript
// Modify vault.service.ts getQuota to include advisory flag
async getQuota(userId: string): Promise<QuotaResponseDto & { advisory: boolean }> {
  const quota = await this.getBaseQuota(userId);
  const isByoUser = await this.isUserByo(userId);
  return {
    ...quota,
    advisory: isByoUser,  // BYO users see advisory quota, not enforced
  };
}

// checkQuota should skip enforcement for BYO users
async checkQuota(userId: string, additionalBytes: number): Promise<boolean> {
  const isByoUser = await this.isUserByo(userId);
  if (isByoUser) return true;  // Advisory only -- always allow
  const quota = await this.getBaseQuota(userId);
  return quota.usedBytes + additionalBytes <= QUOTA_LIMIT_BYTES;
}
```

### Settings STORAGE Tab Pattern

```typescript
// apps/web/src/components/settings/StorageTab.tsx
// Follows existing tab panel pattern from SettingsPage.tsx

export function StorageTab() {
  const [mode, setMode] = useState<'cipherbox' | 'external' | 'dual'>('cipherbox');
  const [endpoint, setEndpoint] = useState('');
  const [authToken, setAuthToken] = useState('');
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [isDirty, setIsDirty] = useState(false);

  const handleTest = async () => {
    const result = await testConnection(endpoint, authToken);
    setTestResult(result);
  };

  return (
    <div className="settings-storage">
      <h3 className="settings-section-heading">{'// pinning mode'}</h3>

      {/* Radio selector for pinning mode */}
      <fieldset className="storage-mode-selector" role="radiogroup">
        <label>
          <input type="radio" name="pinning-mode" value="cipherbox"
            checked={mode === 'cipherbox'} onChange={() => setMode('cipherbox')} />
          CipherBox only (default)
        </label>
        <label>
          <input type="radio" name="pinning-mode" value="external"
            checked={mode === 'external'} onChange={() => setMode('external')} />
          External only
        </label>
        <label>
          <input type="radio" name="pinning-mode" value="dual"
            checked={mode === 'dual'} onChange={() => setMode('dual')} />
          Dual-pin (both)
        </label>
      </fieldset>

      {/* Provider config (shown when external or dual selected) */}
      {mode !== 'cipherbox' && (
        <>
          <label className="storage-field">
            endpoint URL
            <input type="url" value={endpoint} onChange={...} />
          </label>
          <label className="storage-field">
            auth token
            <input type="password" value={authToken} onChange={...} />
          </label>
          <button type="button" onClick={handleTest}>[--test connection]</button>

          {testResult && (
            <div className="connection-test-result">
              {testResult.success
                ? `> connected (${testResult.latencyMs}ms) // detected: ${testResult.protocol} ${testResult.version ?? ''}`
                : `> failed: ${testResult.error}`}
              {testResult.corsError && (
                <pre className="cors-instructions">{testResult.corsInstructions}</pre>
              )}
            </div>
          )}
        </>
      )}

      {/* Save/Discard buttons */}
      {isDirty && (
        <div className="storage-actions">
          <button type="button" disabled={mode !== 'cipherbox' && !testResult?.success}
            onClick={handleSave}>[--save]</button>
          <button type="button" onClick={handleDiscard}>[--discard]</button>
        </div>
      )}
    </div>
  );
}
```

### TEE Migration Job Structure

```typescript
// apps/api/src/migration/migration.entity.ts
@Entity('pin_migrations')
export class PinMigration {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid', name: 'user_id' })
  userId!: string;

  @Column({ type: 'varchar', length: 20 })
  status!: 'pending' | 'running' | 'paused' | 'completed' | 'failed';

  @Column({ type: 'int', name: 'total_cids', default: 0 })
  totalCids!: number;

  @Column({ type: 'int', name: 'migrated_cids', default: 0 })
  migratedCids!: number;

  @Column({ type: 'int', name: 'failed_cids', default: 0 })
  failedCids!: number;

  @Column({ type: 'text', name: 'source_config_encrypted' })
  sourceConfigEncrypted!: string; // ECIES-wrapped with TEE public key

  @Column({ type: 'text', name: 'dest_config_encrypted' })
  destConfigEncrypted!: string; // ECIES-wrapped with TEE public key

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @Column({ type: 'timestamp', name: 'completed_at', nullable: true })
  completedAt!: Date | null;
}
```

## State of the Art

| Old Approach                   | Current Approach                      | When Changed | Impact                                        |
| ------------------------------ | ------------------------------------- | ------------ | --------------------------------------------- |
| Server-side IPFS provider only | Client-direct with SDK providers      | Phase 21     | Users control their own IPFS infrastructure   |
| Server stores all config       | Vault metadata on IPFS for BYO config | Phase 21     | True zero-knowledge for provider credentials  |
| Single IPFS protocol (Kubo)    | PSA + Kubo dual protocol support      | Phase 21     | Covers managed services AND self-hosted nodes |
| Hard quota enforcement         | Advisory quota for BYO users          | Phase 21     | BYO users manage their own storage limits     |

**Important PSA ecosystem notes:**

- The PSA spec (v1.0.0) has been stable since 2021 with no breaking changes
- web3.storage classic tokens were revoked November 2025; new w3up protocol uses UCAN auth, not PSA
- Pinata's PSA endpoint is at `https://api.pinata.cloud/psa`; their primary upload API is proprietary (`uploads.pinata.cloud/v3/files`)
- Filebase supports PSA and has configurable CORS per-bucket
- Kubo RPC API is `POST`-based for all operations (not REST), requires explicit CORS config for browser access

## Open Questions

1. **PSA "external only" data path**
   - What we know: PSA can only pin by CID reference. Data must exist on IPFS network first.
   - What's unclear: In "external only" mode with PSA, should CipherBox node serve as transient ingest point? This means CipherBox API still sees the encrypted blob briefly.
   - Recommendation: Use CipherBox as transient ingest for PSA in v1.0. Encrypted data is safe. Add provider-specific upload adapters in a future phase for true zero-relay.

2. **Vault blob v2 dependency**
   - What we know: Phase 20 introduces vault blob v2 on IPFS. BYO config should be stored there.
   - What's unclear: If Phase 20 is not yet complete, where does BYO config go?
   - Recommendation: If vault blob v2 exists, extend it with `byoIpfs` field. If not, store BYO config as a separate encrypted blob at a dedicated IPNS name (less ideal but decoupled from Phase 20).

3. **TEE migration endpoint authentication**
   - What we know: TEE worker currently uses shared secret (`TEE_AUTH_SECRET`) for API auth.
   - What's unclear: Migration endpoint needs to access two external IPFS services. Should TEE reach out to arbitrary URLs?
   - Recommendation: TEE migration worker fetches from source and pushes to destination. Both URLs come from the migration job payload (encrypted with TEE key). Allowlist is not practical since users can use any IPFS service. Input validation on URLs (HTTPS-only, no private IPs) provides basic safety.

4. **Download path in BYO mode**
   - What we know: Uploads go to user's node in external-only mode.
   - What's unclear: Downloads -- should they come from user's node or from CipherBox?
   - Recommendation: Downloads should try user's node first (for external-only mode), fall back to CipherBox gateway. For Kubo, use `/api/v0/cat`. For PSA, PSA has no retrieval API -- must use IPFS gateway.

## Validation Architecture

### Test Framework

| Property           | Value                                                                 |
| ------------------ | --------------------------------------------------------------------- |
| Framework          | vitest 3.0.5+                                                         |
| Config file        | `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts` |
| Quick run command  | `pnpm --filter @cipherbox/sdk-core test`                              |
| Full suite command | `pnpm test` (all packages)                                            |

### Phase Requirements to Test Map

| Req ID | Behavior                                    | Test Type   | Automated Command                                                                       | File Exists?                    |
| ------ | ------------------------------------------- | ----------- | --------------------------------------------------------------------------------------- | ------------------------------- |
| BYO-01 | PsaProvider implements pin/unpin/status     | unit        | `pnpm --filter @cipherbox/sdk-core test -- --run src/__tests__/pinning.test.ts`         | Wave 0                          |
| BYO-02 | DualPinProvider orchestrates both providers | unit        | `pnpm --filter @cipherbox/sdk-core test -- --run src/__tests__/pinning.test.ts`         | Wave 0                          |
| BYO-03 | BYO config stored in vault metadata         | unit        | `pnpm --filter @cipherbox/core test -- --run src/__tests__/vault.test.ts`               | Extend existing                 |
| BYO-04 | STORAGE tab renders and handles input       | manual-only | Playwright MCP verification                                                             | N/A                             |
| BYO-05 | Connection test detects protocol + CORS     | unit        | `pnpm --filter @cipherbox/sdk-core test -- --run src/__tests__/connection-test.test.ts` | Wave 0                          |
| BYO-06 | IPNS publishes unchanged                    | integration | `pnpm --filter @cipherbox/sdk test -- --run src/__tests__/client.test.ts`               | Existing (verify no regression) |
| BYO-07 | Advisory quota for BYO users                | unit        | `pnpm --filter api test -- --run src/vault/vault.service.spec.ts`                       | Extend existing                 |

### Sampling Rate

- **Per task commit:** `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test`
- **Per wave merge:** `pnpm test` (full monorepo)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `packages/sdk-core/src/__tests__/pinning.test.ts` -- KuboProvider, PsaProvider, DualPinProvider unit tests with mocked fetch
- [ ] `packages/sdk-core/src/__tests__/connection-test.test.ts` -- protocol detection, CORS error detection
- [ ] `apps/api/src/migration/migration.service.spec.ts` -- migration job lifecycle tests
- [ ] `apps/api/src/ipfs/ipfs.controller.spec.ts` -- registerCid endpoint tests (extend existing)
- [ ] `apps/api/src/vault/vault.service.spec.ts` -- advisory quota mode tests (extend existing)

## Sources

### Primary (HIGH confidence)

- Existing codebase: `apps/api/src/ipfs/providers/ipfs-provider.interface.ts` -- IpfsProvider contract
- Existing codebase: `apps/api/src/ipfs/providers/local.provider.ts` -- Kubo RPC implementation
- Existing codebase: `packages/sdk-core/src/ipfs/index.ts` -- Current upload flow via API relay
- Existing codebase: `packages/sdk/src/client.ts` -- CipherBoxClient architecture
- Existing codebase: `apps/api/src/republish/` -- BullMQ queue pattern
- Existing codebase: `tee-worker/src/services/key-manager.ts` -- ECIES credential wrapping
- [IPFS Pinning Service API spec (YAML)](https://github.com/ipfs/pinning-services-api-spec/blob/main/ipfs-pinning-service.yaml) -- PSA endpoints, schemas, auth
- [IPFS Pinning Service API docs](https://ipfs.github.io/pinning-services-api-spec/) -- PSA reference documentation

### Secondary (MEDIUM confidence)

- [Kubo RPC API reference](https://docs.ipfs.tech/reference/kubo/rpc/) -- Kubo endpoint documentation
- [Kubo CORS configuration](https://github.com/ipfs/kubo/blob/master/docs/config.md) -- API.HTTPHeaders CORS setup
- [Pinata PSA endpoint docs](https://docs.pinata.cloud/api-reference/pinning-service-api) -- Pinata's PSA at `/psa`
- [Pinata upload docs](https://docs.pinata.cloud/pinning/pinning-files) -- Proprietary upload API
- [Filebase CORS configuration](https://filebase.com/blog/simplifying-cors-configurations-for-ipfs-pinning/) -- Per-bucket CORS policy

### Tertiary (LOW confidence)

- web3.storage PSA compatibility -- classic API deprecated Nov 2025; w3up uses UCAN, not standard PSA. Needs validation if users want to use web3.storage.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - all libraries already in repo, no new dependencies
- Architecture: MEDIUM-HIGH - SDK provider pattern is clear, PSA pin-by-CID caveat is well-understood
- Pitfalls: HIGH - CORS, PSA data path, and vault metadata ordering are well-documented edge cases
- TEE migration: MEDIUM - follows existing republish pattern but migration is new territory for this codebase

**Research date:** 2026-03-24
**Valid until:** 2026-04-24 (PSA spec is stable; CORS behavior is browser-constant)

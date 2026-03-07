# Architecture: IPFS Infrastructure v1.1

**Domain:** IPNS reliability, database minimization, BYO-IPFS, performance baselines
**Researched:** 2026-03-07
**Confidence:** HIGH (existing codebase analyzed; Kubo APIs verified against official docs)

---

## Table of Contents

1. [Existing Architecture Summary](#1-existing-architecture-summary)
2. [IPNS Resolution: Replace delegated-ipfs.dev](#2-ipns-resolution-replace-delegated-ipfsdev)
3. [Database Minimization: Migration Path](#3-database-minimization-migration-path)
4. [BYO-IPFS Node Support](#4-byo-ipfs-node-support)
5. [Performance Instrumentation](#5-performance-instrumentation)
6. [Component Boundary Map](#6-component-boundary-map)
7. [Data Flow Changes](#7-data-flow-changes)
8. [Suggested Build Order](#8-suggested-build-order)
9. [Sources](#9-sources)

---

## 1. Existing Architecture Summary

### Current IPNS Flow (What Changes)

```text
Client                     API                        delegated-ipfs.dev        Kubo
  |                         |                               |                    |
  |-- sign IPNS record ---->|                               |                    |
  |                         |-- upsert folder_ipns (DB) --->|                    |
  |                         |-- PUT /routing/v1/ipns/:name ->|                    |
  |                         |<-- 200 OK or 502 -------------|                    |
  |<-- { sequenceNumber } --|                               |                    |
  |                         |                               |                    |
  |-- resolve IPNS -------->|                               |                    |
  |                         |-- GET /routing/v1/ipns/:name ->|                    |
  |                         |<-- record bytes or 502 --------|                    |
  |                         |-- fallback: query folder_ipns --|                   |
  |<-- { cid, seqNum } -----|                               |                    |
```

**Key problem:** `delegated-ipfs.dev` is the sole IPNS resolution path from the API. The DB-cached CID is the fallback, but this means the DB is doing double duty as both CID cache and the reliable resolution source. The external service adds latency (10s timeout, 3 retries with backoff) and has documented 502 reliability issues.

### Current Database Tables (What Shrinks)

| Table                     | Rows/User          | Purpose                                                                           | Can Migrate to IPFS?                                   |
| ------------------------- | ------------------ | --------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `users`                   | 1                  | UUID, publicKey                                                                   | NO -- identity anchor                                  |
| `auth_methods`            | 1-5                | Auth provider links                                                               | NO -- server-side auth                                 |
| `refresh_tokens`          | 1-3                | JWT sessions                                                                      | NO -- server-side auth                                 |
| `vaults`                  | 1                  | encryptedRootFolderKey, encryptedRootIpnsPrivateKey, rootIpnsName, ownerPublicKey | PARTIALLY -- rootFolderKey to IPFS                     |
| `folder_ipns`             | N folders+files    | latestCid, sequenceNumber, encryptedIpnsPrivateKey, keyEpoch                      | YES -- but serves as CID cache and concurrency tracker |
| `pinned_cids`             | N files            | CID, sizeBytes (quota tracking)                                                   | NO -- server enforces quota                            |
| `ipns_republish_schedule` | N folders+files    | TEE republish state                                                               | NO -- TEE orchestration is server-side                 |
| `shares`                  | N shares           | Sharer, recipient, encryptedKey, revocation                                       | FUTURE -- CRDT inbox research                          |
| `share_keys`              | N file/folder keys | Per-item encrypted keys for shares                                                | FUTURE -- CRDT inbox research                          |
| `share_invites`           | sparse             | Link sharing tokens                                                               | NO -- server-validated tokens                          |
| `device_approvals`        | sparse             | MFA device approval state                                                         | NO -- short-lived server state                         |
| `tee_key_state`           | 1                  | TEE epoch tracking                                                                | NO -- server-side TEE coordination                     |
| `tee_key_rotation_log`    | sparse             | Rotation audit trail                                                              | NO -- admin audit                                      |

### Current IPFS Provider Abstraction

The existing `IpfsProvider` interface is minimal (3 methods):

```typescript
interface IpfsProvider {
  pinFile(data: Buffer, metadata?: Record<string, string>): Promise<{ cid: string; size: number }>;
  unpinFile(cid: string): Promise<void>;
  getFile(cid: string): Promise<Buffer>;
}
```

Only `LocalProvider` (Kubo) exists. The interface is injected via `IPFS_PROVIDER` DI token in `IpfsModule.forRootAsync()`, configured from env vars `IPFS_LOCAL_API_URL` and `IPFS_LOCAL_GATEWAY_URL`.

---

## 2. IPNS Resolution: Replace delegated-ipfs.dev

### 2.1 Recommendation: DB-First Resolution + Kubo DHT Verification

**Strategy:** Invert the current resolution priority. Make the DB-cached CID the primary resolution source (it is already written synchronously on every publish). Use the self-hosted Kubo node's `/api/v0/name/resolve` endpoint for background DHT verification. Demote `delegated-ipfs.dev` to a disabled-by-default fallback.

**Why this approach:**

1. **Eliminates external dependency.** The self-hosted Kubo node already participates in the IPFS DHT. It can resolve IPNS names directly without delegated-ipfs.dev.
2. **DB cache is already the reliable source.** The `IpnsService.resolveRecord()` method (lines 290-350 of `ipns.service.ts`) already prefers DB cache when its sequence number is higher than the network result. Making DB-first explicit simplifies the architecture.
3. **Kubo DHT resolution has improved.** Kubo 0.38+ has sweep providers with 97% fewer DHT lookups for large-scale operations. IPNS TTL defaults dropped from 1 hour to 5 minutes in recent releases, so changes propagate faster.
4. **PubSub for same-node resolution.** Kubo supports `Ipns.UsePubsub` for near-instant IPNS record propagation between connected peers. When both the publishing client and the TEE republisher connect through the same Kubo node, PubSub makes resolution instantaneous.

### 2.2 Architecture Change

**Before (current):**

```text
IpnsService.resolveRecord()
  -> DelegatedRoutingClient.resolve() -> https://delegated-ipfs.dev (primary, 10s timeout)
  -> folder_ipns DB query (fallback on 502/timeout)
  -> Compare sequence numbers, return highest
```

**After:**

```text
IpnsService.resolveRecord()
  -> folder_ipns DB query (primary, <5ms)
  -> Return DB result immediately to caller
  -> Async: KuboIpnsClient.resolve() -> http://kubo:5001/api/v0/name/resolve (background)
     -> If DHT has higher sequence number, update DB cache
     -> If DHT fails, no-op (DB is authoritative for our records)
```

### 2.3 New Component: KuboIpnsClient

Wraps Kubo's RPC API for IPNS operations:

```typescript
// apps/api/src/ipns/kubo-ipns.client.ts
@Injectable()
export class KuboIpnsClient {
  constructor(private readonly configService: ConfigService) {
    this.kuboApiUrl = configService.get('IPFS_LOCAL_API_URL', 'http://localhost:5001');
  }

  /**
   * Resolve IPNS name via Kubo DHT.
   * POST /api/v0/name/resolve?arg=<ipnsName>&dht-timeout=5s&nocache=true
   * Returns the resolved /ipfs/<cid> path or null if not found.
   */
  async resolve(ipnsName: string): Promise<{ path: string } | null> {
    /* ... */
  }

  /**
   * Publish via Kubo's native IPNS publisher (for TEE republish path).
   * Requires key imported into Kubo's keystore first.
   * POST /api/v0/name/publish?arg=/ipfs/<cid>&key=<keyName>&ttl=5m
   */
  async publish(keyName: string, cid: string, options?: { ttl?: string }): Promise<void> {
    /* ... */
  }

  /**
   * Import an Ed25519 private key into Kubo's keystore.
   * POST /api/v0/key/import?arg=<keyName>&format=libp2p-protobuf-cleartext
   * Body: multipart/form-data with key bytes
   */
  async importKey(keyName: string, privateKeyBytes: Uint8Array): Promise<void> {
    /* ... */
  }

  /**
   * List keys in Kubo's keystore (for cleanup).
   * POST /api/v0/key/list
   */
  async listKeys(): Promise<string[]> {
    /* ... */
  }

  /**
   * Remove a key from Kubo's keystore.
   * POST /api/v0/key/rm?arg=<keyName>
   */
  async removeKey(keyName: string): Promise<void> {
    /* ... */
  }
}
```

### 2.4 Publishing Path: Keep Pre-Signed Records for Client Publishes

The current publishing flow has clients sign IPNS records locally and send pre-signed bytes to the API. This is correct for zero-knowledge -- the server never has the unencrypted IPNS private key. This does NOT change.

**For client publishes:** The API receives pre-signed record bytes via `POST /ipns/publish`. The API:

1. Upserts the `folder_ipns` DB record (unchanged -- this is the reliable CID source)
2. Broadcasts the pre-signed record to the DHT via Kubo's `/api/v0/routing/put` (replaces delegated-ipfs.dev)
3. Falls back to delegated-ipfs.dev only if Kubo routing put fails and the fallback is enabled

**For TEE republishes:** The TEE already has the decrypted IPNS private key in hardware. Instead of TEE signing a record and the API broadcasting via delegated routing, the TEE can return the raw Ed25519 private key bytes (still inside the TEE boundary), and the API can:

1. Import the key temporarily into Kubo's keystore (`/api/v0/key/import`)
2. Call `/api/v0/name/publish` directly through Kubo
3. Remove the key from Kubo's keystore (`/api/v0/key/rm`)

This bypasses delegated-ipfs.dev entirely for republishing. However, this is an optimization, not a requirement. The existing TEE->signed record->delegated routing path still works as a fallback.

**Security note on Kubo key import:** The IPNS private key is transiently present in Kubo's memory during the publish call. This is acceptable because:

- Kubo already runs on the same host as the API in a Docker network
- The key is encrypted at rest in the DB (encrypted with TEE public key)
- The key is removed from Kubo's keystore immediately after publish
- The alternative (delegated-ipfs.dev) sends the signed record over the internet, which is a larger attack surface

### 2.5 Kubo Configuration Changes

Enable on the self-hosted Kubo node:

```json
{
  "Ipns": {
    "UsePubsub": true
  },
  "Routing": {
    "Type": "auto"
  }
}
```

`Routing.Type: "auto"` (default) uses both DHT and any configured delegated routers. `Ipns.UsePubsub: true` enables near-instant resolution when both publisher and resolver subscribe to the same pubsub topic. This is especially useful for same-node operations (client publishes, then immediately resolves on the same Kubo instance).

### 2.6 Impact on Recovery Tool

The recovery tool (`apps/web/public/recovery.html`) currently resolves IPNS via `delegated-ipfs.dev` directly from the browser (no API needed -- the tool works offline from the CipherBox API).

Updated resolution order for recovery:

1. Try the CipherBox API's `/ipns/resolve` endpoint (DB-first + Kubo DHT)
2. Fall back to `delegated-ipfs.dev` only if the API is unreachable (true offline recovery)
3. The tool should accept a manual CID input as a last resort (user pastes CID from backup)

### 2.7 Modified Files

| File                                            | Change                                                           |
| ----------------------------------------------- | ---------------------------------------------------------------- |
| `apps/api/src/ipns/kubo-ipns.client.ts`         | NEW -- Kubo RPC client for IPNS operations                       |
| `apps/api/src/ipns/kubo-ipns.client.spec.ts`    | NEW -- Unit tests                                                |
| `apps/api/src/ipns/ipns.service.ts`             | MODIFY `resolveRecord()` to DB-first with async DHT verification |
| `apps/api/src/ipns/delegated-routing.client.ts` | MODIFY -- Add config flag to disable, demote to fallback         |
| `apps/api/src/ipns/ipns.module.ts`              | MODIFY -- Register `KuboIpnsClient`                              |
| `apps/api/src/republish/republish.service.ts`   | MODIFY -- Option to use Kubo native publish for TEE path         |
| `apps/api/.env.example`                         | ADD `IPNS_DELEGATED_ROUTING_ENABLED=false`                       |
| `apps/web/public/recovery.html`                 | MODIFY -- Updated resolution order                               |

---

## 3. Database Minimization: Migration Path

### 3.1 Table-by-Table Analysis

#### 3.1.1 `vaults.encryptedRootFolderKey` -- MIGRATE TO IPFS

**Current state:** The `vaults` table stores `encryptedRootFolderKey` (ECIES-wrapped with user's publicKey) and `encryptedRootIpnsPrivateKey` (also ECIES-wrapped, but redundant since the IPNS key is HKDF-derivable).

**Migration:** Move `encryptedRootFolderKey` into the IPFS blob pointed at by the root vault IPNS record. The blob currently contains only AES-GCM encrypted folder metadata. The new format prepends the ECIES-wrapped root folder key.

**New blob format (version 2):**

```text
Vault IPFS Blob v2:
  Byte 0:       version = 0x02
  Bytes 1-2:    encryptedRootFolderKey length (uint16, big-endian)
  Bytes 3..N:   ECIES-encrypted rootFolderKey
  Bytes N+1..:  AES-GCM encrypted folder metadata (unchanged)

Vault IPFS Blob v1 (current, no version byte):
  All bytes:    AES-GCM encrypted folder metadata
```

Detection: If the first byte is `0x02`, parse as v2. If the first bytes are a valid AES-GCM ciphertext (IV + ciphertext + tag), parse as v1.

**Login flow change:**

Before:

```text
Login -> API GET /vault -> { encryptedRootFolderKey, rootIpnsName }
      -> Derive IPNS key via HKDF
      -> Resolve IPNS -> fetch blob -> decrypt metadata with rootFolderKey
```

After:

```text
Login -> Derive IPNS key via HKDF (no API call needed for key material)
      -> API GET /ipns/resolve?ipnsName=<root> -> { cid }
      -> API GET /ipfs/<cid> -> blob v2
      -> Extract encryptedRootFolderKey from blob header
      -> ECIES decrypt rootFolderKey with privateKey
      -> Decrypt folder metadata with rootFolderKey
```

**Migration strategy (dual-write, version-aware read):**

1. **Write path:** Client publishes root metadata in blob v2 format (encryptedRootFolderKey in header). ALSO continues sending encryptedRootFolderKey in the vault init call for backward compatibility with older clients and the current recovery tool.
2. **Read path:** Client checks first byte of blob. v2 -> extract key from blob. v1 or unrecognizable -> fall back to `GET /vault` for the key.
3. **Cutover criteria:** When all active clients support blob v2 reading, the `GET /vault` endpoint can stop returning `encryptedRootFolderKey`. The column is kept in the DB as disaster recovery fallback but is no longer the primary source.

#### 3.1.2 `vaults.encryptedRootIpnsPrivateKey` -- ELIMINATE

This field is redundant. The root IPNS private key is deterministically derivable from the user's secp256k1 private key via HKDF:

```text
rootIpnsPrivateKey = HKDF(userPrivateKey, info="cipherbox-root-ipns")
```

The client already performs this derivation. The server-stored copy was a bootstrapping convenience from v0.1 that is no longer needed. Stop sending it in vault init. Keep the DB column for backward compatibility but mark it deprecated.

#### 3.1.3 `folder_ipns` -- KEEP BUT REDUCE ROLE

The `folder_ipns` table currently serves four purposes:

1. **CID cache** -- Reliable fallback when IPNS DHT resolution fails
2. **Sequence number tracking** -- Optimistic concurrency control (409 Conflict detection)
3. **Encrypted IPNS key storage** -- For TEE enrollment
4. **Record type metadata** -- folder vs file distinction

With reliable Kubo IPNS resolution (section 2):

- Purpose 1 (CID cache) is still valuable as a fast path (<5ms vs seconds for DHT), but no longer critical as the sole reliable source
- Purpose 2 (sequence numbers) is essential and CANNOT move to IPFS. You need to know the current sequence BEFORE publishing. This is inherently a server-side coordination concern.
- Purpose 3 (encrypted IPNS key) is duplicated in `ipns_republish_schedule`. Can be deduplicated by having the republish schedule reference `folder_ipns` instead of storing its own copy. Minor cleanup.
- Purpose 4 (record type) is metadata, could be derived but not worth the effort to remove.

**Recommendation:** Keep `folder_ipns` as a "publish coordination table." Rename its conceptual role in documentation. Do NOT attempt to eliminate it -- sequence number tracking is a hard requirement for conflict detection.

#### 3.1.4 `shares`, `share_keys` -- FUTURE (CRDT INBOX RESEARCH ONLY)

Per the CRDT-based IPNS inbox todo, this milestone performs research only. The tables stay as-is. Key findings:

- G-Set CRDT solves concurrent share additions (append-only inbox)
- Write-access control via signed envelopes prevents inbox spam
- Revocation by key rotation (not by modifying inbox) aligns with existing lazy revocation pattern
- State size growth needs compaction strategy
- **Dependency:** Requires reliable IPNS resolution (section 2) before inbox-based discovery is viable
- **Scope for v1.1:** Document the CRDT approach as a design RFC. Do NOT implement.

#### 3.1.5 `device_approvals` -- MIGRATE TO IPFS (POSSIBLE BUT NOT RECOMMENDED)

Device approvals are short-lived (15-minute expiry), require real-time status updates (pending -> approved/denied), and involve server-mediated notification polling. IPNS polling at 30s intervals is too slow for MFA approval UX. Keep server-side.

#### 3.1.6 `pinned_cids` -- KEEP (QUOTA ENFORCEMENT)

The server must enforce storage quotas. If quota tracking moves to IPFS, a malicious client could lie about their storage usage. The server must independently track pinned CID sizes.

### 3.2 Post-Migration Database Role

After v1.1 migrations, the database serves these purposes:

| Purpose              | Tables                                                             | Why Server-Side                   |
| -------------------- | ------------------------------------------------------------------ | --------------------------------- |
| Identity             | `users`, `auth_methods`                                            | Server-mediated auth              |
| Sessions             | `refresh_tokens`                                                   | JWT lifecycle                     |
| Quota enforcement    | `pinned_cids`                                                      | Server must prevent quota abuse   |
| Publish coordination | `folder_ipns`                                                      | Sequence numbers for concurrency  |
| TEE orchestration    | `ipns_republish_schedule`, `tee_key_state`, `tee_key_rotation_log` | Server schedules TEE work         |
| Sharing graph        | `shares`, `share_keys`, `share_invites`                            | Until CRDT inbox (v1.2+)          |
| MFA                  | `device_approvals`                                                 | Short-lived approval state        |
| Vault metadata       | `vaults` (reduced)                                                 | ownerPublicKey, rootIpnsName only |

**What was eliminated:** Server no longer stores any user crypto material (encryptedRootFolderKey, encryptedRootIpnsPrivateKey). The server becomes a coordination relay, not a key escrow.

---

## 4. BYO-IPFS Node Support

### 4.1 Recommendation: Server-Relay Model with Provider Abstraction

**Decision:** Server-relay (not client-direct) because:

1. **Quota tracking:** Server must see upload sizes to enforce quota. Client-direct bypasses quota enforcement entirely.
2. **IPNS publish coordination:** Sequence numbers are tracked server-side in `folder_ipns`. Bypassing the API means no conflict detection.
3. **CORS/connectivity:** Kubo's RPC API has no CORS headers by default. Client-direct from the browser requires the user's node to be publicly accessible or configured with CORS -- unreliable for home nodes behind NAT.
4. **Credential safety:** Server-relay means user's IPFS node credentials (API keys, auth tokens) are stored server-side, but the data passing through is already AES-256-GCM encrypted ciphertext. The server cannot read content regardless of relay model.

**Future exception:** Desktop clients (Tauri) can pin directly to a user's local Kubo node because there are no CORS restrictions and the desktop app is trusted. This is a v1.2+ enhancement.

### 4.2 Provider Abstraction Extension

Extend the existing `IpfsProvider` with a per-user factory:

```typescript
// apps/api/src/ipfs/providers/ipfs-provider.interface.ts -- ADDITIONS
export interface IpfsProviderFactory {
  /** Get the appropriate IPFS provider for a given user */
  getProvider(userId: string): Promise<IpfsProvider>;
  /** Get the default (CipherBox-managed) provider */
  getDefaultProvider(): IpfsProvider;
}

export const IPFS_PROVIDER_FACTORY = 'IPFS_PROVIDER_FACTORY';
```

The factory checks for per-user IPFS configuration. If none exists, it returns the default `LocalProvider`. If the user has a custom node configured, it returns a dual-pin provider that pins to both nodes.

### 4.3 New Provider: UserCustomProvider

```typescript
// apps/api/src/ipfs/providers/user-custom.provider.ts
export class UserCustomProvider implements IpfsProvider {
  constructor(
    private readonly endpoint: string,
    private readonly authToken?: string,
    private readonly providerType: 'kubo' | 'pinning-api'
  ) {}

  async pinFile(data: Buffer): Promise<{ cid: string; size: number }> {
    if (this.providerType === 'kubo') {
      // Kubo RPC: POST /api/v0/add?pin=true&cid-version=1
      return this.pinViaKuboApi(data);
    } else {
      // IPFS Pinning Service API (spec: ipfs.github.io/pinning-services-api-spec)
      // POST /pins with CID (requires content already available on IPFS network)
      // For fresh uploads, use /api/v0/add equivalent or add+pin flow
      return this.pinViaPinningApi(data);
    }
  }

  async unpinFile(cid: string): Promise<void> {
    /* provider-specific unpin */
  }
  async getFile(cid: string): Promise<Buffer> {
    /* provider-specific fetch */
  }
}
```

**Provider types supported:**

| Provider Type | Protocol                   | Examples                       | Auth Method                    |
| ------------- | -------------------------- | ------------------------------ | ------------------------------ |
| `kubo`        | Kubo RPC API (`/api/v0/*`) | Self-hosted Kubo, IPFS Desktop | None (localhost) or Basic Auth |
| `pinning-api` | IPFS Pinning Service API   | Pinata, Filebase, web3.storage | Bearer token                   |

### 4.4 Dual-Pin Provider

The actual provider used for BYO-IPFS users wraps both the default and custom providers:

```typescript
// apps/api/src/ipfs/providers/dual-pin.provider.ts
export class DualPinProvider implements IpfsProvider {
  constructor(
    private readonly defaultProvider: IpfsProvider,
    private readonly customProvider: IpfsProvider
  ) {}

  async pinFile(data: Buffer): Promise<{ cid: string; size: number }> {
    // Always pin to default (CipherBox) node first -- this is the reliable source
    const result = await this.defaultProvider.pinFile(data);

    // Best-effort pin to user's custom node
    try {
      await this.customProvider.pinFile(data);
    } catch (error) {
      // Log warning but do NOT fail the upload
      logger.warn(`BYO-IPFS pin failed: ${error.message}`);
    }

    return result; // Return CID from default node
  }

  async getFile(cid: string): Promise<Buffer> {
    // Try default node first, fall back to custom
    try {
      return await this.defaultProvider.getFile(cid);
    } catch {
      return await this.customProvider.getFile(cid);
    }
  }

  async unpinFile(cid: string): Promise<void> {
    // Only unpin from CipherBox's node (user manages their own retention)
    await this.defaultProvider.unpinFile(cid);
  }
}
```

### 4.5 User Settings Entity

```sql
CREATE TABLE user_ipfs_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  provider_type VARCHAR(20) NOT NULL DEFAULT 'default',  -- 'default' | 'kubo' | 'pinning-api'
  endpoint_url VARCHAR(500),
  auth_token_encrypted BYTEA,                             -- encrypted with server-side key
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

**`auth_token_encrypted`:** Encrypted with a server-side symmetric key (from env var), NOT the user's key. The server needs to decrypt it to authenticate with the user's IPFS node. This is acceptable because the data being relayed is already AES-256-GCM encrypted ciphertext -- the server cannot read it regardless.

### 4.6 API Endpoints

```text
GET    /vault/ipfs-config           Get user's IPFS node configuration
PUT    /vault/ipfs-config           Set/update IPFS node configuration
DELETE /vault/ipfs-config           Remove custom config (revert to default)
POST   /vault/ipfs-config/test      Test connectivity to user's IPFS node
```

The test endpoint attempts a small pin+unpin operation on the user's node to verify connectivity and auth.

### 4.7 Web UI: Settings Page Extension

Add an "IPFS Node" section to the existing settings page:

```text
[IPFS Storage]
  Provider:     ( ) CipherBox Default  ( ) Custom Kubo Node  ( ) Pinning Service
  Endpoint:     [http://my-node:5001                                            ]
  Auth Token:   [optional, for pinning services                                 ]
  [Test Connection]  [Save Configuration]

  Status: Connected -- last verified 2 minutes ago
```

### 4.8 IPNS and Conflict Detection Implications

BYO-IPFS affects ONLY where encrypted data is pinned. It does NOT affect:

- **IPNS publishing:** All publishes still go through the CipherBox API. The client signs IPNS records, the API broadcasts to the DHT.
- **Sequence numbers:** Still tracked in `folder_ipns`. Conflict detection is unchanged.
- **TEE republishing:** Unaffected -- TEE uses CipherBox's Kubo node.
- **IPNS resolution:** Unaffected -- IPNS resolves to a CID, and the CID is available from any node that has it pinned.

If a future version allows publishing directly to the user's node (bypassing the API), conflict detection would need to move client-side. This is NOT in v1.1 scope.

### 4.9 Modified/New Files

| File                                                           | Change                                                     |
| -------------------------------------------------------------- | ---------------------------------------------------------- |
| `apps/api/src/ipfs/providers/ipfs-provider.interface.ts`       | ADD `IpfsProviderFactory` interface                        |
| `apps/api/src/ipfs/providers/user-custom.provider.ts`          | NEW -- Custom Kubo/Pinning API provider                    |
| `apps/api/src/ipfs/providers/user-custom.provider.spec.ts`     | NEW -- Unit tests                                          |
| `apps/api/src/ipfs/providers/dual-pin.provider.ts`             | NEW -- Dual-pin wrapper provider                           |
| `apps/api/src/ipfs/providers/dual-pin.provider.spec.ts`        | NEW -- Unit tests                                          |
| `apps/api/src/ipfs/providers/provider-factory.service.ts`      | NEW -- Per-user provider resolution                        |
| `apps/api/src/ipfs/providers/provider-factory.service.spec.ts` | NEW -- Unit tests                                          |
| `apps/api/src/ipfs/ipfs.module.ts`                             | MODIFY -- Register factory, user config repository         |
| `apps/api/src/ipfs/ipfs.controller.ts`                         | MODIFY -- Use factory instead of direct provider injection |
| `apps/api/src/vault/entities/user-ipfs-config.entity.ts`       | NEW -- User IPFS config entity                             |
| `apps/api/src/vault/dto/ipfs-config.dto.ts`                    | NEW -- IPFS config CRUD DTOs                               |
| `apps/api/src/vault/vault.controller.ts`                       | MODIFY -- Add IPFS config endpoints                        |
| `apps/api/src/migrations/XXXXXXXXX-AddUserIpfsConfig.ts`       | NEW -- Create table migration                              |
| `apps/web/src/components/settings/IpfsNodeConfig.tsx`          | NEW -- IPFS config UI                                      |
| `apps/web/src/routes/SettingsPage.tsx`                         | MODIFY -- Add IPFS config section                          |

---

## 5. Performance Instrumentation

### 5.1 Existing Infrastructure

The API already has Prometheus metrics via `prom-client`:

- **Histogram:** `cipherbox_http_request_duration_seconds` with labels (method, route, status_code) and buckets [0.01 to 10s]
- **Counters:** file uploads/downloads/unpins, IPNS publishes/resolves, republish runs, auth logins
- **Gauges:** users total, files total, storage bytes, IPNS entries by type, republish schedule by status
- **Interceptor:** `HttpMetricsInterceptor` captures all HTTP request durations automatically
- **Endpoint:** `GET /metrics` exposes Prometheus-compatible output
- **Polling:** DB gauges refresh every 30 seconds

### 5.2 New Server-Side Metrics

Add domain-specific histograms for IPFS/IPNS latency tracking:

```typescript
// IPNS resolution latency by source and outcome
readonly ipnsResolveDuration: client.Histogram;
// Labels: source (db|kubo_dht|delegated), result (hit|miss|error)
// Buckets: [0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10]

// IPNS publish latency by target and outcome
readonly ipnsPublishDuration: client.Histogram;
// Labels: target (db|kubo_dht|delegated), result (success|error)
// Buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 30]

// IPFS operation latency (pin/unpin/get)
readonly ipfsOperationDuration: client.Histogram;
// Labels: operation (pin|unpin|get), provider (default|byo), result (success|error)
// Buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]

// TEE republish batch processing duration
readonly republishBatchDuration: client.Histogram;
// Labels: result (success|partial|error)
// Buckets: [0.5, 1, 2.5, 5, 10, 30, 60, 120]
```

### 5.3 Client-Side Performance Utility

Add a lightweight timing utility for the web app:

```typescript
// apps/web/src/lib/perf.ts
export function startTimer(label: string): () => number {
  const start = performance.now();
  return () => {
    const durationMs = performance.now() - start;
    logger.debug(`[perf] ${label}: ${durationMs.toFixed(1)}ms`);
    return durationMs;
  };
}
```

**Key operations to instrument:**

| Operation                           | File                     | What to Measure                        |
| ----------------------------------- | ------------------------ | -------------------------------------- |
| IPNS resolve (API round trip)       | `folder.service.ts`      | API call latency                       |
| IPNS publish (API round trip)       | `folder.service.ts`      | API call + DB + DHT publish            |
| File upload (encrypt + upload)      | `upload.service.ts`      | Full pipeline including encryption     |
| File download (fetch + decrypt)     | `download.service.ts`    | Full pipeline including decryption     |
| Folder metadata decrypt             | `folder.service.ts`      | AES-GCM decryption of metadata blob    |
| AES-GCM encrypt throughput          | `packages/crypto`        | Encryption speed in MB/s               |
| Full page load to interactive       | `useAuth.ts`             | Auth completion to first folder render |
| Folder navigation (click to render) | `useFolderNavigation.ts` | Navigate + resolve + decrypt + render  |

### 5.4 Baseline Collection Strategy

1. **Instrument:** Add timing hooks with minimal overhead (no-op when not collecting)
2. **Collect baselines:** Run standardized workloads against staging environment
3. **Document:** Store baselines in `.planning/baselines/PERFORMANCE_BASELINES.md` with environment specs, dates, and methodology
4. **Automate (stretch goal):** Add a Playwright E2E test suite that measures key user journeys and asserts maximum latencies

**Standardized workload scenarios:**

| Scenario                          | Description                                        | Target Metric                |
| --------------------------------- | -------------------------------------------------- | ---------------------------- |
| Login flow                        | Auth -> vault init -> root resolve -> first render | Total wall time              |
| Upload 1 MB                       | Encrypt -> API upload -> IPNS publish -> confirm   | Total wall time              |
| Upload 50 MB                      | Same as above, larger payload                      | Total wall time, memory peak |
| Download 1 MB                     | API fetch -> decrypt -> save                       | Total wall time              |
| Navigate 3 levels deep            | Resolve root -> subfolder -> subfolder             | Total wall time              |
| IPNS publish + resolve round trip | Publish -> immediately resolve same name           | Latency                      |
| Search 100 files                  | Index lookup -> render results                     | Latency                      |
| Share a folder                    | Wrap key -> API call -> confirm                    | Total wall time              |

### 5.5 Modified/New Files

| File                                            | Change                                         |
| ----------------------------------------------- | ---------------------------------------------- |
| `apps/api/src/metrics/metrics.service.ts`       | ADD new histograms (4 new metrics)             |
| `apps/api/src/ipns/ipns.service.ts`             | ADD histogram observations in resolve/publish  |
| `apps/api/src/ipfs/ipfs.controller.ts`          | ADD histogram observations in pin/get/unpin    |
| `apps/api/src/republish/republish.service.ts`   | ADD histogram observation for batch processing |
| `apps/web/src/lib/perf.ts`                      | NEW -- Client-side performance timing utility  |
| `apps/web/src/services/folder.service.ts`       | ADD timing instrumentation                     |
| `apps/web/src/services/upload.service.ts`       | ADD timing instrumentation                     |
| `apps/web/src/services/download.service.ts`     | ADD timing instrumentation                     |
| `tests/e2e/tests/performance-baselines.spec.ts` | NEW -- Baseline collection E2E test (stretch)  |

---

## 6. Component Boundary Map

### New Components

```text
apps/api/src/
  ipns/
    kubo-ipns.client.ts                 NEW -- Kubo RPC client for IPNS
    kubo-ipns.client.spec.ts            NEW -- Unit tests

  ipfs/
    providers/
      user-custom.provider.ts           NEW -- BYO-IPFS provider (Kubo + Pinning API)
      user-custom.provider.spec.ts      NEW -- Unit tests
      dual-pin.provider.ts              NEW -- Dual-pin wrapper
      dual-pin.provider.spec.ts         NEW -- Unit tests
      provider-factory.service.ts       NEW -- Per-user provider resolution
      provider-factory.service.spec.ts  NEW -- Unit tests

  vault/
    entities/
      user-ipfs-config.entity.ts        NEW -- User IPFS node config entity
    dto/
      ipfs-config.dto.ts                NEW -- IPFS config CRUD DTOs

  migrations/
    XXXXXXXXX-AddUserIpfsConfig.ts      NEW -- user_ipfs_config table

apps/web/src/
  lib/
    perf.ts                             NEW -- Performance timing utility

  components/
    settings/
      IpfsNodeConfig.tsx                NEW -- IPFS node config UI
```

### Modified Components

```text
apps/api/src/
  ipns/
    ipns.service.ts                     MODIFY -- DB-first resolution, async DHT verify
    ipns.module.ts                      MODIFY -- Register KuboIpnsClient
    delegated-routing.client.ts         MODIFY -- Add disable flag, demote to fallback

  ipfs/
    ipfs.module.ts                      MODIFY -- Use provider factory pattern
    ipfs.controller.ts                  MODIFY -- Use factory, add perf instrumentation

  vault/
    vault.service.ts                    MODIFY -- Handle vault blob v2 format
    vault.controller.ts                 MODIFY -- Add IPFS config endpoints

  republish/
    republish.service.ts                MODIFY -- Optional Kubo native publish for TEE

  metrics/
    metrics.service.ts                  MODIFY -- Add 4 new histograms

apps/web/src/
  services/
    folder.service.ts                   MODIFY -- Vault blob v2 reading, perf timers
    upload.service.ts                   MODIFY -- Perf instrumentation
    download.service.ts                 MODIFY -- Perf instrumentation

  routes/
    SettingsPage.tsx                     MODIFY -- Add IPFS node config section

  public/
    recovery.html                       MODIFY -- Vault blob v2, updated IPNS resolution

packages/crypto/src/
  vault/
    types.ts                            MODIFY -- Add blob v2 type definitions
    blob.ts                             NEW -- Blob v2 serialization/deserialization
```

### Inter-Component Communication

```text
IpfsController --> ProviderFactory --> LocalProvider (default)
                                   --> DualPinProvider --> LocalProvider (always)
                                                      --> UserCustomProvider (best-effort)

IpnsController --> IpnsService --> folder_ipns DB (primary, fast path)
                                --> KuboIpnsClient (async DHT verification)
                                --> DelegatedRoutingClient (disabled-by-default fallback)

RepublishService --> TeeService (signing)
                 --> KuboIpnsClient (Kubo native publish, preferred)
                 --> DelegatedRoutingClient (fallback if Kubo fails)

MetricsService <-- IpnsService (resolve/publish duration)
               <-- IpfsController (operation duration)
               <-- RepublishService (batch duration)
               <-- ProviderFactory (BYO-IPFS operation duration)
```

---

## 7. Data Flow Changes

### 7.1 IPNS Resolution (Changed)

**Before:**

```text
Client -> API /ipns/resolve
  -> DelegatedRoutingClient.resolve() [10s timeout, 3 retries]
  -> Parse IPNS record bytes
  -> Compare with DB-cached CID (folder_ipns)
  -> Return highest sequence number result
```

**After:**

```text
Client -> API /ipns/resolve
  -> DB query folder_ipns WHERE ipnsName = ? [<5ms]
  -> Return DB result immediately
  -> Fire-and-forget: KuboIpnsClient.resolve() [5s DHT timeout]
    -> If DHT has higher sequence number, update folder_ipns
    -> If DHT fails, no-op
```

### 7.2 IPNS Publishing (Changed for TEE Path)

**Before (TEE republish):**

```text
RepublishService -> TeeService.republish() -> signed record bytes
                 -> DelegatedRoutingClient.publish() -> delegated-ipfs.dev
```

**After (TEE republish, preferred path):**

```text
RepublishService -> TeeService.republish() -> signed record bytes
                 -> KuboIpnsClient.importKey() -> Kubo keystore
                 -> KuboIpnsClient.publish() -> Kubo DHT native
                 -> KuboIpnsClient.removeKey() -> cleanup
                 -> Fallback: DelegatedRoutingClient.publish() if Kubo fails
```

### 7.3 Vault Access on Login (Changed)

**Before:**

```text
Client -> API GET /vault -> { encryptedRootFolderKey, rootIpnsName, teeKeys }
       -> Derive IPNS key via HKDF
       -> API GET /ipns/resolve -> { cid }
       -> API GET /ipfs/<cid> -> blob v1 (encrypted metadata only)
       -> Decrypt metadata with rootFolderKey from vault response
```

**After (v1.1, with blob v2):**

```text
Client -> API GET /vault -> { rootIpnsName, teeKeys, ownerPublicKey }
       -> Derive IPNS key via HKDF
       -> API GET /ipns/resolve -> { cid }
       -> API GET /ipfs/<cid> -> blob v2
       -> Parse blob: extract encryptedRootFolderKey header
       -> ECIES decrypt rootFolderKey with privateKey
       -> Decrypt metadata with rootFolderKey
       -> Fallback: if blob is v1, GET /vault.encryptedRootFolderKey
```

### 7.4 BYO-IPFS Upload (New)

```text
Client -> encrypt file -> API POST /ipfs/upload { file }
       -> ProviderFactory.getProvider(userId)
       -> If user has custom config:
         -> DualPinProvider.pinFile(data)
           -> LocalProvider.pinFile(data)           // CipherBox node (always, reliable)
           -> UserCustomProvider.pinFile(data)       // User node (best-effort, logged)
       -> If no custom config:
         -> LocalProvider.pinFile(data)             // CipherBox node only
       -> VaultService.recordPin(userId, cid, size) // Quota tracking (unchanged)
       -> return { cid, size }
```

### 7.5 BYO-IPFS Download (New Path)

```text
Client -> API GET /ipfs/:cid
       -> ProviderFactory.getProvider(userId)
       -> If user has custom config:
         -> DualPinProvider.getFile(cid)
           -> Try LocalProvider.getFile(cid)         // CipherBox node first
           -> If not found: UserCustomProvider.getFile(cid)  // Fall back to user node
       -> If no custom config:
         -> LocalProvider.getFile(cid)
       -> return file buffer
```

---

## 8. Suggested Build Order

### Phase 1: Performance Instrumentation

**Why first:** Zero risk to existing functionality. Purely additive. Establishes baselines BEFORE making any architectural changes. Without baselines, we cannot measure whether subsequent phases improve or regress performance.

**Scope:**

- Add 4 new Prometheus histograms to `MetricsService`
- Instrument `IpnsService.resolveRecord()` and `publishRecord()` with timing
- Instrument `IpfsController` upload/download/unpin with timing
- Instrument `RepublishService.processRepublishBatch()` with timing
- Create client-side `perf.ts` utility
- Instrument key web app operations (folder navigate, upload, download)
- Run standardized baseline collection against staging
- Document baselines in `.planning/baselines/`

**Dependencies:** None. Uses existing `prom-client` and `MetricsService` infrastructure.
**Risk:** LOW. Additive instrumentation only. No behavioral changes.
**Estimated scope:** Small. ~10 modified files, no new entities or migrations.

### Phase 2: IPNS Resolution Improvement

**Why second:** Fixes the most critical reliability issue (delegated-ipfs.dev dependency). Required before Phase 3 because moving rootFolderKey to IPFS makes IPNS resolution a login-critical path. Baselines from Phase 1 enable before/after comparison.

**Scope:**

- Implement `KuboIpnsClient` for native Kubo IPNS resolution
- Refactor `IpnsService.resolveRecord()` to DB-first with async DHT verification
- Make `DelegatedRoutingClient` optional with config flag (`IPNS_DELEGATED_ROUTING_ENABLED`)
- Configure Kubo with `Ipns.UsePubsub: true`
- Optionally update `RepublishService` to use Kubo native publish
- Update recovery tool IPNS resolution fallback chain
- Measure resolution latency against Phase 1 baselines

**Dependencies:** Phase 1 (for before/after measurement).
**Risk:** MEDIUM. Changing the resolution path could cause resolution failures if Kubo DHT is slower than expected. Mitigated by: (1) DB-first strategy means the fast path is always local, (2) delegated routing remains as a disabled-by-default fallback, (3) existing retry logic in the delegated client.
**Estimated scope:** Medium. 1 new file, ~5 modified files, Kubo config change.

### Phase 3: Database Minimization (rootFolderKey to IPFS)

**Why third:** Requires reliable IPNS resolution (Phase 2). The vault blob v2 format is a breaking metadata change that needs careful migration across web, desktop, and recovery tool.

**Scope:**

- Define vault blob v2 format in `packages/crypto/src/vault/`
- Implement blob v2 serialization/deserialization
- Implement dual-write in web client (blob v2 on publish, DB on vault init)
- Implement version-aware blob reading (v2 -> extract key, v1 -> fall back to DB)
- Update vault init flow to make encryptedRootFolderKey optional
- Mark encryptedRootIpnsPrivateKey as deprecated
- Update recovery tool for blob v2 format
- Update desktop client blob parsing
- Migration testing: new user, existing user upgrade, recovery
- Update `docs/METADATA_SCHEMAS.md` per evolution protocol

**Dependencies:** Phase 2 (IPNS must be reliable before making it login-critical).
**Risk:** MEDIUM-HIGH. Metadata format change affects all clients. Mitigated by: (1) dual-write ensures backward compatibility, (2) version detection allows graceful fallback, (3) DB column is never dropped -- kept as disaster recovery.
**Estimated scope:** Large. New type definitions, serialization code, changes in 3 clients (web, desktop, recovery).

### Phase 4: BYO-IPFS Node Support

**Why last:** Largest surface area (new entity, new providers, new UI, new API endpoints). Benefits from stable IPNS resolution (Phase 2) and reduced DB dependency (Phase 3). Independent in design but benefits from the improved infrastructure.

**Scope:**

- Create `user_ipfs_config` entity and migration
- Implement `UserCustomProvider` with Kubo RPC and Pinning Service API support
- Implement `DualPinProvider` wrapper
- Implement `ProviderFactory` for per-user provider resolution
- Refactor `IpfsController` to use factory
- Add IPFS config CRUD endpoints to vault controller
- Add connection test endpoint
- Build IPFS node configuration UI in settings page
- Implement dual-pin strategy (CipherBox node always + user node best-effort)
- Add BYO-IPFS specific Prometheus metrics
- E2E test: configure custom node, upload, verify pinned

**Dependencies:** Phase 2 (reliable IPNS) and Phase 3 (reduced DB) are not strict blockers but provide a better foundation.
**Risk:** MEDIUM. New provider implementations need thorough testing against real IPFS nodes and pinning services. Connectivity to arbitrary user nodes introduces unpredictable failure modes. Mitigated by: (1) dual-pin always keeps a copy on CipherBox node, (2) best-effort approach for user node, (3) connection test endpoint validates before saving config.
**Estimated scope:** Large. New entity, migration, 4+ new files, UI component, multiple API endpoints.

### Build Order Summary

```text
Phase 1: Performance Instrumentation
    [No dependencies, zero-risk baseline establishment]
    |
    v
Phase 2: IPNS Resolution Improvement
    [Eliminates delegated-ipfs.dev, enables Phase 3]
    |
    v
Phase 3: Database Minimization
    [Moves rootFolderKey to IPFS, requires reliable IPNS from Phase 2]
    |
    v
Phase 4: BYO-IPFS Node Support
    [New capability, benefits from improved infrastructure]
```

**Critical dependency:** Phase 2 MUST precede Phase 3. Moving rootFolderKey to IPFS without reliable IPNS resolution means users cannot log in if Kubo DHT is slow.

**Parallel opportunity:** Phase 4's design and provider implementation can be developed in parallel with Phase 3's blob format work, but integration testing should wait for Phase 3 completion.

---

## 9. Sources

### HIGH Confidence (Official Documentation, Verified)

- [Kubo RPC API v0 Reference](https://docs.ipfs.tech/reference/kubo/rpc/) -- `/api/v0/name/resolve`, `/api/v0/name/publish`, `/api/v0/key/import` endpoints verified against v0.40.0
- [Kubo Configuration Reference](https://github.com/ipfs/kubo/blob/master/docs/config.md) -- `Ipns.UsePubsub`, `Routing.Type` configuration
- [IPFS Pinning Service API Spec](https://ipfs.github.io/pinning-services-api-spec/) -- Vendor-agnostic pinning API standard (OpenAPI spec)
- [IPNS Concepts](https://docs.ipfs.tech/concepts/ipns/) -- IPNS TTL default (5 minutes), PubSub resolution
- [prom-client GitHub](https://github.com/siimon/prom-client) -- Histogram, Counter, Gauge APIs

### MEDIUM Confidence (Multiple Sources Agreeing)

- [Kubo v0.38+ Release Notes](https://github.com/ipfs/kubo/releases) -- Sweep provider with 97% fewer DHT lookups, IPNS TTL changes
- [Kubo Issue #10484: Download & Upload IPNS Records](https://github.com/ipfs/kubo/issues/10484) -- Confirms `/api/v0/routing/put` for pre-signed records
- [Kubo Issue #8542: Publish IPNS with Signature](https://github.com/ipfs/kubo/issues/8542) -- Confirms key import workflow
- [Kubo Delegated Routing Docs](https://github.com/ipfs/kubo/blob/master/docs/delegated-routing.md) -- `put-ipns` and `get-ipns` routing methods
- [IP Shipyard 2025 Year in Review](https://ipshipyard.com/blog/2025-shipyard-ipfs-year-in-review/) -- DHT improvements context

### Codebase Analysis (Direct Code Review)

- `apps/api/src/ipns/ipns.service.ts` -- Current resolution logic, DB fallback (resolveRecord lines 290-350)
- `apps/api/src/ipns/delegated-routing.client.ts` -- Current publish/resolve implementation (3 retries, 10s timeout)
- `apps/api/src/ipfs/providers/ipfs-provider.interface.ts` -- Existing 3-method provider interface
- `apps/api/src/ipfs/providers/local.provider.ts` -- Current Kubo provider (pin/unpin/get via RPC API)
- `apps/api/src/ipfs/ipfs.module.ts` -- Current DI config (env var driven, single provider)
- `apps/api/src/ipfs/ipfs.controller.ts` -- Current upload/download/unpin with metrics
- `apps/api/src/vault/vault.service.ts` -- Current vault init with encryptedRootFolderKey
- `apps/api/src/vault/entities/vault.entity.ts` -- Current vault schema (6 columns)
- `apps/api/src/metrics/metrics.service.ts` -- Existing Prometheus infrastructure (gauges, counters, histogram)
- `apps/api/src/metrics/http-metrics.interceptor.ts` -- Existing HTTP duration tracking
- `apps/api/src/republish/republish.service.ts` -- Current TEE republish via delegated routing
- `apps/api/src/ipns/entities/folder-ipns.entity.ts` -- CID cache + sequence tracking
- `apps/api/src/republish/republish-schedule.entity.ts` -- TEE scheduling state
- All 13 database entities analyzed for migration feasibility

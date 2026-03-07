# Technology Stack: v1.1 IPFS Infrastructure

**Project:** CipherBox
**Milestone:** v1.1 -- IPFS Infrastructure
**Researched:** 2026-03-07
**Confidence:** HIGH
**Mode:** Ecosystem (stack additions for new IPFS infrastructure capabilities)

## Executive Summary

Milestone v1.1 is an infrastructure-hardening milestone, not a feature milestone. The four workstreams -- IPNS reliability, database minimization, BYO-IPFS, and performance baselines -- require **remarkably few new dependencies**. The dominant finding is that the existing Kubo v0.34.0 node already has the capabilities needed for reliable IPNS resolution; the problem is that CipherBox routes around Kubo and talks to `delegated-ipfs.dev` directly via HTTP. The fix is architectural, not technological.

The key recommendations are:

1. **IPNS reliability:** Enable `Gateway.ExposeRoutingAPI` on the existing Kubo v0.34.0 node (available since Kubo v0.23.0) and point the `DelegatedRoutingClient` at `http://localhost:8080/routing/v1` instead of `https://delegated-ipfs.dev`. This gives sub-second IPNS resolution via local DHT with zero new dependencies. Optionally upgrade to Kubo v0.40.1 for improved IPNS-over-PubSub and default routing API exposure.

2. **Database minimization:** No new dependencies. This is a data migration and metadata schema evolution problem using existing TypeORM, IPFS pinning, and IPNS publishing infrastructure.

3. **BYO-IPFS:** Implement a `RemotePinningProvider` that speaks the standard IPFS Pinning Service API (OpenAPI spec, bearer-token auth). No SDK needed -- the API is simple enough to call with native `fetch`. The existing `IpfsProvider` interface already abstracts pin/unpin/get.

4. **Performance baselines:** `prom-client` (already installed) for server-side IPFS/IPNS latency histograms. Grafana k6 v1.0 (standalone Go binary, not an npm dependency) for load testing scripts. No changes to the web app.

**Total new npm dependencies: zero.** The milestone adds configuration changes, data migrations, a new provider implementation, new Prometheus metrics, and k6 test scripts -- all using existing libraries.

---

## Existing Stack (DO NOT CHANGE)

These are validated and deployed. Listed for reference on integration points only.

| Component          | Package / Tool           | Version      |
| ------------------ | ------------------------ | ------------ |
| Backend Framework  | `@nestjs/core`           | ^11.0.0      |
| ORM                | `typeorm`                | ^0.3.28      |
| Database           | PostgreSQL               | 16.x         |
| Queue              | `bullmq` + `ioredis`     | ^5.67 / ^5.9 |
| IPFS Node          | Kubo (Docker)            | v0.34.0      |
| IPFS Provider      | `LocalProvider` (custom) | N/A          |
| IPNS Client        | `DelegatedRoutingClient` | N/A (custom) |
| Prometheus Metrics | `prom-client`            | ^15.1.3      |
| HTTP Metrics       | `HttpMetricsInterceptor` | N/A (custom) |
| JWT / Auth         | `jose`                   | ^6.1.3       |
| Frontend Framework | `react` + `react-dom`    | ^18.3.1      |
| API Client Gen     | `orval`                  | ^7.3.0       |
| API Client         | `axios`                  | ^1.13.2      |

---

## Feature 1: IPNS Reliability (Replace delegated-ipfs.dev)

### Architecture Decision

The current system publishes and resolves IPNS records via `delegated-ipfs.dev`, a public delegated routing endpoint. This endpoint is unreliable (known 502 errors). However, the self-hosted Kubo v0.34.0 node **already participates in the Amino DHT** and can resolve IPNS records locally via its RPC API or via the Routing V1 HTTP API.

**Recommendation: Use the local Kubo node as the primary IPNS routing endpoint.**

Since Kubo v0.23.0, the `Gateway.ExposeRoutingAPI` config option exposes the standard Delegated Routing V1 HTTP API at `http://127.0.0.1:8080/routing/v1`. This means the `DelegatedRoutingClient` can be pointed at the local Kubo gateway instead of the public internet, with zero code changes to its HTTP client logic (same API contract: `GET /routing/v1/ipns/{name}`, `PUT /routing/v1/ipns/{name}`).

**Resolution path:** Local Kubo DHT lookup (primary) -> DB-cached CID (fallback, already implemented) -> `delegated-ipfs.dev` (tertiary fallback, degraded mode only).

### Configuration Changes Required

| What                                   | Current                                | New                                                 |
| -------------------------------------- | -------------------------------------- | --------------------------------------------------- |
| `DELEGATED_ROUTING_URL` env var        | `https://delegated-ipfs.dev`           | `http://localhost:8080`                             |
| Kubo config `Gateway.ExposeRoutingAPI` | Not set (defaults to `false` on v0.34) | Set to `true`                                       |
| Docker compose `ipfs` service          | No config volume mount                 | Mount custom config or use `ipfs config` init       |
| Fallback routing                       | None (single source + DB cache)        | Chain: local Kubo -> DB cache -> delegated-ipfs.dev |

### Optional: Upgrade Kubo to v0.40.1

| Benefit                                         | Kubo v0.34.0  | Kubo v0.40.1                         |
| ----------------------------------------------- | ------------- | ------------------------------------ |
| `Gateway.ExposeRoutingAPI` available            | Yes (opt-in)  | Yes (default on)                     |
| IPNS-over-PubSub duplicate rejection            | Basic         | Improved (persists max seq per peer) |
| DHT sweep provider (efficient content announce) | Not available | Default                              |
| Default IPNS TTL                                | 5 minutes     | 5 minutes                            |

**Recommendation:** Upgrade to Kubo v0.40.1 for production. Keep v0.34.0 for initial development if the upgrade would delay the milestone. The API contract is identical -- only the Docker image tag changes.

### Alternative Considered: Self-hosted Someguy

[Someguy](https://github.com/ipfs/someguy) (v0.11.1, Feb 2026) is the software that powers `delegated-ipfs.dev`. It could be self-hosted as a Docker container (`ghcr.io/ipfs/someguy:v0.11.1`) alongside Kubo.

**Why NOT Someguy:** Someguy is a proxy that forwards requests to the DHT via a Kubo-like client. Running Someguy next to Kubo adds a middleman with no benefit -- Kubo already does DHT lookups directly. Someguy makes sense for serving many light clients at scale (the `delegated-ipfs.dev` use case), not for a single application with its own Kubo node.

**When Someguy makes sense:** If CipherBox ever needs to serve delegated routing for many browser-based light clients that cannot run DHT, a Someguy instance behind the API reverse proxy would be the right approach. Not needed for v1.1.

### New Dependencies: NONE

### Confidence: HIGH

The Delegated Routing V1 HTTP API is a stable IETF-track specification. Kubo has supported `Gateway.ExposeRoutingAPI` since v0.23.0 (over a year). The `DelegatedRoutingClient` already speaks this exact API contract -- only the base URL changes.

---

## Feature 2: Database Minimization (Migrate State to IPFS/IPNS)

### Architecture Decision

Five categories of data currently live in PostgreSQL that should move to IPFS/IPNS:

| Data                      | Current Location        | Target Location                     | Migration Approach                |
| ------------------------- | ----------------------- | ----------------------------------- | --------------------------------- |
| `encryptedRootFolderKey`  | `vaults` table          | Root vault IPNS blob on IPFS        | New blob format, client migration |
| Share records             | `shares` / `share_keys` | IPNS inbox per recipient (future)   | Defer to CRDT research            |
| Device registry           | N/A (client-side)       | Vault IPNS blob extension           | Metadata schema extension         |
| Folder/file IPNS tracking | `folder_ipns` table     | Derivable from folder metadata tree | Client-side traversal             |
| Pinned CID tracking       | `pinned_cids` table     | Keep in DB (quota enforcement)      | No change                         |

**Key insight from the todo analysis:** Moving `encryptedRootFolderKey` to IPFS is the highest-value migration. It eliminates all crypto material from the server, making the database purely auth-related. The other migrations are either lower priority (share discovery via CRDT is research-only this milestone per PROJECT.md) or already partially in place (device registry is client-side).

### Technology Needed

**None new.** The migration uses:

- Existing `@cipherbox/crypto` package for metadata schema evolution (add `encryptedRootFolderKey` to the root vault IPNS blob format)
- Existing `IpfsProvider.pinFile()` for writing the new blob
- Existing `IpnsService.publishRecord()` for publishing the updated IPNS record
- Existing TypeORM migrations for deprecating the `vaults.encrypted_root_folder_key` column
- Existing `docs/METADATA_EVOLUTION_PROTOCOL.md` for the schema versioning process

### What to Build (Not Install)

1. **Vault blob v2 format** -- Extend the root IPNS blob to include `{ encryptedRootFolderKey, encryptedIpnsPrivateKey, metadata }` (currently only `metadata`)
2. **Client-side migration** -- On login, if blob is v1 format, read `encryptedRootFolderKey` from API, write it into a v2 blob, publish to IPNS
3. **Server-side deprecation path** -- Mark `vaults.encrypted_root_folder_key` as nullable, add `vault_format_version` column, stop writing after migration window
4. **Recovery tool update** -- `apps/web/public/recovery.html` must handle v2 blob format
5. **IPNS resolution on critical path** -- Moving rootFolderKey to IPFS means IPNS resolution is now required for login. The DB-cached CID fallback (already implemented in `IpnsService.resolveRecord()`) mitigates resolution failures.

### Database Changes

| Entity       | Change                                                 | Migration Type  |
| ------------ | ------------------------------------------------------ | --------------- |
| `Vault`      | `encryptedRootFolderKey` becomes nullable              | ALTER COLUMN    |
| `Vault`      | Add `vaultFormatVersion` (int, default 1)              | ADD COLUMN      |
| `FolderIpns` | Possibly remove rows once client derives from metadata | Cleanup (later) |

### New Dependencies: NONE

### Confidence: HIGH

This is a data migration, not a technology selection. The existing stack handles everything. The risk is in the migration protocol (see PITFALLS.md), not in missing libraries.

---

## Feature 3: BYO-IPFS Node Support

### Architecture Decision

Users should be able to configure their own IPFS pinning endpoint. The IPFS ecosystem has a vendor-agnostic [Pinning Service API specification](https://ipfs.github.io/pinning-services-api-spec/) (OpenAPI 3.0) that is implemented by Pinata, Filebase, web3.storage, IPFS Cluster, and can be self-hosted via Kubo's `ipfs pin remote` subsystem.

**Recommendation: Implement a `RemotePinningProvider` that speaks the IPFS Pinning Service API.**

The API is minimal (4 endpoints, bearer-token auth, JSON request/response):

| Endpoint                   | Method | Purpose                  |
| -------------------------- | ------ | ------------------------ |
| `POST /pins`               | POST   | Request pinning of a CID |
| `GET /pins`                | GET    | List pins with filters   |
| `GET /pins/{requestid}`    | GET    | Check pin status         |
| `DELETE /pins/{requestid}` | DELETE | Remove a pin             |

Authentication is a bearer token in the `Authorization` header. Pin status values: `queued`, `pinning`, `pinned`, `failed`.

**Important distinction:** The Pinning Service API pins by CID (the content must already be available on the IPFS network). For BYO-IPFS, the flow is:

1. Client uploads encrypted blob to CipherBox's Kubo node (existing flow, gets CID)
2. CipherBox backend requests remote pin of that CID on user's configured endpoint
3. User's IPFS node fetches the content from CipherBox's Kubo via the DHT
4. Once pinned remotely, content is available from both nodes

This avoids the CORS and connectivity issues of client-direct upload while keeping the server zero-knowledge (it only sees encrypted blobs and CIDs).

### Provider Implementation

The existing `IpfsProvider` interface:

```typescript
export interface IpfsProvider {
  pinFile(data: Buffer, metadata?: Record<string, string>): Promise<{ cid: string; size: number }>;
  unpinFile(cid: string): Promise<void>;
  getFile(cid: string): Promise<Buffer>;
}
```

For BYO-IPFS, add a **companion** provider that mirrors pins to the user's endpoint after local pinning succeeds:

```typescript
// New: RemotePinningProvider (mirrors pins, does not replace local)
export interface RemotePinningConfig {
  endpoint: string; // e.g., "https://api.pinata.cloud/psa"
  accessToken: string; // Bearer token
  providerName: string; // Display name for UI
}
```

The `RemotePinningProvider` calls `POST /pins` with the CID after local pinning. It does NOT replace the local provider -- it supplements it. The local Kubo node remains the source of truth for reads.

### User Settings Storage

Per-user IPFS configuration stored in the vault settings (encrypted, client-side):

```typescript
// In vault metadata (IPNS blob, client-encrypted)
interface VaultSettings {
  remotePinning?: {
    enabled: boolean;
    endpoint: string;
    providerName: string;
    // accessToken stored separately in memory, NOT in metadata
  };
}
```

The access token is stored encrypted in IndexedDB (using existing `idb` from M2) or entered per-session. It is NEVER sent to the CipherBox API -- the remote pinning calls are made by the NestJS backend using a token the user provides via an encrypted channel.

**Alternative approach considered: Client-direct pinning.** The web app could call the user's pinning endpoint directly. This avoids the server seeing the access token but introduces CORS issues (most pinning services don't set `Access-Control-Allow-Origin` for arbitrary origins) and breaks desktop parity (Tauri apps don't have CORS restrictions but would need a different code path).

**Recommendation: Server-relay for v1.1.** The server relays pin requests using an access token the user provides encrypted with the server's public key. The server sees the token but never the plaintext content (it only pins CIDs of encrypted blobs). Evaluate client-direct as a privacy upgrade in a future milestone.

### Quota and Conflict Considerations

| Concern            | BYO-IPFS Behavior                                             |
| ------------------ | ------------------------------------------------------------- |
| Storage quota      | Advisory only. Server can't enforce quotas on user's node.    |
| Conflict detection | Still works -- IPNS publish goes through CipherBox API.       |
| TEE republishing   | Unaffected -- TEE republishes IPNS records, not file content. |
| File availability  | Content available from both local Kubo and user's node.       |
| User's node down   | Content still available from CipherBox's Kubo node.           |
| CipherBox down     | Content available from user's node (if user has IPNS keys).   |

### New Dependencies: NONE

The Pinning Service API is a REST API with 4 endpoints. Native `fetch` (already used by `LocalProvider` and `DelegatedRoutingClient`) is sufficient. No SDK needed.

### What NOT to Use

| Library / Approach                      | Why Not                                                                |
| --------------------------------------- | ---------------------------------------------------------------------- |
| `@ipfs-shipyard/pinning-service-client` | Adds a dependency for 4 simple HTTP calls. Use native `fetch`.         |
| Kubo `ipfs pin remote` CLI              | Shell-out from NestJS is fragile. HTTP calls are more reliable.        |
| Client-direct pinning                   | CORS issues with most pinning services. Server-relay is more reliable. |
| Full IPFS node in browser (Helia)       | Massive bundle size (~500KB+), unnecessary when server has Kubo.       |

### Confidence: HIGH

The IPFS Pinning Service API is a stable, vendor-agnostic specification. Multiple production services implement it. The integration is straightforward REST calls with bearer-token auth.

---

## Feature 4: Performance Baselines

### Architecture Decision

Performance baselines require two tooling layers:

1. **Runtime instrumentation** -- Prometheus metrics emitted by the running application (server-side) and measured by the client (client-side timing)
2. **Load testing** -- Scripted scenarios that exercise the system under controlled conditions and record baseline measurements

CipherBox already has Prometheus metrics via `prom-client` ^15.1.3 with an `HttpMetricsInterceptor` that records HTTP request duration histograms. The existing `MetricsService` tracks file uploads, downloads, IPNS publishes, and resolves as counters.

### What to Add: IPFS/IPNS Latency Histograms

The existing metrics track **counts** but not **latency** for IPFS/IPNS operations. Add histograms to the existing `MetricsService`:

| Metric Name                               | Type      | Labels                     | Purpose                             |
| ----------------------------------------- | --------- | -------------------------- | ----------------------------------- |
| `cipherbox_ipfs_pin_duration_seconds`     | Histogram | `provider` (local/remote)  | Time to pin a file to IPFS          |
| `cipherbox_ipfs_get_duration_seconds`     | Histogram | `provider` (local/remote)  | Time to retrieve a file from IPFS   |
| `cipherbox_ipns_publish_duration_seconds` | Histogram | `target` (local/delegated) | Time to publish an IPNS record      |
| `cipherbox_ipns_resolve_duration_seconds` | Histogram | `source` (dht/db_cache)    | Time to resolve an IPNS name to CID |
| `cipherbox_ipfs_pin_size_bytes`           | Histogram | `provider`                 | Size distribution of pinned files   |

**Bucket configuration for latency histograms:**

```typescript
// IPFS operations are slower than HTTP -- wider buckets
const ipfsBuckets = [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60];

// IPNS resolution can be very slow via DHT
const ipnsBuckets = [0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120];
```

These use the existing `prom-client` library (already installed) and the existing `MetricsService` singleton pattern. No new dependencies.

### What to Add: k6 Load Testing Scripts

[Grafana k6](https://k6.io/) v1.0 (released May 2025) is the standard for API load testing. It runs as a standalone Go binary -- it is NOT an npm dependency. Test scripts are written in TypeScript (natively supported since k6 v0.57 / v1.0).

| Component        | Tool       | Version | Installation                      |
| ---------------- | ---------- | ------- | --------------------------------- |
| Load test runner | k6         | v1.0+   | `brew install k6` or Docker image |
| Test scripts     | TypeScript | N/A     | `tests/perf/*.ts`                 |
| Results storage  | JSON/CSV   | N/A     | `k6 run --out json=results.json`  |

**k6 test script structure:**

```text
tests/perf/
  api-health.ts          -- Baseline: GET /health response time
  auth-login.ts          -- Auth flow latency
  ipfs-upload.ts         -- File upload + pin latency
  ipfs-download.ts       -- File download latency
  ipns-publish.ts        -- IPNS record publish latency
  ipns-resolve.ts        -- IPNS resolution latency (DHT vs DB cache)
  e2e-upload-browse.ts   -- Full user journey: auth -> upload -> browse -> download
  thresholds.json        -- Baseline thresholds (p95, p99, error rate)
```

**Threshold targets (based on project constraints):**

| Operation         | p50 Target | p95 Target | p99 Target | Error Rate |
| ----------------- | ---------- | ---------- | ---------- | ---------- |
| API health        | <10ms      | <50ms      | <100ms     | <0.1%      |
| Auth login        | <500ms     | <2s        | <5s        | <1%        |
| IPFS upload (1MB) | <500ms     | <2s        | <5s        | <1%        |
| IPFS download     | <200ms     | <1s        | <3s        | <0.5%      |
| IPNS publish      | <1s        | <3s        | <10s       | <2%        |
| IPNS resolve      | <500ms     | <2s        | <5s        | <1%        |

These are initial baselines to be established, not SLAs. The point is to have numbers to compare against after future changes.

### Client-Side Timing (Web)

For client-side encryption throughput baselines, use the browser's built-in `Performance` API (no dependencies):

```typescript
performance.mark('encrypt-start');
const encrypted = await encrypt(data, key);
performance.mark('encrypt-end');
performance.measure('encryption', 'encrypt-start', 'encrypt-end');
```

Results are logged to the browser console or sent to a lightweight telemetry endpoint. No npm package needed.

### What NOT to Use

| Tool / Library            | Why Not                                                                                                                                  |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Artillery                 | Less TypeScript-native than k6 v1.0. k6 has better Prometheus integration.                                                               |
| Apache JMeter             | Java-based, XML config. Not developer-friendly for a TypeScript team.                                                                    |
| autocannon                | Good for raw HTTP throughput but lacks k6's scenario/threshold model.                                                                    |
| `nestjs-prometheus`       | Adds an abstraction over `prom-client` that is unnecessary -- CipherBox already has a custom `MetricsService` with fine-grained control. |
| Grafana Cloud k6          | Paid service. Local k6 CLI is sufficient for baseline establishment.                                                                     |
| `clinic.js`               | Node.js profiling tool, not load testing. Useful for debugging, not baselines.                                                           |
| Web Vitals (`web-vitals`) | Measures page load metrics, not crypto/IPFS operation latency.                                                                           |

### New npm Dependencies: NONE

### New Dev Tools (Not npm)

| Tool | Version | Installation                            | Purpose          |
| ---- | ------- | --------------------------------------- | ---------------- |
| k6   | v1.0+   | `brew install k6` / Docker `grafana/k6` | Load test runner |

### Confidence: HIGH

`prom-client` is already installed and the `MetricsService` pattern is established. k6 v1.0 is the industry standard for developer-friendly load testing. TypeScript support is native. No new npm dependencies.

---

## Consolidated New Dependencies

### npm Dependencies: NONE

This milestone requires zero new npm packages. Every capability is built using existing dependencies or configuration changes.

### Docker Image Changes

| Service | Current             | Recommended         | Reason                             |
| ------- | ------------------- | ------------------- | ---------------------------------- |
| IPFS    | `ipfs/kubo:v0.34.0` | `ipfs/kubo:v0.40.1` | Default routing API, improved IPNS |
| (new)   | N/A                 | N/A                 | No new containers needed           |

**Kubo upgrade is optional for v1.1.** v0.34.0 supports `Gateway.ExposeRoutingAPI` (the critical feature). v0.40.1 makes it the default and adds IPNS reliability improvements. Recommend upgrading but it is not blocking.

### Dev Tooling (Not Committed to Repo)

| Tool | Version | Purpose                  | Installation      |
| ---- | ------- | ------------------------ | ----------------- |
| k6   | v1.0+   | Performance load testing | `brew install k6` |

---

## What NOT to Add (and Why)

| Library / Tool                          | Temptation                    | Why Not                                                                                                           |
| --------------------------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Helia (JS IPFS)                         | "Run IPFS in the browser"     | 500KB+ bundle, CipherBox uses server-side Kubo. Browser IPFS is unnecessary when API relays all operations.       |
| `ipfs-http-client`                      | "Official IPFS client"        | Deprecated. CipherBox uses direct Kubo RPC calls via `fetch`, which is lighter and more maintainable.             |
| `@ipfs-shipyard/pinning-service-client` | "IPFS Pinning API client"     | 4 REST endpoints. `fetch` is sufficient. Avoid dependency for trivial HTTP calls.                                 |
| Someguy (self-hosted)                   | "Replace delegated-ipfs.dev"  | Kubo already does DHT lookups. Someguy adds a middleman with zero benefit for single-app use.                     |
| `yjs` / Automerge                       | "CRDTs for IPNS conflict"     | CRDT-based IPNS inbox is research-only this milestone (per PROJECT.md). Do not add CRDT deps yet.                 |
| `nestjs-prometheus`                     | "Prometheus NestJS module"    | CipherBox has a mature custom `MetricsService`. Adding a wrapper module would require refactoring for no benefit. |
| Grafana / Loki / Tempo stack            | "Full observability"          | Over-engineered for baseline establishment. k6 JSON output + existing Prometheus metrics is sufficient.           |
| DNSLink                                 | "Alternative IPNS resolution" | Requires DNS infrastructure per user. Not viable for per-folder IPNS names (hundreds per user).                   |
| IPNS-over-PubSub (standalone)           | "Faster IPNS"                 | Already available in Kubo when both publisher and resolver are connected. Not a separate dependency.              |

---

## Integration Points with Existing Stack

### IPNS Reliability: DelegatedRoutingClient Refactor

The `DelegatedRoutingClient` (at `apps/api/src/ipns/delegated-routing.client.ts`) needs a small refactor:

| Current                             | New                                                                              |
| ----------------------------------- | -------------------------------------------------------------------------------- |
| Single `delegatedRoutingUrl` config | `PRIMARY_ROUTING_URL` (local Kubo) + `FALLBACK_ROUTING_URL` (delegated-ipfs.dev) |
| Retries only to same endpoint       | Try primary, fall through to fallback on failure                                 |
| No latency tracking                 | Wrap calls with Prometheus histogram observations                                |

The refactor preserves the existing interface (`publish()` and `resolve()` methods) while adding endpoint chaining.

### BYO-IPFS: IpfsModule Provider Selection

The `IpfsModule.forRootAsync()` currently creates a single `LocalProvider`. For BYO-IPFS, extend to support a `CompositeProvider` that:

1. Pins locally via `LocalProvider` (always)
2. Mirrors the pin to user's remote endpoint via `RemotePinningProvider` (if configured)
3. Reads from `LocalProvider` (always -- remote pinning services don't serve content)

The `IPFS_PROVIDER` injection token continues to provide a single interface. The composite pattern is internal.

### Database Minimization: Migration Sequence

| Step | Migration                                               | Reversible? |
| ---- | ------------------------------------------------------- | ----------- |
| 1    | Add `vault_format_version` column (default 1)           | Yes         |
| 2    | Deploy client code that writes v2 blobs on next publish | N/A         |
| 3    | Background job: migrate vaults still at v1              | Yes         |
| 4    | Make `encrypted_root_folder_key` nullable               | Yes         |
| 5    | (Future) Drop `encrypted_root_folder_key` column        | No          |

Step 5 is deferred until all users have migrated and a full backup cycle has completed.

### Performance: MetricsService Extensions

New histogram registrations in the existing `MetricsService` constructor. New `observe()` calls in `LocalProvider`, `DelegatedRoutingClient`, and the new `RemotePinningProvider`. No structural changes to the metrics pipeline.

### TypeORM Migrations

| Migration Name                        | Type         | Table              |
| ------------------------------------- | ------------ | ------------------ |
| `AddVaultFormatVersion`               | ADD COLUMN   | `vaults`           |
| `MakeEncryptedRootFolderKeyNullable`  | ALTER COLUMN | `vaults`           |
| `AddUserIpfsConfig`                   | CREATE TABLE | `user_ipfs_config` |
| (Future) `DropEncryptedRootFolderKey` | DROP COLUMN  | `vaults`           |

The `user_ipfs_config` table stores server-side relay configuration (endpoint URL, encrypted access token). This is NOT the user's vault settings -- it is the server's record of where to mirror pins for this user.

```text
user_ipfs_config
  - id (uuid PK)
  - user_id (uuid FK to users, unique)
  - endpoint_url (varchar 500)
  - encrypted_access_token (bytea) -- encrypted with server's key, NOT user's
  - provider_name (varchar 100)
  - enabled (boolean, default false)
  - created_at, updated_at
```

**Security note:** The access token is encrypted with the server's operational key (not the user's publicKey) because the server needs to decrypt it to make pinning API calls. This is a pragmatic tradeoff -- the server sees the user's pinning service token but never sees plaintext file content. The alternative (client-direct pinning) has CORS issues.

---

## Version Compatibility

| Component A              | Compatible With          | Notes                                                         |
| ------------------------ | ------------------------ | ------------------------------------------------------------- |
| Kubo v0.34.0             | Routing V1 API           | `Gateway.ExposeRoutingAPI = true` needed                      |
| Kubo v0.40.1             | Routing V1 API           | Default on, improved IPNS-over-PubSub                         |
| Kubo v0.34.0 / v0.40.1   | IPFS Pinning Service API | Supported via `ipfs pin remote` since v0.8.0                  |
| `prom-client` ^15.1.3    | Node.js 18+              | Already validated in current deployment                       |
| k6 v1.0+                 | TypeScript (native)      | No bundler needed. `.ts` files run directly.                  |
| `DelegatedRoutingClient` | Routing V1 spec          | Same HTTP contract for both Kubo local and delegated-ipfs.dev |

---

## Roadmap Implications for Stack

### Phase Ordering by Stack Dependency

1. **IPNS reliability first** -- Enables `Gateway.ExposeRoutingAPI`, points routing at local Kubo. No code dependencies on other features. Unblocks everything else.

2. **Performance baselines second** -- Add Prometheus histograms before any other changes so you have "before" measurements. k6 scripts establish the baseline numbers.

3. **Database minimization third** -- Depends on reliable IPNS (moving rootFolderKey to IPFS puts IPNS on the login critical path). Benefits from "before" performance baselines to measure migration impact.

4. **BYO-IPFS fourth** -- Most self-contained feature. Benefits from all other infrastructure being stable. The `RemotePinningProvider` is additive (mirrors pins, doesn't replace local).

### Risk Assessment

| Feature               | Stack Risk | Rationale                                                             |
| --------------------- | ---------- | --------------------------------------------------------------------- |
| IPNS reliability      | LOW        | Config change + URL swap. Same API contract.                          |
| Performance baselines | LOW        | Existing `prom-client`, k6 is external tooling.                       |
| DB minimization       | MEDIUM     | Data migration protocol. Risk is in migration correctness, not stack. |
| BYO-IPFS              | LOW        | Standard REST API (Pinning Service). Simple `fetch` calls.            |

---

## Sources

### Primary (HIGH confidence)

- [Delegated Routing V1 HTTP API Spec](https://specs.ipfs.tech/routing/http-routing-v1/) -- IPNS PUT/GET endpoint contract
- [IPFS Pinning Service API Spec](https://ipfs.github.io/pinning-services-api-spec/) -- OpenAPI 3.0 spec for remote pinning
- [Kubo v0.34.0 Release Notes](https://github.com/ipfs/kubo/releases/tag/v0.34.0) -- Current version, IPNS TTL change
- [Kubo v0.40.0 Release Notes](https://github.com/ipfs/kubo/releases/tag/v0.40.0) -- Routing V1 default, IPNS-over-PubSub improvements
- [Kubo Configuration Docs](https://github.com/ipfs/kubo/blob/master/docs/config.md) -- `Gateway.ExposeRoutingAPI` option
- [Someguy GitHub](https://github.com/ipfs/someguy) -- Delegated routing server (v0.11.1, Feb 2026)
- [Grafana k6 1.0 Release](https://grafana.com/blog/grafana-k6-1-0-release/) -- TypeScript-native load testing
- [prom-client GitHub](https://github.com/siimon/prom-client) -- Prometheus client for Node.js
- [Work with Pinning Services (IPFS Docs)](https://docs.ipfs.tech/how-to/work-with-pinning-services/) -- Kubo remote pinning integration

### Secondary (MEDIUM confidence)

- [IPIP-0379: Delegated IPNS HTTP API](https://specs.ipfs.tech/ipips/ipip-0379/) -- IPNS delegation spec
- [Someguy Environment Variables](https://github.com/ipfs/someguy/blob/main/docs/environment-variables.md) -- Configuration for self-hosted routing
- [Filebase Pinning Service API Docs](https://docs.filebase.com/api-documentation/ipfs-pinning-service-api) -- Example implementation
- [IP Shipyard 2025 Year in Review](https://ipshipyard.com/blog/2025-shipyard-ipfs-year-in-review/) -- IPFS ecosystem state

### Codebase (HIGH confidence)

- `apps/api/src/ipns/delegated-routing.client.ts` -- Current routing client implementation
- `apps/api/src/ipfs/providers/ipfs-provider.interface.ts` -- Provider abstraction interface
- `apps/api/src/ipfs/providers/local.provider.ts` -- Current Kubo integration
- `apps/api/src/metrics/metrics.service.ts` -- Existing Prometheus metrics
- `apps/api/src/ipns/ipns.service.ts` -- IPNS publish/resolve with DB fallback
- `docker/docker-compose.yml` -- Kubo v0.34.0 configuration

---

_Stack research for: CipherBox v1.1 IPFS Infrastructure_
_Researched: 2026-03-07_

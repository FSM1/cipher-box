# Phase 8: TEE Integration - Research

**Researched:** 2026-02-07
**Domain:** Phala Cloud TEE, IPNS republishing, NestJS queue scheduling, key epoch management
**Confidence:** MEDIUM (Phala Cloud platform well-documented; key epoch rotation requires custom design)

## Summary

Phase 8 requires integrating a Phala Cloud TEE worker that receives encrypted IPNS private keys, decrypts them inside a Confidential VM (CVM), signs new IPNS records, and publishes them via delegated routing -- all without the user being online. The CipherBox backend manages scheduling, retry queues, and TEE key epochs.

Research confirmed that Phala Cloud's dstack platform runs standard Docker containers inside Intel TDX Confidential VMs, with a TypeScript SDK (`@phala/dstack-sdk`) providing deterministic key derivation and remote attestation. The TEE worker will be a standalone Node.js/Express HTTP service deployed as a CVM, called by the CipherBox backend via HTTPS. IPNS record creation uses the same `ipns` npm package already in the codebase. Key epoch rotation is NOT a built-in Phala feature -- it must be designed as application-level logic using dstack's deterministic key derivation.

For backend scheduling, BullMQ with `@nestjs/bullmq` is the standard for production NestJS queue-based scheduling, providing job persistence (via Redis), exponential backoff retries, and distributed-safe cron execution. This replaces the simpler `@nestjs/schedule` which does not support job persistence or retry.

**Primary recommendation:** Deploy a standalone Phala Cloud CVM running a Node.js/Express TEE worker with an HTTP API. The CipherBox backend calls this API via BullMQ job processing on a 6-hour cron schedule. Use dstack's `DstackClient.getKey()` to derive deterministic secp256k1 keys per epoch for ECIES operations inside the TEE.

## Standard Stack

### Core

| Library             | Version | Purpose                                 | Why Standard                              |
| ------------------- | ------- | --------------------------------------- | ----------------------------------------- |
| `@phala/dstack-sdk` | ^0.5+   | TEE SDK for key derivation, attestation | Official Phala SDK for CVM containers     |
| `@nestjs/bullmq`    | ^11.x   | Queue-based job scheduling              | NestJS official BullMQ integration        |
| `bullmq`            | ^5.x    | Underlying queue engine                 | Redis-backed, persistent, retry support   |
| `ipns`              | ^10.1.3 | IPNS record creation/marshaling         | Already in codebase (`@cipherbox/crypto`) |
| `eciesjs`           | ^0.4.16 | ECIES encryption/decryption             | Already in codebase (`@cipherbox/crypto`) |
| `@noble/ed25519`    | ^2.2.3  | Ed25519 signing                         | Already in codebase                       |
| `@libp2p/crypto`    | ^5.1.13 | libp2p key conversion                   | Already in codebase                       |
| `ioredis`           | ^5.x    | Redis client for BullMQ                 | BullMQ's recommended Redis driver         |

### Supporting

| Library                       | Version | Purpose                       | When to Use                             |
| ----------------------------- | ------- | ----------------------------- | --------------------------------------- |
| `express`                     | ^4.x    | HTTP framework for TEE worker | TEE worker API server                   |
| `@phala/dstack-sdk` simulator | -       | Local TEE testing             | Development/testing without Phala Cloud |

### Alternatives Considered

| Instead of            | Could Use                 | Tradeoff                                                                                                                                     |
| --------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| BullMQ (Redis)        | `@nestjs/schedule` (cron) | Schedule has no persistence, no retry, no distributed lock. Only suitable for single-instance. BullMQ is required for production.            |
| Standalone CVM worker | Embedded in backend       | CVM must be a separate deployment -- TEE hardware isolation requires its own Docker container on Phala Cloud. Backend cannot run inside TEE. |
| HTTP API to TEE       | gRPC                      | HTTP is simpler, Phala's proxy only supports HTTP/HTTPS, and request volume is low (4x/day/folder).                                          |

**Installation (API):**

```bash
pnpm --filter api add @nestjs/bullmq bullmq ioredis
```

**Installation (TEE worker -- new package):**

```bash
npm install @phala/dstack-sdk eciesjs @noble/ed25519 @noble/hashes @libp2p/crypto ipns express
```

## Architecture Patterns

### Recommended Project Structure

```text
apps/
  api/
    src/
      tee/
        tee.module.ts                    # NestJS module for TEE integration
        tee.service.ts                   # TEE client - HTTP calls to Phala CVM
        tee-key-state.service.ts         # TEE key epoch management
        tee-key-state.entity.ts          # tee_key_state TypeORM entity
        tee-key-rotation-log.entity.ts   # tee_key_rotation_log entity
      republish/
        republish.module.ts              # NestJS module for republish scheduling
        republish.service.ts             # Core republish orchestration
        republish.processor.ts           # BullMQ worker/processor
        republish-schedule.entity.ts     # ipns_republish_schedule entity
        republish-health.controller.ts   # Admin health endpoint
      ipns/
        # Existing IPNS module -- extended with TEE key delivery

tee-worker/                              # Standalone Phala Cloud CVM app
  src/
    index.ts                             # Express server
    routes/
      republish.ts                       # POST /republish endpoint
      health.ts                          # GET /health
      attestation.ts                     # GET /attestation
    services/
      ipns-signer.ts                     # IPNS record creation & signing
      key-manager.ts                     # ECIES decrypt, key zeroing
      tee-keys.ts                        # DstackClient key derivation
  Dockerfile
  docker-compose.yml                     # Phala Cloud deployment config
  package.json
```

### Pattern 1: TEE Worker as HTTP Microservice

**What:** The TEE worker is a standalone Express HTTP server deployed on Phala Cloud CVM. The CipherBox backend calls it via HTTPS for each republish batch.

**When to use:** Always -- Phala Cloud CVMs expose HTTP endpoints through their proxy (dstack-gateway). This is the only supported communication pattern.

**Example:**

```typescript
// TEE Worker: POST /republish endpoint
app.post('/republish', async (req, res) => {
  const { entries } = req.body; // Array of { encryptedIpnsKey, keyEpoch, ipnsName, latestCid, sequenceNumber }

  const results = [];
  for (const entry of entries) {
    try {
      // 1. Get TEE private key for the entry's epoch
      const teePrivateKey = await getTeePrivateKey(entry.keyEpoch);

      // 2. ECIES decrypt the IPNS private key inside TEE
      const ipnsPrivateKey = eciesDecrypt(entry.encryptedIpnsKey, teePrivateKey);

      // 3. Create and sign new IPNS record with incremented sequence
      const record = await createIpnsRecord(
        ipnsPrivateKey,
        `/ipfs/${entry.latestCid}`,
        BigInt(entry.sequenceNumber) + 1n,
        48 * 60 * 60 * 1000 // 48h lifetime
      );
      const recordBytes = marshalIpnsRecord(record);

      // 4. IMMEDIATELY zero the IPNS private key
      ipnsPrivateKey.fill(0);

      results.push({
        ipnsName: entry.ipnsName,
        success: true,
        signedRecord: Buffer.from(recordBytes).toString('base64'),
        newSequenceNumber: (BigInt(entry.sequenceNumber) + 1n).toString(),
      });
    } catch (error) {
      results.push({ ipnsName: entry.ipnsName, success: false, error: error.message });
    }
  }

  res.json({ results });
});
```

### Pattern 2: BullMQ Cron + Processor for Republish Scheduling

**What:** A BullMQ job scheduler fires every 6 hours. The processor fetches due entries from the database, batches them, sends to TEE worker, then publishes signed records to delegated routing.

**When to use:** Always -- this is the core scheduling pattern.

**Example:**

```typescript
// republish.module.ts
@Module({
  imports: [
    BullModule.registerQueue({ name: 'republish' }),
    TypeOrmModule.forFeature([IpnsRepublishSchedule, TeeKeyState]),
  ],
  providers: [RepublishService, RepublishProcessor],
})
export class RepublishModule implements OnModuleInit {
  constructor(@InjectQueue('republish') private readonly queue: Queue) {}

  async onModuleInit() {
    // Create repeating job scheduler: every 6 hours
    await this.queue.upsertJobScheduler(
      'republish-cron',
      {
        pattern: '0 */6 * * *', // Every 6 hours
      },
      {
        name: 'republish-batch',
      }
    );
  }
}

// republish.processor.ts
@Processor('republish')
export class RepublishProcessor extends WorkerHost {
  async process(job: Job) {
    // 1. Query all entries where next_republish_at < NOW()
    // 2. Batch into groups of 50
    // 3. Send each batch to TEE worker HTTP endpoint
    // 4. Publish signed records to delegated routing
    // 5. Update next_republish_at and sequence numbers
    // 6. Handle failures with exponential backoff
  }
}
```

### Pattern 3: Deterministic TEE Key Derivation (Epoch-based)

**What:** The TEE worker uses `DstackClient.getKey()` with an epoch identifier in the derivation path to produce deterministic secp256k1 keys. Since dstack key derivation is deterministic per app identity + path, the same epoch always produces the same key, even across CVM restarts.

**When to use:** For all TEE key operations. The epoch number is part of the derivation path.

**Example:**

```typescript
// TEE Worker: key derivation
import { DstackClient } from '@phala/dstack-sdk';

const client = new DstackClient();

async function getTeeKeypair(
  epoch: number
): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  // Deterministic derivation: same epoch always produces same key
  const keyResult = await client.getKey(`cipherbox/ipns-republish/epoch-${epoch}`, 'secp256k1');
  const privateKeyBytes = keyResult.asUint8Array().slice(0, 32); // 32-byte secp256k1 private key

  // Derive public key from private key
  const { getPublicKey } = await import('@noble/secp256k1');
  const publicKey = getPublicKey(privateKeyBytes, false); // Uncompressed 65-byte format

  return { publicKey, privateKey: privateKeyBytes };
}
```

### Pattern 4: Key Epoch Rotation with Grace Period

**What:** The CipherBox backend manages epoch transitions. When a new epoch is initiated, both current and previous epoch keys remain valid during a 4-week grace period. The TEE worker tries current epoch first, falls back to previous.

**When to use:** During key rotation events and every republish operation.

**Rotation flow:**

1. Admin triggers epoch rotation (or automated based on schedule)
2. Backend queries TEE worker for new epoch's public key
3. Backend updates `tee_key_state` table: previous <- current, current <- new
4. Clients receive new keys on next login/refresh
5. During grace period, TEE worker can decrypt with either epoch
6. TEE worker re-encrypts old-epoch entries with current epoch during republish
7. After grace period, old epoch deprecated

### Anti-Patterns to Avoid

- **Running TEE logic inside the CipherBox backend:** The backend cannot be deployed on Phala Cloud. TEE operations MUST happen in the CVM. Backend only orchestrates.
- **Storing TEE private keys in the database:** TEE private keys never leave the TEE. Only the public key is stored in `tee_key_state`. The TEE derives its private key deterministically on every request.
- **Direct client-to-TEE communication:** The backend mediates ALL TEE interactions. Clients only know the TEE public key.
- **Polling-based republish checking:** Use BullMQ cron scheduler, not a polling loop. BullMQ provides distributed-safe scheduling.
- **Using `@nestjs/schedule` for republishing:** `@nestjs/schedule` has no job persistence, no retry, no distributed lock. If the server restarts mid-job, the job is lost.

## Don't Hand-Roll

| Problem                      | Don't Build                         | Use Instead                                    | Why                                                                                          |
| ---------------------------- | ----------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Job scheduling with retry    | Custom setTimeout/setInterval loops | BullMQ with `@nestjs/bullmq`                   | Redis persistence, exponential backoff, distributed-safe, job visibility                     |
| IPNS record creation         | Manual protobuf/CBOR encoding       | `ipns` npm package (`createIPNSRecord`)        | Already proven in codebase, handles V1+V2 signatures, CBOR encoding                          |
| ECIES encryption/decryption  | Custom ECDH + AES-GCM               | `eciesjs` library                              | Already proven in codebase, handles ephemeral keys, HKDF, auth tags                          |
| Distributed cron locking     | Database-based advisory locks       | BullMQ job schedulers                          | BullMQ handles single-execution guarantees via Redis atomics                                 |
| TEE attestation verification | Custom quote parsing                | Phala attestation API + `@phala/dstack-sdk`    | Phala provides verification endpoint at `cloud-api.phala.network/api/v1/attestations/verify` |
| HTTP retry with backoff      | Custom retry loops                  | BullMQ built-in retry with exponential backoff | Configurable per-job, handles jitter, max attempts                                           |

**Key insight:** The TEE worker is surprisingly simple -- it is just an Express server that receives encrypted keys, decrypts with dstack-derived keys, signs IPNS records, and returns them. All the complexity lives in the backend scheduling, retry logic, and epoch management, which BullMQ handles well.

## Common Pitfalls

### Pitfall 1: TEE Private Key Leakage Through Logs or Error Messages

**What goes wrong:** IPNS private keys or TEE private keys appear in error logs, stack traces, or HTTP responses.
**Why it happens:** Default error handlers serialize full error objects including function arguments.
**How to avoid:** Never log key material. Use structured logging that explicitly excludes sensitive fields. Wrap all TEE crypto operations in try/catch that only returns success/failure + non-sensitive metadata.
**Warning signs:** Stack traces in production logs containing Buffer or Uint8Array contents.

### Pitfall 2: IPNS Sequence Number Conflicts

**What goes wrong:** TEE republishes with a sequence number lower than or equal to the latest published record, causing the publish to be silently ignored by the IPFS network.
**Why it happens:** Client publishes a new record while TEE is mid-republish cycle, or database sequence number is stale.
**How to avoid:** Always read the latest sequence number from `folder_ipns.sequence_number` immediately before each republish. The TEE-signed record must use `current_sequence + 1`. After successful publish, atomically update the stored sequence number.
**Warning signs:** IPNS names resolving to stale CIDs despite successful republish logs.

### Pitfall 3: BullMQ Redis Connection Not Configured

**What goes wrong:** Application fails to start or jobs silently disappear.
**Why it happens:** BullMQ requires a running Redis instance. If Redis is not available, BullMQ either fails to connect or queues jobs that are never processed.
**How to avoid:** Add Redis as a required dependency in the development setup. Configure health checks that verify Redis connectivity. Use `ioredis` connection options with retry strategy.
**Warning signs:** Empty queue dashboard, jobs created but never processed.

### Pitfall 4: CVM Proxy Timeout on Batch Republish

**What goes wrong:** Large batches of IPNS republishes cause the HTTP request to TEE worker to time out.
**Why it happens:** Phala's dstack-gateway proxy has request timeouts. Each IPNS signing takes ~10-50ms, but batches of 100+ entries plus ECIES decryption can exceed proxy limits.
**How to avoid:** Limit batch size to 50 entries per HTTP request. Process multiple batches sequentially. Set appropriate timeout on the HTTP client.
**Warning signs:** 502/504 errors from TEE worker endpoint, partial batch completion.

### Pitfall 5: Key Epoch Mismatch After CVM Redeployment

**What goes wrong:** After redeploying the TEE worker CVM (e.g., Docker image update), derived keys might change if the app identity (image hash) changes.
**Why it happens:** Dstack's KMS derives keys from `(deployer_id, app_hash, path, epoch)`. A different Docker image = different `app_hash` = different derived keys.
**How to avoid:** Treat CVM image updates as key rotation events. Before updating the CVM image, trigger a planned epoch rotation: derive new public key from new image, update `tee_key_state`, allow grace period for migration.
**Warning signs:** All ECIES decryptions failing after CVM update.

### Pitfall 6: Delegated Routing Publish Failures

**What goes wrong:** The signed IPNS record is created successfully by the TEE but fails to publish to delegated-ipfs.dev.
**Why it happens:** delegated-ipfs.dev has occasional outages (already encountered in Phase 7). The TEE worker returns the signed record but the backend's publish step fails.
**How to avoid:** Separate TEE signing from IPNS publishing in the job pipeline. If signing succeeds but publishing fails, store the signed record and retry publishing without re-invoking the TEE. Use the existing retry infrastructure.
**Warning signs:** TEE worker returning success but IPNS names still resolving to old CIDs.

## Code Examples

### IPNS Record Creation Inside TEE Worker

```typescript
// Source: packages/crypto (existing codebase pattern)
import { createIPNSRecord } from 'ipns';
import { marshalIPNSRecord } from 'ipns';
import { privateKeyFromRaw } from '@libp2p/crypto/keys';
import * as ed from '@noble/ed25519';

async function signIpnsRecord(
  ed25519PrivateKey: Uint8Array, // 32-byte seed
  cid: string,
  sequenceNumber: bigint
): Promise<Uint8Array> {
  // Convert to libp2p format (64 bytes: private + public)
  const publicKey = ed.getPublicKey(ed25519PrivateKey);
  const libp2pKeyBytes = new Uint8Array(64);
  libp2pKeyBytes.set(ed25519PrivateKey, 0);
  libp2pKeyBytes.set(publicKey, 32);
  const libp2pPrivateKey = privateKeyFromRaw(libp2pKeyBytes);

  // Zero intermediate material
  libp2pKeyBytes.fill(0);

  // Create signed IPNS record (48h lifetime for TEE republished records)
  const record = await createIPNSRecord(
    libp2pPrivateKey,
    `/ipfs/${cid}`,
    sequenceNumber,
    48 * 60 * 60 * 1000, // 48 hours
    { v1Compatible: true }
  );

  return marshalIPNSRecord(record);
}
```

### ECIES Decrypt Inside TEE

```typescript
// Source: packages/crypto (existing codebase pattern using eciesjs)
import { decrypt } from 'eciesjs';

function decryptIpnsKey(
  encryptedIpnsKey: Uint8Array,
  teePrivateKey: Uint8Array // 32-byte secp256k1 private key
): Uint8Array {
  const decrypted = decrypt(teePrivateKey, encryptedIpnsKey);
  return new Uint8Array(decrypted); // 32-byte Ed25519 private key
}
```

### BullMQ Queue Setup in NestJS

```typescript
// Source: NestJS BullMQ docs + BullMQ docs
import { BullModule } from '@nestjs/bullmq';

// In module imports:
BullModule.forRootAsync({
  imports: [ConfigModule],
  useFactory: (config: ConfigService) => ({
    connection: {
      host: config.get('REDIS_HOST', 'localhost'),
      port: config.get<number>('REDIS_PORT', 6379),
    },
  }),
  inject: [ConfigService],
}),
BullModule.registerQueue({ name: 'republish' }),
```

### TEE Worker Docker Compose (Phala Cloud)

```yaml
# docker-compose.yml for Phala Cloud CVM deployment
version: '3.8'
services:
  tee-worker:
    image: cipherbox/tee-worker:latest
    volumes:
      - /var/run/tappd.sock:/var/run/tappd.sock # Required for dstack SDK
    ports:
      - '3001:3001' # HTTP API exposed through Phala proxy
    restart: unless-stopped
    environment:
      - NODE_ENV=production
      - PORT=3001
```

### DstackClient Key Derivation

```typescript
// Source: @phala/dstack-sdk npm + Phala docs
import { DstackClient } from '@phala/dstack-sdk';

const client = new DstackClient(); // Auto-connects to /var/run/dstack.sock

// Derive deterministic secp256k1 key for epoch
const keyResult = await client.getKey(
  'cipherbox/ipns-republish', // path
  `epoch-${epochNumber}` // subject
);

// Get raw 32-byte private key
const privateKeyBytes = keyResult.asUint8Array().slice(0, 32);
```

### Admin Health Endpoint

```typescript
// republish-health.controller.ts
@Controller('admin')
export class RepublishHealthController {
  @Get('republish-health')
  async getHealth() {
    const stats = await this.republishService.getHealthStats();
    return {
      pending: stats.pending, // Jobs due for republish
      failed: stats.failed, // Jobs in retry
      stale: stats.stale, // Jobs that exhausted retries
      lastRunAt: stats.lastRunAt, // Timestamp of last cron execution
      teeEpoch: stats.currentEpoch,
      teeConnected: stats.teeHealthy,
    };
  }
}
```

## State of the Art

| Old Approach                | Current Approach             | When Changed        | Impact                                                                         |
| --------------------------- | ---------------------------- | ------------------- | ------------------------------------------------------------------------------ |
| Phala Phat Contracts (ink!) | dstack Docker CVMs           | 2024-2025           | Deploy any Docker app, not just ink! contracts. Node.js fully supported.       |
| `TappdClient.deriveKey()`   | `DstackClient.getKey()`      | dstack v0.5+ (2025) | New API, deterministic keys, clearer semantics. Old API deprecated.            |
| Intel SGX enclaves          | Intel TDX Confidential VMs   | 2024                | Full VM isolation instead of enclave. Standard Docker, no SGX-specific coding. |
| `@nestjs/bull` (Bull v3)    | `@nestjs/bullmq` (BullMQ v5) | 2023-2024           | BullMQ is the maintained successor, better job schedulers, cleaner API.        |

**Deprecated/outdated:**

- **Phat Contracts / ink!:** Old Phala programming model. dstack replaced this entirely.
- **TappdClient:** Deprecated in dstack v0.5+. Use `DstackClient` instead.
- **`@nestjs/bull`:** Wrapper for Bull v3 (legacy). Use `@nestjs/bullmq` for BullMQ v5.

## Phala Cloud Platform Details

### Deployment Model (HIGH confidence)

- Deploy standard Docker containers into Intel TDX Confidential VMs (CVMs)
- Use `docker-compose.yml` for deployment configuration
- CLI: `phala cvms create --name <name> --compose <file> --vcpu 1 --memory 2048 --disk-size 20`
- CVMs expose HTTP ports through dstack-gateway proxy
- Public endpoint format: `https://<app-id>-<port>.dstack-prod5.phala.network`

### Pricing (HIGH confidence)

| Tier       | Spec                      | Cost                     |
| ---------- | ------------------------- | ------------------------ |
| tdx.medium | 1 vCPU, 2GB RAM, 40GB SSD | $0.07/hour (~$50/month)  |
| tdx.large  | 2 vCPU, 4GB RAM, 80GB SSD | $0.14/hour (~$100/month) |

For CipherBox's low-frequency republishing (4x/day), `tdx.medium` ($50/month) is sufficient. The CVM runs continuously to be available for on-demand requests.

Storage: $0.10/GB/month

Free trial: $20 credits, no credit card required.

### SDK (MEDIUM confidence)

- `@phala/dstack-sdk` provides `DstackClient` class
- Connects via Unix socket `/var/run/dstack.sock` (must be mounted as Docker volume)
- Key methods:
  - `getKey(path, subject)` -- deterministic key derivation (secp256k1)
  - `getQuote(reportData)` -- generate attestation quote (max 64 bytes reportData)
  - `info()` -- get app configuration
- Key result has `.asUint8Array()` for raw bytes
- Keys derived from `(deployer_id, app_hash, path, subject)` -- deterministic across restarts

### Network Access (HIGH confidence)

- Outbound HTTP/HTTPS allowed through proxy
- Inbound HTTP via dstack-gateway proxy on exposed ports
- No direct host filesystem or network IO access
- Local filesystem within Docker is encrypted and persistent

### Attestation (HIGH confidence)

- RA report generated automatically on CVM bootstrap
- Programmatic attestation via `client.getQuote(reportData)`
- Verification endpoint: `https://cloud-api.phala.network/api/v1/attestations/verify`
- Quote includes Docker image hash, init args, env vars, hardware TEE signature

## Key Epoch Rotation Design

### Design Decision: Application-Level Epoch Management (MEDIUM confidence)

Phala's KMS derives keys deterministically from `(deployer_id, app_hash, path, epoch)`. Phala itself does NOT have a built-in "epoch rotation" concept for application keys. Key epochs must be managed as application-level logic.

**How it works:**

1. The TEE worker derives keys at a specific "path" that includes an epoch number
2. `DstackClient.getKey('cipherbox/ipns-republish', 'epoch-5')` always produces the same key
3. Changing the epoch number produces a different key
4. The CipherBox backend tracks which epoch is "current" in `tee_key_state`

**Rotation trigger options:**

- **Time-based:** Backend triggers rotation every 4 weeks automatically
- **Manual:** Admin endpoint triggers rotation on demand
- **CVM update:** When Docker image is updated (changes app_hash), ALL derived keys change -- this forces a full rotation

**Grace period implementation:**

- `tee_key_state` stores `current_epoch` and `previous_epoch` with their public keys
- During republish, TEE worker tries current epoch first, falls back to previous
- If decryption succeeds with previous epoch, TEE re-encrypts with current epoch and returns upgraded key
- Backend updates `ipns_republish_schedule` with new encrypted key
- After 4 weeks, previous epoch is deprecated

**Critical insight about CVM updates:**

When the TEE worker Docker image is updated, `app_hash` changes, which changes ALL derived keys (even for the same epoch number). This means:

- CVM image updates are equivalent to a FULL key rotation
- Before updating the CVM image, the backend must:
  1. Query the NEW image's public keys for each active epoch
  2. Store them as the new current epoch
  3. Existing encrypted keys become invalid -- clients must re-encrypt on next login
- This is a significant operational constraint -- plan CVM updates carefully

**Recommended approach for CVM updates:** Treat each Docker image version as a "generation." Increment epoch on each image update. The grace period allows old-generation encrypted keys to still work during transition.

### Re-encrypt vs Keep Old Epoch (MEDIUM confidence)

The recommended approach is to re-encrypt during republish (lazy migration).

When the TEE worker encounters an entry encrypted with an old epoch:

1. Decrypt with old epoch key
2. Sign the IPNS record
3. Re-encrypt the IPNS private key with current epoch key
4. Return both the signed record AND the upgraded encrypted key
5. Backend atomically updates `encrypted_ipns_key` and `key_epoch`

This approach:

- Migrates keys lazily over the 6-hour republish cycle
- Does not require re-encryption of all entries at rotation time
- Naturally completes within one republish cycle (all entries processed within 6 hours)
- Old epoch can be deprecated after one full cycle + grace margin

## Backend Integration Pattern

### Architecture: Backend as Orchestrator

```text
  CipherBox Backend (NestJS)              Phala Cloud CVM
  ========================               ================

  BullMQ Cron (every 6h)
       |
       v
  RepublishProcessor
       |
       |-- Query due entries from DB
       |-- Batch into groups of 50
       |
       |-- For each batch:
       |     |
       |     v
       |   HTTP POST to TEE Worker -----> /republish
       |                                    |-- ECIES decrypt each key
       |                                    |-- Sign IPNS records
       |                                    |-- Zero key memory
       |                                    |-- Return signed records
       |     <----- HTTP Response --------+
       |
       |-- Publish each signed record to delegated-ipfs.dev
       |-- Update sequence numbers in DB
       |-- Schedule next republish (now + 6h)
       |-- Handle failures -> retry queue
```

### TEE Worker Authentication (MEDIUM confidence)

The TEE worker needs to verify that requests come from the CipherBox backend, not from arbitrary callers. Options:

1. **Shared secret in encrypted env vars:** Set a `CIPHERBOX_API_SECRET` as an encrypted environment variable during CVM deployment. Backend includes it in request headers. Simple and sufficient for v1.
2. **mTLS:** Both sides verify certificates. More complex, overkill for v1.

**Recommendation:** Shared secret (option 1) for v1. The secret is encrypted in transit (HTTPS) and at rest (Phala encrypts env vars with CVM-specific X25519 keys).

### Redis Requirement

BullMQ requires Redis. The existing CipherBox stack uses PostgreSQL only. Redis must be added as a new dependency.

**Options:**

1. Run Redis locally alongside PostgreSQL (development)
2. Use a managed Redis service in production (e.g., Redis Cloud free tier, or add Redis to Docker Compose)

This is a new infrastructure dependency that must be planned for.

## Open Questions

1. **DstackClient.getKey() return format for secp256k1**
   - What we know: `getKey()` returns a result with `.asUint8Array()` method and is described as returning secp256k1 private keys
   - What's unclear: Exact byte layout of the returned key material. Is it raw 32-byte private key, or does it include additional metadata? The `.slice(0, 32)` approach may need validation.
   - Recommendation: Test with dstack simulator during initial development. Validate that `getPublicKey(result.asUint8Array().slice(0, 32))` produces a valid uncompressed secp256k1 key.

2. **dstack-gateway HTTP timeout limits**
   - What we know: Phala's proxy forwards HTTP requests to CVM
   - What's unclear: Maximum request timeout. Is it 30s, 60s, or configurable?
   - Recommendation: Keep batch sizes small (50 entries) and measure actual latency during testing. If timeouts occur, reduce batch size.

3. **CVM uptime SLA and restart behavior**
   - What we know: Phala claims 99.9% uptime SLA. CVM data persists across restarts.
   - What's unclear: How often CVMs restart unexpectedly. Whether key derivation works immediately after cold boot.
   - Recommendation: Backend retry queue handles CVM unavailability. Monitor TEE health proactively.

4. **DstackClient SDK version stability**
   - What we know: dstack v0.5+ uses `DstackClient` (replacing deprecated `TappdClient`). Still described as "experimental and evolving fast."
   - What's unclear: API stability guarantees. Will `getKey()` change signature in v0.6?
   - Recommendation: Pin SDK version strictly. Wrap all SDK calls behind an abstraction layer in the TEE worker.

5. **Authenticated delegated routing publish from TEE vs. backend**
   - What we know: The backend currently publishes IPNS records to delegated-ipfs.dev. The TEE worker could publish directly.
   - What's unclear: Whether it's better for the TEE to publish directly (simpler) or return signed records to the backend (more control).
   - Recommendation: Have the TEE return signed records to the backend, and the backend publishes. This keeps the TEE's responsibilities minimal (decrypt + sign only) and lets the backend handle all retry/error logic for IPFS publishing.

## Risk Assessment

### High Risk

- **CVM image update breaks all keys:** A Docker image update changes `app_hash`, invalidating all derived keys. Must plan rotation before any CVM update. Mitigation: epoch-based rotation with grace period, automated pre-rotation step in CI/CD.

### Medium Risk

- **dstack SDK instability:** SDK is described as "experimental." API might change. Mitigation: Wrap SDK behind abstraction layer, pin version, monitor releases.
- **delegated-ipfs.dev outages:** Already experienced in Phase 7. Mitigation: Retry queue with exponential backoff, DB-cached CID fallback for resolution (already implemented).
- **Redis as new dependency:** Adding Redis increases operational complexity. Mitigation: Redis is well-understood infrastructure, can start with a simple single-instance setup.

### Low Risk

- **Phala Cloud pricing changes:** Current pricing is clear ($50/month for tdx.medium). Mitigation: Budget headroom, can optimize batch frequency.
- **IPNS record format changes:** The `ipns` npm package is stable (v10.x). Mitigation: Pin version, same package used by client.

## Sources

### Primary (HIGH confidence)

- [Phala Cloud Documentation](https://docs.phala.com) - Platform overview, CVM deployment, FAQs
- [dstack GitHub](https://github.com/Dstack-TEE/dstack) - Architecture, KMS design, SDK integration
- [Phala Cloud CLI](https://github.com/Phala-Network/phala-cloud-cli) - Deployment commands, CVM management
- [BullMQ Documentation](https://docs.bullmq.io) - Job schedulers, retry strategies
- [Phala Cloud Pricing](https://phala.com/pricing) - CVM pricing tiers
- Existing CipherBox codebase: `packages/crypto/src/ipns/`, `apps/api/src/ipns/`

### Secondary (MEDIUM confidence)

- [Phala KMS Protocol](https://docs.phala.com/phala-cloud/key-management/key-management-protocol) - Key derivation details
- [Phala Decentralized Root of Trust analysis](https://phala.com/posts/detailed-analysis-of-phala-clouds-decentralized-root-of-trust-kms-protocol-and-zkp-enhancement) - KDF internals
- [@phala/dstack-sdk npm](https://www.npmjs.com/package/@phala/dstack-sdk) - SDK API surface
- [NestJS BullMQ comparison articles](https://dev.to/juan_castillo/handling-cron-jobs-in-nestjs-with-multiple-instances-using-bull-3pj2) - Production patterns

### Tertiary (LOW confidence)

- `DstackClient.getKey()` exact return format for secp256k1 -- based on search results and documentation excerpts, not hands-on testing
- CVM proxy timeout limits -- inferred from architecture, not explicitly documented
- dstack SDK version roadmap -- described as "experimental," stability unknown

## Metadata

**Confidence breakdown:**

- Phala Cloud platform: HIGH - official docs well-documented, CLI clearly specified
- TEE worker architecture: MEDIUM - Docker deployment pattern clear, SDK API details need validation
- Key epoch rotation: MEDIUM - application-level design, Phala does not provide built-in epochs
- BullMQ scheduling: HIGH - well-established NestJS pattern, widely documented
- IPNS signing in TEE: HIGH - reuses exact same libraries already in codebase
- Pitfalls: MEDIUM - identified from architecture analysis and Phase 7 experience

**Research date:** 2026-02-07
**Valid until:** 2026-03-07 (30 days - Phala platform evolving but core Docker/CVM model stable)

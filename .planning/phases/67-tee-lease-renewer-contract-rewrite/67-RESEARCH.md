# Phase 67: TEE Lease-Renewer Contract Rewrite - Research

**Researched:** 2026-07-01
**Domain:** TEE worker security contract, BullMQ republish pipeline, TypeORM migration, IPNS record verify/sign
**Confidence:** HIGH (all claims verified against live tree; no web lookups required for this security-domain-internal research)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01** Verify-in-enclave lease renewer: relay sends marshaled `signedRecord` + `encryptedIpnsKey`; TEE parses + verifies sig + asserts name↔key binding + re-signs same CID + same seq with later EOL only.
- **D-02** Pure scheduler: drop 4 columns from `ipns_republish_schedule` (`encrypted_ipns_key`, `key_epoch`, `latest_cid`, `sequence_number`); all signing inputs from `ipns_records` via JOIN.
- **D-03** TEE-side guard + signal; defer client re-enroll consumer to Phase 68/69. Internal epoch self-derivation (never relay scalars); `currentEpoch − 1` hard floor with structured "re-enroll required" signal.
- **D-04** Local docker + sdk-e2e round-trip; test determinism via DB-write make-due + enqueue ONE BullMQ `republish-batch` job; no timer waits.

### Claude's Discretion

- Whether the EOL-only renewal write reuses `upsertIpnsRecord`'s idempotent (equal-sequence) branch or a dedicated renewal CAS — as long as it uses `WHERE sequence_number = :loaded …`.
- Pre-publish tombstone/revoked gate factoring: both at batch selection (`getDueEntries` JOIN filter) and at the renewal write CAS — required; exact factoring is discretion.
- Structured shape of the "re-enroll required" signal.
- Whether marshaled record sent to TEE is raw `signed_record` bytes or a re-marshaled form.
- Internal migration factoring (drop the 4 schedule columns, re-wire signing-input JOIN).

### Deferred Ideas (OUT OF SCOPE)

- Client re-enroll / re-wrap recovery path → Phase 68 (web) / Phase 69 (FUSE).
- Durable client `{nodeId → highestGeneration/Seq}` high-water → Phase 68 (ROT-07).
- Broader cross-layer `ValidityType == 0` verify hardening (`crates/core`, `tests/vectors`) — planner-scoped, may defer.
- Client publish-path equal-seq CID equivocation (`ipns.service.ts:311-317`) — if planner decides to tighten, may exceed scope; else leave as pre-existing Phase-58 behavior.
- Richer `ipns_records` status enum.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TEE-01 | TEE is a record-lease-renewer: receives marshaled `signedRecord`, verifies sig, re-emits same CID + same seq with only a later EOL | Q4 + Q3: `@cipherbox/crypto` `verifyIpnsRecordSignature` + `parseIpnsRecord` already in tee-worker deps; `createIpnsRecord` from `@cipherbox/core` for re-sign |
| TEE-02 | Republish never increments sequence; remove `+ 1n` from `republish.ts:79` | Q4: confirmed line; `signIpnsRecord` call at `republish.ts:80` reconstructed to pass verified seq unchanged |
| TEE-03 | `ipns_records` sole signing-input source; schedule's 4 duplicated columns collapsed | Q6: 4 columns confirmed at `republish-schedule.entity.ts:39-60`; migration template at `1750000000000-ApiSchemaCutover.ts` |
| TEE-06 | Enclave bindings: internal epoch self-derivation, name↔key binding, migration durability (stale-key guard + re-enroll signal) | Q7 + Q4: `getKeypair(epoch)` at `tee-keys.ts:30`; `decryptWithFallback` at `key-manager.ts:47-71`; `publicKeyFromIpnsName` in `@cipherbox/crypto` |
</phase_requirements>

## Summary

Phase 67 is a security-critical rewrite of the TEE worker's signing contract. Today the worker operates as a record **originator** — it receives relay-supplied scalars (`latestCid`, `sequenceNumber + 1`, relay-provided `currentEpoch`), creates a fresh IPNS record from scratch, and has no cryptographic binding to the incoming record. The target makes it a **lease renewer**: it receives the marshaled canonical record, verifies the Ed25519 signature, asserts the name derives from the decrypted key, and re-signs only with a later EOL — it cannot repoint the CID or increment the sequence.

The research confirms all CONTEXT D-01..D-04 locked decisions are implementable with the existing codebase without new package dependencies. Both `@cipherbox/crypto` (verify/parse/publicKeyFromIpnsName) and `@cipherbox/core` (createIpnsRecord/marshalIpnsRecord) are already in the tee-worker's `package.json`. The `republish` BullMQ queue's deterministic E2E trigger is via `queue.add('republish-batch', {})` on redis:6380 — no dev-guarded endpoint exists or is needed. The local docker compose needs one service block added (tee-worker on port 3002) alongside the existing `mock-ipns-routing` (port 3001).

**Primary recommendation:** Implement in 6 waves: (1) migration drop 4 schedule columns, (2) relay `getDueEntries` JOIN + teeEntries rebuild, (3) TEE internal epoch + stale-key guard, (4) verify-in-enclave lease-renewer in `republish.ts`, (5) createSubfolder teeKeys wiring, (6) sdk-e2e TEE round-trip suite. Each wave is independently verifiable.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Schedule signing-input sourcing (TEE-03) | API/Backend (`apps/api`) | — | `getDueEntries` JOIN + `teeEntries` map live in `republish.service.ts`; entity and migration are API-side |
| Verify-in-enclave (TEE-01/02) | TEE worker (`apps/tee-worker`) | — | Signature verify + name↔key binding + re-sign must execute inside the enclave; relay is untrusted |
| Epoch self-derivation + stale-key guard (TEE-06) | TEE worker (`apps/tee-worker`) | — | TEE derives its own clock-based epoch; relay's scalar is removed from the contract |
| EOL-only renewal CAS write | API/Backend (`apps/api`) | — | Relay writes the renewed `signed_record` back to `ipns_records` via equality CAS after TEE responds |
| Pre-batch tombstone filter | API/Backend (`apps/api`) | TEE worker | Primary: `getDueEntries` JOIN `tombstoned_at IS NULL`; secondary: renewal CAS `WHERE tombstoned_at IS NULL` rejects at CAS level |
| Delegated-routing publish | API/Backend (`apps/api`) | — | `publishSignedRecord` in `republish.service.ts` — unchanged, TEE returns same-or-later-EOL record bytes |
| E2E round-trip proof | `tests/sdk-e2e` | `docker/docker-compose.yml` | New TEE suite: DB make-due + BullMQ enqueue + assert equal-seq/equal-CID/later-EOL/tombstone-rejected |
| `createSubfolder` TEE enrollment | SDK-core (`packages/sdk-core`) | API/Backend | Folded todo 2: wire `encryptedIpnsPrivateKey` + `keyEpoch` into the initial publish so new subfolders enroll in TEE renewal |

## Standard Stack

### Core (all already in tee-worker deps — no new installs)

| Library | Location | Purpose | Verified |
|---------|----------|---------|----------|
| `@cipherbox/crypto` | `packages/crypto` | `parseIpnsRecord`, `verifyIpnsRecordSignature`, `publicKeyFromIpnsName` | [VERIFIED: `apps/tee-worker/package.json:14`] |
| `@cipherbox/core` | `packages/core` | `createIpnsRecord`, `marshalIpnsRecord`, `unmarshalIpnsRecord` | [VERIFIED: `apps/tee-worker/package.json:13`] |
| `@noble/hashes` | `apps/tee-worker` | HKDF for simulator epoch derivation (already used in `tee-keys.ts`) | [VERIFIED: `apps/tee-worker/package.json:16`] |
| `bullmq` | `apps/api` + `tests/sdk-e2e` | E2E trigger: `new Queue('republish', { connection: { port: 6380 } }).add('republish-batch', {})` | [ASSUMED: sdk-e2e package.json not inspected; bullmq is an API dep, may need adding to sdk-e2e] |
| `typeorm` | `apps/api` | Migration framework — `DROP COLUMN` pattern from Phase-66 template | [VERIFIED: `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts`] |

### IPNS Verify/Parse Primitives (in `@cipherbox/crypto` — NOT `@cipherbox/core`)

[VERIFIED: `packages/crypto/src/index.ts:77-79`]

| Symbol | Signature | Returns | Notes |
|--------|-----------|---------|-------|
| `parseIpnsRecord` | `(marshalledRecord: Uint8Array) => Promise<ParsedIpnsRecord>` | `{ value, sequence, signatureV2?, data?, pubKey? }` | `pubKey` is usually `undefined` for Ed25519 identity keys — use `publicKeyFromIpnsName` for name↔key binding |
| `verifyIpnsRecordSignature` | `(ipnsName: string, marshalledRecord: Uint8Array) => Promise<boolean>` | `boolean` | Uses `ipns/validator`; rejects expired EOL + bad sig; returns `false` on error (no throw) |
| `publicKeyFromIpnsName` | `(ipnsName: string) => Uint8Array` | 32-byte Ed25519 raw pubkey | Synchronous; throws `CryptoError` for non-Ed25519 names |

### IPNS Create/Marshal Primitives (in `@cipherbox/core`)

[VERIFIED: `packages/core/src/ipns/index.ts:14-23`]

| Symbol | Signature | Notes |
|--------|-----------|-------|
| `createIpnsRecord` | `(ed25519PrivateKey: Uint8Array, value: string, sequenceNumber: bigint, lifetimeMs?: number) => Promise<IPNSRecord>` | Existing use in `ipns-signer.ts:30`; extend to accept parsed-record's `value` + `sequence` as inputs |
| `marshalIpnsRecord` | `(record: IPNSRecord) => Uint8Array` | Protobuf encoding for wire transmission |
| `unmarshalIpnsRecord` | `(bytes: Uint8Array) => IPNSRecord` | Available but `parseIpnsRecord` from `@cipherbox/crypto` is the preferred entry point |

## Package Legitimacy Audit

> This phase installs NO new external packages. All required primitives are already bundled in `apps/tee-worker` and `packages/api`. Package audit not required.

**Packages added:** none.

## Architecture Patterns

### System Architecture Diagram

```
E2E test
  │
  ├─ DB write: UPDATE ipns_republish_schedule SET next_republish_at = NOW() - 1s
  │
  ├─ queue.add('republish-batch', {}) → redis:6380
  │
  ▼
RepublishProcessor.process()
  │
  ▼
processRepublishBatch()
  │
  ├─ getDueEntries() → JOIN ipns_records WHERE tombstoned_at IS NULL
  │   → returns { schedule row + record.signed_record + record.encrypted_ipns_private_key + record.key_epoch }
  │
  ├─ Build teeEntries (RepublishEntry[]):
  │   { encryptedIpnsKey, ipnsName, signedRecord [NEW], keyEpoch }
  │   (no currentEpoch / previousEpoch — TEE derives internally)
  │
  ├─ POST http://tee-worker:3001/republish
  │                │
  │    ┌──────────────────────────────┐
  │    │ TEE Worker (enclave)         │
  │    │                              │
  │    │ 1. parseIpnsRecord(signedRecord) → {value(CID), seq, pubKey?}
  │    │ 2. verifyIpnsRecordSignature(ipnsName, signedRecord) → must be true
  │    │ 3. decryptIpnsKey(encryptedKey) with internal epoch
  │    │    - internalCurrentEpoch from TEE clock
  │    │    - try currentEpoch, then currentEpoch-1
  │    │    - if both fail → ReEnrollRequired signal
  │    │ 4. derive pubkey from decrypted key
  │    │ 5. assert publicKeyFromIpnsName(ipnsName) == derivedPubkey == record.pubKey(if present)
  │    │ 6. createIpnsRecord(decryptedKey, same_value, same_seq, TEE_RECORD_LIFETIME_MS)
  │    │    → new record with later EOL, ValidityType=0 (via ipns package)
  │    │ 7. marshalIpnsRecord() → signedRecord bytes
  │    │ 8. reEncryptForEpoch(decryptedKey, internalCurrentEpoch) if needed
  │    │ 9. zero decryptedKey
  │    │                              │
  │    └──────────────────────────────┘
  │
  ├─ publishSignedRecord(ipnsName, renewedRecord) → delegated routing (someguy)
  │
  └─ Equality CAS on ipns_records:
      UPDATE WHERE sequence_number = :loaded AND tombstoned_at IS NULL
      SET signed_record = :renewedBytes
      (no sequence_number increment — same seq, new EOL bytes)
```

### Recommended Project Structure Changes

```
apps/tee-worker/src/
├── routes/
│   └── republish.ts          # Remove + 1n; remove latestCid/seq signing; add parse+verify+re-sign
├── services/
│   ├── ipns-signer.ts        # Add renewIpnsRecord(key, parsedRecord, lifetimeMs): re-sign same CID+seq
│   ├── key-manager.ts        # Remove currentEpoch/previousEpoch params; derive internally
│   └── tee-keys.ts           # Add getInternalCurrentEpoch(): { current, previous }
apps/api/src/republish/
├── republish.service.ts      # getDueEntries JOIN; teeEntries rebuild; renewIpnsRecordSeq CAS
├── republish-schedule.entity.ts  # Remove 4 columns
apps/api/src/migrations/
└── 1751000000000-ScheduleCollapse.ts  # DROP 4 columns from ipns_republish_schedule
packages/sdk-core/src/folder/
└── registration.ts           # Wire teeKeys encryptedIpnsPrivateKey+keyEpoch into createSubfolder publish
tests/sdk-e2e/src/suites/
└── tee-republish.test.ts     # New: DB make-due + BullMQ trigger + assert equal-seq/CID/later-EOL/tombstone
docker/
└── docker-compose.yml        # Add tee-worker service block (TEE_MODE=simulator, port 3002→3001)
```

## Research Findings by Priority Question

### Q1: BullMQ Republish Trigger Surface

[VERIFIED: `apps/api/src/republish/republish.module.ts:1-50` + `republish.processor.ts:1-52`]

**Queue name:** `'republish'` (`@Processor('republish')` + `BullModule.registerQueue({ name: 'republish' })`).

**Cron mechanism:** `onModuleInit()` calls `this.queue.upsertJobScheduler('republish-cron', { pattern: '0 */6 * * *' }, { name: 'republish-batch' })` — this is BullMQ 5.x job scheduler, NOT a `@Cron` decorator. The scheduler creates `republish-batch` jobs on the `republish` queue at 6-hour intervals.

**Processor entry point:** `RepublishProcessor.process(job: Job)` → `this.republishService.processRepublishBatch()`. The processor runs any job landed on the `republish` queue regardless of how it was added.

**Deterministic E2E trigger (D-04):** There is NO dev-guarded HTTP endpoint to trigger `processRepublishBatch()` directly. The canonical trigger mechanism for the sdk-e2e suite is:

```typescript
// 1. Make schedule row due (direct DB or REST — any way that sets next_republish_at to the past)
await testDb.query(`UPDATE ipns_republish_schedule SET next_republish_at = NOW() - interval '1 second' WHERE ipns_name = $1`, [ipnsName]);

// 2. Enqueue ONE job on the 'republish' queue (redis:6380)
import { Queue } from 'bullmq';
const queue = new Queue('republish', { connection: { host: 'localhost', port: 6380 } });
await queue.add('republish-batch', {});
await queue.close(); // clean up connection
```

The processor picks up the `republish-batch` job, calls `processRepublishBatch()`, which calls `getDueEntries()`, finds the make-due row, calls TEE, and runs the full path. No timer wait needed.

**Key nuance:** `upsertJobScheduler` creates repeating jobs using BullMQ's built-in scheduler — this is distinct from `queue.add(...)`. The E2E test's `queue.add('republish-batch', {})` enqueues a ONE-SHOT job into the same queue that the processor consumes. The processor does not care whether the job came from the scheduler or from `queue.add`.

### Q2: Local-Compose TEE_WORKER_URL Wiring

[VERIFIED: `docker/docker-compose.yml:1-126` + `docker/docker-compose.staging.yml:96-115` + `apps/api/src/tee/tee.service.ts:59`]

**Staging block (reference):** `docker/docker-compose.staging.yml:96-115`
```yaml
tee-worker:
  image: ghcr.io/${GITHUB_REPOSITORY_OWNER:-OWNER}/cipherbox-tee-worker:${TAG:-latest}
  restart: unless-stopped
  environment:
    PORT: 3001
    TEE_MODE: simulator
    CIPHERBOX_ENVIRONMENT: staging
    TEE_WORKER_SECRET: ${TEE_WORKER_SECRET}
  # no host ports — API reaches it via internal Docker network as http://tee-worker:3001
```

**Local compose gap:** `docker/docker-compose.yml` has NO tee-worker. It has `mock-ipns-routing` on `127.0.0.1:3001:3001` (host port 3001 taken).

**Port conflict:** The tee-worker's container port is 3001 (`PORT: 3001`). Since the API runs on the **host** (not in Docker) during local development, the tee-worker container must expose a host port. Port 3001 is occupied by mock-ipns-routing. Use `127.0.0.1:3002:3001`.

**Block to add to `docker/docker-compose.yml`:**

```yaml
  tee-worker:
    build:
      context: ../apps/tee-worker
      dockerfile: Dockerfile
    container_name: cipherbox-tee-worker
    restart: unless-stopped
    environment:
      PORT: 3001
      TEE_MODE: simulator
      CIPHERBOX_ENVIRONMENT: development
      TEE_WORKER_SECRET: ${TEE_WORKER_SECRET:-dev-secret}
    ports:
      - '127.0.0.1:3002:3001'
    healthcheck:
      test: ['CMD-SHELL', 'wget -qO- http://localhost:3001/health || exit 1']
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
```

**Relay reads TEE_WORKER_URL from:** `this.configService.get<string>('TEE_WORKER_URL', 'http://localhost:3001')` (`tee.service.ts:59`). Default is `http://localhost:3001` — must be overridden in the API's `.env` to `TEE_WORKER_URL=http://localhost:3002`.

**`TEE_WORKER_SECRET`:** The auth header uses `TEE_WORKER_SECRET` (both TEE worker and relay read this env var). In local dev, set `TEE_WORKER_SECRET=dev-secret` (matching the compose `TEE_WORKER_SECRET:-dev-secret` default).

**Note:** The `tee-worker` container image needs to exist or be built. The staging block uses a ghcr.io image. For local, `build: context: ../apps/tee-worker` with a Dockerfile is needed. Check if a `Dockerfile` exists; if not, the build context may just use `npm run build` + `node dist/index.js`.

### Q3: Relay Sourcing of Signing Inputs from `ipns_records`

[VERIFIED: `apps/api/src/republish/republish.service.ts:43-105` + `apps/api/src/tee/tee.service.ts:9-44`]

**Current `RepublishEntry` shape (tee.service.ts:9-24):**
```typescript
interface RepublishEntry {
  encryptedIpnsKey: string;   // from schedule.encryptedIpnsKey
  keyEpoch: number;           // from schedule.keyEpoch
  ipnsName: string;
  latestCid: string;          // from schedule.latestCid  ← REMOVED after D-02
  sequenceNumber: string;     // from schedule.sequenceNumber ← REMOVED after D-02
  currentEpoch: number;       // from teeState.currentEpoch ← REMOVED (TEE self-derives)
  previousEpoch: number|null; // from teeState.previousEpoch ← REMOVED (TEE self-derives)
}
```

**Target `RepublishEntry` shape (after D-01 + D-02 + D-03):**
```typescript
interface RepublishEntry {
  encryptedIpnsKey: string;   // from ipns_records.encrypted_ipns_private_key (hex→base64)
  keyEpoch: number;           // from ipns_records.key_epoch (optional — see Q7)
  ipnsName: string;
  signedRecord: string;       // NEW: from ipns_records.signed_record (base64-encoded bytes)
  // removed: latestCid, sequenceNumber, currentEpoch, previousEpoch
}
```

**Current `getDueEntries` (republish.service.ts:43-52):** Returns `IpnsRepublishSchedule[]` with no JOIN to `ipns_records`. After D-02, the schedule no longer has the signing fields — they must come from `ipns_records`.

**New `getDueEntries` query shape (JOIN required):**
```typescript
async getDueEntries(): Promise<Array<{ schedule: IpnsRepublishSchedule; record: IpnsRecord }>> {
  return this.scheduleRepository
    .createQueryBuilder('s')
    .innerJoin(IpnsRecord, 'r', 'r.ipns_name = s.ipns_name AND r.tombstoned_at IS NULL')
    .select(['s', 'r'])
    .where('s.status IN (:...statuses)', { statuses: ['active', 'retrying'] })
    .andWhere('s.next_republish_at <= :now', { now: new Date() })
    .orderBy('s.next_republish_at', 'ASC')
    .take(2000)
    .getRawAndEntities()
    ... // or use a different join approach
}
```

The `tombstoned_at IS NULL` filter at the JOIN level ensures tombstoned names never enter the batch (§5.5 defense layer 1). The CAS renewal write enforces it again at the write level (defense layer 2).

**`teeEntries` map (republish.service.ts:97-105):**

Currently reads `entry.encryptedIpnsKey`, `entry.latestCid`, etc. from the schedule row. After D-02, reads from the joined `record`:

```typescript
const teeEntries: RepublishEntry[] = batch.map(({ schedule, record }) => ({
  encryptedIpnsKey: record.encryptedIpnsPrivateKey!.toString('base64'),
  keyEpoch: record.keyEpoch!,
  ipnsName: schedule.ipnsName,
  signedRecord: record.signedRecord!.toString('base64'),
}));
```

**Success branch (republish.service.ts:133-163):**

After TEE responds with `signedRecord` (renewed bytes, same seq), the relay:
1. Calls `publishSignedRecord(schedule.ipnsName, result.signedRecord)` — unchanged
2. Updates schedule row: `nextRepublishAt`, `lastRepublishAt`, `consecutiveFailures`, `status` — still on `scheduleRepository`
3. Handles epoch upgrade (`upgradedEncryptedKey` → write back to `ipns_records.encrypted_ipns_private_key` + `key_epoch`)
4. Updates `ipns_records.signed_record` via equality CAS (replaces `syncIpnsRecordSequence`) — see Q5

**`enrollFolder` after D-02:** No longer accepts `encryptedIpnsKey`, `keyEpoch`, `latestCid`, `sequenceNumber` — these live in `ipns_records`. New signature: `enrollFolder(userId, ipnsName)` → just creates/updates the schedule row's `nextRepublishAt`. The TEE enrollment is driven by `ipns_records` having `encryptedIpnsPrivateKey != null`.

### Q4: Verify-in-Enclave Primitives (D-01)

[VERIFIED: `packages/crypto/src/index.ts:77-79`, `packages/crypto/src/ipns/parse-record.ts`, `packages/crypto/src/ipns/verify-record.ts`, `packages/crypto/src/ipns/derive-name.ts`, `packages/core/src/ipns/create-record.ts`, `apps/tee-worker/package.json:13-14`]

**Both `@cipherbox/crypto` and `@cipherbox/core` are already dependencies of `apps/tee-worker`.** [VERIFIED: `apps/tee-worker/package.json:13-14`] No new dependency needed.

**Symbols for the TEE renewer path:**

```typescript
// From @cipherbox/crypto:
import { parseIpnsRecord, verifyIpnsRecordSignature, publicKeyFromIpnsName } from '@cipherbox/crypto';

// From @cipherbox/core:
import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';

// New renewIpnsRecord function in ipns-signer.ts:
export async function renewIpnsRecord(
  ed25519PrivateKey: Uint8Array,
  marshaledExistingRecord: Uint8Array,
  lifetimeMs: number = TEE_RECORD_LIFETIME_MS
): Promise<Uint8Array> {
  // Parse the existing record to extract value + sequence
  const parsed = await parseIpnsRecord(marshaledExistingRecord);
  // Re-sign with same value (CID) + same sequence + later EOL
  // createIpnsRecord wraps the ipns package which sets ValidityType=0 (EOL) automatically
  const record = await createIpnsRecord(ed25519PrivateKey, parsed.value, parsed.sequence, lifetimeMs);
  return marshalIpnsRecord(record);
}
```

**Name↔key binding assertion (D-01 §6.7-2):**

```typescript
import * as ed from '@noble/ed25519'; // already in @cipherbox/core

// After decrypting IPNS private key:
const derivedPublicKey = ed.getPublicKey(ipnsPrivateKey); // 32 bytes
const namePublicKey = publicKeyFromIpnsName(entry.ipnsName);  // 32 bytes from name

// Assert equality (constant-time compare preferred for security):
if (!derivedPublicKey.every((b, i) => b === namePublicKey[i])) {
  throw new Error('Name-key binding violation: decrypted key does not derive to ipnsName');
}
```

**`@noble/ed25519` availability:** Already imported in `packages/core/src/ipns/create-record.ts:10`. Already a transitive dep via `@cipherbox/core` in the tee-worker. [VERIFIED: `packages/core/src/ipns/create-record.ts:10`]

**`record.pubKey` from `parseIpnsRecord`:** Usually `undefined` for Ed25519 identity records (per `parse-record.ts:38-44` — `extractPublicKeyFromIPNSRecord` returns undefined for identity-multihash keys). Do NOT rely on it for the name↔key binding. Always use `publicKeyFromIpnsName(ipnsName)` as the authoritative source.

**`verifyIpnsRecordSignature` behavior:** Uses `ipns/validator`'s `validate()` internally — this validates the Ed25519 SignatureV2 AND rejects records with expired EOL. For a fresh record that was just published (EOL not expired), this passes. Returns `false` on error (no throw). The TEE must check `== true` and throw on `false`. [VERIFIED: `packages/crypto/src/ipns/verify-record.ts:33-53`]

**`ValidityType == 0` (folded todo 3):** The `ipns` npm package (used by `createIpnsRecord`) always sets `ValidityType = 0` (EOL type) — it is the only valid type per the IPNS spec. `createIpnsRecord` already emits this correctly. No special handling required. [VERIFIED: `packages/core/src/ipns/create-record.ts:67` — `ipnsCreate(libp2pPrivateKey, value, sequenceNumber, lifetimeMs, { v1Compatible: true })`]

### Q5: Equality-CAS Renewal Write (TEE-04 carryover)

[VERIFIED: `apps/api/src/ipns/ipns.service.ts:231-437` + `apps/api/src/republish/republish.service.ts:372-403`]

**Phase-66 fused CAS (ipns.service.ts:379-392):**
```typescript
.where(
  'ipns_name = :ipnsName AND sequence_number = :expected AND generation <= CAST(:incoming AS bigint) AND tombstoned_at IS NULL',
  { ipnsName, expected: effectiveExpected, incoming: effectiveIncomingGeneration }
)
```

**Idempotent equal-seq branch (ipns.service.ts:311-317):**
```typescript
if (embeddedSeq === dbSeq) {
  // Idempotent republish — TEE 6-hour re-sign path (D-09 / Pitfall 4).
  // Do NOT increment the DB sequence, but still update latestCid/signedRecord below.
  isIdempotentRepublish = true;
} else if (embeddedSeq === dbSeq + 1n) {
  // Normal forward publish — increment allowed.
```

**Current weak write-back (republish.service.ts:386-397) — TO BE REPLACED:**
```typescript
await this.ipnsRecordRepository.update(
  {
    userId,
    ipnsName,
    tombstonedAt: IsNull(),
    sequenceNumber: LessThanOrEqual(newSequenceNumber),  // ← WEAK: allows forward races
  },
  { sequenceNumber: newSequenceNumber, signedRecord: Buffer.from(signedRecordBase64, 'base64') }
);
```

**Recommended replacement — dedicated equality CAS for EOL-only renewal:**

```typescript
// In republish.service.ts — new method to replace syncIpnsRecordSequence:
private async renewIpnsRecordEol(
  ipnsName: string,
  loadedSequenceNumber: string,
  renewedSignedRecord: Buffer
): Promise<void> {
  const result = await this.ipnsRecordRepository
    .createQueryBuilder()
    .update(IpnsRecord)
    .set({ signedRecord: renewedSignedRecord, updatedAt: new Date() })
    .where(
      'ipns_name = :ipnsName AND sequence_number = :expected AND tombstoned_at IS NULL',
      { ipnsName, expected: loadedSequenceNumber }
    )
    .execute();

  if (result.affected === 0) {
    // Forward publish raced the renewal (seq already advanced) OR tombstoned.
    // Either way the renewal write is harmlessly discarded — the forward publish
    // already wrote a later-EOL record (it signs fresh); tombstone is enforced.
    this.logger.debug(`EOL renewal CAS miss for ${ipnsName} (seq advanced or tombstoned) — discarding`);
  }
}
```

**Design choice:** A dedicated `renewIpnsRecordEol` (rather than reusing `upsertIpnsRecord`) is recommended because:
- The relay cannot supply a new `signedRecord` with an extended EOL via `upsertIpnsRecord` — that path calls `verifyIpnsRecordSignature` which rejects an expired-or-future record (and requires `embeddedSeq == dbSeq + 1n` OR `embeddedSeq == dbSeq`).
- The renewal write only updates `signed_record` (not `latestCid` or `sequenceNumber`), which is semantically distinct from a publish.
- Using the same `WHERE sequence_number = :expected AND tombstoned_at IS NULL` shape satisfies §6.6 / TEE-04 "guarded identically."

**`isIdempotentRepublish` path in `upsertIpnsRecord`:** After Phase 67, the TEE's `newSequenceNumber` in the result will equal the incoming `sequenceNumber` (no increment). If the relay still calls `upsertIpnsRecord` with the renewed record, the embedded-seq gate would see `embeddedSeq == dbSeq`, hit the idempotent branch, and update `signedRecord`. This COULD work if the relay posts the full renewed record to the publish endpoint — but it bypasses the publish path's `verifyIpnsRecordSignature` re-check (already verified in the TEE). A dedicated `renewIpnsRecordEol` is cleaner and avoids calling the full publish pipeline.

### Q6: Schedule-Collapse Migration (TEE-03, D-02)

[VERIFIED: `apps/api/src/republish/republish-schedule.entity.ts:39-60` + `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts`]

**4 columns to drop:**
- `encrypted_ipns_key` (bytea, NOT NULL, line 39-40)
- `key_epoch` (int, NOT NULL, line 46-47)
- `latest_cid` (varchar(255), NOT NULL, line 52-53)
- `sequence_number` (bigint, default 0, line 59-60)

**Phase-66 migration as structural template:** `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts` — drop-recreate pattern with `down()` throwing. For Phase 67, the simpler pattern is `ALTER TABLE DROP COLUMN` (not full drop-recreate, since the table is otherwise intact):

```typescript
// apps/api/src/migrations/1751000000000-ScheduleCollapse.ts
export class ScheduleCollapse1751000000000 implements MigrationInterface {
  name = 'ScheduleCollapse1751000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // TEE-03: collapse duplicated signing-input columns from ipns_republish_schedule.
    // All signing inputs now source from ipns_records via JOIN on ipns_name.
    // Greenfield waiver (D-01 / D-02): down() throws.
    await queryRunner.query(`
      ALTER TABLE "ipns_republish_schedule"
        DROP COLUMN IF EXISTS "encrypted_ipns_key",
        DROP COLUMN IF EXISTS "key_epoch",
        DROP COLUMN IF EXISTS "latest_cid",
        DROP COLUMN IF EXISTS "sequence_number"
    `);

    // Add index on ipns_name for the JOIN to ipns_records (if not already present)
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_ipns_republish_schedule_ipns_name"
        ON "ipns_republish_schedule" ("ipns_name")
    `);
  }

  public async down(_queryRunner: QueryRunner): Promise<void> {
    throw new Error('ScheduleCollapse migration is irreversible — greenfield waiver (D-02)');
  }
}
```

**Migration timestamp:** Use `1751000000000` (after Phase-66's `1750000000000`). [ASSUMED — pick any timestamp after 1750000000000; verify against the actual migration runner ordering.]

**Entity update:** Remove the 4 column declarations from `republish-schedule.entity.ts`. No FK SQL constraint exists between `ipns_republish_schedule` and `ipns_records` (confirmed in Phase-66 migration comment — plain varchar join). [VERIFIED: Phase-66 migration comment: "ipns_republish_schedule/shares/vaults reference ipns_name as a plain varchar(255) — no SQL FK constraints point at folder_ipns"]

### Q7: TEE Internal Epoch Derivation + Stale-Key Guard (TEE-06, D-03)

[VERIFIED: `apps/api/src/tee/tee-key-state.service.ts:1-173`, `apps/tee-worker/src/services/tee-keys.ts:30-85`, `apps/tee-worker/src/services/key-manager.ts:47-90`]

**Current epoch supply mechanism:** The relay reads `teeState.currentEpoch` from `TeeKeyState` (DB row in `tee_key_state` table) and passes it as `entry.currentEpoch` / `entry.previousEpoch` scalars in `RepublishEntry`. The TEE worker has NO clock-based epoch today.

**Epoch schedule math:** The relay's `TeeKeyState` has `currentEpoch` (integer) and `gracePeriodEndsAt = 4 weeks`. The TEE must independently derive the same epoch. Two options:
- Option A: Embed the epoch schedule constants (epoch zero timestamp + 4-week duration) in the TEE and derive from clock.
- Option B: Use `keyEpoch` from the request body (supplied by relay from `ipns_records.key_epoch`) as the hint for which epoch to try, with the guard that `keyEpoch < internalCurrentEpoch - 1` means stale.

**Recommended approach (Option B + internal verification):**

The cleanest `decryptWithFallback` rewrite does NOT need a full epoch schedule — it just tries two epochs: `keyEpoch` (the epoch the key was encrypted for, from `ipns_records.key_epoch`) and, if that fails, `keyEpoch - 1` (grace period). The stale-key guard derives `internalCurrentEpoch` from the TEE clock and refuses if `keyEpoch < internalCurrentEpoch - 1`.

```typescript
// In tee-keys.ts: add epoch self-derivation
// Constants must match the relay's epoch schedule
const EPOCH_ZERO_TIMESTAMP_MS = /* The timestamp of epoch 1 start — must be determined */ 0;
const EPOCH_DURATION_MS = 4 * 7 * 24 * 60 * 60 * 1000; // 4 weeks

export function getInternalCurrentEpoch(): number {
  return Math.max(1, Math.floor((Date.now() - EPOCH_ZERO_TIMESTAMP_MS) / EPOCH_DURATION_MS) + 1);
}

// In key-manager.ts: new signature (no relay params)
export async function decryptWithFallback(
  encryptedIpnsKey: Uint8Array,
  keyEpoch: number           // from ipns_records.key_epoch (hint for which epoch was used)
): Promise<{ ipnsPrivateKey: Uint8Array; usedEpoch: number }> {
  const internalCurrentEpoch = getInternalCurrentEpoch();

  // Guard: key older than currentEpoch - 1 is unrenewable
  if (keyEpoch < internalCurrentEpoch - 1) {
    throw new ReEnrollRequiredError(keyEpoch, internalCurrentEpoch);
  }

  // Try keyEpoch first (the epoch the key is encrypted for)
  try {
    const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsKey, keyEpoch);
    return { ipnsPrivateKey, usedEpoch: keyEpoch };
  } catch { /* fall through */ }

  // Try internalCurrentEpoch (in case keyEpoch is previous epoch but currentEpoch also works)
  if (keyEpoch !== internalCurrentEpoch) {
    try {
      const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsKey, internalCurrentEpoch);
      return { ipnsPrivateKey, usedEpoch: internalCurrentEpoch };
    } catch { /* fall through */ }
  }

  throw new Error('ECIES decryption failed: key may be corrupted');
}
```

**`reEncryptForEpoch` retarget:** Change to always use `getInternalCurrentEpoch()` as the target:

```typescript
export async function reEncryptForCurrentEpoch(ipnsPrivateKey: Uint8Array): Promise<{ encrypted: Uint8Array; epoch: number }> {
  const targetEpoch = getInternalCurrentEpoch();
  const targetPublicKey = await getPublicKey(targetEpoch);
  return { encrypted: await wrapKey(ipnsPrivateKey, targetPublicKey), epoch: targetEpoch };
}
```

**`ReEnrollRequiredError` (structured signal):**

```typescript
export class ReEnrollRequiredError extends Error {
  readonly requiresReEnroll = true;
  constructor(readonly keyEpoch: number, readonly currentEpoch: number) {
    super(`IPNS key epoch ${keyEpoch} is older than currentEpoch-1 (${currentEpoch - 1}). Re-enrollment required.`);
  }
}
```

The relay's `RepublishResult` must surface this: `{ success: false, error: 'RE_ENROLL_REQUIRED', requiresReEnroll: true }`. The `RepublishEntry.keyEpoch` field stays in the request body — removed are `currentEpoch` + `previousEpoch`. [VERIFIED: D-03 explicitly removes relay-supplied epoch scalars; `keyEpoch` stays as the encrypted-for hint]

**CRITICAL OPEN:** `EPOCH_ZERO_TIMESTAMP_MS` is not defined anywhere in the codebase. The relay's epoch counter (`TeeKeyState.currentEpoch`) is an integer that was initialized manually at first boot via `teeKeyStateService.initializeEpoch(1, publicKey)`. There is no epoch schedule math in the relay. The TEE cannot independently verify epoch from a clock without knowing `EPOCH_ZERO_TIMESTAMP_MS`. **Recommended resolution:** For Phase 67, keep `keyEpoch` in the request body (relay-supplied from `ipns_records.key_epoch`) and have the TEE attempt ONLY `keyEpoch` and `keyEpoch - 1` (the known grace period). The guard becomes: if `keyEpoch < relay_current - 1` AND neither epoch decrypts → re-enroll. This avoids the clock-derivation problem entirely since `currentEpoch` is not sent by the relay. **OR:** add `currentEpoch` back as a single relay-provided scalar (not `previousEpoch`) for the floor check only, with the TEE never using it as the re-encryption target. Flagged as an open question for the planner to resolve.

### Q8: Folded Todo Implementation Surfaces

[VERIFIED: `packages/sdk-core/src/folder/registration.ts:86-101`, `apps/api/src/ipns/ipns.service.ts:311-317`, `apps/tee-worker/src/services/ipns-signer.ts:1-37`]

**Folded todo 1 — equal-seq CID equivocation (`ipns.service.ts:311-317`):**

```typescript
if (embeddedSeq === dbSeq) {
  isIdempotentRepublish = true;
  // Currently: STILL updates latestCid/signedRecord even at equal seq
}
```

The idempotent branch still calls `SET latestCid = :cid` even when `embeddedSeq == dbSeq`. §6.2 says "sequence advances iff the CID changes." An equal-seq CID change would be an equivocation. **Planner decision:** This is pre-existing Phase-58 behavior out of the strict TEE-worker scope. The lease-renewer contract (D-01) resolves this on the renewal path by construction (TEE re-signs the verified record's own value — cannot change CID). For the client publish path, leave as-is unless the planner decides to tighten it. Tightening would change the idempotent branch to reject `embeddedCid != storedCid` at equal seq. Flagged as planner discretion.

**Folded todo 2 — `createSubfolder` teeKeys wiring (`registration.ts:86-101`):**

```typescript
// Current code at registration.ts:86-101:
await createAndPublishIpnsRecord({
  ipnsPrivateKey,
  ipnsName,
  metadataCid: cid,
  sequenceNumber: 1n,
  ctx: params.ctx,
  // ← MISSING: encryptedIpnsPrivateKey, keyEpoch from params.teeKeys
});
return {
  node,
  ipnsPrivateKey,
  rootReadKey: readKey,
  rootWriteKey: writeKey,
  // TEE republishing (phase 65): encryptedIpnsPrivateKey and keyEpoch not wired yet ← COMMENT
};
```

**Fix:** Pass `params.teeKeys?.encryptedIpnsPrivateKey` and `params.teeKeys?.keyEpoch` into `createAndPublishIpnsRecord` (which calls `publishRecord` which calls `upsertIpnsRecord` with these fields → auto-enrolls in TEE). After Phase 67's schedule collapse, the schedule enrollment is driven entirely by `ipns_records.encrypted_ipns_private_key != null`. If `encryptedIpnsPrivateKey` is passed, `upsertIpnsRecord` at line 460-476 auto-enrolls via `enrollFolder`.

**Folded todo 3 — `ValidityType == 0` in `ipns-signer.ts`:**

The `createIpnsRecord` from `@cipherbox/core` uses `ipns` npm package's `createIPNSRecord` with `{ v1Compatible: true }`. The `ipns` package always sets `ValidityType = 0` (EOL — the only valid type per IPNS spec). This is correct by construction and requires no additional code. [VERIFIED: `packages/core/src/ipns/create-record.ts:67`]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| IPNS record parsing | Custom protobuf decoder | `parseIpnsRecord` from `@cipherbox/crypto` | Already battle-tested; handles `extractPublicKeyFromIPNSRecord` fallback |
| Ed25519 signature verify | Manual sig check | `verifyIpnsRecordSignature` from `@cipherbox/crypto` | Uses `ipns/validator` which validates sig + EOL atomically |
| IPNS name → pubkey | Manual CID decode | `publicKeyFromIpnsName` from `@cipherbox/crypto` | Handles libp2p-key CID, identity multihash, 32-byte raw extraction |
| IPNS record re-sign | Custom protobuf encode | `createIpnsRecord` + `marshalIpnsRecord` from `@cipherbox/core` | V1+V2 compatible; ValidityType=0 automatic |
| BullMQ job trigger in E2E | HTTP poll loop | `new Queue('republish', {...}).add('republish-batch', {})` | Direct enqueue on redis:6380; no timer wait |
| Epoch math | Complex clock logic | Simple `keyEpoch` + grace fallback (see Q7 open question) | Avoids `EPOCH_ZERO_TIMESTAMP_MS` undefined problem |

## Common Pitfalls

### Pitfall 1: `record.pubKey` is undefined for Ed25519 identity records

**What goes wrong:** The TEE calls `parseIpnsRecord(signedRecord)` and tries to use `parsed.pubKey` for name↔key binding. It is `undefined`.

**Why it happens:** Ed25519 identity IPNS records encode the public key in the name (identity multihash), not in the record's protobuf field 7. `extractPublicKeyFromIPNSRecord` returns `undefined` for identity keys. [VERIFIED: `packages/crypto/src/ipns/parse-record.ts:38-44`]

**How to avoid:** Always use `publicKeyFromIpnsName(ipnsName)` from `@cipherbox/crypto` as the authoritative public key source for name↔key binding. Never rely on `parsed.pubKey`.

### Pitfall 2: `verifyIpnsRecordSignature` rejects records with an expired EOL

**What goes wrong:** A test publishes a record, waits a very long time, and the TEE's verify call returns `false` because the existing `signedRecord`'s EOL has passed.

**Why it happens:** `verifyIpnsRecordSignature` uses `ipns/validator` which validates not just the sig but also that the validity window has not expired. [VERIFIED: `packages/crypto/src/ipns/verify-record.ts:48`]

**How to avoid:** In tests, ensure `signedRecord` bytes were recently published (EOL is 24–48h from publish time). For the E2E test, publish fresh + immediately trigger republish. Production: the 6h republish cycle ensures records are never near expiry.

### Pitfall 3: Port conflict for local tee-worker (`mock-ipns-routing` on 3001)

**What goes wrong:** Planner adds tee-worker to local compose with port `127.0.0.1:3001:3001` — conflicts with `mock-ipns-routing`. API fails to connect to either service.

**Why it happens:** `mock-ipns-routing` already occupies host port 3001 (`docker/docker-compose.yml:114-115`). [VERIFIED]

**How to avoid:** Use port 3002 for tee-worker (`127.0.0.1:3002:3001`) and set `TEE_WORKER_URL=http://localhost:3002` in API env. The internal container port stays 3001.

### Pitfall 4: `upsertJobScheduler` vs `queue.add` — different BullMQ paths

**What goes wrong:** E2E test tries to trigger republish by calling `queue.upsertJobScheduler(...)` thinking that fires a job immediately.

**Why it happens:** `upsertJobScheduler` registers a REPEATING scheduler — it does NOT immediately enqueue a job. [VERIFIED: `apps/api/src/republish/republish.module.ts:34-48`]

**How to avoid:** Use `queue.add('republish-batch', {})` to enqueue a single one-shot job that the processor handles immediately.

### Pitfall 5: `syncIpnsRecordSequence` LessThanOrEqual still in place after TEE rewrite

**What goes wrong:** After Phase 67, the TEE returns `newSequenceNumber == loadedSeq` (no increment). The old `LessThanOrEqual` guard at `republish.service.ts:386-397` passes (since `loadedSeq <= loadedSeq`), but then tries to `SET sequenceNumber = :same` and `SET signedRecord = :renewedBytes` — this works but the `LessThanOrEqual` on seq allows forward races where a user publish advances the seq AFTER the batch loaded it but BEFORE this UPDATE runs, causing the user's newer seq to be silently overwritten to the older seq. [VERIFIED: `republish.service.ts:386-397`]

**How to avoid:** Replace with equality CAS (`sequence_number = :loaded`): only applies if seq hasn't changed since batch load. If the user publish advanced seq, the equality CAS misses — harmless, the renewal write is discarded.

### Pitfall 6: `enrollFolder` called with 4 dropped parameters after schedule collapse

**What goes wrong:** Code that calls `republishService.enrollFolder(userId, ipnsName, encryptedKey, keyEpoch, latestCid, seqNum)` (the old 6-param signature) breaks after D-02 removes those columns.

**Why it happens:** `enrollFolder` currently writes those 4 fields to the schedule row. After the migration drops them, the method signature must change. [VERIFIED: `republish.service.ts:210-249`]

**How to avoid:** Refactor `enrollFolder` to 2-param signature `(userId, ipnsName)` during the same wave as the entity/migration change. Also check `ipns.service.ts:421-434` which calls `enrollFolder` with the old signature.

### Pitfall 7: `EPOCH_ZERO_TIMESTAMP_MS` is undefined — TEE cannot self-derive epoch from clock alone

**What goes wrong:** Planner implements internal epoch derivation using `Math.floor((Date.now() - EPOCH_ZERO_TIMESTAMP) / EPOCH_DURATION_MS) + 1` but `EPOCH_ZERO_TIMESTAMP` has never been defined anywhere in the codebase. The relay's `TeeKeyState.currentEpoch` was set to `1` at first boot — there is no epoch schedule anchor.

**How to avoid:** See Q7 recommendation — use the relay-supplied `keyEpoch` (from `ipns_records.key_epoch`) as the hint for which TEE epoch to try, rather than clock-derived epoch. The stale-key guard can still use `currentEpoch` if the planner retains it as a single non-retargeting scalar in the request. Otherwise, leave `EPOCH_ZERO_TIMESTAMP_MS` as a new configuration constant to be set once (and committed). Flagged as open question.

## Code Examples

### Pattern 1: TEE Lease-Renewer Core (new logic in `republish.ts`)

```typescript
// Source: packages/crypto/src/ipns/parse-record.ts, verify-record.ts, derive-name.ts
// Source: packages/core/src/ipns/create-record.ts, marshal.ts

// Inside the per-entry try block in republish.ts:
const signedRecordBytes = Buffer.from(entry.signedRecord, 'base64');

// Step 1: Parse the existing record
const parsed = await parseIpnsRecord(signedRecordBytes);
// parsed.value = "/ipfs/<cid>", parsed.sequence = BigInt, parsed.pubKey = usually undefined

// Step 2: Verify signature against the name
const isValid = await verifyIpnsRecordSignature(entry.ipnsName, signedRecordBytes);
if (!isValid) {
  throw new Error('IPNS signature verification failed');
}

// Step 3: Decrypt IPNS key
const { ipnsPrivateKey: decryptedKey, usedEpoch } = await decryptWithFallback(
  encryptedIpnsKey,
  entry.keyEpoch
);

// Step 4: Name↔key binding
const derivedPubkey = ed.getPublicKey(decryptedKey);
const namePubkey = publicKeyFromIpnsName(entry.ipnsName);
if (!derivedPubkey.every((b, i) => b === namePubkey[i])) {
  decryptedKey.fill(0);
  throw new Error('Name-key binding violation');
}

// Step 5: Re-sign same value + same sequence, later EOL
const renewedRecord = await renewIpnsRecord(decryptedKey, signedRecordBytes, TEE_RECORD_LIFETIME_MS);
// renewedRecord: same CID, same seq, new EOL bytes

// Step 6: Zero key immediately
decryptedKey.fill(0);

// Step 7: Optional epoch upgrade
let upgradedEncryptedKey: string | undefined;
let upgradedKeyEpoch: number | undefined;
const internalCurrent = getInternalCurrentEpoch();
if (usedEpoch !== internalCurrent) {
  const { encrypted, epoch } = await reEncryptForCurrentEpoch(decryptedKey); // already zeroed — restructure as needed
  upgradedEncryptedKey = Buffer.from(encrypted).toString('base64');
  upgradedKeyEpoch = epoch;
}
```

### Pattern 2: getDueEntries JOIN (after schedule collapse)

```typescript
// Source: apps/api/src/republish/republish.service.ts (target state)
async getDueEntries(): Promise<Array<{ schedule: IpnsRepublishSchedule; record: IpnsRecord }>> {
  // TypeORM raw query to JOIN on ipns_name with tombstone filter
  const rows = await this.scheduleRepository
    .createQueryBuilder('s')
    .innerJoin(
      IpnsRecord,
      'r',
      's.ipns_name = r.ipns_name AND r.tombstoned_at IS NULL AND r.encrypted_ipns_private_key IS NOT NULL'
    )
    .addSelect(['r.ipns_name', 'r.signed_record', 'r.encrypted_ipns_private_key', 'r.key_epoch'])
    .where("s.status IN ('active', 'retrying')")
    .andWhere('s.next_republish_at <= :now', { now: new Date() })
    .orderBy('s.next_republish_at', 'ASC')
    .take(2000)
    .getRawAndEntities();
  // ... parse raw columns into paired objects
}
```

### Pattern 3: E2E TEE Round-Trip Test

```typescript
// Source: tests/sdk-e2e/src/suites/tee-republish.test.ts (new file)
import { Queue } from 'bullmq';

it('republish re-signs same CID + same seq with later EOL', async () => {
  // 1. Publish a record with TEE keys enrolled
  const { ipnsName, signedRecord, sequenceNumber } = await publishWithTeeKeys(fixture.alice);

  // 2. Make the schedule row due immediately
  await testDb.query(
    `UPDATE ipns_republish_schedule SET next_republish_at = NOW() - interval '1 second' WHERE ipns_name = $1`,
    [ipnsName]
  );

  // 3. Enqueue ONE republish job
  const queue = new Queue('republish', { connection: { host: 'localhost', port: 6380 } });
  await queue.add('republish-batch', {});
  await queue.close();

  // 4. Wait for processor to complete (poll ipns_records for signedRecord change)
  await waitFor(async () => {
    const record = await testDb.query(`SELECT signed_record FROM ipns_records WHERE ipns_name = $1`, [ipnsName]);
    return !record.rows[0].signed_record.equals(signedRecord); // signedRecord bytes changed (new EOL)
  }, { timeout: 10_000 });

  // 5. Parse renewed record and assert invariants
  const renewedBytes = await fetchCurrentSignedRecord(ipnsName);
  const renewed = await parseIpnsRecord(renewedBytes);
  const original = await parseIpnsRecord(signedRecord);

  expect(renewed.sequence).toBe(original.sequence); // same seq
  expect(renewed.value).toBe(original.value);        // same CID
  // EOL must be later (the validity data in the CBOR is different → renewed bytes !== original bytes)
  expect(Buffer.from(renewedBytes).equals(Buffer.from(signedRecord))).toBe(false);
});

it('tombstoned name is never re-signed forward', async () => {
  const { ipnsName } = await publishWithTeeKeys(fixture.alice);
  await tombstoneName(fixture.alice, ipnsName);

  await setScheduleDue(ipnsName);
  const queue = new Queue('republish', { connection: { host: 'localhost', port: 6380 } });
  await queue.add('republish-batch', {});
  await queue.close();

  // tombstoned names should be filtered out; no TEE call should occur
  // verify by checking the republish schedule row: row was deleted (unenrolled) or not processed
  // The tombstone filter in getDueEntries JOIN ensures the name never reaches the TEE
  const scheduleRow = await testDb.query(
    `SELECT status FROM ipns_republish_schedule WHERE ipns_name = $1`,
    [ipnsName]
  );
  // After tombstone + unenroll (from Phase 66's tombstoneRecord → republishService.unenrollIpns):
  expect(scheduleRow.rows).toHaveLength(0);
});
```

## Runtime State Inventory

> This phase is NOT a rename/refactor phase — no runtime state inventory required. The only runtime state change is the `ipns_republish_schedule` table losing 4 columns (pure schema; data in `ipns_records` is the source of truth). No stored data moves; no live service config changes beyond adding TEE_WORKER_URL to the local .env; no OS-registered state; no secrets renamed.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | vitest (apps/tee-worker) + vitest (tests/sdk-e2e) |
| Config file | `apps/tee-worker/vitest.config.ts` (tee-worker unit), `tests/sdk-e2e/vitest.config.ts` (E2E) |
| Quick run command (tee-worker unit) | `pnpm --filter cipherbox-tee-worker test` |
| Quick run command (api unit) | `pnpm --filter @cipherbox/api test:unit` |
| E2E run command | `pnpm --filter @cipherbox/sdk-e2e test` (requires local stack) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TEE-01 | TEE re-signs same CID + same seq, later EOL | E2E + unit | `pnpm --filter @cipherbox/sdk-e2e test -- --grep "tee-republish"` | ❌ Wave 6 (new `tee-republish.test.ts`) |
| TEE-02 | No `+ 1n` increment; `newSequenceNumber == entry.sequenceNumber` | unit | `pnpm --filter cipherbox-tee-worker test -- --grep "republish"` | ✅ (extend `republish.test.ts`) |
| TEE-03 | Schedule collapse; getDueEntries joins ipns_records | unit | `pnpm --filter @cipherbox/api test:unit -- --grep "getDueEntries"` | ❌ Wave 1 |
| TEE-06 | Internal epoch derivation; stale-key guard; name↔key binding | unit | `pnpm --filter cipherbox-tee-worker test -- --grep "key-manager\|tee-keys"` | ✅ (extend `key-manager.test.ts` + `tee-keys.test.ts`) |
| TEE-06 (name↔key) | Name↔key binding assertion rejects wrong key | unit | `pnpm --filter cipherbox-tee-worker test -- --grep "binding"` | ❌ (new test case in `republish.test.ts`) |
| TEE-06 (stale) | Re-enroll signal for key older than currentEpoch-1 | unit | `pnpm --filter cipherbox-tee-worker test -- --grep "re-enroll"` | ❌ (new test case) |
| tombstone | Tombstoned name filtered from batch (getDueEntries JOIN) | E2E | `pnpm --filter @cipherbox/sdk-e2e test -- --grep "tombstoned"` | ❌ Wave 6 |
| `createSubfolder` | New subfolders enrolled in TEE renewal after teeKeys wired | unit | `pnpm --filter @cipherbox/sdk-core test -- --grep "createSubfolder"` | ❌ (extend existing test) |

### Sampling Rate

- Per task commit: `pnpm --filter cipherbox-tee-worker test` (tee-worker unit, < 5s)
- Per wave merge: `pnpm --filter @cipherbox/api test:unit` + `pnpm --filter cipherbox-tee-worker test`
- Phase gate: full E2E suite with local docker stack (`pnpm --filter @cipherbox/sdk-e2e test`) — orchestrator/human gate per D-04

### Wave 0 Gaps

- [ ] `tests/sdk-e2e/src/suites/tee-republish.test.ts` — covers TEE-01, TEE-02, tombstone (new file)
- [ ] Extend `apps/tee-worker/src/__tests__/republish.test.ts` — covers TEE-02 (seq no-increment), name↔key binding, stale-key guard
- [ ] Extend `apps/tee-worker/src/__tests__/key-manager.test.ts` — covers TEE-06 stale-key guard + re-enroll signal
- [ ] `apps/api/src/republish/republish.service.spec.ts` (new or extend) — covers TEE-03 getDueEntries JOIN + tombstone filter

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | yes | Tombstone gate at `getDueEntries` JOIN; owner-only TEE enrollment (`shouldUpdateKey` guard in `upsertIpnsRecord`) |
| V5 Input Validation | yes | TEE validates `signedRecord` sig before any processing; relay validates `ipnsName` + record shape |
| V6 Cryptography | yes | Ed25519 verify via `ipns/validator`; ECIES via `@cipherbox/crypto`; immediate zero after use |

### Known Threat Patterns for TEE Signing Contract

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Relay sends arbitrary CID/seq to increment | Tampering | D-01: TEE parses + verifies the incoming marshaled record sig; cannot sign what wasn't already signed by the key |
| Relay supplies wrong `currentEpoch` to force re-encryption to wrong epoch | Elevation | D-03: TEE derives epoch internally; relay's epoch scalars removed from contract |
| Tombstoned name re-signed after rotation | Tampering / Spoofing | Two-layer: `getDueEntries` JOIN `tombstoned_at IS NULL` (pre-batch) + CAS `WHERE tombstoned_at IS NULL` (write) |
| Name↔key binding bypass (relay sends record for name A with key B) | Spoofing | D-01: TEE asserts `publicKeyFromIpnsName(ipnsName) == derivedPubkey(decryptedKey)`; mismatch throws |
| Stale key re-enrollment (epoch N-2 key survives) | Elevation | D-03: `keyEpoch < currentEpoch - 1` → `ReEnrollRequiredError`; key is NOT decrypted |
| Key material leak in error messages | Information Disclosure | Existing: zero on every code path; `catch` blocks zero before re-throw; error messages never contain key bytes |

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Docker | tee-worker container | ✓ | — | — |
| redis:6380 | BullMQ E2E trigger | ✓ | redis:7-alpine (from docker-compose.yml) | — |
| `apps/tee-worker` Dockerfile | local compose build | [ASSUMED] | — | Use staging image if Dockerfile present |

**Missing dependencies with no fallback:**
- `EPOCH_ZERO_TIMESTAMP_MS` — not defined in codebase; planner must define or use relay-supplied `keyEpoch` as the epoch hint (see Q7 open question)

## Open Questions

1. **`EPOCH_ZERO_TIMESTAMP_MS` — epoch schedule anchor for TEE clock-based self-derivation**
   - What we know: `tee-keys.ts` has no clock-based epoch logic; `tee-key-state.service.ts` stores `currentEpoch` as an integer initialized at first boot, with no epoch-zero anchor defined
   - What's unclear: Whether to (a) define a new constant `EPOCH_ZERO_TIMESTAMP_MS` that matches the production epoch schedule, or (b) keep `keyEpoch` in the request body as the hint (removing only the relay-supplied `currentEpoch`/`previousEpoch` scalars), or (c) retain `currentEpoch` as a single read-only scalar for the floor check (not for re-encryption target)
   - Recommendation: Option (b) — use `entry.keyEpoch` (from `ipns_records.key_epoch`) as the ECIES epoch hint; the stale guard checks `keyEpoch < (last successful epoch the TEE has a key for) - 1`. This avoids the undefined clock anchor problem while still satisfying D-03's "internal derivation" intent (re-encryption target is always `internalCurrentEpoch` from clock; only the incoming key's epoch hint is trusted from the relay).

2. **`bullmq` in `tests/sdk-e2e` package.json — dependency present?**
   - What we know: `bullmq` is an `apps/api` dep. The sdk-e2e test must enqueue a BullMQ job to trigger the processor.
   - What's unclear: Whether `bullmq` is already in `tests/sdk-e2e/package.json`.
   - Recommendation: Planner verifies; if absent, add `bullmq` as a devDependency to `tests/sdk-e2e`.

3. **`apps/tee-worker` Dockerfile — exists for local compose build?**
   - What we know: The staging compose uses a pre-built ghcr.io image. Local development would need either the image or a Dockerfile.
   - What's unclear: Whether a Dockerfile exists in `apps/tee-worker/`.
   - Recommendation: Planner inspects; if absent, create a minimal Dockerfile (`FROM node:20-alpine; WORKDIR /app; COPY . .; RUN npm ci; RUN npm run build; CMD ["node", "dist/index.js"]`).

4. **`createSubfolder` — does `createAndPublishIpnsRecord` accept `encryptedIpnsPrivateKey`?**
   - What we know: `createSubfolder` calls `createAndPublishIpnsRecord` at `registration.ts:86-92`. The Phase-66 `publishRecord` endpoint accepts `encryptedIpnsPrivateKey` + `keyEpoch` in the DTO.
   - What's unclear: Whether `createAndPublishIpnsRecord` SDK helper passes through these TEE enrollment fields to the API call.
   - Recommendation: Planner traces `createAndPublishIpnsRecord` → `publishRecord` API call; if the SDK helper drops these fields, add them to the SDK helper's params.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `bullmq` is available or easily addable to `tests/sdk-e2e` | Q1 / Validation | E2E test would need alternative trigger mechanism |
| A2 | A `Dockerfile` exists or can be trivially created for `apps/tee-worker` | Q2 / Environment | Local compose would need to use staging image; adds CI dependency |
| A3 | BullMQ 5.x `queue.add('republish-batch', {})` one-shot job is picked up by `@Processor('republish')` decorator | Q1 | If BullMQ version mismatch, may need different API |
| A4 | `EPOCH_ZERO_TIMESTAMP_MS` will be resolved by using `entry.keyEpoch` as hint instead of clock-derivation | Q7 | If clock-based epoch is required by design, a new constant must be introduced and committed |
| A5 | `migration:run` TypeORM CLI picks up new migration `1751000000000-ScheduleCollapse.ts` automatically | Q6 | Planner must verify migration runner config includes the new migration file |

## Sources

### Primary (HIGH confidence)

- `apps/tee-worker/src/routes/republish.ts` — `:79-80` `+ 1n` confirm; `:25-32` RepublishEntry; `:71-93` decrypt→sign path [VERIFIED]
- `apps/tee-worker/src/services/ipns-signer.ts` — `:12` lifetime; `:25-37` `signIpnsRecord` [VERIFIED]
- `apps/tee-worker/src/services/key-manager.ts` — `:47-71` `decryptWithFallback`; `:84-90` `reEncryptForEpoch` [VERIFIED]
- `apps/tee-worker/src/services/tee-keys.ts` — `:30-85` `getKeypair` [VERIFIED]
- `apps/tee-worker/package.json` — `:13-14` confirms `@cipherbox/core` + `@cipherbox/crypto` [VERIFIED]
- `packages/crypto/src/ipns/parse-record.ts` — `parseIpnsRecord` + `ParsedIpnsRecord` shape [VERIFIED]
- `packages/crypto/src/ipns/verify-record.ts` — `verifyIpnsRecordSignature` via `ipns/validator` [VERIFIED]
- `packages/crypto/src/ipns/derive-name.ts` — `publicKeyFromIpnsName` sync, 32-byte return [VERIFIED]
- `packages/core/src/ipns/index.ts` — exports `createIpnsRecord`, `marshalIpnsRecord` [VERIFIED]
- `packages/core/src/ipns/create-record.ts` — `createIpnsRecord` uses `ipnsCreate` with `v1Compatible: true` [VERIFIED]
- `apps/api/src/republish/republish.module.ts` — BullMQ queue name `'republish'`; `upsertJobScheduler` 6h cron [VERIFIED]
- `apps/api/src/republish/republish.processor.ts` — `@Processor('republish')`; `processRepublishBatch()` [VERIFIED]
- `apps/api/src/republish/republish.service.ts` — `:43-52` `getDueEntries`; `:97-105` `teeEntries`; `:386-397` weak write-back [VERIFIED]
- `apps/api/src/republish/republish-schedule.entity.ts` — `:39-60` 4 columns to drop [VERIFIED]
- `apps/api/src/ipns/ipns.service.ts` — `:231` `upsertIpnsRecord`; `:311-317` idempotent branch; `:384-391` fused CAS WHERE [VERIFIED]
- `apps/api/src/ipns/entities/ipns-record.entity.ts` — `:14` entity; `:56-57` `signed_record`; `:64-65` `encrypted_ipns_private_key`; `:72-73` `key_epoch`; `:86-87` `tombstoned_at`; `:94-95` `generation` [VERIFIED]
- `apps/api/src/tee/tee.service.ts` — `:59` `TEE_WORKER_URL` ConfigService key + default [VERIFIED]
- `docker/docker-compose.yml` — no tee-worker; `mock-ipns-routing` on port 3001 [VERIFIED]
- `docker/docker-compose.staging.yml:96-115` — tee-worker simulator block [VERIFIED]
- `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts` — Phase-66 template (drop-recreate + down() throws) [VERIFIED]
- `packages/sdk-core/src/folder/registration.ts:86-101` — `createSubfolder` teeKeys not wired [VERIFIED]

### Secondary (MEDIUM confidence)

- `apps/tee-worker/src/__tests__/republish.test.ts` — existing test structure; `signIpnsRecord` is mocked; `newSequenceNumber = '6'` assert confirms current `+ 1n` behavior [VERIFIED]
- `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` — sdk-e2e test pattern for BullMQ-less scenarios [VERIFIED]

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all primitives verified in live tree against package.json
- Architecture: HIGH — all file:line refs verified; line drift minor and documented
- Pitfalls: HIGH — verified from actual code behavior
- Open questions: LOW — epoch schedule anchor and Dockerfile are unresolved; flagged explicitly

**Research date:** 2026-07-01
**Valid until:** 2026-08-01 (package versions stable; BullMQ API stable; IPNS spec stable)

---

### CONTEXT.md Line Reference Drift Report

All CONTEXT canonical_refs verified against live tree. Drift found:

| CONTEXT Reference | Actual Location | Drift |
|-------------------|-----------------|-------|
| `key-manager.ts:53-67` `decryptWithFallback` | Full function: `:47-71`; body core: `:53-67` | Minor — `:47-71` is the function declaration; `:53-67` is the core try/catch body |
| `key-manager.ts:88-89` `reEncryptForEpoch` | Full function: `:84-90`; body: `:88-89` | Minor — `:84-90` is full function; `:88-89` is the body |
| `ipns-signer.ts:30-35` | Actual: `:25-37` (function declaration starts at :25) | Minor — CONTEXT cites the function body; declaration at :25 |
| All other refs | Verified exact | None |

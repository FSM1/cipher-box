# CipherBox Capacity Model

> Observed performance limits, infrastructure bottlenecks, and scaling recommendations.
> Based on baseline data captured during Phases 18, 19, 19.2, and 22.
>
> **Last updated:** 2026-06-23
> **Environment:** Single API server + single Kubo node + someguy routing sidecar + PostgreSQL

## Table of Contents

1. [Observed Limits](#1-observed-limits)
2. [Infrastructure Bottlenecks](#2-infrastructure-bottlenecks)
3. [Scaling Recommendations](#3-scaling-recommendations)
4. [Growth Projections](#4-growth-projections)
5. [Load Test Thresholds](#5-load-test-thresholds)
6. [References](#6-references)

---

## 1. Observed Limits

### 1.1 Single-User Performance (Phase 18)

Client-side round-trip timings captured against staging (2 vCPU, 8GB RAM VPS) using `curl` with a 10KB test file:

| Operation           | p50   | p95   | p99   |
| ------------------- | ----- | ----- | ----- |
| IPNS Resolve        | 147ms | 224ms | 278ms |
| IPFS Pin (upload)   | 138ms | 218ms | 227ms |
| IPFS Cat (download) | 133ms | 215ms | 219ms |

Server-side Prometheus histograms (cumulative across benchmark + 5-client load test):

| Operation    | Source  | Count | p50   | p95   | p99   | Mean  |
| ------------ | ------- | ----- | ----- | ----- | ----- | ----- |
| IPNS Publish | --      | 1,367 | 180ms | 519ms | 904ms | 196ms |
| IPNS Resolve | network | 529   | 135ms | 284ms | 488ms | 126ms |
| IPNS Resolve | db      | 84    | 35ms  | 93ms  | 187ms | 36ms  |
| IPFS Pin     | --      | 1,923 | 8ms   | 18ms  | 31ms  | 8ms   |
| IPFS Cat     | --      | 704   | 2ms   | 5ms   | 9ms   | 2ms   |

HTTP API response times (server-side, routes with >= 10 requests):

| Route                    | Count | p50   | p95   | p99   |
| ------------------------ | ----- | ----- | ----- | ----- |
| POST /ipfs/upload [201]  | 1,923 | 8ms   | 45ms  | 50ms  |
| GET /ipfs/:cid [200]     | 704   | 5ms   | 10ms  | 10ms  |
| GET /ipns/resolve [200]  | 852   | 50ms  | 245ms | 467ms |
| POST /ipns/publish [201] | 621   | 165ms | 477ms | 871ms |
| POST /auth/login [200]   | 14    | 155ms | 240ms | 248ms |
| GET /vault [200]         | 12    | 5ms   | 9ms   | 10ms  |
| GET /vault/quota [200]   | 838   | 5ms   | 9ms   | 10ms  |

### 1.2 Concurrent User Scaling (Phase 19.2)

Upload throughput scaling measured with SDK-based load test harness against local infrastructure (pebbleds datastore, concurrent SDK pins):

| Clients | uploadFile p50 | uploadFile p95 | Throughput | Errors |
| ------- | -------------- | -------------- | ---------- | ------ |
| 1       | 131ms          | 287ms          | 6.36 ops/s | 0      |
| 5       | 1,016ms        | 1,871ms        | 4.97 ops/s | 0      |
| 10      | 2,499ms        | 3,768ms        | 3.95 ops/s | 0      |
| 20      | 5,897ms        | 8,806ms        | 3.43 ops/s | 0      |
| 50      | 14,789ms       | 19,315ms       | 3.36 ops/s | 0      |
| 75      | 21,969ms       | 25,316ms       | 3.51 ops/s | 0      |

Staging CI load tests (GitHub Actions runner against staging VPS, post-optimization):

| Clients | uploadFile p50 | uploadFile p95 | Throughput  | Errors | Error Rate |
| ------- | -------------- | -------------- | ----------- | ------ | ---------- |
| 50      | 3,242ms        | 4,615ms        | 15.10 ops/s | 0      | 0%         |
| 100     | 5,300ms        | 8,300ms        | 18.76 ops/s | 0      | 0%         |
| 200     | 10,500ms       | 15,500ms       | 19.22 ops/s | 58     | 1.5%       |

Mixed workload scaling (staging, weighted mix of CRUD operations):

| Clients | createFolder p50 | uploadFile p50 | Throughput  | Errors |
| ------- | ---------------- | -------------- | ----------- | ------ |
| 5       | 511ms            | 613ms          | 9.32 ops/s  | 0      |
| 50      | 2,000ms          | 2,700ms        | 22.86 ops/s | 0      |
| 100     | 3,700ms          | 5,100ms        | 24.05 ops/s | 0      |
| 200     | 6,200ms          | 8,800ms        | 28.50 ops/s | 4      |

**Environment caveat:** Local and staging measurements are not directly comparable. Local infrastructure has different network characteristics, CPU, and I/O profiles than the staging VPS. The three-point local comparison (Phase 19.2) provides matched-environment data; the staging CI data provides production-representative data.

### 1.3 IPNS Publish Throughput (Phase 19)

IPNS publish storm with Someguy sidecar (5 clients x 50 folder create-rename-delete cycles = 750 ops):

| Environment                | Duration | Throughput  | createFolder p50 | createFolder p95 | Errors |
| -------------------------- | -------- | ----------- | ---------------- | ---------------- | ------ |
| Staging (warm DHT, 8h)     | 49.1s    | 15.28 ops/s | 468ms            | 848ms            | 0      |
| Local (delegated-ipfs.dev) | 69.7s    | 10.75 ops/s | 606ms            | 1,220ms          | 0      |
| Local (someguy, cold DHT)  | 89.3s    | 8.39 ops/s  | 728ms            | 1,070ms          | 0      |

**Key finding:** DHT warm-up matters significantly. Staging someguy (8h uptime) is ~2x faster than local someguy with a cold DHT (10min uptime).

### 1.4 Server-Side Pin Latency (Prometheus, Post-Optimization)

Kubo pin latency distribution captured from staging after 20,944 pin operations (pebbleds datastore):

| Bucket   | Count  | Cumulative % |
| -------- | ------ | ------------ |
| <= 10ms  | 28     | 0.1%         |
| <= 50ms  | 181    | 0.9%         |
| <= 100ms | 564    | 2.7%         |
| <= 250ms | 2,042  | 9.7%         |
| <= 500ms | 4,944  | 23.6%        |
| <= 1s    | 9,341  | 44.6%        |
| <= 2.5s  | 17,477 | 83.4%        |
| <= 5s    | 20,898 | 99.8%        |
| <= 10s   | 20,944 | 100%         |

**Mean pin latency:** 1.37s (down from 1.73s pre-optimization, -20.8%)

### 1.5 Re-baseline (2026-06): provider CPU and someguy contention

A 2026-06 staging re-baseline (upload-throughput @ 50 clients) measured ~10 ops/s versus the 15.10 ops/s recorded in Phase 19.2 (§1.2). Object count was ruled out as the cause: a garbage-collection from 294,811 to 20,038 datastore objects did not change throughput.

CPU-limit sweep (all runs share the same datastore state, `Provide.Strategy=roots`, on the 2 vCPU staging host):

| ipfs cpus | someguy cpus | uploadFile p50 | uploadFile p95 | Throughput  |
| --------- | ------------ | -------------- | -------------- | ----------- |
| 1.0       | 1.0          | 5,779ms        | 8,001ms        | 8.71 ops/s  |
| 1.5       | 1.0          | 4,894ms        | 6,506ms        | 10.28 ops/s |
| 2.0       | 1.0          | 5,105ms        | 7,385ms        | 9.80 ops/s  |
| 2.0       | 0.4          | 5,855ms        | 7,501ms        | 8.66 ops/s  |

Findings:

- **Two cores are the wall.** During load, ipfs and someguy together saturate the host's two cores (combined CPU 160-176% of 200%). Raising ipfs past 1.5 gives nothing (2.0 ties 1.5) because the physical cores, shared with someguy, are the ceiling. 1.5 is the measured knee (+18% over 1.0).
- **someguy is a per-upload participant, not a parasite.** Each upload publishes two IPNS records through the API's delegated-routing client (someguy): one per-file record and one parent-folder record. Throttling someguy to 0.4 made throughput _worse_ (8.66 ops/s) by bottlenecking the publish path - it is on the critical path and must not be starved.
- **Object count is not the throughput driver** (GC test above). It affects background provide/DHT CPU, which `Provide.Strategy=roots` already bounds to the pin-root count (~18k roots vs ~76k blocks under the default `all`).
- **Hardware note:** the host is a 2 vCPU / 8 GB / 100 GB NVMe plan (Hostinger KVM 2) and always has been - a 4 vCPU / 8 GB host is not an offered Hostinger plan, so the "4 vCPU" figure once in §1.1 was a documentation error (now corrected). The 15.10 ops/s Phase 19.2 figure is therefore same-hardware, making the drop to ~10 ops/s a software/contention regression on the same two cores, not a hardware change.

Applied remediation (PR): Kubo upgraded v0.40.0 -> v0.42.0, ipfs limits raised to `cpus: 1.5` / `memory: 3G`, `Provide.Strategy=roots` made reproducible via a `/container-init.d` script. Recommended next: defer the per-file IPNS publish off the upload critical path (§3.2, a same-hardware win), and/or upgrade to the next Hostinger tier (4 vCPU / 16 GB) to lift the two-core ceiling.

---

## 2. Infrastructure Bottlenecks

### 2.1 Kubo IPFS Node

Kubo's `pin add` operation is the **dominant bottleneck**, consuming ~95% of upload endpoint latency. Each `uploadFile` SDK call requires 3 sequential pin operations (ciphertext, file metadata, folder metadata), totaling ~4-5s server-side at mean.

**Optimization impact (pebbleds datastore):**

| Metric               | flatfs (pre) | pebbleds (post) | Change     |
| -------------------- | ------------ | --------------- | ---------- |
| Pin mean latency     | 1.73s        | 1.37s           | -20.8%     |
| Pin p50 (estimated)  | ~1.7s        | ~1.0s           | -41%       |
| IPNS publish mean    | ~120ms       | ~50ms           | -58%       |
| 75-client errors     | 10           | 0               | Eliminated |
| 75-client throughput | 2.44 ops/s   | 3.51 ops/s      | +43.9%     |

Concurrent pins from multiple clients cause contention on the Kubo datastore. At 50 clients, throughput plateaus at ~3.4-3.7 ops/s locally and ~15-19 ops/s on staging. At 75 clients with flatfs, errors begin appearing; pebbleds eliminates this failure mode entirely.

**Memory and CPU:** Kubo uses Go's goroutine scheduler. Pin operations are I/O-bound on the datastore. The pebbleds LSM-tree datastore batches writes, reducing I/O contention under concurrent load.

**CPU contention (2026-06):** On the 2 vCPU staging host, Kubo's container CPU cap is the binding constraint under concurrent uploads, not datastore I/O. At a 1.0 cap Kubo pegs at 100% during load; raising it to `cpus: 1.5` yields +18% throughput (§1.5). Kubo shares the two cores with the someguy sidecar, which is active on the upload path, so they contend at peak. Kubo runs `v0.42.0` with `Provide.Strategy=roots` (announces pin roots only; the 0.40 `Reprovider.*` keys were renamed to `Provide.*`).

### 2.2 PostgreSQL

Auth lookups, IPNS record cache reads/writes, and vault operations are fast:

| Operation        | Mean Latency |
| ---------------- | ------------ |
| Vault lookup     | < 5ms        |
| Quota check      | < 5ms        |
| IPNS DB resolve  | 23-36ms      |
| IPNS DB upsert   | ~50ms        |
| Auth login (JWT) | 104-155ms    |

PostgreSQL is **not the bottleneck** at current scale. The `folder_ipns` table grows linearly with `users x folders`, but even at 200 concurrent clients, DB operations remain sub-100ms.

**Connection pooling:** TypeORM manages the connection pool. Default pool size handles current concurrency levels without exhaustion.

### 2.3 API Server (NestJS)

Request processing overhead is minimal (~5-10ms per request excluding downstream IPFS/IPNS calls). The API server acts primarily as a pass-through to Kubo for IPFS operations and to PostgreSQL for IPNS record management.

- **Rate limiting:** ThrottlerGuard protects against abuse. Load tests bypass throttling via `THROTTLE_BYPASS_SECRET` in test mode.
- **Connection handling:** NestJS handles concurrent HTTP connections efficiently. No observed issues at 200 concurrent clients.
- **CPU:** Not a bottleneck. Server-side processing time per request is dominated by Kubo pin latency, not application logic.

### 2.4 Redis

Used for rate limiting state and session management. Sub-millisecond operations. Not a bottleneck at any observed concurrency level.

### 2.5 Someguy (Delegated Routing Sidecar)

IPNS publish DHT propagation happens asynchronously and does not block client responses. DHT propagation latency:

| Outcome | Mean  | Count   | Error Rate |
| ------- | ----- | ------- | ---------- |
| Success | 838ms | 147,285 | --         |
| Error   | 17.2s | 324     | 0.22%      |

DHT propagation errors do not affect client-facing operations (fire-and-forget). Someguy's warm DHT is critical for IPNS resolution performance in non-API contexts (recovery tool, TEE republishing).

**Per-upload load (2026-06):** someguy is also on the upload critical path - each `uploadFile` publishes two IPNS records through it (per-file + parent-folder), so its CPU tracks upload volume (spiking to 80-90% under 50-client load). Throttling it _reduces_ upload throughput (§1.5). Note someguy is a read/proxy delegated-routing _resolver_ and cannot accept provide writes, so Kubo's content announcing cannot be offloaded to it; reducing per-upload publishes (§3.2) is the lever, not delegating providing to someguy.

---

## 3. Scaling Recommendations

### 3.1 When to Scale

| Signal                                     | Threshold              | Action                                     |
| ------------------------------------------ | ---------------------- | ------------------------------------------ |
| Upload p95 > 5s consistently (staging)     | Kubo pin contention    | Add second Kubo node or upgrade hardware   |
| Upload p95 > 15s consistently (staging)    | Kubo saturated         | Kubo cluster mode or dedicated pin workers |
| API response time p95 > 500ms (non-IPFS)   | API CPU bound          | Add API replica behind load balancer       |
| PostgreSQL connections > 80% pool          | DB saturated           | Increase pool size or add read replica     |
| Kubo datastore > 80% disk                  | Storage full           | Expand volume or enable garbage collection |
| IPNS publish queue depth > 100             | Publish backlog        | Tune Kubo worker concurrency               |
| Mixed workload error rate > 1%             | Infrastructure ceiling | Scale horizontally (Kubo + API)            |
| Throughput plateaus despite adding clients | Single-node ceiling    | Horizontal scaling required                |

### 3.2 How to Scale

**Kubo IPFS Node:**

- **Vertical:** Increase CPU/RAM/SSD. Pebbleds datastore benefits significantly from faster I/O. Move from HDD to NVMe SSD for pin operations.
- **Horizontal:** Run multiple Kubo nodes behind the API. Each API instance pins to a designated Kubo node. Requires content routing coordination (IPFS Cluster or custom routing).
- **Cluster mode:** [IPFS Cluster](https://cluster.ipfs.io/) adds pinning coordination but introduces operational complexity. Recommended only when single-node Kubo reaches sustained saturation.
- **CPU sizing (2026-06):** The host is 2 vCPU; under 50-client load ipfs and the someguy sidecar saturate both cores (§1.5). Upgrading to the next Hostinger tier (4 vCPU / 16 GB) lets ipfs (`cpus: 1.5`) and someguy (`cpus: 1.0`) run without contending, or move someguy to its own host/cores.
- **Reduce per-upload IPNS publishes:** Each upload issues two someguy publishes (per-file + parent-folder). The per-file record is published at sequence 1 on every upload but is only needed for later in-place version updates - deferring it off the upload critical path (publish lazily on first file mutation) would roughly halve someguy's per-upload load with no hardware change.

**API Server (NestJS):**

- The API is stateless (session state in Redis, no in-memory state). Adding replicas behind Caddy or nginx is straightforward.
- Ensure all replicas share the same Redis instance for rate limiting and session consistency.
- Database connection pool per replica needs coordination (total connections = replicas x pool_size).

**PostgreSQL:**

- **Read replicas:** IPNS cache reads can be directed to read replicas. Write scaling is unnecessary at current volume.
- **Connection pooling:** Use PgBouncer if connection count exceeds PostgreSQL's `max_connections`.
- **Sharding:** Premature for a tech demo. Only consider if user count exceeds ~100,000.

**TEE Republishing:**

- Independent scaling path. Add TEE workers to increase IPNS republish batch throughput.
- Each TEE worker processes a batch of IPNS names every 6 hours.
- Batch duration grows linearly with IPNS name count. Monitor `cipherbox_republish_batch_duration_seconds`.

---

## 4. Growth Projections

### 4.1 Storage Growth

All files are encrypted with unique keys, so IPFS deduplication does not apply.

**Formula:**

```text
storage_bytes = users * avg_files_per_user * avg_encrypted_file_size * 1.05
```

The 1.05 multiplier accounts for ~5% metadata overhead (file metadata CIDs, folder metadata CIDs, IPNS records).

| Users  | Files/User | Avg File Size | IPFS Storage | Monthly Growth (10 files/user/mo) |
| ------ | ---------- | ------------- | ------------ | --------------------------------- |
| 100    | 100        | 500KB         | ~5 GB        | ~500 MB/mo                        |
| 1,000  | 100        | 500KB         | ~50 GB       | ~5 GB/mo                          |
| 10,000 | 100        | 500KB         | ~500 GB      | ~50 GB/mo                         |
| 1,000  | 100        | 5MB           | ~500 GB      | ~50 GB/mo                         |

### 4.2 IPNS Name Growth

Each user has:

- 1 vault blob IPNS name
- N folder IPNS names (1 per folder including root)
- M file IPNS names (1 per file)

**Formula:**

```text
ipns_names = users * (1 + avg_folders_per_user + avg_files_per_user)
```

| Users  | Folders/User | Files/User | Total IPNS Names | TEE Republish Batch Size |
| ------ | ------------ | ---------- | ---------------- | ------------------------ |
| 100    | 10           | 100        | ~11,100          | ~11,100 every 6h         |
| 1,000  | 10           | 100        | ~111,000         | ~111,000 every 6h        |
| 10,000 | 10           | 100        | ~1,110,000       | ~1,110,000 every 6h      |

TEE republish batch duration scales linearly with IPNS name count. At current Someguy publish throughput (~15 ops/s), 111,000 names would take ~2 hours to republish -- within the 6-hour window. At 1.1M names, multiple TEE workers or batching optimizations would be needed.

### 4.3 Database Growth

| Table         | Growth Driver             | Rows at 1,000 Users | Rows at 10,000 Users |
| ------------- | ------------------------- | ------------------- | -------------------- |
| users         | 1 per user                | 1,000               | 10,000               |
| vaults        | 1 per user                | 1,000               | 10,000               |
| folder_ipns   | users x (folders + files) | ~111,000            | ~1,110,000           |
| device_tokens | users x avg_devices       | ~2,000              | ~20,000              |

The `folder_ipns` table is the largest growth driver. With proper indexing (already in place on `user_id`, with a unique constraint on `(user_id, ipns_name)`), queries remain efficient at millions of rows.

### 4.4 Cost Estimates (Single Server Deployment)

These are rough estimates for a self-hosted tech demo deployment, not production SLAs.

| Component     | 100 Users      | 1,000 Users     | 10,000 Users     |
| ------------- | -------------- | --------------- | ---------------- |
| VPS (CPU/RAM) | $10-20/mo      | $40-80/mo       | $150-300/mo      |
| Storage (SSD) | $5/mo (50GB)   | $25/mo (250GB)  | $100/mo (1TB)    |
| Bandwidth     | $5/mo          | $20/mo          | $100/mo          |
| Domain/SSL    | $15/yr         | $15/yr          | $15/yr           |
| **Total**     | **~$20-30/mo** | **~$85-125/mo** | **~$350-500/mo** |

**Notes:**

- VPS pricing based on Hostinger/Hetzner tier estimates
- Storage assumes SSD volumes at ~$0.10/GB/mo
- Bandwidth depends heavily on download patterns and provider egress pricing
- Does not include TEE infrastructure costs (Phala Cloud pricing varies)

---

## 5. Load Test Thresholds

Automated pass/fail thresholds are defined in `tests/load/src/harness/thresholds.ts` and integrated into all 8 load test scenarios. Thresholds are 2-3x observed baselines to avoid CI flakiness while still catching significant regressions.

| Scenario           | Operation    | p95 Threshold | Error Rate Max | Rationale                                 |
| ------------------ | ------------ | ------------- | -------------- | ----------------------------------------- |
| upload-throughput  | uploadFile   | 10,000ms      | 5%             | 19.2 p95 was 2,841ms at 5 clients (~3.5x) |
| mixed-workload     | uploadFile   | 10,000ms      | 10%            | Mixed has higher error rate historically  |
| mixed-workload     | createFolder | 5,000ms       | 10%            | 19.2 p95 was 936ms at 5 clients (~5x)     |
| ipns-publish-storm | createFolder | 10,000ms      | 10%            | IPNS contention scenario, high variance   |
| sustained-load     | uploadFile   | 10,000ms      | 5%             | Same as upload-throughput                 |
| sustained-load     | createFolder | 5,000ms       | 5%             | Folder ops should stay fast               |
| spike-test (burst) | uploadFile   | 15,000ms      | 15%            | Spike: intentional overload               |
| spike-test (burst) | createFolder | 15,000ms      | 15%            | Spike: intentional overload               |

**How thresholds work:**

1. Each scenario runs its workload and collects `OperationMetrics` via `aggregateAndReport()`
2. `checkThresholds()` compares observed p95 latency and error rate against the threshold table
3. If any threshold is breached, the test fails with a descriptive violation message listing the operation, observed value, and threshold
4. The CI workflow (`load-test.yml`) runs via `workflow_dispatch` (manual trigger), not on every push

**Updating thresholds:** When baselines shift significantly (new infrastructure, new optimizations), update the threshold values in each scenario file. Keep thresholds at 2-3x observed values to maintain a buffer against normal variance.

---

## 7. Retention Consequence of BYO Advisory Rows

### 7.1 Background

CipherBox supports two storage modes for each file CID in `pinned_cids`:

- **Hosted rows**: CIDs pinned via the CipherBox relay (`isByoUser = false`). The CipherBox
  Kubo node physically holds the content.
- **BYO advisory rows**: CIDs registered by BYO-IPFS users (`isByoUser = true`). These rows
  track what the user claims is pinned on their own infrastructure; the CipherBox Kubo node
  does NOT hold these CIDs.

### 7.2 The Retention Consequence

The `guardedUnpin` refcount query counts ALL `pinned_cids` rows for a given CID regardless of
origin — both hosted and BYO advisory rows contribute to the refcount (D-07 design, WR-07
disposition: accepted).

**Consequence:** If a BYO advisory row exists for a CID that is also held by the CipherBox Kubo
node (hosted), deleting the hosted row will NOT trigger a physical unpin of the CID from Kubo
until the BYO advisory row is also removed. The CID is retained in Kubo for as long as any BYO
advisory row references it.

**When this occurs:**

1. User A uploads a file via the CipherBox relay (hosted `pinned_cids` row created).
2. User B (BYO-IPFS mode) registers the same CID (advisory `pinned_cids` row created).
3. User A deletes their file — their hosted row is removed and their quota is decremented
   immediately (D-03), but the CID remains pinned in Kubo because User B's advisory row
   keeps the refcount above zero.
4. Kubo storage is freed only when User B also removes their advisory row.

**Impact on capacity planning:** In environments with significant BYO-IPFS usage, Kubo storage
consumption may exceed what is attributable to hosted users alone. Monitor
`cipherbox_pending_unpin_queue_depth` and `cipherbox_drift_orphaned_pins_total` for divergence
between DB-accounted and Kubo-actual pin counts.

**Operator action:** No action is required — this is intentional design. If an operator needs
to reclaim Kubo storage held by a BYO-referenced CID, they must first remove the BYO advisory
row (e.g., by having the BYO user delete their reference), which will allow the next
`drain-pending-unpins` BullMQ run to physically unpin it.

---

## 6. References

### Baseline Documents

- `.planning/baselines/18-performance-baselines.md` -- Server-side Prometheus baselines (Phase 18)
- `.planning/baselines/19-someguy-ipns-baselines.md` -- IPNS resolution baselines with Someguy sidecar (Phase 19)
- `.planning/baselines/19.2-pre-optimization-baselines.md` -- Upload baselines before concurrent pins + pebbleds
- `.planning/baselines/19.2-post-optimization-baselines.md` -- Comprehensive post-optimization baselines with three-point comparison

### Load Test Infrastructure

- `tests/load/src/harness/thresholds.ts` -- Threshold checking module (ThresholdConfig, checkThresholds)
- `tests/load/src/harness/metrics.ts` -- MetricsCollector with percentile calculation
- `tests/load/src/harness/client-pool.ts` -- Multi-client pool management
- `tests/load/src/scenarios/` -- 8 load test scenarios with threshold assertions
- `.github/workflows/load-test.yml` -- CI workflow for staging load tests

### Architecture

- `docs/ARCHITECTURE.md` -- System architecture overview
- `docs/METADATA_SCHEMAS.md` -- Metadata schema reference

---

_This is a living document. Update when baselines change, infrastructure scales, or new performance data is captured._

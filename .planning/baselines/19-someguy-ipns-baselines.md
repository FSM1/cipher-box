# Performance Baselines - Phase 19 (Someguy IPNS Sidecar)

## Capture Information

| Field            | Value                                                              |
| ---------------- | ------------------------------------------------------------------ |
| **Capture Date** | 2026-03-23                                                         |
| **Environment**  | Staging (api-staging.cipherbox.cc) + Local (192.168.133.114)       |
| **Kubo Version** | v0.40.0                                                            |
| **Someguy**      | v0.11.1 (ghcr.io/ipfs/someguy)                                     |
| **API Image**    | cipher-box-v0.26.5                                                 |
| **VPS**          | Hostinger KVM2, 4 vCPU, 8GB RAM                                    |
| **Test Suite**   | SDK E2E (83 tests) + Load tests (vitest, custom metrics collector) |
| **DHT Warm-up**  | ~8 hours on staging, ~10 minutes on local                          |

## Someguy Configuration

| Setting                     | Previous (broken, PR #284) | Fixed (PR #325)              |
| --------------------------- | -------------------------- | ---------------------------- |
| libp2p port 4004            | Not exposed                | Exposed (TCP + UDP)          |
| DHT mode                    | `standard`                 | `accelerated`                |
| Connection limits           | 50/300                     | 100/3000 (defaults)          |
| `SOMEGUY_LIBP2P_MAX_MEMORY` | 512MB                      | 1073741824 (1GB)             |
| Container memory            | 768MB                      | 2GB                          |
| Container CPU               | 0.5                        | 1.0                          |
| Healthcheck start period    | 30s                        | 60s                          |
| Fallback URL                | None                       | `https://delegated-ipfs.dev` |

Root cause of Phase 19's initial failure: no libp2p port exposed meant DHT couldn't receive inbound connections, `standard` mode skipped accelerated FullRT client, and tight resource limits triggered libp2p Resource Manager errors.

## SDK E2E Results (83 tests)

| Environment       | Passed | Failed | Skipped |
| ----------------- | ------ | ------ | ------- |
| Local (someguy)   | 83     | 0      | 0       |
| Staging (someguy) | 83     | 0      | 0       |

All 83 tests pass with zero errors on both environments.

## Load Test: IPNS Publish Storm (5 clients × 50 cycles = 750 ops)

### Cross-environment comparison

| Metric           | Staging (someguy, warm DHT) | Local (delegated-ipfs.dev) | Local (someguy, cold DHT) |
| ---------------- | --------------------------- | -------------------------- | ------------------------- |
| Duration         | **49.1s**                   | 69.7s                      | 89.3s                     |
| Throughput       | **15.28 ops/s**             | 10.75 ops/s                | 8.39 ops/s                |
| Errors           | **0**                       | **0**                      | **0**                     |
| createFolder p50 | **468ms**                   | 606ms                      | 728ms                     |
| createFolder p95 | **848ms**                   | 1.22s                      | 1.07s                     |
| createFolder p99 | **1.0s**                    | 1.62s                      | 1.27s                     |
| deleteItem p50   | **246ms**                   | 395ms                      | 469ms                     |
| deleteItem p95   | **476ms**                   | 690ms                      | 795ms                     |
| renameItem p50   | **182ms**                   | 305ms                      | 520ms                     |
| renameItem p95   | **377ms**                   | 704ms                      | 1.06s                     |

### Comparison vs Phase 18 baselines

| Metric              | Phase 18 (Kubo direct, 5 clients) | Phase 19 staging (someguy, 5 clients) | Change         |
| ------------------- | --------------------------------- | ------------------------------------- | -------------- |
| Throughput          | 1.25 ops/sec                      | **15.28 ops/sec**                     | **+12.2x**     |
| Error rate          | 4.6% (18/395)                     | **0%** (0/750)                        | **Eliminated** |
| Total ops attempted | 395                               | 750                                   | +90% more ops  |
| Total ops succeeded | 377                               | 750                                   | +99%           |

Note: Phase 18 measured via Playwright browser automation (higher overhead per op), Phase 19 via SDK direct calls. The measurement difference accounts for some of the throughput gap, but the zero error rate is the significant improvement — Phase 18 had 18 timeouts under identical concurrency.

## Load Test: Mixed Workload (5 clients × 45 mixed ops)

| Metric           | Staging (someguy) | Local (delegated-ipfs.dev) | Local (someguy, cold DHT) |
| ---------------- | ----------------- | -------------------------- | ------------------------- |
| Duration         | **23.6s**         | 40.4s                      | 58.9s                     |
| Throughput       | **9.32 ops/s**    | 5.50 ops/s                 | 3.68 ops/s                |
| Errors           | **0**             | **0**                      | **0**                     |
| createFolder p50 | **511ms**         | 840ms                      | 1.4s                      |
| deleteItem p50   | **215ms**         | 338ms                      | 539ms                     |
| moveItem p50     | **442ms**         | 659ms                      | 1.2s                      |
| renameItem p50   | **195ms**         | 390ms                      | 623ms                     |
| uploadFile p50   | **613ms**         | 1.1s                       | 1.5s                      |
| Data transferred | 2.5MB             | 2.9MB                      | 2.6MB                     |

## Key Observations

1. **DHT warm-up matters significantly**: Staging someguy (8h uptime) is ~2x faster than local someguy (10min uptime). The accelerated DHT routing table fills over time, improving lookup speed.

2. **Someguy with warm DHT beats delegated-ipfs.dev**: 42% higher throughput and ~40-50% lower median latency across all operations. The public fleet advantage disappears once the local sidecar's DHT is populated.

3. **Zero errors across all test runs**: Both SDK E2E (83 tests) and load tests (750+ ops) complete with zero failures, compared to Phase 18's 4.6% error rate.

4. **DB-first resolve architecture unchanged**: IPNS resolution still goes through the database as primary source of truth. Someguy's value is in reliable DHT publishing for TEE republishing and the standalone recovery tool, not in replacing DB resolves.

5. **Fallback to delegated-ipfs.dev**: Configured via `DELEGATED_ROUTING_FALLBACK_URL`. Prometheus counter `cipherbox_delegated_routing_fallbacks_total` tracks when primary (someguy) fails and fallback is used.

## Prometheus Metrics Available

New metrics added in this phase for ongoing monitoring:

| Metric                                        | Labels                      | Purpose                                       |
| --------------------------------------------- | --------------------------- | --------------------------------------------- |
| `cipherbox_delegated_routing_requests_total`  | operation, backend, outcome | Every routing request tagged primary/fallback |
| `cipherbox_delegated_routing_fallbacks_total` | operation                   | Count of primary→fallback triggers            |
| `cipherbox_ipns_publish_duration_seconds`     | outcome                     | Delegated routing publish latency             |
| `cipherbox_ipns_resolve_duration_seconds`     | source, outcome             | End-to-end resolve latency                    |

## Extended Load Test: Mixed Workload Scaling (10–100 clients)

Captured 2026-03-23 via GitHub Actions against staging. Mixed Workload scenario: weighted mix of createFolder, uploadFile, moveItem, deleteItem, renameItem.

### Throughput scaling

| Clients | Total Ops | Errors | Throughput  | Duration | Data   |
| ------- | --------- | ------ | ----------- | -------- | ------ |
| 5       | 220       | 0      | 9.32 ops/s  | 23.6s    | 2.5MB  |
| 10      | 434       | 0      | 4.49 ops/s  | 96.6s    | 5.2MB  |
| 20      | 856       | 0      | 8.42 ops/s  | 101.7s   | 9.6MB  |
| 30      | 1,299     | 0      | 12.14 ops/s | 107.0s   | 14.4MB |
| 100     | 4,355     | 0      | 24.05 ops/s | 181.1s   | 49.4MB |

Note: The 5-client baseline was run separately (different network path). The 10–100 client runs are directly comparable.

### Latency by operation (p50 / p95 / p99)

| Operation    | 10 clients          | 20 clients          | 30 clients          | 100 clients         |
| ------------ | ------------------- | ------------------- | ------------------- | ------------------- |
| createFolder | 1.9s / 3.1s / 4.4s  | 2.0s / 3.3s / 3.6s  | 2.4s / 3.5s / 4.2s  | 3.7s / 6.5s / 8.0s  |
| uploadFile   | 2.6s / 3.9s / 4.7s  | 2.8s / 4.4s / 4.8s  | 3.0s / 4.5s / 5.2s  | 5.1s / 7.8s / 11.6s |
| moveItem     | 1.9s / 2.6s / 3.4s  | 1.9s / 2.9s / 3.4s  | 2.3s / 3.1s / 3.7s  | 3.5s / 5.6s / 6.7s  |
| deleteItem   | 815ms / 1.8s / 2.4s | 881ms / 1.8s / 2.0s | 929ms / 1.8s / 2.1s | 1.9s / 3.2s / 4.3s  |
| renameItem   | 712ms / 1.5s / 1.6s | 758ms / 1.8s / 2.3s | 1.1s / 1.8s / 2.1s  | 1.9s / 3.2s / 3.6s  |

### Scaling observations

1. **Sub-linear throughput at 100 clients**: 10x clients (10→100) yields 5.4x throughput (4.49→24.05 ops/s). The staging VPS handles 100 concurrent clients but is showing diminishing returns.
2. **uploadFile p50 doubles at 100 clients**: 2.6s→5.1s. p99 jumps to 11.6s. This is the operation most sensitive to concurrency.
3. **Zero errors across all concurrency levels**: No timeouts, no 5xx, no IPNS publish failures up to 100 concurrent clients.
4. **Metadata-only operations degrade gracefully**: deleteItem/renameItem p50 grows from ~750ms (10 clients) to ~1.9s (100 clients) — still usable.

## Upload Flow Latency Breakdown (Prometheus Server-Side)

Captured from staging `/metrics` endpoint after the 100-client run. These are cumulative histograms across all load test runs.

### Where uploadFile time goes

A single SDK `uploadFile` call makes 5 sequential API calls:

| Step | API Call                        | Server Mean | Role                             |
| ---- | ------------------------------- | ----------- | -------------------------------- |
| 1    | POST /ipfs/upload (ciphertext)  | **1.73s**   | Pin encrypted file to Kubo       |
| 2    | POST /ipfs/upload (metadata)    | **1.73s**   | Pin encrypted file metadata      |
| 3    | POST /ipns/publish-batch        | 0.11s       | DB upsert for file IPNS record   |
| 4    | POST /ipfs/upload (folder meta) | **1.73s**   | Pin updated folder metadata      |
| 5    | POST /ipns/publish              | 0.14s       | DB upsert for folder IPNS record |

**Total server-side: ~5.4s** — aligns with the 5.1s p50 client-side at 100 clients.

### Internal operation timing

| Metric                          | Count   | Mean  | Notes                                              |
| ------------------------------- | ------- | ----- | -------------------------------------------------- |
| IPFS Pin (Kubo `pin add`)       | 140,816 | 1.64s | ~95% of upload endpoint time                       |
| HTTP POST /ipfs/upload          | 140,816 | 1.73s | Pin + quota check + DB write                       |
| IPNS Publish (DB upsert)        | 103,998 | 141ms | Fast — just a database write                       |
| IPNS Publish Batch (DB upsert)  | 18,380  | 107ms | Similar to single publish                          |
| Async DHT propagation (success) | 122,054 | 906ms | Fire-and-forget, does not block client             |
| Async DHT propagation (error)   | 324     | 17.2s | 0.26% error rate, does not affect client responses |

### Bottleneck analysis

**Kubo IPFS pinning is the dominant bottleneck**, consuming ~95% of the upload endpoint latency. Each `uploadFile` requires 3 sequential pin operations (ciphertext, file metadata, folder metadata), totaling ~5s server-side at mean.

IPNS publishing is negligible in the request path (DB upsert only, ~100-140ms). DHT propagation happens asynchronously and does not block the client.

**Levers for improving upload performance:**

- **Concurrent pins**: The 3 pin calls per upload are currently sequential. Pins 1+2 (ciphertext + file metadata) could be parallelized since they're independent.
- **Kubo tuning**: Pin performance degrades under concurrent load — likely contention on Kubo's datastore. Investigate Kubo's `--pin-workers` setting or a faster datastore backend.
- **Pin batching**: Multiple small metadata pins could potentially be coalesced.

## Comparison Targets

Phase 22 (Performance Baselines Completion) should:

- Re-capture server-side Prometheus histograms for direct comparison with Phase 18 internal timings
- Add client-side instrumentation for real user latency measurement
- Fill in 50/75 client data points (runs queued 2026-03-23)
- Document capacity limits and scaling recommendations
- Performance regression threshold: >20% p95 increase requires investigation

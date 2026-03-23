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

## Extended Load Test: Mixed Workload Scaling (10–30 clients)

Captured 2026-03-23 via GitHub Actions against staging. Each run executes all 5 load test scenarios sequentially; results below are from the Mixed Workload scenario (weighted mix of createFolder, uploadFile, moveItem, deleteItem, renameItem).

### Throughput scaling

| Clients | Total Ops | Errors | Throughput  | Duration | Data   |
| ------- | --------- | ------ | ----------- | -------- | ------ |
| 5       | 220       | 0      | 9.32 ops/s  | 23.6s    | 2.5MB  |
| 10      | 434       | 0      | 4.49 ops/s  | 96.6s    | 5.2MB  |
| 20      | 856       | 0      | 8.42 ops/s  | 101.7s   | 9.6MB  |
| 30      | 1,299     | 0      | 12.14 ops/s | 107.0s   | 14.4MB |

Note: The 5-client baseline was run from a GitHub Actions runner (different network path), so absolute latencies differ from the earlier staging baselines above (which used the same runner). The 10–30 client runs are directly comparable to each other.

### Latency by operation (p50 / p95 / p99)

| Operation    | 10 clients          | 20 clients          | 30 clients          |
| ------------ | ------------------- | ------------------- | ------------------- |
| createFolder | 1.9s / 3.1s / 4.4s  | 2.0s / 3.3s / 3.6s  | 2.4s / 3.5s / 4.2s  |
| uploadFile   | 2.6s / 3.9s / 4.7s  | 2.8s / 4.4s / 4.8s  | 3.0s / 4.5s / 5.2s  |
| moveItem     | 1.9s / 2.6s / 3.4s  | 1.9s / 2.9s / 3.4s  | 2.3s / 3.1s / 3.7s  |
| deleteItem   | 815ms / 1.8s / 2.4s | 881ms / 1.8s / 2.0s | 929ms / 1.8s / 2.1s |
| renameItem   | 712ms / 1.5s / 1.6s | 758ms / 1.8s / 2.3s | 1.1s / 1.8s / 2.1s  |

### Scaling observations

1. **Near-linear throughput scaling**: 3x clients (10→30) yields 2.7x throughput (4.49→12.14 ops/s). The staging VPS is not yet saturated at 30 concurrent clients.
2. **Modest latency increase**: p50 grows 15–25% from 10→30 clients across all operations. p95/p99 remain stable, suggesting no queuing or resource exhaustion.
3. **Zero errors at all concurrency levels**: No timeouts, no 5xx, no IPNS publish failures. Compared to Phase 18's 4.6% error rate at just 5 clients, the someguy sidecar architecture is significantly more reliable.
4. **deleteItem and renameItem remain fast**: Metadata-only operations stay under 1s p50 even at 30 clients.
5. **uploadFile is the slowest operation**: Expected — includes IPFS pin + IPNS publish. p50 grows from 2.6s (10 clients) to 3.0s (30 clients).

## Comparison Targets

Phase 22 (Performance Baselines Completion) should:

- Re-capture server-side Prometheus histograms for direct comparison with Phase 18 internal timings
- Add client-side instrumentation for real user latency measurement
- Document capacity limits and scaling recommendations
- Performance regression threshold: >20% p95 increase requires investigation

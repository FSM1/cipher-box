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

## Comparison Targets

Phase 22 (Performance Baselines Completion) should:

- Re-capture server-side Prometheus histograms for direct comparison with Phase 18 internal timings
- Add client-side instrumentation for real user latency measurement
- Run k6 load tests at higher concurrency (10, 20, 50 clients)
- Document capacity limits and scaling recommendations
- Performance regression threshold: >20% p95 increase requires investigation

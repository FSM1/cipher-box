# Performance Baselines - Phase 18

## Capture Information

| Field            | Value                                                           |
| ---------------- | --------------------------------------------------------------- |
| **Capture Date** | 2026-03-07T16:55:31Z (updated 2026-03-08)                       |
| **Environment**  | Staging (api-staging.cipherbox.cc)                              |
| **Kubo Version** | v0.34.0                                                         |
| **API Image**    | v0.24.2-staging-rc-1                                            |
| **VPS**          | Hostinger 76.13.151.200, 4 vCPU, 8GB RAM                        |
| **Script**       | `scripts/baseline-benchmark.sh` + `tests/e2e/load-test.spec.ts` |
| **Iterations**   | 20 measured + 3 warmup per operation (benchmark script)         |
| **File Size**    | 10KB random data (upload/download) for benchmark script         |

## Methodology

Baselines are captured using `scripts/baseline-benchmark.sh` which:

1. Discovers the user's root IPNS name via `GET /vault`
2. Runs 3 warmup iterations (discarded) followed by 20 measured iterations
3. Measures client-side round-trip time via `curl -w "%{time_total}"`
4. Computes p50/p95/p99 from sorted timing values
5. IPNS Publish is excluded (requires signed record) -- captured from Prometheus

Server-side histograms (`cipherbox_ipfs_ipns_duration_seconds`) provide internal timing without network overhead. Client-side timings from this script include network latency and are useful for end-to-end comparison.

## Client-Side Timings (curl round-trip)

| Operation           | p50    | p95    | p99    | Notes                                   |
| ------------------- | ------ | ------ | ------ | --------------------------------------- |
| IPNS Resolve        | 0.147s | 0.224s | 0.278s | `GET /ipns/resolve?ipnsName=<name>`     |
| IPNS Publish        | --     | --     | --     | See Prometheus (requires signed record) |
| IPFS Pin (upload)   | 0.138s | 0.218s | 0.227s | `POST /ipfs/upload` with 10KB file      |
| IPFS Cat (download) | 0.133s | 0.215s | 0.219s | `GET /ipfs/<cid>` for 10KB file         |

## Server-Side Histograms (Prometheus)

Captured from the API's `/metrics` endpoint via SSH on 2026-03-08. Includes cumulative data from the baseline-benchmark script run (single-client, ~38 ops) plus the 5-client load test (~377 ops across 5 concurrent users).

### `cipherbox_ipfs_ipns_duration_seconds` — per-operation breakdown

Percentiles computed from Prometheus histogram buckets (linear interpolation within bucket boundaries).

| Operation        | Source  | Count | p50    | p95    | p99    | Mean   | Notes                                         |
| ---------------- | ------- | ----- | ------ | ------ | ------ | ------ | --------------------------------------------- |
| **publish**      | --      | 1367  | 180 ms | 519 ms | 904 ms | 196 ms | Kubo IPNS publish — dominant bottleneck       |
| **resolve**      | network | 529   | 135 ms | 284 ms | 488 ms | 126 ms | Kubo DHT lookup (cache miss)                  |
| **resolve**      | db      | 84    | 35 ms  | 93 ms  | 187 ms | 36 ms  | DB cache hit (success path)                   |
| **resolve** (fb) | db      | 239   | 23 ms  | 84 ms  | 230 ms | 32 ms  | DB cache fallback (Kubo resolve failed)       |
| **resolve**      | network | 42    | 231 ms | 650 ms | 930 ms | 251 ms | Network errors (Kubo resolve timeout/failure) |
| **pin**          | --      | 1923  | 8 ms   | 18 ms  | 31 ms  | 8 ms   | Kubo `pin add` — very fast for small files    |
| **cat**          | --      | 704   | 2 ms   | 5 ms   | 9 ms   | 2 ms   | Kubo `cat` — sub-5ms for cached content       |

Note: Resolve has 4 series because the API tries Kubo first (source=network), then falls back to DB cache (source=db). The `result` label distinguishes success/error at the Kubo level.

### Other histograms

| Metric                                       | Status  | Notes                                      |
| -------------------------------------------- | ------- | ------------------------------------------ |
| `cipherbox_republish_batch_duration_seconds` | No data | Mock TEE provider doesn't report durations |
| `cipherbox_http_request_duration_seconds`    | Below   | Per-route breakdown in HTTP table          |

## HTTP API Performance (from Prometheus)

Response times by route — computed from `cipherbox_http_request_duration_seconds` histogram (routes with ≥10 requests):

| Route                            | Count | p50    | p95    | p99    | Mean   | Notes                              |
| -------------------------------- | ----- | ------ | ------ | ------ | ------ | ---------------------------------- |
| `POST /ipfs/upload` [201]        | 1923  | 8 ms   | 45 ms  | 50 ms  | 13 ms  | Small–medium files (up to 500KB)   |
| `GET /ipfs/:cid` [200]           | 704   | 5 ms   | 10 ms  | 10 ms  | 2 ms   | Extremely fast server-side         |
| `GET /ipns/resolve` [200]        | 852   | 50 ms  | 245 ms | 467 ms | 91 ms  | Includes DB cache fallback path    |
| `GET /ipns/resolve` [404]        | 42    | 231 ms | 650 ms | 930 ms | 251 ms | IPNS name not found (new accounts) |
| `POST /ipns/publish` [201]       | 621   | 165 ms | 477 ms | 871 ms | 172 ms | Kubo IPNS publish — dominant cost  |
| `POST /ipns/publish-batch` [201] | 373   | 275 ms | 793 ms | 959 ms | 303 ms | TEE republish batch path           |
| `GET /vault` [200]               | 12    | 5 ms   | 9 ms   | 10 ms  | 3 ms   |                                    |
| `GET /vault/quota` [200]         | 838   | 5 ms   | 9 ms   | 10 ms  | 1 ms   |                                    |
| `GET /health` [200]              | 539   | 5 ms   | 10 ms  | 32 ms  | 4 ms   |                                    |
| `POST /auth/login` [200]         | 14    | 155 ms | 240 ms | 248 ms | 140 ms | JWT generation + Web3Auth verify   |
| `POST /auth/test-login` [200]    | 11    | 89 ms  | 229 ms | 246 ms | 104 ms |                                    |
| `POST /vault/init` [201]         | 12    | 5 ms   | 9 ms   | 10 ms  | 7 ms   |                                    |

## Kubo Health Observations

| Metric             | Value    | Notes                                                             |
| ------------------ | -------- | ----------------------------------------------------------------- |
| Peer Connections   | N/A      | Kubo v0.34.0 does not expose libp2p metrics to Prometheus         |
| Inbound Bandwidth  | N/A      | Grafana panel shows "No data"                                     |
| Outbound Bandwidth | N/A      | Grafana panel shows "No data"                                     |
| Memory Usage       | N/A      | Grafana panel shows "No data"                                     |
| Goroutines         | N/A      | Not exposed by Kubo                                               |
| Datastore Size     | ~320 MiB | From dashboard "Total Storage Used" stat (includes all user data) |

## Load Test Details

### Run 1: Manual stress test (single client)

To populate initial IPNS publish histogram data, a manual stress test was performed via Playwright against the staging web app:

| Operation     | Count      | Details                                                   |
| ------------- | ---------- | --------------------------------------------------------- |
| Folder create | 8          | stress-01 through -05, nested-subfolder, rapid-fire-01–03 |
| File upload   | 13         | 10 small (7–48 KB) + 3 large (1 MB, 5 MB, 10 MB)          |
| Rename        | 4          | 2 files, 1 folder, 1 large file                           |
| Move          | 3          | Files into stress-02, stress-03, renamed-folder-01        |
| Delete        | 10         | 5 files + 5 folders (some with contents)                  |
| **Total**     | **~38–43** | Each mutates metadata → IPNS publish                      |

Concurrently, `baseline-benchmark.sh` ran 20 iterations of resolve/pin/cat (+ warmups).

### Run 2: Automated load test (5 concurrent clients)

`tests/e2e/load-test.spec.ts` — 5 clients with unique wallets, launched simultaneously (no staggering), each running ~70 file operations.

| Metric              | Value                                       |
| ------------------- | ------------------------------------------- |
| **Clients**         | 5 (all started at the same time)            |
| **Total ops**       | 395 attempted, 377 succeeded (95.4%)        |
| **Failed ops**      | 18 (all timeouts — 30s per-op limit)        |
| **Total time**      | 317s (5.3 minutes)                          |
| **Throughput**      | 1.25 ops/sec (aggregate across all clients) |
| **IPNS publishes**  | ~377 (one per successful mutation)          |
| **Account cleanup** | 5/5 accounts deleted                        |

Per-client breakdown:

| Client | Succeeded | Failed | Notes                                         |
| ------ | --------- | ------ | --------------------------------------------- |
| C1     | 79        | 0      | Finished first — got head start before others |
| C2     | 72        | 7      | Warm-up timeout + move dialog timeouts        |
| C3     | 78        | 1      | Single upload timeout in images folder        |
| C4     | 73        | 6      | Warm-up timeout + folder creation timeout     |
| C5     | 75        | 4      | Warm-up timeout + batch delete timeout        |

Failure pattern: C2–C5 all timed out on their warm-up folder operation (30s) while C1 raced ahead. Subsequent failures clustered around move dialog waits and folder navigation — consistent with server-side IPNS publish latency increasing under concurrent load. The 5-client workload drove ~1,300 IPNS publishes through Kubo simultaneously.

## Notes

- Client-side timings captured 2026-03-07 via `baseline-benchmark.sh` (5 runs × 20 iterations per operation = 100 data points per operation, 300 total across resolve/pin/cat)
- Server-side histogram values captured 2026-03-08 via SSH to staging VPS (`curl http://localhost:3000/metrics`) — cumulative across benchmark script + 5-client load test
- 5-client load test run 2026-03-08 via `tests/e2e/load-test.spec.ts` — 5 concurrent Playwright browsers, ~70 ops each, all launched simultaneously
- IPNS Publish is the dominant bottleneck at ~519ms p95 server-side (904ms p99) — essentially all time in Kubo, negligible HTTP overhead
- Under 5-client concurrency, publish-batch p95 reaches 793ms (vs 477ms for single publish) — batching multiple IPNS names increases latency
- IPNS Resolve network errors (n=42) have high latency (p50=231ms, p95=650ms) — these are Kubo timeouts that trigger DB cache fallback
- DB cache fallback is fast (p50=23ms) and handles 74% of resolve calls (239/323 db-path resolves were error-fallback)
- Pin and Cat remain extremely fast under load (p50=8ms and 2ms) — client-side timings (~130ms) are dominated by network latency
- Kubo v0.34.0 does not expose libp2p metrics — Kubo Health section is N/A
- TEE Republish Batch Duration shows "No data" — mock TEE provider doesn't report real durations
- These baselines will be compared against post-Phase 19 and Phase 22 measurements
- The benchmark script is deterministic: same iterations, same file size, same warmup count
- The load test script (`tests/e2e/load-test.spec.ts`) is parameterized: `LOAD_TEST_CLIENTS` env var (default: 5)

## Comparison Target

Phase 22 (after IPFS infrastructure changes) will re-run this benchmark and document:

- Performance regression threshold: >20% p95 increase requires investigation
- Performance improvement targets vary by operation (see Phase 22 plan)

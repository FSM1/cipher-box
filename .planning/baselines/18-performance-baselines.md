# Performance Baselines - Phase 18

## Capture Information

| Field            | Value                                            |
| ---------------- | ------------------------------------------------ |
| **Capture Date** | 2026-03-07T16:55:31Z (updated 2026-03-07T17:30Z) |
| **Environment**  | Staging (api-staging.cipherbox.cc)               |
| **Kubo Version** | v0.34.0                                          |
| **API Image**    | v0.24.2-staging-rc-1                             |
| **VPS**          | Hostinger 76.13.151.200, 4 vCPU, 8GB RAM         |
| **Script**       | `scripts/baseline-benchmark.sh`                  |
| **Iterations**   | 20 measured + 3 warmup per operation             |
| **File Size**    | 10KB random data (upload/download)               |

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

Captured from Grafana Cloud dashboard snapshot after stress test (~43 UI operations + 60 benchmark iterations).
Snapshot: `CipherBox Staging - 2026-03-07 18:30`

| Metric                                       | Operation  | p50 | p95       | p99 | Notes                                      |
| -------------------------------------------- | ---------- | --- | --------- | --- | ------------------------------------------ |
| `cipherbox_ipfs_ipns_duration_seconds`       | resolve    | --  | --        | --  | See HTTP table below (internal metric TBD) |
| `cipherbox_ipfs_ipns_duration_seconds`       | publish    | --  | --        | --  | See HTTP table below (internal metric TBD) |
| `cipherbox_ipfs_ipns_duration_seconds`       | pin        | --  | --        | --  | See HTTP table below (internal metric TBD) |
| `cipherbox_ipfs_ipns_duration_seconds`       | cat        | --  | --        | --  | See HTTP table below (internal metric TBD) |
| `cipherbox_republish_batch_duration_seconds` | batch      | --  | --        | --  | No data (mock TEE provider doesn't report) |
| `cipherbox_http_request_duration_seconds`    | all routes | --  | see below | --  | Per-route breakdown in HTTP table          |

Note: The internal `cipherbox_ipfs_ipns_duration_seconds` histogram values could not be extracted from the Grafana snapshot (new dashboard format does not embed query results for anonymous viewers). The per-route HTTP duration histogram below provides equivalent server-side timing data.

## HTTP API Performance (from Grafana dashboard)

Response Time by Route (p95) — mean and max over 6h window (12:30–18:30 UTC):

| Route                      | p95 Mean | p95 Max | Notes                                 |
| -------------------------- | -------- | ------- | ------------------------------------- |
| `POST /ipfs/upload`        | 328 ms   | 1.67 s  | Includes 1MB/5MB/10MB uploads         |
| `GET /ipfs/:cid`           | 9.50 ms  | 9.50 ms | Extremely fast server-side            |
| `GET /ipns/resolve`        | 286 ms   | 887 ms  | Includes DB cache fallback path       |
| `POST /ipns/publish`       | 860 ms   | 919 ms  | Slowest operation — Kubo IPNS publish |
| `POST /ipns/publish-batch` | 813 ms   | 950 ms  | TEE republish batch path              |
| `GET /vault`               | 9.50 ms  | 9.50 ms |                                       |
| `GET /vault/quota`         | 9.50 ms  | 9.50 ms |                                       |
| `GET /health`              | 11.1 ms  | 48 ms   |                                       |
| `POST /auth/test-login`    | 177 ms   | 243 ms  |                                       |

Overall Response Time (all routes combined, from time-series chart):

- p50: ~10 ms (most routes are fast DB lookups)
- p95: ~300 ms (dominated by IPNS resolve)
- p99: ~900 ms (dominated by IPNS publish, spikes to ~3s under load)

## Kubo Health Observations

| Metric             | Value    | Notes                                                             |
| ------------------ | -------- | ----------------------------------------------------------------- |
| Peer Connections   | N/A      | Kubo v0.34.0 does not expose libp2p metrics to Prometheus         |
| Inbound Bandwidth  | N/A      | Grafana panel shows "No data"                                     |
| Outbound Bandwidth | N/A      | Grafana panel shows "No data"                                     |
| Memory Usage       | N/A      | Grafana panel shows "No data"                                     |
| Goroutines         | N/A      | Not exposed by Kubo                                               |
| Datastore Size     | ~320 MiB | From dashboard "Total Storage Used" stat (includes all user data) |

## Stress Test Details

To populate IPNS publish histogram data, a manual stress test was performed via Playwright against the staging web app:

| Operation     | Count      | Details                                                   |
| ------------- | ---------- | --------------------------------------------------------- |
| Folder create | 8          | stress-01 through -05, nested-subfolder, rapid-fire-01–03 |
| File upload   | 13         | 10 small (7–48 KB) + 3 large (1 MB, 5 MB, 10 MB)          |
| Rename        | 4          | 2 files, 1 folder, 1 large file                           |
| Move          | 3          | Files into stress-02, stress-03, renamed-folder-01        |
| Delete        | 10         | 5 files + 5 folders (some with contents)                  |
| **Total**     | **~38–43** | Each mutates metadata → IPNS publish                      |

Concurrently, `baseline-benchmark.sh` ran 20 iterations of resolve/pin/cat (+ warmups).

## Notes

- Client-side timings captured 2026-03-07 via `baseline-benchmark.sh` (5 total runs, 100 data points)
- Server-side HTTP timings captured from Grafana Cloud dashboard snapshot at 18:30 UTC
- IPNS Publish is the dominant bottleneck at ~860ms p95 — this is Kubo's native IPNS publish latency
- Kubo v0.34.0 does not expose libp2p metrics — Kubo Health section is N/A
- TEE Republish Batch Duration shows "No data" — mock TEE provider doesn't report real durations
- These baselines will be compared against post-Phase 19 and Phase 22 measurements
- The benchmark script is deterministic: same iterations, same file size, same warmup count

## Comparison Target

Phase 22 (after IPFS infrastructure changes) will re-run this benchmark and document:

- Performance regression threshold: >20% p95 increase requires investigation
- Performance improvement targets vary by operation (see Phase 22 plan)

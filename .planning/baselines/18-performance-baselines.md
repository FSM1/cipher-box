# Performance Baselines - Phase 18

## Capture Information

| Field            | Value                                                    |
| ---------------- | -------------------------------------------------------- |
| **Capture Date** | TBD -- run baseline-benchmark.sh on staging after deploy |
| **Environment**  | Staging (api-staging.cipherbox.cc)                       |
| **Kubo Version** | v0.34.0                                                  |
| **API Image**    | TBD (tag from deploy)                                    |
| **VPS**          | Hostinger 76.13.151.200, 4 vCPU, 8GB RAM                 |
| **Script**       | `scripts/baseline-benchmark.sh`                          |
| **Iterations**   | 20 measured + 3 warmup per operation                     |
| **File Size**    | 10KB random data (upload/download)                       |

## Methodology

Baselines are captured using `scripts/baseline-benchmark.sh` which:

1. Discovers the user's root IPNS name via `GET /vault`
2. Runs 3 warmup iterations (discarded) followed by 20 measured iterations
3. Measures client-side round-trip time via `curl -w "%{time_total}"`
4. Computes p50/p95/p99 from sorted timing values
5. IPNS Publish is excluded (requires signed record) -- captured from Prometheus

Server-side histograms (`cipherbox_ipfs_ipns_duration_seconds`) provide internal timing without network overhead. Client-side timings from this script include network latency and are useful for end-to-end comparison.

## Client-Side Timings (curl round-trip)

| Operation           | p50 | p95 | p99 | Notes                                   |
| ------------------- | --- | --- | --- | --------------------------------------- |
| IPNS Resolve        | TBD | TBD | TBD | `GET /ipns/resolve?ipnsName=<name>`     |
| IPNS Publish        | --  | --  | --  | See Prometheus (requires signed record) |
| IPFS Pin (upload)   | TBD | TBD | TBD | `POST /ipfs/upload` with 10KB file      |
| IPFS Cat (download) | TBD | TBD | TBD | `GET /ipfs/<cid>` for 10KB file         |

## Server-Side Histograms (Prometheus)

Captured from Grafana Cloud after sufficient organic staging usage.

| Metric                                       | Operation  | p50 | p95 | p99 | Notes                 |
| -------------------------------------------- | ---------- | --- | --- | --- | --------------------- |
| `cipherbox_ipfs_ipns_duration_seconds`       | resolve    | TBD | TBD | TBD | Source: db vs network |
| `cipherbox_ipfs_ipns_duration_seconds`       | publish    | TBD | TBD | TBD |                       |
| `cipherbox_ipfs_ipns_duration_seconds`       | pin        | TBD | TBD | TBD |                       |
| `cipherbox_ipfs_ipns_duration_seconds`       | cat        | TBD | TBD | TBD |                       |
| `cipherbox_republish_batch_duration_seconds` | batch      | TBD | TBD | TBD | TEE provider: mock    |
| `cipherbox_http_request_duration_seconds`    | all routes | TBD | TBD | TBD | Existing dashboard    |

## HTTP API Performance (from existing dashboard)

| Route                | p50 | p95 | p99 | Notes               |
| -------------------- | --- | --- | --- | ------------------- |
| `POST /ipfs/upload`  | TBD | TBD | TBD |                     |
| `GET /ipfs/:cid`     | TBD | TBD | TBD |                     |
| `GET /ipns/resolve`  | TBD | TBD | TBD |                     |
| `POST /ipns/publish` | TBD | TBD | TBD |                     |
| Overall              | TBD | TBD | TBD | All routes combined |

## Kubo Health Observations

| Metric             | Value | Notes                                                                                        |
| ------------------ | ----- | -------------------------------------------------------------------------------------------- |
| Peer Connections   | TBD   | `libp2p_swarm_connections_opened_total - closed_total` or manual `ipfs swarm peers \| wc -l` |
| Inbound Bandwidth  | TBD   | `rate(libp2p_network_in_bytes_total)` -- may need manual check if metric unavailable         |
| Outbound Bandwidth | TBD   | `rate(libp2p_network_out_bytes_total)`                                                       |
| Memory Usage       | TBD   | `go_memstats_alloc_bytes`                                                                    |
| Goroutines         | TBD   | `go_goroutines`                                                                              |
| Datastore Size     | TBD   | Check via `ipfs repo stat` if no Prometheus metric available                                 |

## Notes

- All TBD values will be filled after Phase 18 code is deployed to staging
- IPNS Publish baseline requires organic usage or E2E test runs to populate histogram buckets
- Kubo v0.34.0 may not expose all libp2p metrics -- fallback metrics noted in Kubo Health section
- These baselines will be compared against Phase 22 (post-architectural-change) measurements
- The benchmark script is deterministic: same iterations, same file size, same warmup count

## Comparison Target

Phase 22 (after IPFS infrastructure changes) will re-run this benchmark and document:

- Performance regression threshold: >20% p95 increase requires investigation
- Performance improvement targets vary by operation (see Phase 22 plan)

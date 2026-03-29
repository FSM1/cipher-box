# BYO-IPFS Load Test Baselines Plan

## Status: DEFERRED -- Awaiting External IPFS Provider Infrastructure

Phase 21 BYO benchmarks were previously deferred (see STATE.md). This constraint
still applies: no external IPFS provider (Pinata, Filebase, etc.) is configured
for automated staging load tests.

## Prerequisites

1. **External IPFS Provider Account** -- Pinata (recommended, PinataProvider already implemented)
   or any PSA-compatible provider with staging-appropriate rate limits
2. **Provider API Key** -- Stored as staging environment secret
3. **BYO Config Seeding** -- Test accounts must have BYO-IPFS config stored as
   encrypted IPNS entry (see BYO config storage pattern in STATE.md decisions)

## Test Scenarios (Ready to Execute)

Three existing load test scenarios in `tests/load/src/scenarios/`:

| Scenario             | File                            | What It Measures                            |
| -------------------- | ------------------------------- | ------------------------------------------- |
| BYO Upload           | `byo-upload-throughput.test.ts` | Upload latency with IPFS offloaded          |
| BYO Mixed            | `byo-mixed-workload.test.ts`    | Full workflow with BYO pinning              |
| BYO Capacity Ceiling | `byo-capacity-ceiling.test.ts`  | Max concurrent BYO users before degradation |

### Scenario Details

**BYO Upload Throughput** (`byo-upload-throughput.test.ts`):
- 10 BYO clients x 20 files (1KB-500KB) by default
- Measures per-operation latency: byo-pin, register-cid, ipns-publish
- Compares against CipherBox-only upload-throughput baseline from Phase 19.2
- Gracefully skips if `BYO_IPFS_ENDPOINT` is not set

**BYO Mixed Workload** (`byo-mixed-workload.test.ts`):
- 50 CB-only + 200 BYO clients x 10 files by default (configurable via env vars)
- Answers: "How does adding BYO users affect existing CipherBox-only users?"
- Reports metrics per segment (CB-only vs BYO) for direct comparison
- Supports ratio sweeps via `LOAD_TEST_CB_CLIENTS` / `LOAD_TEST_BYO_CLIENTS`

**BYO Capacity Ceiling** (`byo-capacity-ceiling.test.ts`):
- Stepped concurrency: 50, 100, 200, 500, 1000 BYO clients x 5 files
- Reveals where CipherBox API starts to degrade under BYO load
- Separates provider-side latency (byo-pin) from API-side latency (register-cid, ipns-publish)

## Environment Variables

| Variable                 | Required | Default | Description                          |
| ------------------------ | -------- | ------- | ------------------------------------ |
| `BYO_IPFS_ENDPOINT`     | Yes      | --      | External provider endpoint URL       |
| `BYO_IPFS_AUTH_TOKEN`    | Yes      | --      | Auth token for external provider     |
| `BYO_IPFS_PROTOCOL`     | No       | `kubo`  | `kubo` or `psa`                      |
| `BYO_IPFS_PROVIDER_NAME`| No       | --      | Provider label for reports           |
| `LOAD_TEST_CLIENTS`     | No       | `10`    | Number of BYO clients (upload test)  |
| `LOAD_TEST_CB_CLIENTS`  | No       | `50`    | CB-only clients (mixed workload)     |
| `LOAD_TEST_BYO_CLIENTS` | No       | `200`   | BYO clients (mixed workload)         |

## Execution Plan (When Provider Available)

1. Configure Pinata API key in staging environment
2. Seed 5-50 test accounts with BYO-IPFS config pointing to Pinata
3. Run scenarios sequentially:
   ```bash
   cd tests/load
   LOAD_TARGET=staging LOAD_TEST_CLIENTS=5 pnpm test -- src/scenarios/byo-upload-throughput.test.ts
   LOAD_TARGET=staging LOAD_TEST_CB_CLIENTS=10 LOAD_TEST_BYO_CLIENTS=20 pnpm test -- src/scenarios/byo-mixed-workload.test.ts
   LOAD_TARGET=staging LOAD_TEST_CLIENTS=25 pnpm test -- src/scenarios/byo-capacity-ceiling.test.ts
   ```
4. Record metrics: API p50/p95/p99 response times, error rates, Pinata pin latency,
   CipherBox API CPU/memory (via Grafana), throughput (ops/sec)
5. Compare against non-BYO baselines to quantify IPFS offload benefit

## Expected Outcomes

- API response times should decrease (no IPFS pinning overhead on CipherBox server)
- Throughput (ops/sec) should increase proportionally
- Pinata pin latency adds to client-perceived upload time but removes server load
- Capacity ceiling should be higher than non-BYO (API only handles auth + metadata)
- Phase 21 early Pinata baselines showed: pin p50=2.0s (+47% vs local Kubo),
  tail latency p99 13.5% better, 98% CipherBox API load reduction per file

## Metrics to Capture

| Metric                    | Non-BYO Baseline (Phase 19.2/22)     | BYO Expected |
| ------------------------- | ------------------------------------ | ------------ |
| Upload p50 (API)          | 3,242ms (50 clients, staging)        | ~300ms       |
| Upload p95 (API)          | 4,615ms (50 clients, staging)        | ~800ms       |
| Concurrent user ceiling   | 200 (1.5% error rate, staging)       | ~500+        |
| API CPU at 50 users       | ~70%                                 | ~30%         |
| API error rate at ceiling | <2% at 200 clients                   | <2% at 500   |
| Throughput at 50 clients  | 15.10 ops/s (staging)                | ~40+ ops/s   |

_Non-BYO baselines from Phase 19.2/22 capacity tests (see docs/CAPACITY.md)_

## Baseline File Format

When executed, results should be saved to `tests/load/baselines/byo-staging-baselines.json`:

```json
{
  "captured": "YYYY-MM-DD",
  "environment": "staging",
  "provider": "pinata",
  "scenarios": {
    "byo-upload-throughput": {
      "clients": 5,
      "files_per_client": 20,
      "byo_pin_p50_ms": null,
      "register_cid_p50_ms": null,
      "ipns_publish_p50_ms": null,
      "throughput_ops_sec": null,
      "errors": null
    },
    "byo-mixed-workload": {
      "cb_clients": 10,
      "byo_clients": 20,
      "cb_segment_upload_p50_ms": null,
      "byo_segment_register_cid_p50_ms": null,
      "cb_segment_error_rate": null,
      "byo_segment_error_rate": null
    },
    "byo-capacity-ceiling": {
      "steps": [50, 100, 200, 500, 1000],
      "ceiling_client_count": null,
      "ceiling_error_rate": null,
      "ceiling_throughput_ops_sec": null
    }
  }
}
```

## References

- `docs/CAPACITY.md` -- Non-BYO capacity model and baseline data
- `tests/load/src/scenarios/byo-*.test.ts` -- Test scenario implementations
- `tests/load/src/harness/client-pool.ts` -- BYO client pool creation
- `tests/load/src/workloads/byo-file-workload.ts` -- BYO file workload runner
- `.planning/STATE.md` -- BYO benchmark deferral decision (Phase 21)

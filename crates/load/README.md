# cipherbox-load

The dispatch-tier load harness (`blueprint/testing.md`, Dispatch / scheduled).
It drives `cipherbox-engine`'s real API client over the desktop `Http` seam, so
a run measures the shipping client path and the harness cannot drift from the
contract.

Load runs are dispatch-only, never merge-blocking — run them from
`.github/workflows/load-test.yml`. The crate's own unit tests do block merges,
in CI's `Rust` area's `Workspace tests (Linux)` job.

## Scenarios

| Scenario         | Surface                                                      |
| ---------------- | ------------------------------------------------------------ |
| `content-ingest` | `POST /content/upload` — caller-addressed block ingest       |
| `gateway-read`   | the read accelerator; the API process serves no bytes in v2  |
| `name-wave`      | `POST /registry/register` + `/retire` under a bulk name wave |
| `mixed`          | ingest, registry, quota and a mailbox round-trip interleaved |
| `byo-advisory`   | a BYO account's advisory pin rows, which never gate          |
| `rotation-wave`  | a whole engine's read cut sweep and write cut name wave      |

v1's `sustained-load` and `spike-test` are not scenarios here: a sustained run
is a large `--ops-per-client`, and a spike is the default `--ramp-ms 0`, where
every virtual client starts at once.

Two v1 scenario families do not port as written. `ipns-publish-storm` had no
API counterpart to keep — clients PUT `/routing/v1` themselves — so `name-wave`
carries its registry half. The `byo-*` family drove an external pinning
provider through v1's TypeScript `sdk-core`; v2 has no provider layer yet, so
`byo-advisory` exercises the API-side BYO surface only.

## Running it locally

The harness needs a live API. With the docker stack up:

```sh
export LOAD_TEST_SECRET=<the API's TEST_LOGIN_SECRET>
cargo run --release -p cipherbox-load -- \
  --scenario mixed --target local --clients 5 --ops-per-client 20
```

`--help` lists every flag and environment variable. A JSON report lands in
`load-reports/`, and the process exits non-zero when a threshold breaches.

## The rotation-wave scenario

`rotation-wave` runs one whole engine over the desktop production seams, not
test-login accounts, on the `local` target only. The workflow passes no
`--clients`, so its numbers compare with the one-engine table in
`tools/perf/RESULTS.md`. `load-test.yml` also runs it every week at 16 nodes.
Each engine signs in with a fresh identity, builds a folder of `--nodes`
subfolders, and mints a read link at it, so that the folder is a scope root.
Then it runs a read cut (`RotateNow`) and a write cut (`RotateWriteNow`), in
that order, and records spans from the engine's own events, on the engine
clock:

- `sweep-converge`: from the read cut to the end of the sweep run that reports
  no node at the old epoch (`sweepConvergence`). `sweep-last-reseal` runs to
  the end of the last sweep run that re-sealed a node.
- `name-wave`: from `nameWaveStarted` to `nameWaveEnded`. `name-wave-node` is
  the time each node took to land.

Each phase waits one throttle window first, so it starts on a full content
bucket. The scenario also needs the `/routing/v1` endpoints, in
`LOAD_TEST_ROUTING_ENDPOINTS`; `local` defaults to the mock store on `:3001`.
No command deletes the account, so each engine leaves its account behind.

The API's content bucket allows 60 uploads a minute per account, and each node
that the sweep re-seals or the wave moves uploads a block. Past about 55 nodes
the wave stops part way, the cut becomes owed work, and the run exits non-zero.
The proof that the sweep converged then waits for the idle job, one
`sweep_cadence` (15 minutes) after the engine started. `--nodes` stops at 64
for that reason.

## Targets

`local` only ever reaches a loopback URL; `staging` only ever reaches a
non-loopback https URL supplied by the workflow's gated `staging` environment.
There is no production target, and every dimension of a run — accounts,
iterations, block size, batch size, delays — is bounded per target, staging
tightest, because it is one 2-vCPU VPS whose cores Kubo and someguy already
share.

`gateway-read` against staging additionally needs `LOAD_TEST_GATEWAY_TOKEN`:
the read accelerator sits behind `forward_auth`.

## Thresholds

The bands in `thresholds.rs` are collapse detectors, not per-surface SLOs —
they read the whole-run `all` row and are deliberately wide. Regression bands
against a persisted series belong to the performance-baseline work, not here.

## Rate limiting

v2 has no throttle bypass. Per-surface 429s are the API keeping its promise, so
they are counted apart from failures and never breach on their own — though a
run in which nothing succeeded does. Staging runs pace each account just under
the 60-per-minute content bucket; to measure the system rather than the
throttler, keep `--ops-per-client` under the bucket for the surface you are
exercising (`apps/api/src/ops/throttling.ts`).

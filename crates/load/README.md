# cipherbox-load

The dispatch-tier load harness (`blueprint/testing.md`, Dispatch / scheduled).
It drives `cipherbox-engine`'s real API client, so a run measures the shipping
client path and the harness cannot drift from the contract.

Load runs are dispatch-only, never merge-blocking — run them from
`.github/workflows/load-test.yml`. The crate's own unit tests do block merges,
in CI's `Cargo Check & Test (Linux)` job.

## Scenarios

| Scenario         | Surface                                                            |
| ---------------- | ------------------------------------------------------------------ |
| `content-ingest` | `POST /content/upload` — caller-addressed block ingest             |
| `gateway-read`   | the read accelerator; the API process serves no bytes in v2        |
| `name-wave`      | `POST /registry/register` + `/retire` under a bulk name wave       |
| `mixed`          | ingest, register-first, quota and a mailbox round-trip interleaved |
| `byo-advisory`   | a BYO account's advisory pin rows, which never gate                |

v1's `sustained-load` and `spike-test` are not scenarios here: a sustained run
is a large `--ops-per-client`, and a spike is the default `--ramp-ms 0`, where
every virtual client starts at once.

v1's `ipns-publish-storm` has no v2 counterpart on the API — clients PUT
`/routing/v1` themselves — so `name-wave` carries its registry half.

## Running it locally

The harness needs a live API. With the docker stack up:

```sh
export LOAD_TEST_SECRET=<the API's TEST_LOGIN_SECRET>
cargo run --release -p cipherbox-load -- \
  --scenario mixed --target local --clients 5 --ops-per-client 20
```

`--help` lists every flag and environment variable. A JSON report lands in
`load-reports/`, and the process exits non-zero when a threshold breaches.

## Targets

`local` only ever reaches a loopback URL; `staging` only ever reaches a
non-loopback https URL supplied by the workflow's gated `staging` environment.
There is no production target, and both targets bound how many accounts and
operations a run may use — staging tightest, because it is one 2-vCPU VPS whose
cores Kubo and someguy already share.

## Rate limiting

v2 has no throttle bypass. Per-surface 429s are the API keeping its promise, so
they are counted apart from failures and never breach a threshold. Staging runs
pace each account just under the 60-per-minute content bucket; if you want a run
that measures the system rather than the throttler, keep `--ops-per-client`
under the bucket for the surface you are exercising
(`apps/api/src/ops/throttling.ts`).

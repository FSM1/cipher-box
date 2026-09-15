# Recorded performance baselines — issues #658, #1398, #1397

The v2 successor to v1's `scripts/baseline-benchmark.sh`. Every number below is
reproducible from this directory: the API-surface rows come from
`cipherbox-load`, which drives `cipherbox-engine`'s real API client over the
desktop `Http` seam, and the framing rows come from the engine's own bench and
profile targets. Nothing here gates a merge — `blueprint/testing.md` puts the
perf tier on dispatch, because a shared runner's timings cannot fail a PR.

## How to reproduce

**The API surface, locally.** Bring the stack up
(`docker compose -f docker/docker-compose.yml up -d postgres ipfs someguy mock-ipns-routing`),
then apply the migrations and start the API from `apps/api` with a known
`TEST_LOGIN_SECRET`; `tests/web-e2e/README.md` holds the full step list. Then:

```sh
export LOAD_TEST_API_URL=http://localhost:3100
export LOAD_TEST_SECRET=<the API's TEST_LOGIN_SECRET>
pnpm --filter @cipherbox/perf baseline -- --target local
```

The runner takes two runs of every scenario and records the second. The first
run measures the cold start, not the system: on 2026-09-15 a cold
`content-ingest` retire leg read 8.6 s against the same stack that read 1.1 s
warm, and a cold `registry-register` read 121 ms against a warm 15 ms.

**The API surface, on staging.** The staging login secret is a repository
secret, so a staging baseline is taken from the workflow that holds it rather
than from a developer machine:

```sh
gh workflow run load-test.yml --ref main \
  -f environment=staging -f scenario=<name> -f clients=5 -f ops_per_client=20
gh run download <run-id>    # metrics-<scenario>-staging.json
```

**The framing.** `cargo run --release -p cipherbox-engine --example
ranged_profile` prints the ranged-fetch table, and `Perf Benches` with
`job: ranged-fetch` runs it beside the framing bench.

**The cross-client convergence latency.** Dispatch `Desktop E2E Tests`, then
`Perf Benches` with `job: cross-client-latency` and that run's id.

## The environments

|        | Local                                        | Staging                                 |
| ------ | -------------------------------------------- | --------------------------------------- |
| Host   | Apple M3 Pro, 11 cores, 36 GiB, macOS 26.6.2 | one 2-vCPU VPS                          |
| Stack  | docker: Postgres 16, Kubo 0.42.0, someguy    | the same processes, on one box          |
| Client | the harness on the same host as the stack    | a GitHub `ubuntu-latest` runner         |
| Pacing | none                                         | 1200 ms between an account's operations |
| Taken  | 2026-09-15                                   | 2026-09-15                              |

**Read staging against the ceiling, not against local.** Kubo, someguy, the API
and Postgres share two vCPUs there (`blueprint/deploy.md`), and the client is a
different machine across the internet from the stack it drives. A staging row
that is slower than its local twin is the hardware and the network, and is not a
regression. Staging `ops/s` is likewise not a capacity figure: the harness paces
each account at 1200 ms to stay under the API's 60-per-minute content bucket, so
the column reports the pace it was given.

## Local baseline — 5 accounts, 20 iterations each

<!-- the second run of each scenario; `pnpm --filter @cipherbox/perf baseline -- --target local` -->

| Scenario         | Operation           |   n | 429 | err | p50 ms | p95 ms | p99 ms | ops/s |
| ---------------- | ------------------- | --: | --: | --: | -----: | -----: | -----: | ----: |
| `content-ingest` | `auth-test-login`   |   5 |   0 |   0 |   16.5 |   28.5 |   28.5 |   3.0 |
| `content-ingest` | `content-upload`    | 100 |   0 |   0 |   46.9 |  112.3 |  131.7 |  60.1 |
| `content-ingest` | `registry-retire`   |   5 |   0 |   0 |  308.2 |  339.6 |  339.6 |   3.0 |
| `content-ingest` | `account-delete`    |   5 |   0 |   0 |   13.3 |   14.3 |   14.3 |   3.0 |
| `content-ingest` | `all`               | 115 |   0 |   0 |   46.4 |  175.6 |  320.2 |  69.1 |
| `gateway-read`   | `auth-test-login`   |   5 |   0 |   0 |   11.4 |   21.4 |   21.4 |  11.2 |
| `gateway-read`   | `content-upload`    |  20 |   0 |   0 |   32.4 |   67.8 |   74.7 |  44.8 |
| `gateway-read`   | `gateway-read`      | 100 |   0 |   0 |    3.3 |   10.1 |   22.0 | 224.2 |
| `gateway-read`   | `registry-retire`   |   5 |   0 |   0 |   69.3 |   81.8 |   81.8 |  11.2 |
| `gateway-read`   | `account-delete`    |   5 |   0 |   0 |   12.4 |   13.2 |   13.2 |  11.2 |
| `gateway-read`   | `all`               | 135 |   0 |   0 |    3.8 |   64.5 |   75.2 | 302.7 |
| `name-wave`      | `auth-test-login`   |   5 |   0 |   0 |   14.2 |   19.8 |   19.8 |   7.3 |
| `name-wave`      | `registry-register` | 100 |   0 |   0 |   13.7 |   17.5 |   21.2 | 145.2 |
| `name-wave`      | `registry-retire`   | 100 |   0 |   0 |   13.9 |   16.8 |   20.2 | 145.2 |
| `name-wave`      | `account-delete`    |   5 |   0 |   0 |   10.9 |   15.3 |   15.3 |   7.3 |
| `name-wave`      | `all`               | 210 |   0 |   0 |   13.7 |   18.2 |   20.7 | 304.8 |
| `mixed`          | `auth-test-login`   |   5 |   0 |   0 |   16.0 |   21.7 |   21.7 |   2.2 |
| `mixed`          | `content-upload`    | 100 |   0 |   0 |   30.6 |  107.0 |  155.6 |  44.9 |
| `mixed`          | `registry-register` | 100 |   0 |   0 |   14.7 |   18.8 |   23.5 |  44.9 |
| `mixed`          | `account-quota`     | 100 |   0 |   0 |    3.5 |    4.9 |    5.6 |  44.9 |
| `mixed`          | `mailbox-post`      | 100 |   0 |   0 |   17.0 |   22.5 |   25.1 |  44.9 |
| `mixed`          | `mailbox-poll`      | 100 |   0 |   0 |    3.5 |    6.0 |    6.5 |  44.9 |
| `mixed`          | `mailbox-ack`       | 100 |   0 |   0 |    2.8 |    4.6 |    5.4 |  44.9 |
| `mixed`          | `registry-retire`   |  10 |   0 |   0 |  134.1 |  231.6 |  231.6 |   4.5 |
| `mixed`          | `account-delete`    |   5 |   0 |   0 |   16.4 |   20.6 |   20.6 |   2.2 |
| `mixed`          | `all`               | 620 |   0 |   0 |   11.3 |   50.0 |  155.6 | 278.2 |
| `byo-advisory`   | `auth-test-login`   |   5 |   0 |   0 |   19.1 |   22.6 |   22.6 |   0.7 |
| `byo-advisory`   | `account-byo`       |   5 |   0 |   0 |    7.4 |   10.4 |   10.4 |   0.7 |
| `byo-advisory`   | `registry-register` | 100 |   0 |   0 |   25.5 |   39.4 |   43.8 |  14.5 |
| `byo-advisory`   | `account-quota`     | 100 |   0 |   0 |    4.7 |    8.0 |   12.0 |  14.5 |
| `byo-advisory`   | `registry-retire`   | 200 |   0 |   0 |  148.7 |  223.9 |  259.2 |  29.0 |
| `byo-advisory`   | `account-delete`    |   5 |   0 |   0 |    9.5 |   11.3 |   11.3 |   0.7 |
| `byo-advisory`   | `all`               | 415 |   0 |   0 |   39.1 |  204.1 |  254.9 |  60.1 |

No threshold breached, and no operation was throttled or failed.

`registry-retire` is the slowest surface on every scenario that pins: a retire
unpins at Kubo, and the retire leg of `content-ingest` drops a whole run's
blocks in one call.

## Staging baseline — 5 accounts, 20 iterations each, 1200 ms pace

| Scenario         | Operation           |   n | 429 | err | p50 ms | p95 ms | p99 ms | ops/s |
| ---------------- | ------------------- | --: | --: | --: | -----: | -----: | -----: | ----: |
| `mixed`          | `auth-test-login`   |   5 |   0 |   0 |  154.8 |  698.7 |  698.7 |   0.1 |
| `mixed`          | `content-upload`    | 100 |   0 |   0 |  270.8 |  634.3 |  849.9 |   1.9 |
| `mixed`          | `registry-register` | 100 |   0 |   0 |  155.5 |  272.4 |  512.3 |   1.9 |
| `mixed`          | `account-quota`     | 100 |   0 |   0 |  136.3 |  238.1 |  265.8 |   1.9 |
| `mixed`          | `mailbox-post`      | 100 |   0 |   0 |  159.8 |  337.5 |  479.0 |   1.9 |
| `mixed`          | `mailbox-poll`      | 100 |   0 |   0 |  135.1 |  229.3 |  320.9 |   1.9 |
| `mixed`          | `mailbox-ack`       | 100 |   0 |   0 |  136.1 |  184.2 |  244.1 |   1.9 |
| `mixed`          | `registry-retire`   |  10 |   0 |   0 |  572.7 |  970.1 |  970.1 |   0.2 |
| `mixed`          | `account-delete`    |   5 |   0 |   0 |  133.0 |  143.5 |  143.5 |   0.1 |
| `mixed`          | `all`               | 620 |   0 |   0 |  151.3 |  427.8 |  808.6 |  11.8 |
| `content-ingest` | `auth-test-login`   |   5 |   0 |   0 |  135.8 |  216.2 |  216.2 |   0.2 |
| `content-ingest` | `content-upload`    | 100 |   0 |   0 |  175.8 |  527.2 |  607.7 |   3.1 |
| `content-ingest` | `registry-retire`   |   5 |   0 |   0 |  857.0 |  907.1 |  907.1 |   0.2 |
| `content-ingest` | `account-delete`    |   5 |   0 |   0 |  123.2 |  135.7 |  135.7 |   0.2 |
| `content-ingest` | `all`               | 115 |   0 |   0 |  175.7 |  614.4 |  870.6 |   3.6 |
| `name-wave`      | `auth-test-login`   |   5 |   0 |   0 |  195.6 |  794.6 |  794.6 |   0.1 |
| `name-wave`      | `registry-register` | 100 |   0 |   0 |  178.1 |  583.8 |  666.3 |   1.7 |
| `name-wave`      | `registry-retire`   | 100 |   0 |   0 |  168.8 |  189.3 |  251.7 |   1.7 |
| `name-wave`      | `account-delete`    |   5 |   0 |   0 |  163.9 |  230.4 |  230.4 |   0.1 |
| `name-wave`      | `all`               | 210 |   0 |   0 |  172.0 |  370.8 |  666.3 |   3.6 |
| `byo-advisory`   | `auth-test-login`   |   5 |   0 |   0 |  253.0 | 1022.9 | 1022.9 |   0.1 |
| `byo-advisory`   | `account-byo`       |   5 |   0 |   0 |  780.7 | 1002.0 | 1002.0 |   0.1 |
| `byo-advisory`   | `registry-register` | 100 |   0 |   0 |  283.9 |  786.8 | 1059.4 |   0.9 |
| `byo-advisory`   | `account-quota`     | 100 |   0 |   0 |  203.2 |  503.3 |  826.1 |   0.9 |
| `byo-advisory`   | `registry-retire`   | 200 |   0 |   1 |  370.5 |  863.8 | 1208.0 |   1.8 |
| `byo-advisory`   | `account-delete`    |   5 |   0 |   0 |  259.0 |  342.0 |  342.0 |   0.1 |
| `byo-advisory`   | `all`               | 415 |   0 |   1 |  323.9 |  817.3 | 1208.0 |   3.8 |

No threshold breached, and nothing was throttled. The floor of every staging row
is one round trip from a GitHub runner to the VPS: the cheapest surface,
`mailbox-poll`, reads 135 ms where its local twin reads 3.5 ms, so read the
difference above that floor rather than the ratio. One `byo-advisory` retire of
415 operations lost its connection to the API, which is 0.24 % against the 1 %
band; a rerun of a staging row that shows one transport error is a rerun, and
not a finding.

One staging scenario is not recorded. `gateway-read` needs the
`IPFS_GATEWAY_TOKEN` secret, which no workflow sets today: the read accelerator
sits behind `forward_auth`, and the dispatch refuses the scenario without it.
Dispatch one staging scenario at a time — the
`load-test-staging` concurrency group holds one queued run, so a second
dispatch made while one is pending cancels the one before it.

## Ranged fetch over the frozen framing

`ContentProfile::PRODUCTION` frames a 1 048 536-byte plaintext chunk, which
seals to a 1 MiB block exactly. The flat DAG maps a byte range to a leaf range
by division, so a range costs whole sealed leaves and nothing else.

<!-- cargo run --release -p cipherbox-engine --example ranged_profile -->

| Object | Range            |  Asked B | Leaves |   Wire B | Over-fetch |
| ------ | ---------------- | -------: | -----: | -------: | ---------: |
| 64 KiB | first 4 KiB      |     4096 |      1 |  1048576 |    256.00x |
| 64 KiB | last 4 KiB       |     4096 |      1 |  1048576 |    256.00x |
| 64 KiB | 1 MiB at 0       |    65536 |      1 |  1048576 |     16.00x |
| 64 KiB | resume at 3/4    |    16384 |      1 |  1048576 |     64.00x |
| 64 KiB | whole object     |    65536 |      1 |  1048576 |     16.00x |
| 4 MiB  | first 4 KiB      |     4096 |      1 |  1048576 |    256.00x |
| 4 MiB  | last 4 KiB       |     4096 |      2 |  2097152 |    512.00x |
| 4 MiB  | 1 MiB at 0       |  1048576 |      2 |  2097152 |      2.00x |
| 4 MiB  | 1 MiB at 512 KiB |  1048576 |      2 |  2097152 |      2.00x |
| 4 MiB  | resume at 3/4    |  1048576 |      2 |  2097152 |      2.00x |
| 4 MiB  | whole object     |  4194304 |      5 |  5242880 |      1.25x |
| 64 MiB | first 4 KiB      |     4096 |      1 |  1048576 |    256.00x |
| 64 MiB | last 4 KiB       |     4096 |      2 |  2097152 |    512.00x |
| 64 MiB | 1 MiB at 0       |  1048576 |      2 |  2097152 |      2.00x |
| 64 MiB | 1 MiB at 512 KiB |  1048576 |      2 |  2097152 |      2.00x |
| 64 MiB | resume at 3/4    | 16777216 |     17 | 17825792 |      1.06x |
| 64 MiB | whole object     | 67108864 |     65 | 68157440 |      1.02x |

Two properties the freeze carries, both visible above.

1. **One leaf is the floor.** A range shorter than a chunk costs one whole
   sealed leaf, so a 4 KiB probe moves 1 MiB. The budget belongs to the block
   because the ecosystem imposes its limits on blocks, and the trade is a
   sequential read that costs 1.02x over the whole object against a small probe
   that costs 256x.
2. **A reader's MiB is never a leaf's MiB.** The plaintext chunk is 40 bytes
   short of a MiB, because the seal overhead is charged to the block. A range a
   reader aligns to 1 MiB therefore straddles two leaves from the second leaf
   onward, which is why the 4 KiB tail of a 4 MiB object costs two leaves and
   not one. A reader that wants one leaf must align to the chunk size, not to a
   power of two.

## Cross-client convergence latency

Not recorded yet. The measurement needs the cross-client harness, which is a
mounted desktop host beside a browser host on one vault, and `Perf Benches`
takes it from a `Desktop E2E Tests` run's wait samples rather than by standing
that stack up again. Until a row lands here, the five `SyncTimingProfile::PRODUCTION`
placeholders — `escalation_window`, `focus_horizon`, `pointer_consult_interval`,
`sweep_cadence` and `migration_window` — keep the values they carry.

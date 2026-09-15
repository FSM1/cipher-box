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

| Scenario | Operation           |   n | 429 | err | p50 ms | p95 ms | p99 ms | ops/s |
| -------- | ------------------- | --: | --: | --: | -----: | -----: | -----: | ----: |
| `mixed`  | `auth-test-login`   |   5 |   0 |   0 |  154.8 |  698.7 |  698.7 |   0.1 |
| `mixed`  | `content-upload`    | 100 |   0 |   0 |  270.8 |  634.3 |  849.9 |   1.9 |
| `mixed`  | `registry-register` | 100 |   0 |   0 |  155.5 |  272.4 |  512.3 |   1.9 |
| `mixed`  | `account-quota`     | 100 |   0 |   0 |  136.3 |  238.1 |  265.8 |   1.9 |
| `mixed`  | `mailbox-post`      | 100 |   0 |   0 |  159.8 |  337.5 |  479.0 |   1.9 |
| `mixed`  | `mailbox-poll`      | 100 |   0 |   0 |  135.1 |  229.3 |  320.9 |   1.9 |
| `mixed`  | `mailbox-ack`       | 100 |   0 |   0 |  136.1 |  184.2 |  244.1 |   1.9 |
| `mixed`  | `registry-retire`   |  10 |   0 |   0 |  572.7 |  970.1 |  970.1 |   0.2 |
| `mixed`  | `account-delete`    |   5 |   0 |   0 |  133.0 |  143.5 |  143.5 |   0.1 |
| `mixed`  | `all`               | 620 |   0 |   0 |  151.3 |  427.8 |  808.6 |  11.8 |

No threshold breached, and no operation was throttled or failed. The floor of
every staging row is one round trip from a GitHub runner to the VPS: the
cheapest surface, `mailbox-poll`, reads 135 ms where its local twin reads
3.5 ms, so read the difference above that floor rather than the ratio.

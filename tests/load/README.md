<!-- generated-by: gsd-doc-writer -->

# @cipherbox/load-tests

Load tests for the CipherBox API and SDK. Measures upload throughput, IPNS publish
concurrency, mixed workloads, sustained traffic, spike behaviour, and BYO-IPFS provider
capacity — all against a live API target.

Part of the [CipherBox monorepo](../../README.md).

## Tooling

[Vitest](https://vitest.dev/) runs the scenarios sequentially (no parallelism). Each test
has a 10-minute timeout. Results are written to `metrics-*.json` files in this directory.

## Scenarios

| Scenario                | File                                          |
| ----------------------- | --------------------------------------------- |
| `upload-throughput`     | `src/scenarios/upload-throughput.test.ts`     |
| `ipns-publish-storm`    | `src/scenarios/ipns-publish-storm.test.ts`    |
| `mixed-workload`        | `src/scenarios/mixed-workload.test.ts`        |
| `sustained-load`        | `src/scenarios/sustained-load.test.ts`        |
| `spike-test`            | `src/scenarios/spike-test.test.ts`            |
| `byo-upload-throughput` | `src/scenarios/byo-upload-throughput.test.ts` |
| `byo-mixed-workload`    | `src/scenarios/byo-mixed-workload.test.ts`    |
| `byo-capacity-ceiling`  | `src/scenarios/byo-capacity-ceiling.test.ts`  |

## Running Locally

Set the required environment variables, then run a single scenario by name:

```bash
LOAD_TEST_API_URL=http://localhost:3000 \
LOAD_TEST_SECRET=<test-login-secret> \
THROTTLE_BYPASS_SECRET=<throttle-bypass-secret> \
LOAD_TEST_CLIENTS=5 \
pnpm exec vitest run --no-coverage mixed-workload
```

For BYO-IPFS scenarios, also set:

```bash
BYO_IPFS_ENDPOINT=https://api.pinata.cloud
BYO_IPFS_AUTH_TOKEN=<token>
BYO_IPFS_PROTOCOL=pinata   # pinata | psa | kubo
BYO_IPFS_PROVIDER_NAME=pinata
```

## Environment Variables

| Variable                 | Required         | Description                                          |
| ------------------------ | ---------------- | ---------------------------------------------------- |
| `LOAD_TEST_API_URL`      | Yes              | Base URL of the API under test                       |
| `LOAD_TEST_SECRET`       | Yes              | `TEST_LOGIN_SECRET` value used to mint test sessions |
| `THROTTLE_BYPASS_SECRET` | Yes              | Secret to bypass API rate limiting during load runs  |
| `LOAD_TEST_CLIENTS`      | No (default `5`) | Number of concurrent virtual clients                 |
| `BYO_IPFS_ENDPOINT`      | byo-\* only      | BYO IPFS provider base URL                           |
| `BYO_IPFS_AUTH_TOKEN`    | byo-\* only      | Auth token for the BYO provider                      |
| `BYO_IPFS_PROTOCOL`      | byo-\* only      | Provider protocol: `pinata`, `psa`, or `kubo`        |
| `BYO_IPFS_PROVIDER_NAME` | byo-\* only      | Label used in metrics output                         |

## CI

The `load-test.yml` workflow (`manual dispatch only`) runs any scenario against `local` or
`staging`. For `local` it spins up Postgres, Kubo IPFS, and Redis service containers and
starts the API before executing. Metrics JSON is uploaded as a workflow artifact
(retained 30 days).

## Related Docs

- [Testing strategy](../TESTING_STRATEGY.md)
- [Full testing reference](../../docs/TESTING.md)

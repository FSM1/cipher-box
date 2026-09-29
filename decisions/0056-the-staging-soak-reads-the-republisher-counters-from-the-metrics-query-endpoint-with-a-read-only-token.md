# ADR 0056 — The staging soak reads the republisher counters from the metrics query endpoint with a read-only token

- **Status:** Proposed
- **Date:** 2026-09-29
- **Relates to:**
  [ADR 0053](./0053-the-staging-soak-signs-in-as-durable-accounts-whose-login-secrets-live-in-the-staging-scope.md)
  D2 (the soak secrets live in the `staging` environment scope, and 1Password is the source of
  truth), and the `blueprint/deploy.md` "Scheduled tier" section (Staging Soak bullet)
- **Implemented by:** the soak counter checks, not landed. The build slice is
  [FSM1/cipher-box#2076](https://github.com/FSM1/cipher-box/issues/2076), under
  [FSM1/cipher-box#2042](https://github.com/FSM1/cipher-box/issues/2042)
- **Amends:** ADR 0053 D2

## Context

The soak checks the republisher counters each night: stale names and skipped walks as a 24-hour
increase, resolve failures flat, and the walk count. The API exposes them on `/metrics`, but the
staging front answers 403 there, and Alloy remote-writes them to Grafana Cloud. The soak therefore
reads them from Grafana Cloud, and ADR 0053 D2 sanctions no credential for that read. Every Grafana
credential that staging held was a write key for the metrics push or the dashboard provisioning.

## Decision

**D1 — The soak reads the counters from the Grafana Cloud Mimir query endpoint with a
`metrics:read` token held in the `staging` environment scope.** The credential is a Grafana Cloud
access-policy token with the `metrics:read` scope only: it cannot write metrics, and it cannot read
logs or traces. It is the secret `STAGING_GRAFANA_READ_TOKEN`, beside the four soak secrets of ADR
0053 D2, and 1Password is its source of truth. The soak sends it by HTTP basic authentication to
the Mimir query endpoint, whose base URL and user come from the staging variables that the metrics
push already uses. The soak does not read through the Grafana stack API: the stack sleeps when
idle, and the Mimir endpoint does not, so a night needs no wake-up loop.

## Alternatives considered

**(a) Scrape `/metrics` through the staging front.** Rejected. The front answers 403 on
`/metrics`. To open it would publish the counters to any caller.

**(b) A new API endpoint that serves the counters.** Rejected. It adds an authenticated surface to
the API residual surface for one test, and the counters already reach Grafana Cloud.

**(c) An existing Grafana credential.** Rejected. Each is a write key, so the soak would hold a
right to write metrics or dashboards.

**(d) A stack service-account token with the Viewer role, through the datasource proxy.**
Rejected. The stack API rejects an access-policy token, and the stack sleeps when idle, so each
night would first wake it with a poll loop.

## Consequences

1. **`blueprint/deploy.md` changes.** The Staging Soak bullet names the Mimir query endpoint and
   `STAGING_GRAFANA_READ_TOKEN` as the read path of the counters.
2. **ADR 0053 D2 changes.** It carries the "Amended by" sentence for D1.
3. **`tests/web-e2e/staging/README.md` changes.** Its list of `staging` secrets names the read
   token, its scope, and its source in 1Password.

## Residuals

None. The owner settled the credential and the read path on 2026-09-29.

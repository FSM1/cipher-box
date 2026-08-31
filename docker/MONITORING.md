# CipherBox Staging Monitoring

Centralized log aggregation, Prometheus metrics, and uptime monitoring for the staging environment.

## Grafana Cloud Free Setup

Grafana Cloud Free tier provides 50 GB logs/month, 10,000 metrics series, and 14-day retention.

### 1. Create Grafana Cloud account

1. Sign up at <https://grafana.com/products/cloud> (select Free plan)
2. Create a Grafana Cloud stack (pick any region)

### 2. Generate Loki credentials (logs)

1. Go to **Connections** > **Loki** (or **Hosted Logs**)
2. Note the **Loki push URL** -- it looks like `https://logs-prod-XXX.grafana.net/loki/api/v1/push`
3. Note the **Username** (numeric instance ID, e.g., `123456`)
4. Click **Generate API key** with the `MetricsPublisher` and `LogsPublisher` roles
5. Copy the API key (shown once)

### 3. Generate Prometheus credentials (metrics)

1. Go to **Connections** > **Prometheus** (or **Hosted Metrics**)
2. Note the **Remote write URL** -- it looks like `https://prometheus-prod-XXX.grafana.net/api/prom/push`
3. Note the **Username** (numeric instance ID, e.g., `789012`)
4. Use the same API key from step 2 (it needs `MetricsPublisher` role), or generate a new one

### 4. Add to GitHub Secrets

Add these secrets to the GitHub repository:

| Secret                        | Value                                                   |
| ----------------------------- | ------------------------------------------------------- |
| `GRAFANA_LOKI_URL`            | `https://logs-prod-XXX.grafana.net/loki/api/v1/push`    |
| `GRAFANA_LOKI_USERNAME`       | Numeric instance ID (e.g., `123456`)                    |
| `GRAFANA_LOKI_API_KEY`        | API key with `LogsPublisher` role                       |
| `GRAFANA_PROMETHEUS_URL`      | `https://prometheus-prod-XXX.grafana.net/api/prom/push` |
| `GRAFANA_PROMETHEUS_USERNAME` | Numeric instance ID (e.g., `789012`)                    |
| `GRAFANA_PROMETHEUS_API_KEY`  | API key with `MetricsPublisher` role                    |

The deploy workflow writes these into `.env.staging` on the VPS, where the Alloy container reads them.

### 5. How it works

- **Grafana Alloy** `v1.6.1` runs as a Docker Compose service beside the application
- It discovers containers through the Docker socket, mounted read-only
- **Logs**: labeled with `service`, `container`, and `project`, then sent to Grafana Cloud Loki
- **Metrics**: three scrape jobs at a 30 second interval, then sent to Grafana Cloud Mimir (Prometheus-compatible)
- The two infra jobs pass a keep-list relabel first, so only a short set of series leaves the box

### 6. Import the dashboard

1. In Grafana Cloud, go to **Dashboards** > **Import**
2. Upload `docker/grafana/dashboards/cipherbox-staging.json`
3. Select the Prometheus and Loki data sources when prompted

## Prometheus Metrics

`docker/alloy-config.river` defines three scrape jobs. Each job sets `job_name` explicitly. The `job` label value is therefore stable across a component rename.

| `job` label | Target         | Path                        | Interval |
| ----------- | -------------- | --------------------------- | -------- |
| `api`       | `api:3000`     | `/metrics`                  | 30s      |
| `kubo`      | `ipfs:5001`    | `/debug/metrics/prometheus` | 30s      |
| `someguy`   | `someguy:8190` | `/debug/metrics/prometheus` | 30s      |

The `up` series exists for all three jobs. Query it as `up{job="api"}`, `up{job="kubo"}`, or `up{job="someguy"}`.

Every `cipherbox_*` metric from v1 is gone. The v2 API keeps no file, storage, or IPNS counter. The API never serves records, so it measures no resolve, no publish, and no pin.

### API series

The API serves `GET /metrics`. The endpoint needs no authentication and stays out of Swagger. `apps/api/src/ops/metrics.service.ts` declares every series below.

| Metric                                 | Type      | Labels                                       |
| -------------------------------------- | --------- | -------------------------------------------- |
| `http_requests_total`                  | counter   | `method`, `route`, `status` (numeric string) |
| `http_request_duration_seconds`        | histogram | `method`, `route`                            |
| `republisher_resolve_failures_total`   | counter   | none                                         |
| `republisher_stale_names_total`        | counter   | none                                         |
| `republisher_last_walk_names`          | gauge     | none                                         |
| `republisher_last_walk_republished`    | gauge     | none                                         |
| `republisher_walks_skipped_total`      | counter   | none                                         |
| `mailbox_pending_messages`             | gauge     | none                                         |
| `mailbox_pending_cap_rejections_total` | counter   | none                                         |
| `auth_attempts_total`                  | counter   | `route`, `outcome`                           |
| `throttle_rejections_total`            | counter   | `route`                                      |
| `gateway_verify_total`                 | counter   | `outcome`                                    |

The histogram exposes the usual `_bucket`, `_sum`, and `_count` series. It carries `method` and `route` only. It has no `status` label. Use `http_requests_total{status=...}` for a status breakdown.

Label values come from the call sites:

- `route` holds an Express route template, or the literal `unmatched`.
- `auth_attempts_total{outcome}` is `success`, `rejected`, or `error`.
- `auth_attempts_total{route}` is one of `/auth/challenge`, `/auth/login`, `/auth/siwe/challenge`, `/auth/refresh`, `/auth/test-login`, `/auth/identity/google`, `/auth/identity/email/send-code`, `/auth/identity/email/verify-code`, or `/auth/identity/wallet`.
- `gateway_verify_total{outcome}` is `accepted` or `refused`. This counter records the `forward_auth` verify leg that the two fronted vhosts call.

prom-client registers its default process and Node series on the same registry. Use them with care. `process_resident_memory_bytes` and `nodejs_eventloop_lag_seconds` are the two that earn a panel.

### Kubo and someguy series, and the keep-list

Kubo alone exports more than 10,000 series. That volume exceeds the Grafana Cloud free tier. Both infra jobs therefore pass through `prometheus.relabel "keep_infra_metrics"`. The rule keeps these names and drops everything else:

```text
up
go_goroutines
go_memstats_alloc_bytes
process_network_receive_bytes_total
process_network_transmit_bytes_total
libp2p_rcmgr_connections
libp2p_swarm_connections_opened_total
libp2p_swarm_connections_closed_total
ipfs_http_requests_total
```

The drop happens before remote write, so a dropped series never reaches Grafana Cloud. A panel or an alert rule that names any other kubo or someguy series stays permanently empty. To use a new infra series, add its name to the keep rule first.

| Metric                                  | Notes                                                                                    |
| --------------------------------------- | ---------------------------------------------------------------------------------------- |
| `libp2p_rcmgr_connections`              | gauge; labels `dir` (`inbound`/`outbound`) and `scope` (`system`/`transient`); both jobs |
| `libp2p_swarm_connections_opened_total` | counter; connection churn; both jobs                                                     |
| `libp2p_swarm_connections_closed_total` | counter; connection churn; both jobs                                                     |
| `process_network_receive_bytes_total`   | counter; process bandwidth in; both jobs                                                 |
| `process_network_transmit_bytes_total`  | counter; process bandwidth out; both jobs                                                |
| `go_goroutines`                         | gauge; both jobs                                                                         |
| `go_memstats_alloc_bytes`               | gauge; both jobs                                                                         |
| `ipfs_http_requests_total`              | counter; labels `code`, `handler`, `method`; kubo only                                   |

`ipfs_http_requests_total{handler="gateway"}` counts read-accelerator traffic. The value `handler="api"` counts the `:5001` API port instead. someguy exposes no HTTP request counter of its own.

### The Kubo libp2p caveat is retired

An earlier note said that Kubo emits no libp2p metrics. That statement was true for Kubo v0.34. Staging now runs `ipfs/kubo:v0.42.0`, which emits 197 metric families. The full `libp2p_*` set is among them. The caveat is therefore retired.

One correction survives the retirement. `libp2p_network_in_bytes_total` and `libp2p_network_out_bytes_total` do not exist in v0.42.0. The v1 dashboard named both. Read bandwidth from `process_network_receive_bytes_total` and `process_network_transmit_bytes_total` instead.

### Cost discipline

The staging VPS has 2 vCPU and the Grafana Cloud tier is small. Do not widen the keep rule. Do not add a histogram-heavy kubo series. Prefer `sum by (...)` over an unaggregated `by (instance)` breakdown.

## Alert Rules

`docker/grafana/alerts/*.json` holds the rule definitions. `docker/grafana/scripts/provision-alerts.sh` posts them to the Grafana provisioning API. Each file holds either one rule object or an array of rule objects.

The script replaces two literal placeholders in every file. Keep both spellings exact:

- `GRAFANA_CLOUD_DATASOURCE_UID` — the Prometheus/Mimir datasource on every query node
- `GRAFANA_ALERTS_FOLDER_UID` — the `folderUID` field

Grafana expression nodes keep `__expr__` as their `datasourceUid`. The script also reads `.title` and `.ruleGroup` from each rule for its upsert lookup.

Check a change with a dry run before a real provision:

```bash
docker/grafana/scripts/provision-alerts.sh "$GRAFANA_URL" "$GRAFANA_API_KEY" "$GRAFANA_DS_UID" --dry-run
```

### Live rules

| File                             | Rules | Signal                                                                                                              |
| -------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------- |
| `api-endpoint-latency.json`      | 4     | p95 and p99 of `http_request_duration_seconds_bucket` on `/auth/login`, `/auth/refresh`, and `/auth/gateway/verify` |
| `test-login-rate.json`           | 1     | `auth_attempts_total{route="/auth/test-login", outcome="success"}` above 100 per hour                               |
| `gateway-verify-failures.json`   | 1     | refused share of `gateway_verify_total` above 25% for 10 minutes                                                    |
| `accelerator-upstream-down.json` | 1     | `up{job="kubo"}` or `up{job="someguy"}` at 0 for 5 minutes                                                          |

The last two rules answer one obligation. Caddy denies a request on any non-204 answer from `forward_auth`. The two gated vhosts write no error line for a deny. An upstream failure therefore surfaces in metrics alone.

The refused-share rule guards its ratio twice. `clamp_min` holds the denominator away from zero. A floor of 20 verify calls in the window stops a fire on a handful of samples.

`accelerator-upstream-down.json` sets `noDataState` to `NoData` and `execErrState` to `Error`. The other rules set both to `OK`. A silent upstream must not read as healthy when the scrape itself stops.

### Retired rules

Five v1 rules queried `cipherbox_*` metrics that no longer exist. All five are deleted.

| File                             | Reason                                                                                                                                           |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `db-fallback-rate.json`          | The API never serves records in v2. CipherBox infra is accelerator-only and each client verifies its own records. No DB resolve fallback exists. |
| `ipns-resolve-latency.json`      | The API performs no resolve for a member, so no API-side latency histogram exists.                                                               |
| `ipns-publish-latency.json`      | The API performs no publish for a member, so no API-side latency histogram exists.                                                               |
| `ipfs-pin-latency.json`          | The API performs no pin for a member, so no API-side latency histogram exists.                                                                   |
| `unpin-cross-user-attempts.json` | v2 exposes no unpin surface and counts no such attempt.                                                                                          |

## Better Stack Uptime Setup

Better Stack (formerly Better Uptime) free tier provides 10 monitors with 3-minute check intervals.

### 1. Create account

1. Sign up at <https://betterstack.com/uptime> (Free plan)

### 2. Create a monitor

1. Create a new monitor:
   - **URL:** `https://api-staging.cipherbox.cc/health`
   - **Check interval:** 3 minutes
   - **Alert method:** Email
2. Optionally create a public status page at `status.staging.cipherbox.cc`

### 3. Configure alerts

- Add email addresses for downtime notifications
- Set up escalation policies if desired (e.g., alert after 2 consecutive failures)

## Useful LogQL Queries (Grafana Cloud)

Use these in the **Explore** panel in Grafana Cloud.

`loki.source.docker` forwards each container line as it stands, and the pipeline
holds no parser stage, so only `service`, `container`, and `project` exist as
labels. A `line_format` template that names any other field renders an empty
line rather than an error. Add a parser such as `| json` before you reference
one.

### By service

```logql
{service="api"}
```

```logql
{service="postgres"}
```

```logql
{service="ipfs"}
```

```logql
{service="caddy"}
```

### Errors

API errors only:

```logql
{service="api"} |~ "(?i)error"
```

All errors across all services:

```logql
{project="cipherbox-staging"} |= "error"
```

### API-specific

NestJS request logs:

```logql
{service="api"} |~ "GET|POST|PUT|DELETE|PATCH"
```

Database queries (if TypeORM logging enabled):

```logql
{service="api"} |= "query:"
```

### IPFS

IPFS peer connections:

```logql
{service="ipfs"} |= "connected"
```

## Useful PromQL Queries (Grafana Cloud)

### Request rate per second

```promql
sum(rate(http_requests_total[5m]))
```

### p95 latency across all routes

```promql
histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))
```

### Error rate (5xx)

```promql
sum(rate(http_requests_total{status=~"5.."}[5m]))
```

### Login outcomes

```promql
sum by (outcome) (rate(auth_attempts_total{route="/auth/login"}[5m]))
```

### Gateway verify refusal share

A labelled series exists only once that outcome has been counted, so the
numerator falls back to zero: without it the healthy all-accepted case reads as
no data rather than as a zero share.

```promql
(sum(rate(gateway_verify_total{outcome="refused"}[10m])) or vector(0))
/ clamp_min(sum(rate(gateway_verify_total[10m])), 0.001)
```

### Throttle rejections by route

```promql
sum by (route) (rate(throttle_rejections_total[5m]))
```

### Republisher health

```promql
rate(republisher_resolve_failures_total[1h])
```

```promql
republisher_last_walk_republished / clamp_min(republisher_last_walk_names, 1)
```

### Mailbox backlog

```promql
mailbox_pending_messages
```

### Accelerator upstream health

```promql
min by (job) (up{job=~"kubo|someguy"})
```

### Accelerator bandwidth

```promql
sum by (job) (rate(process_network_receive_bytes_total{job=~"kubo|someguy"}[5m]))
```

### Kubo gateway request rate

```promql
sum by (code) (rate(ipfs_http_requests_total{handler="gateway"}[5m]))
```

## Architecture

```text
  Containers (api, postgres, ipfs, someguy, caddy)
      |                           |
      | Docker logs               | job=api      api:3000/metrics
      | (json-file driver)        | job=kubo     ipfs:5001/debug/metrics/prometheus
      |                           | job=someguy  someguy:8190/debug/metrics/prometheus
      |                           | (every 30s; kubo and someguy pass the
      |                           |  keep_infra_metrics relabel first)
      v                           v
  Grafana Alloy ──────────────────┘
      |                    |
      | HTTPS (Loki)       | HTTPS (Prometheus remote write)
      v                    v
  Grafana Cloud Loki    Grafana Cloud Mimir
      |                    |
      └────────┬───────────┘
               v
    Grafana Cloud Dashboards
    (import docker/grafana/dashboards/cipherbox-staging.json)

  Better Stack Uptime
      |
      | HTTPS health check every 3 min
      v
  https://api-staging.cipherbox.cc/health
```

## Dashboard Panels

The pre-built dashboard (`docker/grafana/dashboards/cipherbox-staging.json`) includes:

### Overview Row

- Liveness of each job, mailbox pending depth, overall API request rate

### API HTTP Row

- Request rate by route, 4xx and 5xx rates, latency p50/p95/p99, p95 by route

### Authentication and Throttling Row

- Auth attempts by outcome, auth rejections by route, throttle rejections by route

### Read-accelerator Front Row

- Gateway verify accept ratio and rate by outcome, kubo gateway traffic by code, upstream liveness

### Republisher Row

- Names seen and names republished in the last walk, resolve failures, stale names, skipped walks

### Mailbox Row

- Pending message depth, pending-cap rejections

### Node Health Row

- Live connections, connection churn, process bandwidth, goroutines, heap allocation

### Logs Row

- Recent API errors, republisher logs

## Troubleshooting

### Alloy does not ship logs

1. Check Alloy container logs: `docker compose logs alloy`
2. Verify environment variables are set: check `.env.staging` contains all `GRAFANA_*` variables
3. Verify Docker socket is mounted: `docker compose exec alloy ls -la /var/run/docker.sock`
4. Test Loki connectivity manually:

   ```bash
   curl -u "$GRAFANA_LOKI_USERNAME:$GRAFANA_LOKI_API_KEY" "$GRAFANA_LOKI_URL" -d '{"streams":[{"stream":{"test":"true"},"values":[["'$(date +%s)000000000'","test log"]]}]}'
   ```

### Metrics do not appear

1. Verify the API exposes metrics: `curl http://localhost:3000/metrics`
2. Check Alloy can reach the API: `docker compose exec alloy wget -qO- http://api:3000/metrics`
3. Verify Prometheus credentials are set in `.env.staging`
4. Check Alloy logs for scrape errors: `docker compose logs alloy | grep -i "prometheus\|scrape\|error"`

### No logs reach Grafana Cloud

1. Confirm Alloy is running: `docker compose ps alloy`
2. Check the time range in Grafana Cloud Explore (default may be too narrow)
3. Try a broad query: `{project="cipherbox-staging"}`
4. Check Alloy's own metrics: the container exposes a UI at port 12345 (not exposed externally by default)

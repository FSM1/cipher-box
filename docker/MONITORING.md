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

- **Grafana Alloy** runs as a Docker Compose service alongside the application
- It discovers containers via the Docker socket (mounted read-only)
- **Logs**: labeled with `service`, `container`, and `project`, shipped to Grafana Cloud Loki
- **Metrics**: scraped from the API's `/metrics` endpoint every 30 seconds, shipped to Grafana Cloud Mimir (Prometheus-compatible)

### 6. Import the dashboard

1. In Grafana Cloud, go to **Dashboards** > **Import**
2. Upload `docker/grafana/dashboards/cipherbox-staging.json`
3. Select the Prometheus and Loki data sources when prompted

## Prometheus Metrics

The API exposes a `/metrics` endpoint (unauthenticated, excluded from Swagger) with these metrics:

### Gauges (polled from DB every 30s)

| Metric                               | Labels                           | Description                          |
| ------------------------------------ | -------------------------------- | ------------------------------------ |
| `cipherbox_users_total`              |                                  | Total registered users               |
| `cipherbox_files_total`              |                                  | Total pinned files across all users  |
| `cipherbox_storage_bytes_total`      |                                  | Total storage used (bytes)           |
| `cipherbox_ipns_entries_total`       | `record_type` (folder/file)      | Total IPNS entries by type           |
| `cipherbox_republish_schedule_total` | `status` (active/retrying/stale) | Republish schedule entries by status |

### Counters (event-driven)

| Metric                                        | Labels                      | Description                       |
| --------------------------------------------- | --------------------------- | --------------------------------- |
| `cipherbox_file_uploads_total`                |                             | File uploads                      |
| `cipherbox_file_upload_bytes_total`           |                             | Total bytes uploaded              |
| `cipherbox_file_downloads_total`              |                             | File downloads                    |
| `cipherbox_file_unpins_total`                 |                             | File unpins                       |
| `cipherbox_ipns_publishes_total`              | `type` (single/batch)       | IPNS publish operations           |
| `cipherbox_ipns_resolves_total`               | `source` (network/db_cache) | IPNS resolve operations by source |
| `cipherbox_republish_runs_total`              |                             | Republish cron job runs           |
| `cipherbox_republish_entries_processed_total` | `result` (succeeded/failed) | Republish entries processed       |
| `cipherbox_auth_logins_total`                 | `method`, `new_user`        | Successful logins                 |

### Histograms

| Metric                                    | Labels                           | Description          |
| ----------------------------------------- | -------------------------------- | -------------------- |
| `cipherbox_http_request_duration_seconds` | `method`, `route`, `status_code` | HTTP request latency |

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

### By service

```logql
{service="api"}
```

```logql
{service="postgres"}
```

```logql
{service="redis"}
```

```logql
{service="ipfs"}
```

```logql
{service="tee-worker"}
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

### TEE worker

TEE republish activity:

```logql
{service="tee-worker"} |= "republish"
```

### IPFS

IPFS peer connections:

```logql
{service="ipfs"} |= "connected"
```

## Useful PromQL Queries (Grafana Cloud)

### Storage overview

```promql
cipherbox_storage_bytes_total
```

### Request rate per second

```promql
sum(rate(cipherbox_http_request_duration_seconds_count[5m]))
```

### p95 latency

```promql
histogram_quantile(0.95, sum by (le) (rate(cipherbox_http_request_duration_seconds_bucket[5m])))
```

### Error rate (5xx)

```promql
sum(rate(cipherbox_http_request_duration_seconds_count{status_code=~"5.."}[5m]))
```

### IPNS republish success rate

```promql
rate(cipherbox_republish_entries_processed_total{result="succeeded"}[1h])
/ (rate(cipherbox_republish_entries_processed_total{result="succeeded"}[1h]) + rate(cipherbox_republish_entries_processed_total{result="failed"}[1h]))
```

## Architecture

```text
  Containers (api, postgres, redis, ipfs, tee-worker, caddy)
      |                           |
      | Docker logs               | GET /metrics (every 30s)
      | (json-file driver)        |
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

- Total users, files stored, storage used, IPNS entries, IPNS entries by type, uploads (24h)

### File Operations Row

- File uploads over time, downloads/unpins over time, storage growth

### IPNS Operations Row

- IPNS publishes by type, resolves by source (network vs DB cache), entry growth by type

### TEE Republishing Row

- Active/retrying/stale entry counts, republish results over time, schedule status history

### Authentication Row

- Login attempts by method, new vs returning users

### HTTP Performance Row

- Request rate by route, response time percentiles (p50/p95/p99), error rates (4xx/5xx), p95 by route

### Logs Row

- Recent API errors, TEE republish logs

## Troubleshooting

### Alloy not shipping logs

1. Check Alloy container logs: `docker compose logs alloy`
2. Verify environment variables are set: check `.env.staging` contains all `GRAFANA_*` variables
3. Verify Docker socket is mounted: `docker compose exec alloy ls -la /var/run/docker.sock`
4. Test Loki connectivity manually:

   ```bash
   curl -u "$GRAFANA_LOKI_USERNAME:$GRAFANA_LOKI_API_KEY" "$GRAFANA_LOKI_URL" -d '{"streams":[{"stream":{"test":"true"},"values":[["'$(date +%s)000000000'","test log"]]}]}'
   ```

### Metrics not appearing

1. Verify the API exposes metrics: `curl http://localhost:3000/metrics`
2. Check Alloy can reach the API: `docker compose exec alloy wget -qO- http://api:3000/metrics`
3. Verify Prometheus credentials are set in `.env.staging`
4. Check Alloy logs for scrape errors: `docker compose logs alloy | grep -i "prometheus\|scrape\|error"`

### No logs appearing in Grafana Cloud

1. Confirm Alloy is running: `docker compose ps alloy`
2. Check the time range in Grafana Cloud Explore (default may be too narrow)
3. Try a broad query: `{project="cipherbox-staging"}`
4. Check Alloy's own metrics: the container exposes a UI at port 12345 (not exposed externally by default)

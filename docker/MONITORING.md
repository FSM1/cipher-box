# CipherBox Staging Monitoring

Centralized log aggregation and uptime monitoring for the staging environment.

## Grafana Cloud Free Setup

Grafana Cloud Free tier provides 50 GB logs/month with 14-day retention.

### 1. Create Grafana Cloud account

1. Sign up at <https://grafana.com/products/cloud> (select Free plan)
2. Create a Grafana Cloud stack (pick any region)

### 2. Generate Loki credentials

1. Go to **Connections** > **Loki** (or **Hosted Logs**)
2. Note the **Loki push URL** -- it looks like `https://logs-prod-XXX.grafana.net/loki/api/v1/push`
3. Note the **Username** (numeric instance ID, e.g., `123456`)
4. Click **Generate API key** with the `MetricsPublisher` and `LogsPublisher` roles
5. Copy the API key (shown once)

### 3. Add to GitHub Secrets

Add these three secrets to the GitHub repository:

| Secret                  | Value                                                |
| ----------------------- | ---------------------------------------------------- |
| `GRAFANA_LOKI_URL`      | `https://logs-prod-XXX.grafana.net/loki/api/v1/push` |
| `GRAFANA_LOKI_USERNAME` | Numeric instance ID (e.g., `123456`)                 |
| `GRAFANA_LOKI_API_KEY`  | API key generated above                              |

The deploy workflow writes these into `.env.staging` on the VPS, where the Alloy container reads them.

### 4. How it works

- **Grafana Alloy** runs as a Docker Compose service alongside the application
- It discovers containers via the Docker socket (mounted read-only)
- Logs are labeled with `service` (compose service name), `container`, and `project`
- Logs ship to Grafana Cloud Loki over HTTPS with basic auth

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

## Dashboard Suggestions

Create a "CipherBox Staging" dashboard in Grafana Cloud with these panels:

1. **Log volume by service** (bar chart) -- shows which services produce the most logs
2. **Error rate over time** (time series) -- `sum by(service) (count_over_time({project="cipherbox-staging"} |= "error" [5m]))`
3. **Recent errors** (log panel) -- `{project="cipherbox-staging"} |= "error"` with newest first
4. **API request volume** (time series) -- `count_over_time({service="api"} |~ "GET|POST|PUT|DELETE" [5m])`
5. **TEE republish events** (log panel) -- `{service="tee-worker"} |= "republish"`

## Architecture

```text
  Containers (api, postgres, redis, ipfs, tee-worker, caddy)
      |
      | Docker logs (json-file driver, 10m x 3 rotation)
      v
  Grafana Alloy (discovers via Docker socket)
      |
      | HTTPS + basic auth
      v
  Grafana Cloud Loki (50GB/month free)
      |
      v
  Grafana Cloud Dashboards (explore, alerts)

  Better Stack Uptime
      |
      | HTTPS health check every 3 min
      v
  https://api-staging.cipherbox.cc/health
```

## Troubleshooting

### Alloy not shipping logs

1. Check Alloy container logs: `docker compose logs alloy`
2. Verify environment variables are set: check `.env.staging` contains `GRAFANA_LOKI_URL`, `GRAFANA_LOKI_USERNAME`, `GRAFANA_LOKI_API_KEY`
3. Verify Docker socket is mounted: `docker compose exec alloy ls -la /var/run/docker.sock`
4. Test Loki connectivity manually:

   ```bash
   curl -u "$GRAFANA_LOKI_USERNAME:$GRAFANA_LOKI_API_KEY" "$GRAFANA_LOKI_URL" -d '{"streams":[{"stream":{"test":"true"},"values":[["'$(date +%s)000000000'","test log"]]}]}'
   ```

### No logs appearing in Grafana Cloud

1. Confirm Alloy is running: `docker compose ps alloy`
2. Check the time range in Grafana Cloud Explore (default may be too narrow)
3. Try a broad query: `{project="cipherbox-staging"}`
4. Check Alloy's own metrics: the container exposes a UI at port 12345 (not exposed externally by default)

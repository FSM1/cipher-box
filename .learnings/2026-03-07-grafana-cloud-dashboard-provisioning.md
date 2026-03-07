# Grafana Cloud Dashboard Provisioning via API

**Date:** 2026-03-07

## Original Prompt

> Set up auto-provisioning of Grafana dashboards on staging deploys so dashboard changes in the repo automatically push to Grafana Cloud.

## What I Learned

- **Grafana Cloud requires Admin role for dashboard API writes.** The service account Editor role returns 403 on `POST /api/dashboards/db`, even though Grafana OSS docs say Editor is sufficient. This is a Grafana Cloud RBAC quirk.
- **Trailing slashes in the Grafana URL cause 301 redirects.** `curl` does not follow redirects by default, so `https://host//api/...` (double slash from trailing slash + path) silently fails with HTTP 301. Always strip trailing slashes defensively: `GRAFANA_URL="${GRAFANA_URL%/}"`.
- **The 403 response body is just `{}`** — no error message, no hint about permissions. The only way to diagnose is to check the service account role and test with a local curl.
- **Dashboard JSON `__inputs` need runtime substitution.** Grafana export includes `__inputs` for datasource templating with `${DS_*}` placeholder UIDs. These must be replaced with actual datasource UIDs at import time using `jq walk()`.
- **`environment: staging` is required on GitHub Actions jobs** that reference env-scoped vars/secrets. Without it, `vars.*` and `secrets.*` resolve to empty strings silently.

## What Would Have Helped

- Knowing upfront that Grafana Cloud RBAC differs from self-hosted Grafana for API access
- A quick local `curl` test of the token before wiring it into CI would have caught the 403 immediately
- Checking the Grafana URL for trailing slash before the first deploy

## Key Files

- `.github/workflows/deploy-staging.yml` — `provision-dashboard` job
- `docker/grafana/dashboards/cipherbox-staging.json` — dashboard source of truth

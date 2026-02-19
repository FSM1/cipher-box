# Grafana Cloud Loki Token Scopes & Staging Log Fixes

**Date:** 2026-02-13

## Original Prompt

> Not seeing any logs from staging in Grafana Cloud. Help debug and fix.

## What I Learned

- **Grafana Cloud API tokens need explicit `logs:write` scope** for Alloy to push logs. The default token created from the "Hosted Logs" page may only have `read` scope — the token name contains `hl-read` as a hint.
- **Editing token scopes takes effect immediately** — no need to regenerate or redeploy. Alloy retries every ~1s so it picks up the change within seconds.
- **`pg_isready` without `-d` flag defaults to a database matching the username**, not the `POSTGRES_DB` value. On staging, username=`cipherbox` but database=`cipherbox_staging`, causing `FATAL: database "cipherbox" does not exist` every 5 seconds (matching the healthcheck interval).
- **`docker compose restart` does NOT re-read `env_file`** — it reuses the existing container config. Must use `docker compose up -d --force-recreate <service>` to pick up `.env.staging` changes.
- **GSD agent subprocesses can't access 1Password SSH agent** for commit signing. `op-ssh-sign` is called but produces no signature in agent subprocesses, even though it works in the main terminal. Solution: disable signing requirement on branch protection, rely on GitHub's merge commit signatures instead.

## What Would Have Helped

- Knowing upfront that Grafana Cloud "Hosted Logs" page creates read-only tokens by default
- A checklist item in MONITORING.md to verify token scopes include `write`
- Knowing that `docker compose restart` vs `up --force-recreate` behaves differently for env files

## Key Files

- `docker/docker-compose.staging.yml` — healthcheck and Alloy config
- `docker/alloy-config.river` — Grafana Alloy log shipping config
- `docker/MONITORING.md` — setup and troubleshooting guide
- `apps/api/src/main.ts` — CORS origin handling (lines 29-48)

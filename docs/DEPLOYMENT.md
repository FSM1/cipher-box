<!-- generated-by: gsd-doc-writer -->

# Deployment

> **v1 document — partially superseded.** This describes the v1 pipeline as of the freeze (`v1-freeze`, branch `v1`). The v2 scheme is normative in `blueprint/deploy.md` ([FSM1/cipher-box-next](https://github.com/FSM1/cipher-box-next)): single product version, single-component release-please (dormant, dispatch-only during the build); `pr-release-preview.yml`, `release-gate.yml`, and `cargo-lock-release-sync.yml` are deleted. The staging-tag flow and VPS mechanics below still describe the live setup until the v2 cutover; this document will be rewritten during the v2 build.

This document covers the release pipeline, staging deployment, TEE worker deployment, desktop app packaging, and landing page deployment for CipherBox.

## Release Pipeline (Release Please)

CipherBox uses [Release Please](https://github.com/googleapis/release-please) for automated changelog generation, version bumping, and GitHub Release creation. Configuration is in `release-please-config.json` and version state is tracked in `.release-please-manifest.json`.

### How it works

On every push to `main`, the `release-please.yml` workflow runs and creates or updates a release PR accumulating conventional commits. When the release PR is merged, Release Please:

1. Bumps each changed package's version in its manifest file
2. Updates `CHANGELOG.md` entries
3. Creates a GitHub Release with a component-scoped tag

### Versioned packages

All packages use `include-component-in-tag: true` and `bump-minor-pre-major: true`. Tags follow the pattern `{component}-v{version}`.

| Package path          | Component tag prefix      | Release type |
| --------------------- | ------------------------- | ------------ |
| `.` (root)            | `cipher-box-v`            | node         |
| `apps/api`            | `@cipherbox/api-v`        | node         |
| `apps/web`            | `@cipherbox/web-v`        | node         |
| `apps/desktop`        | `cipherbox-desktop-v`     | node         |
| `apps/tee-worker`     | `cipherbox-tee-worker-v`  | node         |
| `packages/core`       | `@cipherbox/core-v`       | node         |
| `packages/crypto`     | `@cipherbox/crypto-v`     | node         |
| `packages/api-client` | `@cipherbox/api-client-v` | node         |
| `packages/sdk-core`   | `@cipherbox/sdk-core-v`   | node         |
| `packages/sdk`        | `@cipherbox/sdk-v`        | node         |
| `crates/crypto`       | `cipherbox-crypto-v`      | rust         |
| `crates/core`         | `cipherbox-core-v`        | rust         |
| `crates/api-client`   | `cipherbox-api-client-v`  | rust         |
| `crates/fuse`         | `cipherbox-fuse-v`        | rust         |
| `crates/sdk`          | `cipherbox-sdk-v`         | rust         |

For `apps/desktop`, Release Please additionally propagates the version to `src-tauri/tauri.conf.json` and `src-tauri/Cargo.toml` via the `extra-files` config.

### Release PR title pattern

```text
chore: release v${version}
```

### Latest release flag

After creating all batch releases, the `release-please.yml` workflow clears the "latest" flag from every release it creates. The desktop release workflow (`desktop-staging-release.yml`) marks the desktop release as latest so that `/releases/latest/` resolves to the desktop download (used by the Tauri auto-updater).

### Release gate (E2E prerequisite)

Before a release PR can be merged, the `release-gate.yml` workflow verifies that E2E tests have passed on the current `main` HEAD:

- Detects which packages changed (web/desktop path patterns) since the previous release tag
- Polls the `ci-e2e.yml` workflow run to confirm Web E2E and/or Desktop E2E passed
- Falls back to the most recent CI E2E run where those tests actually executed

## Staging Deployment

### Triggering a staging deploy

Staging deploys are triggered manually via the `tag-staging.yml` workflow (workflow dispatch in GitHub Actions). The workflow:

1. Resolves the current `main` HEAD SHA
2. Verifies that `main` HEAD carries a release tag (pattern: `cipher-box-v*`, `cipherbox-*-v*`, or `@cipherbox/*`) — you must wait for a release-please PR to merge before tagging staging
3. Runs Web E2E (`web-e2e.yml`) and Desktop E2E (`desktop-e2e.yml`) against the resolved SHA in parallel
4. Requires `staging-approval` environment approval
5. Creates a tag of the form `staging-YYYYMMDD-release-N` (N is a per-day sequential counter) and pushes it
6. Calls `deploy-staging.yml` as a reusable workflow

The `staging-` prefix avoids collision with release-please tag patterns.

### Deploy workflow (`deploy-staging.yml`)

Triggered by `staging-*` tag pushes or by `tag-staging.yml` via `workflow_call`. The workflow runs these jobs in parallel then converges:

- **Build & Push API Image** — builds `apps/api/Dockerfile` from repo root, pushes to `ghcr.io/{owner}/cipherbox-api` with three tags: `{api-version}`, `latest-staging`, `{staging-tag}`
- **Build & Push TEE Worker Image** — builds `apps/tee-worker/Dockerfile` from repo root, pushes to `ghcr.io/{owner}/cipherbox-tee-worker` with the same tagging scheme
- **Build Web App** — installs deps, builds shared packages, then builds `@cipherbox/web` with staging env vars injected at build time; uploads `apps/web/dist/` as a workflow artifact
- **Build Desktop App (macOS / Windows / Linux)** — see [Desktop App Packaging](#desktop-app-packaging) below
- **Deploy to Staging VPS** — waits for the three build jobs above, then SCPs files to the VPS and runs Docker Compose (see [VPS Deployment](#vps-deployment))
- **Provision Grafana Dashboard** — waits for VPS deploy, then pushes `docker/grafana/dashboards/cipherbox-staging.json` to Grafana Cloud

### VPS deployment

The `deploy-vps` job:

1. Downloads the web dist artifact
2. Generates `.env.staging` from GitHub Actions secrets/vars and appends image tags and component versions
3. SCPs `.env.staging`, `docker/docker-compose.staging.yml`, `docker/Caddyfile`, and `docker/alloy-config.river` to `/opt/cipherbox/` on the staging VPS <!-- VERIFY: VPS host address is in STAGING_HOST secret -->
4. Copies the web dist to `/opt/cipherbox/web/` (with `rm: true` to replace previous dist)
5. On the VPS: logs in to GHCR, pulls new images, runs database migrations (`node dist/run-migrations.js`), brings services up with `docker compose up -d`, restarts Caddy, and prunes old images

### Docker Compose services (staging)

Configuration: `docker/docker-compose.staging.yml`

| Service      | Image                                        | Description                                                                                                                              |
| ------------ | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `api`        | `ghcr.io/{owner}/cipherbox-api:{tag}`        | NestJS API, port 3000 (loopback only)                                                                                                    |
| `postgres`   | `postgres:16-alpine`                         | PostgreSQL database, port 5432 (loopback only)                                                                                           |
| `redis`      | `redis:7-alpine`                             | Redis (password-protected), port 6379 (loopback only)                                                                                    |
| `ipfs`       | `ipfs/kubo:v0.42.0`                          | Kubo IPFS node (pebbleds profile), p2p port 4001 public, API/gateway loopback                                                            |
| `tee-worker` | `ghcr.io/{owner}/cipherbox-tee-worker:{tag}` | TEE worker in `TEE_MODE=simulator` for staging                                                                                           |
| `someguy`    | `ghcr.io/ipfs/someguy:v0.11.1`               | Delegated IPFS routing (accelerated DHT), p2p port 4004 public, routing API 8190 internal-only (unlike local dev, where it is published) |
| `caddy`      | `caddy:2-alpine`                             | Reverse proxy / TLS termination / web app static serving                                                                                 |
| `alloy`      | `grafana/alloy:v1.6.1`                       | Log and metrics shipper to Grafana Cloud                                                                                                 |

The `api` service health-checks depend on both `postgres` and `redis` being healthy before starting.

### Rollback procedure

To revert a staging deployment, re-run `tag-staging.yml` pointing at the commit you want, or on the VPS:

```bash
cd /opt/cipherbox/docker
# Set TAG to the previous staging tag
export TAG=staging-YYYYMMDD-release-N
docker compose -f docker-compose.staging.yml pull
docker compose -f docker-compose.staging.yml up -d
```

<!-- VERIFY: confirm rollback steps with ops team for production procedure -->

## TEE Worker Deployment

The TEE worker handles IPNS republishing every 6 hours. It runs in two modes:

| Mode                 | Environment | Description                                        |
| -------------------- | ----------- | -------------------------------------------------- |
| `TEE_MODE=simulator` | Staging     | Runs as a plain Docker container (no hardware TEE) |
| `TEE_MODE=cvm`       | Production  | Runs inside a Phala Cloud CVM (confidential VM)    |

### Staging TEE (simulator mode)

In staging the `tee-worker` service in `docker/docker-compose.staging.yml` sets `TEE_MODE=simulator`. No Phala infrastructure is required.

### Production TEE (Phala Cloud CVM)

Configuration: `apps/tee-worker/docker-compose.phala.yml`

The TEE worker runs as a Phala Cloud CVM with the dstack socket mounted at `/var/run/dstack.sock`. Deploy using the Phala CLI:

```bash
phala deploy -c apps/tee-worker/docker-compose.phala.yml -n cipherbox-tee-staging --wait
```

**Critical:** Always **update** the existing CVM — never delete and recreate. Deleting changes the `app_id`, which would invalidate all existing epoch keys.

The image is pulled from GHCR: `ghcr.io/{owner}/cipherbox-tee-worker:{tag}`.

Environment variables required for the Phala CVM:

| Variable            | Description                              |
| ------------------- | ---------------------------------------- |
| `TEE_WORKER_SECRET` | Shared secret between API and TEE worker |

## Desktop App Packaging

The desktop app (Tauri, `apps/desktop`) is built for macOS, Windows, and Linux as part of the staging deploy workflow. There is also a dedicated `desktop-staging-release.yml` workflow triggered by `cipherbox-desktop-v*` tags.

### Build matrix

| Platform | Runner           | FUSE driver                     | Feature flag        |
| -------- | ---------------- | ------------------------------- | ------------------- |
| macOS    | `macos-latest`   | FUSE-T (installed via Homebrew) | default             |
| Windows  | `windows-latest` | WinFsp v2.1 (downloaded MSI)    | `--features winfsp` |
| Linux    | `ubuntu-22.04`   | libfuse3 (apt)                  | `--features fuse`   |

### Build steps (all platforms)

1. Check out the staging tag
2. Install platform FUSE driver (FUSE-T / WinFsp / libfuse3)
3. Install Rust toolchain (stable)
4. Install Node.js 22 and pnpm dependencies (`--frozen-lockfile`)
5. Build shared packages: `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/api-client`, `@cipherbox/sdk-core`, `@cipherbox/sdk`
6. Run `tauri-apps/tauri-action@v0` from `apps/desktop` with signing keys and staging env vars injected

### Signing

Desktop builds are signed with `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` from GitHub Actions secrets. macOS and Windows builds in staging are **unsigned** (no code-signing certificate) — users must right-click > Open (macOS) or click "More info" > "Run anyway" (Windows) on first launch.

### Auto-updater

`includeUpdaterJson: true` is set for all platforms, generating a `latest.json` updater manifest. The Tauri auto-updater checks `/releases/latest/` (GitHub Releases) which resolves to the most recent desktop release (marked latest by `desktop-staging-release.yml`'s `mark-latest` job).

### Version propagation

Release Please bumps the version in `apps/desktop/package.json` and propagates it to `apps/desktop/src-tauri/tauri.conf.json` and `apps/desktop/src-tauri/Cargo.toml` via the `extra-files` config in `release-please-config.json`.

## Landing Page Deployment

The landing page (`landing/`) is deployed in two ways:

### IPFS via deploy-landing.yml

Triggered on push to `main` affecting `landing/**`. The workflow:

1. Builds the landing page with `npm run build`
2. SCPs the dist to the staging VPS
3. Pins to IPFS via Kubo (`ipfs add -Qr --pin`)
4. Updates a Cloudflare DNSLink TXT record (`_dnslink.cipherbox.cc`) to point to the new CID <!-- VERIFY: confirm domain is cipherbox.cc -->

### Render (render.yaml)

`render.yaml` also defines a static Render service (`cipherbox-landing`) built from `landing/dist`. This serves as an alternative / fallback hosting with PR preview deployments enabled. <!-- VERIFY: confirm active Render deployment URL -->

## Monitoring

Monitoring is documented in detail in `docker/MONITORING.md`. Summary:

- **Grafana Alloy** runs as a Docker Compose sidecar, shipping logs (Docker json-file driver) to Grafana Cloud Loki and scraping the API's `/metrics` endpoint every 30 seconds for Prometheus metrics to Grafana Cloud Mimir
- **Dashboard** provisioned automatically by `deploy-staging.yml` from `docker/grafana/dashboards/cipherbox-staging.json`
- **Better Stack Uptime** monitors `https://api-staging.cipherbox.cc/health` every 3 minutes <!-- VERIFY: confirm uptime monitor is active -->

### Required Grafana secrets (GitHub Actions `staging` environment)

| Secret / Variable             | Description                                            |
| ----------------------------- | ------------------------------------------------------ |
| `GRAFANA_LOKI_URL`            | Loki push endpoint                                     |
| `GRAFANA_LOKI_USERNAME`       | Numeric Loki instance ID                               |
| `GRAFANA_LOKI_API_KEY`        | Loki publisher API key                                 |
| `GRAFANA_PROMETHEUS_URL`      | Prometheus remote write endpoint                       |
| `GRAFANA_PROMETHEUS_USERNAME` | Numeric Prometheus instance ID                         |
| `GRAFANA_PROMETHEUS_API_KEY`  | Prometheus publisher API key                           |
| `GRAFANA_API_KEY`             | Grafana Cloud API key for dashboard provisioning       |
| `GRAFANA_URL`                 | Grafana Cloud instance URL <!-- VERIFY: actual URL --> |
| `GRAFANA_DS_METRICS_UID`      | Prometheus datasource UID in Grafana                   |
| `GRAFANA_DS_LOGS_UID`         | Loki datasource UID in Grafana                         |

## Environment Variables for Staging

The staging VPS deploy generates `.env.staging` from GitHub Actions secrets and vars. The full list of required environment variables is documented in `docs/CONFIGURATION.md`.

Key secrets required in the GitHub Actions `staging` environment:

| Secret                               | Description                                    |
| ------------------------------------ | ---------------------------------------------- |
| `STAGING_SSH_KEY`                    | SSH private key for VPS access                 |
| `STAGING_DB_PASSWORD`                | PostgreSQL password                            |
| `STAGING_JWT_SECRET`                 | JWT signing secret                             |
| `STAGING_TEE_WORKER_SECRET`          | Shared secret between API and TEE worker       |
| `STAGING_REDIS_PASSWORD`             | Redis password                                 |
| `STAGING_TEST_LOGIN_SECRET`          | Test login bypass secret (non-production only) |
| `STAGING_THROTTLE_BYPASS_SECRET`     | Rate-limit bypass secret                       |
| `TAURI_SIGNING_PRIVATE_KEY`          | Desktop app update signing key                 |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Desktop app update signing key password        |
| `CLOUDFLARE_API_TOKEN`               | Cloudflare API token for DNSLink updates       |
| `CLOUDFLARE_ZONE_ID`                 | Cloudflare zone ID for the landing page domain |
| `DNSLINK_RECORD_ID`                  | DNS record ID for `_dnslink.cipherbox.cc`      |

Key vars (non-secret):

| Variable                  | Description                                                     |
| ------------------------- | --------------------------------------------------------------- |
| `STAGING_HOST`            | VPS hostname/IP <!-- VERIFY -->                                 |
| `STAGING_USER`            | VPS SSH username <!-- VERIFY -->                                |
| `STAGING_API_URL`         | Public API URL injected into web/desktop builds <!-- VERIFY --> |
| `STAGING_DB_USERNAME`     | PostgreSQL username                                             |
| `CORS_ALLOWED_ORIGINS`    | Comma-separated allowed CORS origins                            |
| `VITE_WEB3AUTH_CLIENT_ID` | Web3Auth client ID                                              |
| `GOOGLE_CLIENT_ID`        | Google OAuth client ID                                          |
| `VITE_FARO_URL`           | Grafana Faro endpoint                                           |
| `GRAFANA_STACK_ID`        | Grafana stack identifier                                        |
| `SENDGRID_FROM_EMAIL`     | SendGrid sender address                                         |

<!-- generated-by: gsd-doc-writer -->

# Configuration Reference

Environment variables and configuration files for all CipherBox monorepo applications.
For local development setup instructions, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Table of Contents

- [API (`apps/api`)](#api-appsapi)
- [Web (`apps/web`)](#web-appsweb)
- [Desktop (`apps/desktop`)](#desktop-appsdesktop)
- [TEE Worker (`apps/tee-worker`)](#tee-worker-appstee-worker)
- [Docker Compose (local dev)](#docker-compose-local-dev)
- [Docker Compose (staging)](#docker-compose-staging)
- [Observability (staging)](#observability-staging)

---

## API (`apps/api`)

NestJS server. Configuration is loaded via `@nestjs/config` (`ConfigModule.forRoot`) and read
from `.env` at startup. Copy `apps/api/.env.example` to `apps/api/.env` before first run.

### Database

| Variable      | Required | Default     | Description              |
| :------------ | :------- | :---------- | :----------------------- |
| `DB_HOST`     | No       | `localhost` | PostgreSQL host          |
| `DB_PORT`     | No       | `5432`      | PostgreSQL port          |
| `DB_USERNAME` | No       | `postgres`  | PostgreSQL user          |
| `DB_PASSWORD` | No       | `postgres`  | PostgreSQL password      |
| `DB_DATABASE` | No       | `cipherbox` | PostgreSQL database name |

### Redis

| Variable         | Required | Default     | Description                                         |
| :--------------- | :------- | :---------- | :-------------------------------------------------- |
| `REDIS_HOST`     | No       | `localhost` | Redis host                                          |
| `REDIS_PORT`     | No       | `6379`      | Redis port                                          |
| `REDIS_PASSWORD` | No       | —           | Redis password (omit for password-less connections) |

The local dev `docker/docker-compose.yml` maps the Redis container port to `6380` on the host,
so set `REDIS_PORT=6380` when using the local stack.

### Auth

| Variable            | Required | Default | Description                                                                                    |
| :------------------ | :------- | :------ | :--------------------------------------------------------------------------------------------- |
| `JWT_SECRET`        | **Yes**  | —       | HMAC secret used to sign and verify JWT access tokens. Startup fails if absent.                |
| `TEST_LOGIN_SECRET` | No       | —       | When set, enables the `/auth/test-login` endpoint for E2E test usage. Never set in production. |

### CORS

| Variable               | Required | Default                                       | Description                                                                                                     |
| :--------------------- | :------- | :-------------------------------------------- | :-------------------------------------------------------------------------------------------------------------- |
| `CORS_ALLOWED_ORIGINS` | No       | `http://localhost:5173,http://localhost:4173` | Comma-separated list of allowed origins. Supports `*` wildcards (e.g., `https://cipher-box-pr-*.onrender.com`). |

### IPFS

| Variable                 | Required | Default                 | Description                                                                 |
| :----------------------- | :------- | :---------------------- | :-------------------------------------------------------------------------- |
| `IPFS_LOCAL_API_URL`     | No       | `http://localhost:5001` | Kubo RPC API endpoint. The API relays all IPFS operations through this URL. |
| `IPFS_LOCAL_GATEWAY_URL` | No       | `http://localhost:8080` | IPFS HTTP gateway for content retrieval.                                    |

### IPNS / Delegated Routing

| Variable                         | Required | Default                      | Description                                                      |
| :------------------------------- | :------- | :--------------------------- | :--------------------------------------------------------------- |
| `DELEGATED_ROUTING_URL`          | No       | `https://delegated-ipfs.dev` | Primary HTTP delegated routing backend for IPNS publish/resolve. |
| `DELEGATED_ROUTING_FALLBACK_URL` | No       | —                            | Optional secondary backend. Used if the primary request fails.   |

### TEE Integration

| Variable            | Required | Default                 | Description                                                                |
| :------------------ | :------- | :---------------------- | :------------------------------------------------------------------------- |
| `TEE_WORKER_URL`    | No       | `http://localhost:3001` | URL of the TEE worker service. The API forwards IPNS republish jobs here.  |
| `TEE_WORKER_SECRET` | No       | `""` (empty)            | Shared secret sent as `Authorization: Bearer` when calling the TEE worker. |

### Rate Limiting

| Variable                 | Required | Default | Description                                                                                                                                     |
| :----------------------- | :------- | :------ | :---------------------------------------------------------------------------------------------------------------------------------------------- |
| `THROTTLE_BYPASS_SECRET` | No       | —       | When present, requests carrying `X-Throttle-Bypass: <secret>` skip rate limits. Bypass is blocked at the code level when `NODE_ENV=production`. |

### Application

| Variable                     | Required | Default       | Description                                                                                                                          |
| :--------------------------- | :------- | :------------ | :----------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`                       | No       | `3000`        | HTTP listen port.                                                                                                                    |
| `NODE_ENV`                   | No       | `development` | Runtime environment (`development`, `test`, `production`). Controls log verbosity, rate-limit thresholds, and TypeORM query logging. |
| `RECYCLE_BIN_RETENTION_DAYS` | No       | `30`          | Days before soft-deleted items are permanently purged. Must be a positive integer; falls back to `30` on invalid input.              |

---

## Web (`apps/web`)

Vite + React SPA. All configuration is injected as `VITE_*` environment variables at build time.
Copy `apps/web/.env.example` to `apps/web/.env` before first run.

| Variable                  | Required | Default                       | Description                                                                                                                    |
| :------------------------ | :------- | :---------------------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| `VITE_API_URL`            | No       | `http://localhost:3000`       | Base URL of the CipherBox API.                                                                                                 |
| `VITE_WEB3AUTH_CLIENT_ID` | **Yes**  | —                             | Web3Auth project client ID for key derivation and authentication. <!-- VERIFY: obtain from Web3Auth dashboard -->              |
| `VITE_GOOGLE_CLIENT_ID`   | No       | —                             | Google OAuth client ID for the Google Sign-In provider via Web3Auth. <!-- VERIFY: obtain from Google Cloud Console -->         |
| `VITE_ENVIRONMENT`        | No       | `local`                       | Deployment environment label (`local`, `staging`, `production`). Used to show the staging banner in the UI.                    |
| `VITE_APP_VERSION`        | No       | (derived from crypto version) | Application version string injected at build time. Falls back to the internal crypto library version when absent.              |
| `VITE_FARO_URL`           | No       | —                             | Grafana Faro collector endpoint. When absent, frontend observability is disabled. <!-- VERIFY: set to your Faro ingest URL --> |

---

## Desktop (`apps/desktop`)

Tauri + Vite + React application. Uses the same `VITE_*` convention as the web app.
Copy `apps/desktop/.env.example` to `apps/desktop/.env` before first run.

### Build-time (Vite) variables

| Variable                  | Required | Default                 | Description                                                                                         |
| :------------------------ | :------- | :---------------------- | :-------------------------------------------------------------------------------------------------- |
| `VITE_API_URL`            | No       | `http://localhost:3000` | Base URL of the CipherBox API.                                                                      |
| `VITE_WEB3AUTH_CLIENT_ID` | **Yes**  | —                       | Web3Auth project client ID. <!-- VERIFY: obtain from Web3Auth dashboard -->                         |
| `VITE_GOOGLE_CLIENT_ID`   | No       | —                       | Google OAuth client ID. <!-- VERIFY: obtain from Google Cloud Console -->                           |
| `VITE_ENVIRONMENT`        | No       | `local`                 | Deployment environment label.                                                                       |
| `VITE_TEST_LOGIN_SECRET`  | No       | —                       | Enables the test-login path inside the desktop app for E2E testing. Never set in production builds. |

### Runtime (Rust backend) variables

The Tauri Rust backend loads `apps/desktop/.env` at startup and resolves the API base URL in
this order:

1. Runtime env `CIPHERBOX_API_URL` (manual override)
2. Runtime env `VITE_API_URL`
3. Compile-time `VITE_API_URL` (baked into release builds by CI)
4. Fallback `http://localhost:3000`

| Variable            | Required | Default | Description                                                                                                                     |
| :------------------ | :------- | :------ | :------------------------------------------------------------------------------------------------------------------------------ |
| `CIPHERBOX_API_URL` | No       | —       | Runtime override for the API base URL used by the Rust backend (sync engine, FUSE mount). Takes precedence over `VITE_API_URL`. |

### Tauri configuration (`apps/desktop/src-tauri/tauri.conf.json`)

Static build-time configuration — not environment-variable driven.

| Key                                 | Value                         | Description                                  |
| :---------------------------------- | :---------------------------- | :------------------------------------------- |
| `productName`                       | `CipherBox`                   | Application display name.                    |
| `identifier`                        | `com.cipherbox.desktop`       | Bundle identifier used on macOS and Linux.   |
| `plugins.updater.endpoints`         | GitHub Releases `latest.json` | Auto-updater manifest URL.                   |
| `plugins.deep-link.desktop.schemes` | `cipherbox`                   | Custom URL scheme registered with the OS.    |
| `build.devUrl`                      | `http://localhost:1420`       | Vite dev server URL used during `tauri dev`. |

The updater `pubkey` in `tauri.conf.json` is the Minisign public key used to verify update
artifacts — it is safe to commit and is not a secret.

---

## TEE Worker (`apps/tee-worker`)

Standalone Express server. Runs inside a Phala Cloud CVM in production and in a local
Docker container (simulator mode) in development and staging.

Copy `apps/tee-worker/.env.example` to `apps/tee-worker/.env` for local development.

| Variable                | Required | Default           | Description                                                                                                                                                                 |
| :---------------------- | :------- | :---------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`                  | No       | `3001`            | HTTP listen port.                                                                                                                                                           |
| `NODE_ENV`              | No       | —                 | Runtime environment. Setting `production` while `TEE_MODE=simulator` is blocked at startup.                                                                                 |
| `TEE_MODE`              | No       | `simulator`       | Key derivation mode. `simulator` uses HKDF from a fixed seed (development/testing). `cvm` uses Phala dstack SDK for hardware-backed key derivation (production).            |
| `CIPHERBOX_ENVIRONMENT` | No       | —                 | Explicit environment label (`staging`, `production`). Used alongside `NODE_ENV` to enforce that `TEE_MODE=simulator` is never used in production.                           |
| `TEE_WORKER_SECRET`     | **Yes**  | —                 | Shared secret for Bearer token authentication on all protected routes. Must match the `TEE_WORKER_SECRET` set in the API.                                                   |
| `TEE_CURRENT_EPOCH`     | No       | `1`               | The current `keyEpoch` number. The TEE worker exposes the `teePublicKey` for this epoch on `GET /public-key`. Used by the migration route to identify the active key epoch. |
| `IPFS_GATEWAY_URL`      | No       | `https://ipfs.io` | IPFS gateway URL used when fetching CIDs during CID migration operations.                                                                                                   |

### TEE mode semantics

The `TEE_MODE` variable determines how epoch keypairs are derived:

- **`simulator`** — HKDF-SHA256 derivation from a fixed seed. Deterministic across restarts.
  Used for local development and staging. Never allowed when `NODE_ENV=production` or
  `CIPHERBOX_ENVIRONMENT=production`.
- **`cvm`** — Phala dstack `DstackClient.getKey()` call. Hardware-backed, non-extractable.
  Required for production Phala Cloud CVM deployments.

---

## Docker Compose (local dev)

File: `docker/docker-compose.yml`

Starts PostgreSQL, IPFS (Kubo), Redis, Someguy (delegated routing), and a mock IPNS routing
server for local development. Environment variables can be overridden with a `.env` file in the
`docker/` directory or by setting them in the shell before running `docker compose up`.

| Variable      | Default     | Description                                               |
| :------------ | :---------- | :-------------------------------------------------------- |
| `DB_USERNAME` | `postgres`  | PostgreSQL superuser name.                                |
| `DB_PASSWORD` | `postgres`  | PostgreSQL superuser password.                            |
| `DB_DATABASE` | `cipherbox` | Database name to create.                                  |
| `DB_PORT`     | `5432`      | Host port mapped to PostgreSQL 5432 inside the container. |
| `REDIS_PORT`  | `6380`      | Host port mapped to Redis 6379 inside the container.      |

Service ports exposed to the host:

| Service                     | Port(s)                        | Notes                          |
| :-------------------------- | :----------------------------- | :----------------------------- |
| PostgreSQL                  | `5432` (configurable)          |                                |
| IPFS API                    | `5001`                         | Bound to all interfaces in dev |
| IPFS Gateway                | `8080`                         | Bound to all interfaces in dev |
| Redis                       | `6380` (configurable)          |                                |
| Someguy (delegated routing) | `8190` (HTTP), `4004` (libp2p) |                                |
| Mock IPNS routing           | `3001` (localhost only)        |                                |

---

## Docker Compose (staging)

File: `docker/docker-compose.staging.yml`

Deploys the full stack including the API, IPFS, Redis, PostgreSQL, TEE worker, Someguy, Caddy
reverse proxy, and Grafana Alloy for log/metrics forwarding.

The API service reads its environment from `.env.staging` (passed via `env_file`). <!-- VERIFY: create .env.staging on the staging host with all required API variables -->

### Required staging variables

These variables must be set in `.env.staging` (API) or directly in the Docker Compose
environment block (infrastructure services):

| Variable                 | Service          | Notes                                                          |
| :----------------------- | :--------------- | :------------------------------------------------------------- |
| `DB_USERNAME`            | postgres         | Defaults to `cipherbox`                                        |
| `DB_PASSWORD`            | postgres         | **Required** — no default in staging                           |
| `DB_DATABASE`            | postgres         | Defaults to `cipherbox_staging`                                |
| `JWT_SECRET`             | api              | **Required** — any strong random string                        |
| `REDIS_PASSWORD`         | redis / api      | **Required** — staging Redis runs with `requirepass`           |
| `TEE_WORKER_SECRET`      | tee-worker / api | Must match between both services                               |
| `CORS_ALLOWED_ORIGINS`   | api              | Set to the deployed web app origin(s)                          |
| `IPFS_LOCAL_API_URL`     | api              | Typically `http://ipfs:5001` inside compose network            |
| `IPFS_LOCAL_GATEWAY_URL` | api              | Typically `http://ipfs:8080` inside compose network            |
| `DELEGATED_ROUTING_URL`  | api              | Set to `http://someguy:8190` to use the local Someguy instance |
| `TEE_WORKER_URL`         | api              | Typically `http://tee-worker:3001` inside compose network      |

### Phala Cloud CVM (production TEE worker)

File: `apps/tee-worker/docker-compose.phala.yml`

Used for production TEE deployments on Phala Cloud. Key constraint: always **update** the
existing CVM using the same `--name` value — never delete and recreate. Recreating changes the
`app_id`, which invalidates all epoch-derived keys.

| Variable                  | Source           | Notes                                     |
| :------------------------ | :--------------- | :---------------------------------------- |
| `TEE_WORKER_SECRET`       | host environment | Injected at deploy time                   |
| `GITHUB_REPOSITORY_OWNER` | host environment | Used to resolve the container image path  |
| `TAG`                     | host environment | Image tag to deploy; defaults to `latest` |

---

## Observability (staging)

Grafana Alloy (`docker/docker-compose.staging.yml` `alloy` service) ships logs and metrics
to Grafana Cloud. The following variables are passed to the Alloy container:

| Variable                      | Description                                                                           |
| :---------------------------- | :------------------------------------------------------------------------------------ |
| `GRAFANA_LOKI_URL`            | Loki push endpoint <!-- VERIFY: Grafana Cloud Loki ingest URL -->                     |
| `GRAFANA_LOKI_USERNAME`       | Loki basic-auth username <!-- VERIFY: Grafana Cloud username -->                      |
| `GRAFANA_LOKI_API_KEY`        | Loki API key / password <!-- VERIFY: Grafana Cloud API key -->                        |
| `GRAFANA_PROMETHEUS_URL`      | Prometheus remote-write endpoint <!-- VERIFY: Grafana Cloud Prometheus ingest URL --> |
| `GRAFANA_PROMETHEUS_USERNAME` | Prometheus basic-auth username <!-- VERIFY: Grafana Cloud username -->                |
| `GRAFANA_PROMETHEUS_API_KEY`  | Prometheus API key / password <!-- VERIFY: Grafana Cloud API key -->                  |

These values are stored as secrets in the staging deployment environment and are never committed
to the repository.

<!-- generated-by: gsd-doc-writer -->

# Configuration Reference

> **v1 document — partially superseded.** This catalogue was written against the v1 stack as of the freeze (`v1-freeze`, branch `v1`) and still names variables the v2 code no longer reads. The code is authoritative for which names are live; entries here are a starting point, not a contract. For the local stack itself, see the "Getting started" section of the root [`README.md`](../README.md).

Environment variables and configuration files for all CipherBox monorepo applications.

## Table of Contents

- [API (`apps/api`)](#api-appsapi)
- [Web (`apps/web`)](#web-appsweb)
- [Desktop (`apps/desktop`)](#desktop-appsdesktop)
- [Docker Compose (local dev)](#docker-compose-local-dev)
- [Docker Compose (staging)](#docker-compose-staging)
- [Observability (staging)](#observability-staging)

---

## API (`apps/api`)

NestJS server. Configuration is loaded via `@nestjs/config` (`ConfigModule.forRoot`) and read
from `.env` at startup. Copy `apps/api/.env.example` to `apps/api/.env` before first run; that
template carries the local stack's values and is the one this catalogue extends.

### Database

| Variable      | Required | Default     | Description              |
| :------------ | :------- | :---------- | :----------------------- |
| `DB_HOST`     | No       | `localhost` | PostgreSQL host          |
| `DB_PORT`     | No       | `5432`      | PostgreSQL port          |
| `DB_USERNAME` | No       | `postgres`  | PostgreSQL user          |
| `DB_PASSWORD` | No       | `postgres`  | PostgreSQL password      |
| `DB_DATABASE` | No       | `cipherbox` | PostgreSQL database name |

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

| Variable       | Required | Default | Description                                                                             |
| :------------- | :------- | :------ | :-------------------------------------------------------------------------------------- |
| `KUBO_API_URL` | No       | —       | Kubo RPC endpoint for the hosted pin store. Unset, hosted uploads are refused with 503. |

### IPNS / Delegated Routing

| Variable         | Required | Default | Description                                                                                              |
| :--------------- | :------- | :------ | :------------------------------------------------------------------------------------------------------- |
| `ROUTING_V1_URL` | No       | —       | `/routing/v1` endpoint the republisher resolves and re-PUTs through. Unset, the republisher walk no-ops. |

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

| Variable                  | Required | Default                       | Description                                                                                                                                                                    |
| :------------------------ | :------- | :---------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VITE_API_URL`            | No       | `http://localhost:3000`       | Base URL of the CipherBox API.                                                                                                                                                 |
| `VITE_WEB3AUTH_CLIENT_ID` | **Yes**  | —                             | Web3Auth project client ID for key derivation and authentication. <!-- VERIFY: obtain from Web3Auth dashboard -->                                                              |
| `VITE_WEB3AUTH_VERIFIER`  | **Yes**  | —                             | Web3Auth Core Kit verifier name. Login needs this and both client IDs; missing any refuses the session. <!-- VERIFY: obtain from Web3Auth dashboard -->                        |
| `VITE_GOOGLE_CLIENT_ID`   | **Yes**  | —                             | Google OAuth client ID the verifier's Google sub-verifier is registered against — not interchangeable with the Web3Auth one. <!-- VERIFY: obtain from Google Cloud Console --> |
| `VITE_ENVIRONMENT`        | No       | `local`                       | Deployment environment label (`local`, `staging`, `production`). Used to show the staging banner in the UI.                                                                    |
| `VITE_APP_VERSION`        | No       | (derived from crypto version) | Application version string injected at build time. Falls back to the internal crypto library version when absent.                                                              |
| `VITE_FARO_URL`           | No       | —                             | Grafana Faro collector endpoint. When absent, frontend observability is disabled. <!-- VERIFY: set to your Faro ingest URL -->                                                 |

---

## Desktop (`apps/desktop`)

The v2 Tauri shell is a skeleton: it carries no TypeScript sources and reads no environment
variable, so there is no `apps/desktop/.env.example` to copy and nothing here to configure.
The tables that stood here described the v1 desktop app and named variables — `VITE_GOOGLE_CLIENT_ID`,
`VITE_TEST_LOGIN_SECRET`, `CIPHERBOX_API_URL` — that no code reads. They are removed rather
than corrected; `blueprint/desktop.md` is normative for what the shell will need.

---

## Docker Compose (local dev)

File: `docker/docker-compose.yml`

Starts PostgreSQL, IPFS (Kubo), Someguy (delegated routing), and a mock IPNS routing
server for local development. Environment variables can be overridden with a `.env` file in the
`docker/` directory or by setting them in the shell before running `docker compose up`.

| Variable      | Default     | Description                                               |
| :------------ | :---------- | :-------------------------------------------------------- |
| `DB_USERNAME` | `postgres`  | PostgreSQL superuser name.                                |
| `DB_PASSWORD` | `postgres`  | PostgreSQL superuser password.                            |
| `DB_DATABASE` | `cipherbox` | Database name to create.                                  |
| `DB_PORT`     | `5432`      | Host port mapped to PostgreSQL 5432 inside the container. |

Service ports exposed to the host:

| Service                     | Port(s)                        | Notes                          |
| :-------------------------- | :----------------------------- | :----------------------------- |
| PostgreSQL                  | `5432` (configurable)          |                                |
| IPFS API                    | `5001`                         | Bound to all interfaces in dev |
| IPFS Gateway                | `8080`                         | Bound to all interfaces in dev |
| Someguy (delegated routing) | `8190` (HTTP), `4004` (libp2p) |                                |
| Mock IPNS routing           | `3001` (localhost only)        |                                |

---

## Docker Compose (staging)

File: `docker/docker-compose.staging.yml`

Deploys the full stack including the API, IPFS, PostgreSQL, Someguy, Caddy reverse proxy, and
Grafana Alloy for log/metrics forwarding.

The API service reads its environment from `.env.staging` (passed via `env_file`). <!-- VERIFY: create .env.staging on the staging host with all required API variables -->

### Required staging variables

These variables must be set in `.env.staging` (API) or directly in the Docker Compose
environment block (infrastructure services):

| Variable               | Service  | Notes                                                   |
| :--------------------- | :------- | :------------------------------------------------------ |
| `DB_USERNAME`          | postgres | Defaults to `cipherbox`                                 |
| `DB_PASSWORD`          | postgres | **Required** — no default in staging                    |
| `DB_DATABASE`          | postgres | Defaults to `cipherbox_staging`                         |
| `JWT_SECRET`           | api      | **Required** — any strong random string                 |
| `CORS_ALLOWED_ORIGINS` | api      | Set to the deployed web app origin(s)                   |
| `KUBO_API_URL`         | api      | Typically `http://ipfs:5001` inside compose network     |
| `ROUTING_V1_URL`       | api      | `http://someguy:8190` to use the local Someguy instance |

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

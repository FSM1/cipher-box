# Development Guide

## Prerequisites

- **Node.js** 20+
- **pnpm** 9+
- **Docker** (for PostgreSQL, IPFS, Redis)
- **Rust** toolchain (desktop app only)

## Infrastructure

Start the required services:

```bash
docker compose -f docker/docker-compose.yml up -d
```

This starts the `cipherbox-infrastructure` compose project (containers are named `cipherbox-<service>`):

| Service             | Image                                 | Host Port(s)                                     | Purpose                                  |
| :------------------ | :------------------------------------ | :----------------------------------------------- | :--------------------------------------- |
| `postgres`          | `postgres:16-alpine`                  | 5432 (`DB_PORT`)                                 | Database                                 |
| `ipfs`              | `ipfs/kubo:v0.42.0`                   | 5001 (API), 8080 (gateway), 4001 tcp/udp (swarm) | Decentralized storage (Kubo)             |
| `redis`             | `redis:7-alpine`                      | 6380 (`REDIS_PORT`) → container 6379             | BullMQ job queue                         |
| `someguy`           | `ghcr.io/ipfs/someguy:v0.11.1`        | 8190 (routing API), 4004 tcp/udp (libp2p swarm)  | Delegated IPFS routing (accelerated DHT) |
| `mock-ipns-routing` | built from `tools/mock-ipns-routing/` | 3001 (loopback only)                             | Local IPNS resolution for dev/E2E        |

Notes:

- The IPFS node runs with the `server,pebbleds` datastore profile. If you have an `ipfs_data` volume created before the pebbleds switch, recreate it first: `docker compose -f docker/docker-compose.yml down -v --remove-orphans`.
- The `ipfs` container is capped at 3 GB memory / 1.5 CPU; the `someguy` container is capped at 2 GB memory / 1 CPU.
- The staging stack runs a different set of containers (adds `api`, `tee-worker`, `caddy`, `alloy`; drops `mock-ipns-routing`) — see [DEPLOYMENT.md](DEPLOYMENT.md).

## Environment

Copy the example env files:

```bash
cp apps/api/.env.example apps/api/.env
cp apps/web/.env.example apps/web/.env
```

### API (`apps/api/.env`)

Key variables:

| Variable               | Default                 | Notes                                   |
| :--------------------- | :---------------------- | :-------------------------------------- |
| `DB_HOST`              | `localhost`             | PostgreSQL host                         |
| `DB_PORT`              | `5432`                  | PostgreSQL port                         |
| `JWT_SECRET`           | —                       | Required, any random string             |
| `REDIS_HOST`           | `localhost`             | Redis host                              |
| `REDIS_PORT`           | `6380`                  | Redis port (mapped from container 6379) |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173` | Frontend origin                         |

### Web (`apps/web/.env`)

| Variable                  | Default                    | Notes               |
| :------------------------ | :------------------------- | :------------------ |
| `VITE_WEB3AUTH_CLIENT_ID` | Provided in `.env.example` | Web3Auth project ID |
| `VITE_API_URL`            | `http://localhost:3000`    | API endpoint        |

## Running the Web App

```bash
# Install dependencies (first time)
pnpm install

# Start API + web concurrently
pnpm dev
```

- API: <http://localhost:3000>
- Web: <http://localhost:5173>

Or run individually:

```bash
pnpm --filter @cipherbox/api dev    # API only
pnpm --filter @cipherbox/web dev    # Web only
```

## Running the Desktop App

### Additional prerequisites

- **macOS:** [FUSE-T](https://www.fuse-t.org/) (`brew install macos-fuse-t/homebrew-cask/fuse-t`)
- **Windows:** [WinFSP](https://winfsp.dev/)
- **Linux:** `libfuse3-dev` (or equivalent)

```bash
cp apps/desktop/.env.example apps/desktop/.env
pnpm --filter @cipherbox/desktop dev
```

The desktop app defaults to the staging API. For local development, update `apps/desktop/.env`:

```bash
VITE_API_URL=http://localhost:3000
VITE_ENVIRONMENT=local
```

The Rust backend also needs the local API URL. Either set it in your shell or prefix the dev command:

```bash
CIPHERBOX_API_URL=http://localhost:3000 pnpm --filter @cipherbox/desktop dev
```

See [apps/desktop/CLAUDE.md](../apps/desktop/CLAUDE.md) for FUSE architecture details and dev-key mode.

## Testing

### Unit tests

```bash
# Run all unit tests (excludes E2E)
pnpm --filter @cipherbox/api test
pnpm --filter @cipherbox/web test
pnpm --filter @cipherbox/crypto test
```

> **Note:** `pnpm test` runs tests across all workspaces including E2E — use the filtered commands above for unit tests only.

### E2E tests (Playwright)

Playwright auto-starts API + web via `webServer` config (requires infra services: Postgres, IPFS, Redis):

```bash
pnpm test:web-e2e
```

Headed mode (shows browser):

```bash
pnpm test:web-e2e:headed
```

### Desktop E2E

```bash
cd tests/desktop-e2e
pnpm exec playwright test
```

## API Client Generation

After modifying API endpoints, DTOs, or controllers, regenerate the typed client to keep the web app in sync:

```bash
pnpm api:generate
```

This generates the OpenAPI spec from the API, creates the typed client at `packages/api-client/`, and runs lint fixes. Always commit the regenerated files with your API changes.

## Code Quality

- **Linting:** `pnpm lint` (ESLint) / `pnpm lint:fix`
- **Markdown:** `pnpm lint:md` / `pnpm lint:md:fix`
- **Type checking:** `pnpm typecheck`
- **Formatting:** Prettier (runs via lint-staged on commit)
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) enforced by commitlint (`feat:`, `fix:`, `docs:`, etc.)

## Running the TEE Worker (Simulator Mode)

The TEE worker (`apps/tee-worker`) republishes IPNS records. In production it runs inside a Phala Cloud CVM; locally it runs in **simulator mode**, which uses a deterministic HKDF-SHA256 seed instead of hardware-backed key derivation.

Set the required environment variables and start the worker:

```bash
TEE_MODE=simulator TEE_WORKER_SECRET=dev-secret pnpm --filter cipherbox-tee-worker dev
```

The worker listens on port `3001` by default. Note that the `mock-ipns-routing` container also binds `127.0.0.1:3001` — when running the worker alongside the local Docker infrastructure, pick a free port (e.g. `PORT=3002`) and point `TEE_WORKER_URL` at it. The API authenticates to the TEE worker using a shared `Bearer` token — set the same value in `apps/api/.env`:

```bash
TEE_WORKER_SECRET=dev-secret
TEE_WORKER_URL=http://localhost:3001
```

Key variables:

| Variable            | Required | Notes                                           |
| :------------------ | :------- | :---------------------------------------------- |
| `TEE_MODE`          | Yes      | `simulator` (local) or `cvm` (Phala Cloud prod) |
| `TEE_WORKER_SECRET` | Yes      | Shared secret for Bearer token auth             |
| `PORT`              | No       | Defaults to `3001`                              |

`TEE_MODE=simulator` is blocked at runtime if `NODE_ENV=production` or `CIPHERBOX_ENVIRONMENT=production` to prevent accidental use of the fixed seed in production.

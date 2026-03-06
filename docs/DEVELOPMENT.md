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

This starts:

| Service           | Port                       | Purpose                           |
| :---------------- | :------------------------- | :-------------------------------- |
| PostgreSQL 16     | 5432                       | Database                          |
| IPFS (Kubo)       | 5001 (API), 8080 (Gateway) | Decentralized storage             |
| Redis 7           | 6380                       | BullMQ job queue                  |
| Mock IPNS Routing | 3001                       | Local IPNS resolution for dev/E2E |

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
pnpm test:e2e
```

Headed mode (shows browser):

```bash
pnpm test:e2e:headed
```

### Desktop E2E

```bash
cd tests/e2e-desktop
pnpm exec playwright test
```

## API Client Generation

After modifying API endpoints, DTOs, or controllers, regenerate the typed client to keep the web app in sync:

```bash
pnpm api:generate
```

This generates the OpenAPI spec from the API, creates the typed client at `apps/web/src/api/`, and runs lint fixes. Always commit the regenerated files with your API changes.

## Code Quality

- **Linting:** `pnpm lint` (ESLint) / `pnpm lint:fix`
- **Markdown:** `pnpm lint:md` / `pnpm lint:md:fix`
- **Type checking:** `pnpm typecheck`
- **Formatting:** Prettier (runs via lint-staged on commit)
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) enforced by commitlint (`feat:`, `fix:`, `docs:`, etc.)

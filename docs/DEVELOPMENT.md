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
- **Strict IPNS verification cutover (Phase 60):** If your local database was created before the strict-verify cutover landed, it contains `folder_ipns` records with `sequence_number = 0` (embedded-0 records) that the API now rejects. These records cause fail-closed errors on any IPNS publish or resolve. Wipe your local database and let the API recreate it via migrations before running the strict build: `dropdb cipherbox && createdb cipherbox && pnpm --filter @cipherbox/api dev`. See [docs/DATABASE_EVOLUTION_PROTOCOL.md](DATABASE_EVOLUTION_PROTOCOL.md) §7 (Environment Behavior Matrix) for the full reset procedure.

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

### Test architecture and CI coverage (the deliberate split)

The repo follows a deliberate testing split, and CI enforces it accordingly (decision D-06):

- **Reusable / business logic → `packages/sdk` (Vitest, CI-gated).** Any logic worth unit-testing is hoisted out of `apps/web` into `packages/sdk` (or another package), where it is covered by Vitest. These suites run in the blocking CI `Test` job (`.github/workflows/ci.yml`), alongside `crypto`, `core`, `sdk-core`, `sdk`, `api-client`, and `api`.
- **UI behavior → Playwright web-e2e.** User-facing flows are covered by the Playwright web-e2e suite (`pnpm test:web-e2e`), which is dispatch/main-push gated rather than a per-PR blocking unit job.
- **`apps/web` Vitest is intentionally NOT in a blocking CI unit-test job.** A residual `apps/web` `*.test.ts` suite exists (10 files / 67 tests) and must stay green, but it is deliberately excluded from the blocking CI `Test` job. This is a decision, not an accidental gap: gating CI on `apps/web` Vitest would invite UI-coupled unit tests, which the split above is designed to prevent. Logic that deserves a unit test belongs in `packages/sdk`, not in a web-local test.

Two caveats when working with the residual `apps/web` suite:

- **`.spec.ts` is silently skipped.** The `apps/web` Vitest `include` glob matches `*.test.ts` only, so any `*.spec.ts` file is silently excluded — never rely on a `.spec.ts` under `apps/web` being executed.
- **Build the cross-package dist chain first.** Running the web suite locally requires the workspace dist to be built, or workspace-package resolution fails. Build the chain, then run the suite:

  ```bash
  pnpm --filter @cipherbox/crypto build \
    && pnpm --filter @cipherbox/core build \
    && pnpm --filter @cipherbox/api-client build \
    && pnpm --filter @cipherbox/sdk-core build \
    && pnpm --filter @cipherbox/sdk build \
    && cd apps/web && pnpm vitest run
  ```

If a residual `apps/web` test genuinely rots, relocate its logic to `packages/sdk` (Vitest) or remove the dead test — do not add new `apps/web` unit tests, and do not paper over a real failure by skipping it.

### Strict IPNS verification — wipe local DB first

The strict fail-closed IPNS verification cutover (Phase 60 / HARD-11) rejects any IPNS record that embeds sequence `0`. A local dev database created before the cutover holds such "embedded-0" records, so a pre-existing vault or folder will fail strict verification and fail to resolve. Before running the strict build against an existing local DB, wipe it per [`DATABASE_EVOLUTION_PROTOCOL.md`](./DATABASE_EVOLUTION_PROTOCOL.md) (§reset) and log in again — the vault self-bootstraps fresh strict-verified records. Because all IPNS keys are deterministically derived from the Web3Auth key, the wipe is non-destructive to identity.

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

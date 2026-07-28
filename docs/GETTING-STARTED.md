<!-- generated-by: gsd-doc-writer -->

# Getting Started with CipherBox

CipherBox is a privacy-first encrypted cloud storage system using IPFS/IPNS and Web3Auth.
This guide takes you from a fresh checkout to a running local stack.

## Prerequisites

| Tool           | Version    | Notes                                          |
| :------------- | :--------- | :--------------------------------------------- |
| Node.js        | 20+        | Used by all JS/TS workspaces                   |
| pnpm           | 10.33.0    | Declared in `packageManager` field             |
| Docker         | Any recent | Runs PostgreSQL, IPFS, Redis, and mock routing |
| Rust toolchain | stable     | Desktop app, and the web app's engine WASM     |

No `.nvmrc` is present; use your system Node version manager to select Node 20+.

`apps/web` compiles `crates/wasm` into the engine worker's artifact on every `dev`/`build`, so it also
needs the browser target and a `wasm-bindgen-cli` matching the `wasm-bindgen` version in `Cargo.lock`:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version "$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | grep '^version' | head -1 | sed 's/.*"\(.*\)".*/\1/')" --locked
```

For the desktop app, also install the platform FUSE driver:

- **macOS:** `brew install macos-fuse-t/homebrew-cask/fuse-t`
- **Windows:** [WinFSP](https://winfsp.dev/)
- **Linux:** `libfuse3-dev` (or the equivalent for your distribution)

## Installation

```bash
git clone https://github.com/YOUR_ORG/cipher-box.git
cd cipher-box
pnpm install
```

## Local Infrastructure

All required backing services are defined in `docker/docker-compose.yml`. Start them before
running any application:

```bash
docker compose -f docker/docker-compose.yml up -d
```

This starts the following services:

| Service                     | Port(s)                                  | Purpose                               |
| :-------------------------- | :--------------------------------------- | :------------------------------------ |
| PostgreSQL 16               | 5432                                     | Primary database                      |
| IPFS (Kubo v0.40.0)         | 5001 (API), 8080 (Gateway), 4001 (Swarm) | Decentralized file storage            |
| Redis 7                     | 6380 (host) → 6379 (container)           | BullMQ job queue                      |
| Someguy (delegated routing) | 8190 (HTTP), 4004 (libp2p)               | IPFS DHT routing                      |
| Mock IPNS routing           | 3001                                     | Local IPNS resolution for dev and E2E |

Wait for all containers to be healthy before starting the applications:

```bash
docker compose -f docker/docker-compose.yml ps
```

## Environment Setup

Copy the example environment files for each application you intend to run:

```bash
cp apps/api/.env.example apps/api/.env
cp apps/web/.env.example apps/web/.env
```

At minimum, set `JWT_SECRET` in `apps/api/.env` — startup fails without it. The default values
for all other variables in the `.env.example` files match the local Docker Compose stack.

For the full list of variables and their descriptions, see [CONFIGURATION.md](CONFIGURATION.md).

### Redis port note

The Docker Compose file maps the Redis container port to **6380** on the host. Ensure
`apps/api/.env` contains `REDIS_PORT=6380` (this is already set in `.env.example`).

## Running the Web Stack

Start the API and web app together:

```bash
pnpm dev
```

This runs `@cipherbox/api` and `@cipherbox/web` concurrently via `concurrently`.

Or run each individually:

```bash
pnpm --filter @cipherbox/api dev
pnpm --filter @cipherbox/web dev
```

Default URLs:

- API: `http://localhost:3000`
- Web: `http://localhost:5173`

## Running the Desktop App

The desktop app requires the Rust toolchain and a FUSE driver (see Prerequisites above).

```bash
cp apps/desktop/.env.example apps/desktop/.env
pnpm --filter @cipherbox/desktop dev
```

The desktop app targets the **staging API by default**. To develop against your local API,
edit `apps/desktop/.env`:

```env
VITE_API_URL=http://localhost:3000
VITE_ENVIRONMENT=local
```

Also pass the API URL to the Rust backend:

```bash
CIPHERBOX_API_URL=http://localhost:3000 pnpm --filter @cipherbox/desktop dev
```

## Running the TEE Worker

The TEE worker handles IPNS republishing. It is not required for basic web app development.

```bash
pnpm --filter cipherbox-tee-worker dev
```

## First-Use Walkthrough

1. Start infrastructure: `docker compose -f docker/docker-compose.yml up -d`
2. Start the web stack: `pnpm dev`
3. Open `http://localhost:5173` in your browser
4. Log in using Web3Auth (social login or wallet)
5. On first login a new encrypted vault is created — you will be prompted to save your
   recovery factor
6. Upload a file using the drag-and-drop interface or the upload button
7. The file is encrypted client-side and stored on IPFS; the metadata is published to IPNS

## Common Setup Issues

### `JWT_SECRET` is missing

The API exits immediately at startup if `JWT_SECRET` is not set in `apps/api/.env`. Set it
to any non-empty string for local development.

### Redis connection refused

The Docker Compose stack maps Redis to port 6380, not the default 6379. Confirm
`REDIS_PORT=6380` in `apps/api/.env`.

### IPFS container unhealthy

The IPFS container has a 30-second start period. If `docker compose ps` shows it as unhealthy
immediately after starting, wait 30–60 seconds and check again. If it remains unhealthy:

```bash
docker compose -f docker/docker-compose.yml logs ipfs
```

### pnpm version mismatch

The `packageManager` field pins pnpm to `10.33.0`. If your global pnpm differs, enable
[Corepack](https://nodejs.org/api/corepack.html) to use the pinned version automatically:

```bash
corepack enable
```

## Next Steps

- [DEVELOPMENT.md](DEVELOPMENT.md) — build commands, code style, branch conventions, PR process
- [CONFIGURATION.md](CONFIGURATION.md) — full environment variable reference for all apps
- [ARCHITECTURE.md](ARCHITECTURE.md) — system architecture and component overview
- [TESTING.md](TESTING.md) — how to run unit tests and E2E tests

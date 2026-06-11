<!-- generated-by: gsd-doc-writer -->

# @cipherbox/api

NestJS backend for CipherBox. Zero-knowledge relay: issues auth tokens, proxies IPFS uploads and IPNS reads/writes through Kubo, manages TEE key state, and serves share/vault/pinning endpoints. The server never holds plaintext content or unencrypted keys.

Part of the [CipherBox monorepo](../../README.md).

## Module overview

| Module            | Purpose                                                                |
| ----------------- | ---------------------------------------------------------------------- |
| `auth`            | Web3Auth token exchange, JWT issuance, Argon2 password handling        |
| `ipfs`            | File upload/download relay to Kubo                                     |
| `ipns`            | IPNS record publish/resolve relay; delegated routing client            |
| `republish`       | BullMQ queue that schedules TEE-driven IPNS republishing every 6 hours |
| `tee`             | `teePublicKey` state, key-rotation log, TEE attestation endpoints      |
| `shares`          | File/folder share creation, invite management                          |
| `vault`           | Vault export/import coordination                                       |
| `device-approval` | Multi-device approval flow                                             |
| `health`          | `@nestjs/terminus` health checks                                       |
| `metrics`         | Prometheus metrics via `prom-client`                                   |

## Key scripts

```bash
pnpm dev                  # Start with watch mode (NestJS)
pnpm build                # Compile to dist/
pnpm start:prod           # Run compiled output
pnpm lint                 # ESLint
pnpm test                 # Unit tests (jest)
pnpm test:e2e             # End-to-end tests
pnpm migrate:dev          # Run pending TypeORM migrations
pnpm migration:generate   # Generate a new migration from entity diff
pnpm migration:revert     # Revert the last migration
```

## Client regeneration

After modifying any endpoint, DTO, or controller, regenerate the typed API client from the monorepo root:

```bash
pnpm api:generate
```

This generates the OpenAPI spec, rebuilds `@cipherbox/api-client`, and runs lint fixes. Commit the regenerated files alongside your API changes — a pre-commit hook enforces this.

## Configuration

All environment variables are documented in [../../docs/CONFIGURATION.md](../../docs/CONFIGURATION.md) (or `docs/CONFIGURATION.md` from the monorepo root). Copy `.env.example` to `.env` for local development.

## Database migrations

Migration discipline and TypeORM rules are documented in [../../docs/DATABASE_EVOLUTION_PROTOCOL.md](../../docs/DATABASE_EVOLUTION_PROTOCOL.md). Always generate migrations via `pnpm migration:generate` — never edit entity files without a corresponding migration.

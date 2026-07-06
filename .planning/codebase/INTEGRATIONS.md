# External Integrations

**Analysis Date:** 2026-03-27
**Drift review:** 2026-06-19

## APIs & External Services

**IPFS / IPNS:**

- IPFS (Kubo) - Encrypted file content storage and pinning
  - SDK/Client: Kubo HTTP API via `apps/api/src/ipfs/`
  - Auth: None (local daemon)
  - Env: `IPFS_LOCAL_API_URL` (default `http://localhost:5001`), `IPFS_LOCAL_GATEWAY_URL` (default `http://localhost:8080`)
  - CI: `ipfs/kubo:v0.42.0` service container
  - API Endpoints: `POST /ipfs/upload`, `GET /ipfs/:cid`, `POST /ipfs/unpin`

- Delegated IPNS Routing - IPNS record publishing and resolution
  - Client: `apps/api/src/ipns/delegated-routing.client.ts`
  - Primary: Self-hosted Someguy sidecar (staging/production, `http://someguy:8190`)
  - Fallback: `https://delegated-ipfs.dev` (public, unreliable)
  - Env: `DELEGATED_ROUTING_URL`, `DELEGATED_ROUTING_FALLBACK_URL` (optional)
  - Metrics: `cipherbox_delegated_routing_fallbacks_total`
  - API Endpoints: `POST /ipns/publish`, `POST /ipns/publish-batch`, `GET /ipns/resolve`
  - Retry: Exponential backoff (3 retries, 1s base, 30s cap)

**Web3Auth:**

- Web3Auth MPC Core Kit - Authentication and deterministic keypair derivation
  - SDK/Client: `@web3auth/mpc-core-kit` ^3.5.0
  - Location: `apps/web/src/lib/web3auth/`
  - Auth methods: Email OTP, Google OAuth, Magic Link, External Wallet
  - JWKS endpoint: `https://api-auth.web3auth.io/jwks`
  - Backend validation: `apps/api/src/auth/services/web3auth-verifier.service.ts`
  - Env (web): `VITE_WEB3AUTH_CLIENT_ID`
  - Env (desktop): `VITE_WEB3AUTH_CLIENT_ID`, `VITE_GOOGLE_CLIENT_ID`
  - Key feature: MPC-based deterministic keypair derivation with device factor MFA

**TEE Providers:**

- Phala Cloud CVM (production target) - TEE-based IPNS key decryption and record signing. Staging runs the same worker as a local Docker service in simulator mode since PR #472.
  - Worker: `apps/tee-worker/src/`
  - Routes: `GET /health`, `GET /public-key`, `POST /republish`, `POST /migrate`, `POST /connection-test`
  - Features: Intel TDX hardware attestation (CVM mode only), key epoch rotation
  - Schedule: Every 6 hours via backend cron
  - Enrollment: `apps/api/src/republish/republish.service.ts`
  - Docker Compose: `apps/tee-worker/docker-compose.phala.yml` for CVM (mounts `/var/run/dstack.sock`); `docker/docker-compose.staging.yml` for the staging simulator
  - Env: `TEE_WORKER_URL`, `TEE_WORKER_SECRET`, `TEE_MODE` (cvm/simulator)
  - Auth: Shared secret via `TEE_WORKER_SECRET`

- AWS Nitro Enclaves (Planned Fallback) - Backup TEE provider (not yet implemented)

**Email Delivery:**

- SendGrid - Email OTP delivery for passwordless auth
  - SDK: `@sendgrid/mail` ^8.1.6
  - Env: `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL`
  - Required in production/staging; not needed for local dev with test-login

**Ethereum / Blockchain:**

- SIWE (Sign-In with Ethereum) - Wallet-based authentication
  - SDK: `viem` ^2.44.4
  - Backend verification: `apps/api/src/auth/`
  - Domain validation: Uses non-wildcard entries from `CORS_ALLOWED_ORIGINS`

## Data Storage

**Databases:**

- PostgreSQL 16
  - Connection: `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD`, `DB_DATABASE`
  - ORM: TypeORM ^0.3.28 (`apps/api/src/`)
  - Data source: `apps/api/src/data-source.ts`
  - Migrations: `apps/api/src/migrations/`
  - Key entities: users, vaults, refresh_tokens, pinned_cids, ipns_republish_schedule, shares, device_approvals
  - Protocol: `docs/DATABASE_EVOLUTION_PROTOCOL.md`
  - CI: `postgres:16-alpine` service container

**File Storage:**

- IPFS (Kubo) - Decentralized encrypted file content storage
  - All stored content is ciphertext (zero-knowledge server)
  - Pinning managed by API (`pinned_cids` table tracks what to keep pinned)
  - CI: `ipfs/kubo:v0.42.0` service container

**Caching:**

- Redis 7 - Job queue backend (not used as general cache)
  - Connection: `REDIS_HOST`, `REDIS_PORT`
  - Purpose: BullMQ job queue for background tasks (IPNS republishing, etc.)
  - CI: `redis:7-alpine` service container

- In-memory caches (no external service):
  - API: IPNS resolution cache with DB-cached CID fallback
  - Desktop: Metadata cache with background refresh (`apps/desktop/src-tauri/src/fuse/cache.rs`)
  - Desktop: Content cache with prefetch (`apps/desktop/src-tauri/src/fuse/cache.rs`)

## Authentication & Identity

**Auth Provider:** Web3Auth MPC Core Kit (primary) + CipherBox backend JWT

**Implementation:** Two-phase authentication

1. Client authenticates with Web3Auth MPC Core Kit -> receives Web3Auth ID Token
2. Client sends ID Token to CipherBox API -> receives CipherBox access/refresh tokens
3. Backend validates Web3Auth ID Token via JWKS endpoint

**Token types:**

- Web3Auth ID Token (1 hour) - For backend authentication
- CipherBox Access Token (15 min) - API authorization via JWT
- CipherBox Refresh Token (7 days) - Token renewal via HTTP-only cookie

**Auth strategies (backend):**

- `apps/api/src/auth/strategies/jwt.strategy.ts` - CipherBox access token (JWT_SECRET) validation; `apps/api/src/auth/services/web3auth-verifier.service.ts` - Web3Auth ID token validation via JWKS
- JWT signing: `JWT_SECRET` env var, RS256 identity tokens via `IDENTITY_JWT_PRIVATE_KEY`

**Test Authentication (Dev/Staging Only):**

- `POST /auth/test-login` - Bypasses Web3Auth for E2E testing
- Guarded by `TEST_LOGIN_SECRET` env var and `NODE_ENV !== 'production'`
- Desktop dev-key mode: `--dev-key <hex>` CLI flag triggers test-login flow

## Monitoring & Observability

**Metrics:**

- Prometheus via `prom-client` ^15.1.3
- Location: `apps/api/src/metrics/`
- Exposes: HTTP request metrics, delegated routing fallback counts, custom business metrics

**Health Checks:**

- `@nestjs/terminus` ^11.0.0
- Endpoint: `GET /health`

**Error Tracking:**

- None (no Sentry/Datadog/etc.)

**Logs:**

- API: NestJS structured logger
- Web: Console.\* calls
- Desktop (Rust): `log` crate + `env_logger` (`RUST_LOG=debug` for verbose output)
- TEE Worker: Console/stdout
- FUSE-T: `~/Library/Logs/fuse-t/fuse-t.log` (macOS)

## CI/CD & Deployment

**CI Pipeline:** GitHub Actions (`.github/workflows/`)

- `ci.yml` - PR checks: lint, typecheck, unit tests, build, API spec verification, migration drift check, Cargo check/test (Linux/macOS/Windows), cross-language vector parity
- `web-e2e.yml` - Web E2E tests with Playwright (reusable; run on push to main via `ci-e2e.yml`)
- `desktop-e2e.yml` - Desktop E2E tests
- `load-test.yml` - Load test runs

**Staging Deployment:**

- Triggered by pushing `staging-*` tags
- `deploy-staging.yml` builds Docker images, pushes to GHCR, deploys to VPS
- API image: `ghcr.io/<owner>/cipherbox-api`
- TEE image: `ghcr.io/<owner>/cipherbox-tee-worker`
- VPS: 76.13.151.200 (Hostinger)
- Reverse proxy: Caddy (HTTPS termination)
- Domains: `api-staging.cipherbox.cc`, `app-staging.cipherbox.cc`

**Release Automation:**

- `release-please.yml` - Creates/updates release PR on main, publishes GitHub Releases
- Config: `release-please-config.json`, `.release-please-manifest.json`

**Production:**

- Not yet deployed

## Environment Configuration

**API required env vars (`apps/api/.env.example`):**

- `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD`, `DB_DATABASE` - PostgreSQL
- `REDIS_HOST`, `REDIS_PORT` - Redis for BullMQ
- `JWT_SECRET` - Access token signing
- `CORS_ALLOWED_ORIGINS` - Allowed origins (comma-separated, supports wildcards)
- `IPFS_LOCAL_API_URL`, `IPFS_LOCAL_GATEWAY_URL` - IPFS Kubo endpoints
- `DELEGATED_ROUTING_URL` - IPNS delegated routing endpoint
- `DELEGATED_ROUTING_FALLBACK_URL` - Optional fallback routing URL
- `TEE_WORKER_URL`, `TEE_WORKER_SECRET` - TEE worker connection
- `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL` - Email OTP delivery
- `IDENTITY_JWT_PRIVATE_KEY` - RS256 signing key (base64-encoded PKCS8 PEM; ephemeral in dev)
- `TEST_LOGIN_SECRET` - E2E test-login bypass (never in production)
- `THROTTLE_BYPASS_SECRET` - Rate limit bypass for E2E/load tests

**Web required env vars (`apps/web/.env.example`):**

- `VITE_API_URL` - Backend API URL
- `VITE_WEB3AUTH_CLIENT_ID` - Web3Auth project ID

**Desktop required env vars (`apps/desktop/.env.example`):**

- `VITE_WEB3AUTH_CLIENT_ID` - Web3Auth project ID
- `VITE_GOOGLE_CLIENT_ID` - Google OAuth client ID
- `VITE_API_URL` - Backend API URL (defaults to staging)
- `VITE_ENVIRONMENT` - Environment identifier (local/staging/production)
- `VITE_TEST_LOGIN_SECRET` - Test-login secret for dev-key mode

**TEE Worker env vars (`tee-worker/docker-compose.yml`):**

- `NODE_ENV` - Environment
- `PORT` - HTTP port (default 3001)
- `TEE_MODE` - Execution mode (cvm/simulator)
- `TEE_WORKER_SECRET` - Shared auth secret

**Secrets location:**

- `.env` files - Local development (gitignored)
- GitHub Actions secrets/vars - CI/CD (GitHub `staging` environment)
- Docker Compose `.env` - Staging VPS

## Webhooks & Callbacks

**Incoming:**

- None

**Outgoing:**

- None

---

<!-- Integration audit: 2026-03-27 -->

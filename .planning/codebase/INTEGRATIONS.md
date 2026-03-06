# External Integrations

**Analysis Date:** 2026-03-06

## Project Status

CipherBox is a **technology demonstrator** with the following integrations implemented:

- **IPFS (Kubo)**: File storage and IPNS publishing (`apps/api/src/ipfs/`)
- **Web3Auth MPC Core Kit**: Authentication and key derivation (`apps/web/src/lib/web3auth/`)
- **PostgreSQL**: User/vault metadata storage (`apps/api/src/`)
- **Redis/BullMQ**: Job queue for background tasks (`apps/api/src/`)
- **TEE (Phala Cloud)**: IPNS republishing (`tee-worker/`)

## APIs & External Services

**IPFS/IPNS (Implemented):**

- Local IPFS daemon (Kubo) - File storage and IPNS publishing
  - Provider: `apps/api/src/ipfs/providers/local.provider.ts`
  - Connection: `KUBO_API_URL` env var (default: `http://127.0.0.1:5001`)
  - Upload: `POST /ipfs/upload` (multipart/form-data, field `file`)
  - Fetch: `GET /ipfs/:cid`
  - Unpin: `POST /ipfs/unpin`

- Delegated routing (delegated-ipfs.dev) - IPNS record publishing and resolution
  - Client: `apps/api/src/ipns/delegated-routing.client.ts`
  - Publish: `POST /ipns/publish`, `POST /ipns/publish-batch`
  - Resolve: `GET /ipns/resolve`
  - Retry: Exponential backoff (3 retries, 1s base, 30s cap)

**Web3Auth (Implemented):**

- Authentication and key derivation - User identity
  - SDK/Client: `@web3auth/mpc-core-kit` (`apps/web/src/lib/web3auth/`)
  - Auth methods: Email OTP, Google OAuth, Magic Link, External Wallet
  - JWKS endpoint: `https://api-auth.web3auth.io/jwks`
  - Backend validation: `apps/api/src/auth/strategies/web3auth-jwt.strategy.ts`
  - Key feature: MPC-based deterministic keypair derivation with device factor MFA

**TEE Providers (Implemented):**

- Trusted Execution Environment for IPNS republishing

**Phala Cloud (Primary — Implemented):**

- TEE-based IPNS key decryption and signing
  - Worker: `tee-worker/src/`
  - Features: Intel SGX hardware attestation
  - Schedule: Every 3 hours via backend cron
  - Enrollment: `apps/api/src/republish/republish.service.ts`

**AWS Nitro Enclaves (Planned Fallback):**

- Backup TEE provider (not yet implemented)

## Data Storage

**PostgreSQL (Implemented):**

- User accounts, vaults, tokens, audit logs
  - ORM: TypeORM (`apps/api/src/`)
  - Migrations: `apps/api/src/migrations/`
  - Key entities: users, vaults, refresh_tokens, pinned_cids, ipns_republish_schedule, shares, device_approvals
  - Protocol: `docs/DATABASE_EVOLUTION_PROTOCOL.md`

**Redis (Implemented):**

- BullMQ job queue for background tasks
  - Connection: `REDIS_URL` env var
  - Used by: `apps/api/src/` for async job processing

**IPFS (Implemented):**

- Encrypted file content storage (decentralized)
  - Kubo node for pinning and availability
  - All content is ciphertext (zero-knowledge)

**Caching:**

- API: In-memory IPNS resolution cache with DB-cached CID fallback
- Desktop: In-memory metadata cache with background refresh (`apps/desktop/src-tauri/src/fuse/`)

## Authentication & Identity

**Web3Auth (Implemented):**

- Primary authentication and key derivation
  - Implementation: Two-phase auth (Web3Auth MPC Core Kit + CipherBox backend JWT)
  - Token types:
    - Web3Auth ID Token (1 hour) - For backend authentication
    - CipherBox Access Token (15 min) - API authorization
    - CipherBox Refresh Token (7 days) - Token renewal
  - Details: `docs/AUTHENTICATION_ARCHITECTURE.md`

**Test Authentication (Dev/Staging Only):**

- `POST /auth/test-login` - Bypasses real auth for E2E testing
  - Guarded by `TEST_LOGIN_SECRET` env var and `NODE_ENV !== 'production'`

## Monitoring & Observability

**API Metrics (Implemented):**

- Prometheus metrics: `apps/api/src/metrics/`
- Health check: `GET /health`

**Web App:**

- No error tracking service (see CONCERNS.md)
- Console logging only

**Logs:**

- API: NestJS structured logger
- Web: Console.\* calls (tech debt)
- Desktop: Rust `log` crate

## CI/CD & Deployment

**CI Pipeline (Implemented):**

- GitHub Actions (`.github/workflows/`)
  - `ci.yml` - Lint, typecheck, unit tests on PRs
  - `ci-e2e.yml` - Playwright E2E tests on `main` pushes
  - `deploy-staging.yml` - Deploy on `v*-staging*` tags
  - `release-please.yml` - Automated releases on `main`

**Staging (Implemented):**

- VPS: 76.13.151.200 (Hostinger)
- API: `https://api-staging.cipherbox.cc`
- Web: `https://app-staging.cipherbox.cc`
- Deploy: Push tag `v<version>-staging-rc-<N>`

**Production:**

- Not yet deployed

## Environment Configuration

**API (`apps/api/.env.example`):**

- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `KUBO_API_URL` - IPFS daemon endpoint
- `JWT_SECRET` - Access token signing
- `WEB3AUTH_CLIENT_ID` - Web3Auth project ID
- `TEE_PUBLIC_KEY` - Current TEE epoch public key
- `CORS_ORIGINS` - Allowed origins

**Web (`apps/web/.env.example`):**

- `VITE_API_URL` - Backend API URL
- `VITE_WEB3AUTH_CLIENT_ID` - Web3Auth project ID
- `VITE_WEB3AUTH_VERIFIER` - Web3Auth verifier name

**Secrets location:**

- `.env` files (local development)
- GitHub Actions secrets/vars (CI/CD)
- Docker Compose `.env` (staging)

## Webhooks & Callbacks

**Incoming:**

- None

**Outgoing:**

- None

---

Integration audit: 2026-03-06

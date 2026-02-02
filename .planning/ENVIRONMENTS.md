# Environment Architecture

**Created:** 2026-01-25

## Overview

CipherBox requires isolated environments to prevent cross-environment interference, particularly with IPNS sequence numbers. This document defines the environment architecture and solves the Web3Auth key isolation problem.

## The Problem

**Current State:** All environments share the same Web3Auth project (SAPPHIRE_DEVNET) and client ID. This means:

- Same user identity → same derived secp256k1 keypair → same Ed25519 IPNS keypair
- IPNS records use monotonically increasing sequence numbers
- If CI publishes seq=100, local dev (fresh DB) tries seq=1 → rejected by network/delegated routing
- Test repeatability is impossible without manual intervention

## Environment Matrix

| Environment    | IPFS Mode      | Web3Auth Network | IPNS Routing           | Database            | TEE Republishing     | Isolation Level            |
| -------------- | -------------- | ---------------- | ---------------------- | ------------------- | -------------------- | -------------------------- |
| **Local Dev**  | Kubo (offline) | Sapphire Devnet  | Mock service           | Local Postgres      | **Disabled**         | Full                       |
| **CI E2E**     | Kubo (offline) | Sapphire Devnet  | Mock service (per-run) | Ephemeral Postgres  | **Disabled**         | Full per-run               |
| **Staging**    | Kubo (online)  | Sapphire Devnet  | delegated-ipfs.dev     | Managed Postgres    | **Active** (testnet) | Shared with Local/CI users |
| **Production** | Pinata         | Sapphire Mainnet | delegated-ipfs.dev     | Production Postgres | **Active** (mainnet) | Full                       |

## Solution: Environment-Aware Key Derivation

### Recommended Approach: Environment Salt in Ed25519 Key Derivation

The IPNS keypair is derived from the user's vault key. By adding an environment-specific salt to this derivation, we get different IPNS keys per environment while keeping the same Web3Auth identity.

**Key Insight:** The problematic shared state is the **IPNS keypair**, not the user's encryption keypair. We can:

1. Keep the same secp256k1 keypair from Web3Auth (same encryption keys)
2. Add environment salt only to Ed25519 IPNS key derivation (different IPNS identities)

This means:

- Same user can encrypt/decrypt files across environments (if CIDs are known)
  - **Security Note:** CID leakage can expose test or production data across environments. Use separate test accounts/credentials for CI vs production, and sanitize or isolate test data to avoid accidental cross-environment access.
- Different IPNS namespaces per environment → no sequence conflicts
- Test accounts work in all environments without conflicts

### Implementation

```typescript
// packages/crypto/src/ipns.ts

// Fixed HKDF salt for domain separation (extract phase)
const HKDF_SALT = 'CipherBox-IPNS-v1';

// Environment context prefixes for HKDF info (expand phase)
const ENVIRONMENT_CONTEXT = {
  local: 'env:local',
  ci: 'env:ci',
  staging: 'env:staging',
  production: 'env:production',
} as const;

type Environment = keyof typeof ENVIRONMENT_CONTEXT;

export function deriveIpnsKeypair(
  userSecp256k1PrivateKey: Uint8Array,
  folderId: string,
  environment: Environment
): { publicKey: Uint8Array; privateKey: Uint8Array } {
  // HKDF-SHA256: Fixed salt for domain separation, environment/folder in info for context binding
  // This follows RFC 5869 best practices and matches existing deriveKey patterns in the codebase
  const info = `${ENVIRONMENT_CONTEXT[environment]}:folder:${folderId}`;
  // ... derivation logic using HKDF(IKM=userSecp256k1PrivateKey, salt=HKDF_SALT, info=info)
}
```

**Configuration:**

```bash
# .env
CIPHERBOX_ENVIRONMENT=local  # local | ci | staging | production
```

### Alternative: Separate Web3Auth Projects

If you prefer complete user isolation (different user databases per environment):

| Environment | Web3Auth Project  | Network          | Client ID  |
| ----------- | ----------------- | ---------------- | ---------- |
| Local/CI    | cipherbox-dev     | Sapphire Devnet  | `BK...dev` |
| Staging     | cipherbox-staging | Sapphire Devnet  | `BK...stg` |
| Production  | cipherbox-prod    | Sapphire Mainnet | `BK...prd` |

**Pros:**

- Complete isolation including encryption keys
- No code changes needed (just config)
- Clear separation of concerns

**Cons:**

- Need separate test accounts per environment
- Can't share encrypted data between environments
- More Web3Auth dashboard management

## Detailed Environment Specifications

### 1. Local Development Environment

**Purpose:** Isolated development with persistent state, no network dependencies

**Infrastructure:**

```yaml
# docker/docker-compose.local.yml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: cipherbox_local
    ports:
      - '5432:5432'
    volumes:
      - postgres_local_data:/var/lib/postgresql/data

  ipfs:
    image: ipfs/kubo:v0.34.0
    command: daemon --offline # KEY: Offline mode
    ports:
      - '127.0.0.1:5001:5001' # API
      - '127.0.0.1:8080:8080' # Gateway
    volumes:
      - ipfs_local_data:/data/ipfs

  mock-ipns-routing:
    build: ../tools/mock-ipns-routing
    ports:
      - '127.0.0.1:3001:3001'
    volumes:
      - mock_ipns_data:/data # Persistent mock IPNS records

volumes:
  postgres_local_data:
  ipfs_local_data:
  mock_ipns_data:
```

**Configuration:**

```bash
# apps/web/.env.local
VITE_WEB3AUTH_CLIENT_ID=BK...dev  # Devnet client ID
VITE_API_URL=http://localhost:3000
VITE_PINATA_GATEWAY_URL=http://localhost:8080/ipfs
VITE_ENVIRONMENT=local

# apps/api/.env.local
NODE_ENV=development
CIPHERBOX_ENVIRONMENT=local
DB_HOST=localhost
DB_PORT=5432
DB_DATABASE=cipherbox_local
IPFS_PROVIDER=local
IPFS_LOCAL_API_URL=http://localhost:5001
IPFS_LOCAL_GATEWAY_URL=http://localhost:8080
DELEGATED_ROUTING_URL=http://localhost:3001
JWT_SECRET=local-dev-jwt-secret-change-in-production
```

**Characteristics:**

- Kubo runs with `--offline` flag (no DHT, no peer connections)
- Mock IPNS routing with persistent storage (survives restarts)
- Local Postgres with persistent volume
- Environment salt: `local`

### 2. CI E2E Testing Environment

**Purpose:** Isolated, reproducible test runs with fresh state each time

**GitHub Actions Configuration:**

```yaml
# .github/workflows/e2e.yml
services:
  postgres:
    image: postgres:16-alpine
    env:
      POSTGRES_DB: cipherbox_ci
    options: >-
      --health-cmd pg_isready
      --health-interval 5s
      --health-timeout 5s
      --health-retries 5

  ipfs:
    image: ipfs/kubo:v0.34.0
    # No --offline needed in CI (isolated network anyway)
    # No volume mounts (ephemeral state)
    options: >-
      --health-cmd "ipfs id"
      --health-interval 10s
      --health-timeout 5s
      --health-retries 10

env:
  CIPHERBOX_ENVIRONMENT: ci
  DELEGATED_ROUTING_URL: http://localhost:3001
  # Uses same Web3Auth client ID as local (Devnet)
  VITE_WEB3AUTH_CLIENT_ID: ${{ secrets.VITE_WEB3AUTH_CLIENT_ID_DEV }}
```

**Key Difference from Local:**

- No persistent volumes (fresh state each run)
- Mock IPNS routing resets via `/reset` endpoint before each test
- Environment salt: `ci`
- Same Web3Auth project as local (Sapphire Devnet)

**Test Setup Pattern:**

```typescript
// tests/e2e/setup.ts
beforeAll(async () => {
  // Reset mock IPNS routing for clean slate
  await fetch('http://localhost:3001/reset', { method: 'POST' });

  // Database is already fresh (CI service container)
});
```

> **Security Note:** The `/reset` endpoint must be disabled or removed outside local development and CI environments (staging/production) to prevent accidental state resets. See Finding #4 in the security review.

### 3. Staging Environment

**Purpose:** Production-like environment for integration testing, real IPFS network

**Infrastructure:**

```yaml
# docker/docker-compose.staging.yml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: cipherbox_staging
    volumes:
      - postgres_staging_data:/var/lib/postgresql/data

  ipfs:
    image: ipfs/kubo:v0.34.0
    # NO --offline flag (publishes to real DHT)
    ports:
      - '4001:4001/tcp' # Swarm
      - '4001:4001/udp'
      - '127.0.0.1:5001:5001' # API
      - '127.0.0.1:8080:8080' # Gateway
    environment:
      IPFS_PROFILE: server # Production-oriented config
    volumes:
      - ipfs_staging_data:/data/ipfs

volumes:
  postgres_staging_data:
  ipfs_staging_data:
```

**Configuration:**

```bash
# Staging environment
VITE_WEB3AUTH_CLIENT_ID=BK...dev  # Same Devnet client ID
VITE_API_URL=https://staging-api.cipherbox.io
VITE_ENVIRONMENT=staging

CIPHERBOX_ENVIRONMENT=staging
NODE_ENV=production
IPFS_PROVIDER=local
DELEGATED_ROUTING_URL=https://delegated-ipfs.dev  # Real routing
JWT_SECRET=${{ secrets.JWT_SECRET_STAGING }}
```

**Characteristics:**

- Kubo publishes to real DHT (content discoverable)
- Uses real delegated-ipfs.dev for IPNS
- Same Sapphire Devnet Web3Auth (shared identity with local/CI)
- Environment salt: `staging` (different IPNS keys than local/CI)
- Can be used for user acceptance testing

### 4. Production Environment

**Purpose:** Live user-facing environment with production credentials

**Infrastructure:**

- Managed PostgreSQL (AWS RDS / Cloud SQL / etc.)
- Pinata for IPFS pinning (redundant, managed)
- Optional: Self-hosted Kubo cluster for reads

**Configuration:**

```bash
# Production environment
VITE_WEB3AUTH_CLIENT_ID=BK...prod  # DIFFERENT - Production client ID
VITE_WEB3AUTH_NETWORK=sapphire_mainnet  # MAINNET
VITE_API_URL=https://api.cipherbox.io
VITE_ENVIRONMENT=production

CIPHERBOX_ENVIRONMENT=production
NODE_ENV=production
IPFS_PROVIDER=pinata
PINATA_JWT=${{ secrets.PINATA_JWT }}
DELEGATED_ROUTING_URL=https://delegated-ipfs.dev
JWT_SECRET=${{ secrets.JWT_SECRET_PRODUCTION }}
```

**Critical Differences:**

- **Separate Web3Auth Project** (Sapphire Mainnet)
- Different client ID (complete user isolation from dev/staging)
- Pinata for production-grade IPFS pinning
- Environment salt: `production`

## Web3Auth Project Setup

### Required Projects

1. **cipherbox-dev** (Sapphire Devnet)
   - Used for: Local dev, CI, Staging
   - Dashboard: Configure test accounts with static OTP
   - Grouped connections: `cipherbox-grouped-connection`
   - OAuth connections: `cipherbox-google-oauth-2`, `cb-email-testnet`

2. **cipherbox-prod** (Sapphire Mainnet)
   - Used for: Production only
   - Dashboard: Real OAuth credentials
   - Grouped connections: Same structure, production OAuth apps

### Test Account Setup

For Local/CI/Staging (Devnet project):

1. Create test email in Web3Auth dashboard
2. Enable "Test User" mode (static OTP: 000000)
3. Store in GitHub Secrets:
   ```bash
   WEB3AUTH_TEST_EMAIL=test@cipherbox.dev
   WEB3AUTH_TEST_OTP=000000
   ```

### Code Changes for Network Switching

```typescript
// apps/web/src/lib/web3auth/config.ts
import { WEB3AUTH_NETWORK } from '@web3auth/modal';

const NETWORK_CONFIG = {
  local: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  ci: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  staging: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  production: WEB3AUTH_NETWORK.SAPPHIRE_MAINNET,
} as const;

export const web3AuthOptions: Web3AuthOptions = {
  clientId: import.meta.env.VITE_WEB3AUTH_CLIENT_ID,
  web3AuthNetwork: NETWORK_CONFIG[import.meta.env.VITE_ENVIRONMENT || 'local'],
  // ... rest of config
};
```

## Implementation Checklist

### Phase 1: Environment Salt for IPNS Keys

- [ ] Add `CIPHERBOX_ENVIRONMENT` env var to API
- [ ] Add `VITE_ENVIRONMENT` env var to web app
- [ ] Modify Ed25519 key derivation to include environment salt
- [ ] Update mock IPNS routing to support persistent storage mode

### Phase 2: Docker Compose Profiles

- [ ] Create `docker-compose.local.yml` with offline Kubo
- [ ] Create `docker-compose.staging.yml` with online Kubo
- [ ] Add npm scripts: `dev:local`, `dev:staging`
- [ ] Document volume management for data persistence

### Phase 3: CI Updates

- [ ] Update e2e.yml to pass `CIPHERBOX_ENVIRONMENT=ci`
- [ ] Add mock IPNS reset to test setup
- [ ] Verify test isolation

### Phase 4: Production Web3Auth Setup

- [ ] Create production Web3Auth project (Sapphire Mainnet)
- [ ] Configure production OAuth apps (Google, etc.)
- [ ] Update web app to switch networks based on environment
- [ ] Add `VITE_WEB3AUTH_CLIENT_ID_PROD` secret

## Environment Variable Reference

### Web App (Vite)

| Variable                  | Local               | CI                  | Staging                   | Production                |
| ------------------------- | ------------------- | ------------------- | ------------------------- | ------------------------- |
| `VITE_WEB3AUTH_CLIENT_ID` | dev                 | dev                 | dev                       | **prod**                  |
| `VITE_API_URL`            | localhost:3000      | localhost:3000      | staging-api.cipherbox.io  | api.cipherbox.io          |
| `VITE_PINATA_GATEWAY_URL` | localhost:8080/ipfs | localhost:8080/ipfs | gateway.pinata.cloud/ipfs | gateway.pinata.cloud/ipfs |
| `VITE_ENVIRONMENT`        | local               | ci                  | staging                   | production                |

### API (NestJS)

| Variable                | Local           | CI             | Staging               | Production         |
| ----------------------- | --------------- | -------------- | --------------------- | ------------------ |
| `NODE_ENV`              | development     | test           | production            | production         |
| `CIPHERBOX_ENVIRONMENT` | local           | ci             | staging               | production         |
| `DB_DATABASE`           | cipherbox_local | cipherbox_ci   | cipherbox_staging     | cipherbox_prod     |
| `IPFS_PROVIDER`         | local           | local          | local                 | pinata             |
| `DELEGATED_ROUTING_URL` | localhost:3001  | localhost:3001 | delegated-ipfs.dev    | delegated-ipfs.dev |
| `JWT_SECRET`            | dev-secret      | ci-secret      | secrets.JWT_STAGING   | secrets.JWT_PROD   |
| `TEE_ENABLED`           | **false**       | **false**      | true                  | true               |
| `TEE_PROVIDER`          | -               | -              | phala                 | phala              |
| `PHALA_API_URL`         | -               | -              | testnet.phala.network | api.phala.network  |

## TEE Infrastructure by Environment

The TEE (Trusted Execution Environment) layer handles IPNS republishing to prevent record expiry (24-hour TTL). This section defines TEE requirements per environment.

### TEE Environment Matrix

| Environment    | TEE Infrastructure     | IPNS Republishing | Monitoring        | Cleanup                    |
| -------------- | ---------------------- | ----------------- | ----------------- | -------------------------- |
| **Local Dev**  | None                   | Not needed        | None              | User resets to clean slate |
| **CI E2E**     | None                   | Not needed        | None              | Ephemeral per-run          |
| **Staging**    | Active (Phala testnet) | Every 3 hours     | Integration tests | Periodic DHT cleanup       |
| **Production** | Active (Phala mainnet) | Every 3 hours     | Full alerting     | Automated stale detection  |

### Local Development: No TEE

**Rationale:**

- IPNS records stored in mock routing service (persistent volume)
- No real DHT propagation = no expiry concerns
- Users working on non-TEE features don't need republishing complexity
- If IPNS state becomes corrupted, user can reset: `docker-compose down -v && docker-compose up`

**Configuration:**

```bash
# apps/api/.env.local
TEE_ENABLED=false
# No TEE_* environment variables needed
```

**When working on TEE features locally:**

- Use staging environment for TEE development/testing
- Or run mock TEE service (future: `tools/mock-tee-service`)

### CI E2E Testing: No TEE

**Rationale:**

- Test runs complete in minutes, well within 24-hour IPNS TTL
- No benefit to republishing during test execution
- Mock IPNS routing service resets per-run (no accumulated state)
- Simpler CI pipeline without TEE service dependencies

**Configuration:**

```yaml
# .github/workflows/e2e.yml
env:
  TEE_ENABLED: 'false'
  # No TEE service container needed
```

**E2E Test Considerations:**

- Tests should NOT depend on IPNS records surviving between test runs
- Each test suite starts with fresh vault state
- IPNS sequence numbers start at 1 for each test user

### Staging Environment: Active TEE with Testnet

**Purpose:** Integration testing of full CipherBox + TEE + public IPFS stack

**Infrastructure:**

```yaml
# docker/docker-compose.staging.yml (additions)
services:
  # ... existing services ...

  # Staging uses real Phala Cloud testnet
  # TEE service is external - no local container

# Backend cron jobs enabled
```

**Configuration:**

```bash
# apps/api/.env.staging
TEE_ENABLED=true
TEE_PROVIDER=phala
PHALA_API_URL=https://testnet.phala.network/api/v1
PHALA_CONTRACT_ID=${{ secrets.PHALA_CONTRACT_ID_STAGING }}
PHALA_API_KEY=${{ secrets.PHALA_API_KEY_STAGING }}

# Republish schedule (production-like)
TEE_REPUBLISH_INTERVAL_HOURS=3
TEE_KEY_EPOCH_ROTATION_WEEKS=4
```

**Staging-Specific Challenges:**

1. **Web3Auth Testnet Instability**
   - Sapphire Devnet may reset or have unstable user IDs
   - User keypairs could change unexpectedly
   - This orphans IPNS records (old keys, no one to republish)

2. **DHT Pollution**
   - Staging publishes to real public DHT
   - Old test IPNS records accumulate
   - No automatic cleanup (IPNS records naturally expire after 24h without republish)

3. **TEE Key Epochs**
   - Staging TEE uses testnet keys (may be rotated more frequently)
   - 4-week grace period still applies

**Staging Cleanup Strategy:**

```typescript
// tools/staging-cleanup/src/index.ts
// Periodic job to clean up orphaned staging data

interface CleanupJob {
  // 1. Find IPNS records that haven't been republished in >48 hours
  findStaleIpnsRecords(): Promise<FolderIpns[]>;

  // 2. Check if owning user still exists and can republish
  validateUserCanRepublish(record: FolderIpns): Promise<boolean>;

  // 3. Mark orphaned records for cleanup (stop TEE republishing)
  markOrphaned(recordIds: string[]): Promise<void>;

  // 4. Unpin associated IPFS content after grace period
  cleanupOrphanedContent(recordIds: string[], graceDays: number): Promise<void>;
}

// Run weekly in staging
// Cron: 0 0 * * 0 (Sundays at midnight)
```

**Staging Integration Tests:**

```typescript
// tests/integration/tee-republish.test.ts
describe('TEE IPNS Republishing', () => {
  it('should republish IPNS record via TEE within 3 hours', async () => {
    // 1. Create folder with IPNS record
    // 2. Note initial sequence number
    // 3. Wait for TEE republish cycle (or trigger manually)
    // 4. Verify sequence number incremented
    // 5. Verify IPNS resolves to correct CID
  });

  it('should handle TEE key epoch rotation', async () => {
    // 1. Create folder with old epoch key
    // 2. Trigger epoch rotation
    // 3. Verify republishing continues with new epoch
    // 4. Verify old epoch still works during grace period
  });
});
```

### Production Environment: Full TEE with Monitoring

**Infrastructure:**

- Phala Cloud mainnet contract
- Dedicated republishing cron (scales with user count)
- Full observability stack

**Configuration:**

```bash
# apps/api/.env.production
TEE_ENABLED=true
TEE_PROVIDER=phala
PHALA_API_URL=https://api.phala.network/v1
PHALA_CONTRACT_ID=${{ secrets.PHALA_CONTRACT_ID_PROD }}
PHALA_API_KEY=${{ secrets.PHALA_API_KEY_PROD }}

# Production republish settings
TEE_REPUBLISH_INTERVAL_HOURS=3
TEE_KEY_EPOCH_ROTATION_WEEKS=4
TEE_REPUBLISH_BATCH_SIZE=100
TEE_REPUBLISH_CONCURRENCY=10

# Monitoring
TEE_METRICS_ENABLED=true
TEE_ALERT_STALE_THRESHOLD_HOURS=12
```

**Production Monitoring Requirements:**

1. **IPNS Staleness Detection**

   ```sql
   -- Alert: Records not republished in >12 hours
   SELECT folder_ipns.*
   FROM folder_ipns
   WHERE last_republish_at < NOW() - INTERVAL '12 hours'
     AND is_active = true;
   ```

2. **TEE Health Metrics**
   - Republish success rate (target: >99.9%)
   - Republish latency p50/p95/p99
   - TEE API error rate
   - Key epoch rotation completion rate

3. **Alerting Thresholds**

   | Metric                             | Warning | Critical |
   | ---------------------------------- | ------- | -------- |
   | Records not republished in X hours | 12h     | 20h      |
   | TEE API error rate                 | >1%     | >5%      |
   | Republish queue depth              | >1000   | >5000    |
   | Epoch rotation failures            | Any     | >10%     |

4. **Dashboard Panels**
   - Active IPNS records by age since last republish
   - TEE republish throughput (records/minute)
   - Failed republish attempts (with error breakdown)
   - Key epoch distribution (current vs grace period)

**Production Incident Response:**

```markdown
## IPNS Staleness Incident Runbook

### Symptoms

- Users report "folder not found" or stale data
- Monitoring shows records >20h since republish

### Diagnosis

1. Check TEE service health: `curl https://api.phala.network/health`
2. Check backend cron status: `systemctl status cipherbox-republish`
3. Query stale records: `SELECT COUNT(*) FROM folder_ipns WHERE last_republish_at < NOW() - INTERVAL '20 hours'`

### Resolution

1. If TEE service down: Wait for Phala recovery, records have 24h TTL buffer
2. If cron stopped: Restart cron, monitor catch-up
3. If specific records failing: Check encryptedIpnsPrivateKey validity, may need user to re-publish

### User Communication

- <20h stale: No user impact, monitor
- 20-24h stale: Prepare user comms, accelerate fix
- > 24h stale: IPNS records expired, users must re-publish from client
```

### TEE Implementation Checklist

#### Phase 1: Core TEE Infrastructure (Production + Staging)

- [ ] Add `TEE_ENABLED` environment flag
- [ ] Create `TeeService` with Phala Cloud client
- [ ] Implement `ipns_republish_schedule` table
- [ ] Create republish cron job (3-hour interval)
- [ ] Add `encryptedIpnsPrivateKey` to folder publish flow

#### Phase 2: Monitoring & Alerting (Production)

- [ ] Add Prometheus metrics for TEE operations
- [ ] Create Grafana dashboard for IPNS health
- [ ] Configure PagerDuty/Opsgenie alerts for staleness
- [ ] Write incident runbooks

#### Phase 3: Staging Integration Testing

- [ ] Deploy TEE to staging with testnet credentials
- [ ] Create integration test suite for republishing
- [ ] Implement staging cleanup job
- [ ] Add CI job for periodic staging health check

#### Phase 4: Local TEE Development (Optional)

- [ ] Create mock TEE service (`tools/mock-tee-service`)
- [ ] Add `docker-compose.tee-dev.yml` profile
- [ ] Document TEE feature development workflow

## Appendix: Alternative Approaches Considered

### A. Fully Separate Web3Auth Projects per Environment

**Approach:** Create 4 separate Web3Auth projects (local, ci, staging, prod)

**Rejected because:**

- Overhead of managing 4 projects
- Need separate test accounts per environment
- Can't share test fixtures between local/CI/staging
- Environment salt achieves same isolation with less complexity

### B. Backend User Aggregation (Custom Auth)

**Approach:** Backend issues environment-specific tokens, client presents to Web3Auth via Custom Auth

**Rejected because:**

- Significant implementation complexity
- Custom Auth provider setup required
- Adds latency to auth flow
- Over-engineered for the actual problem

### C. IPNS Sequence Reset via Admin API

**Approach:** Reset IPNS sequence numbers between test runs

**Rejected because:**

- IPNS sequence is network-wide, can't be reset
- Would require deleting/recreating IPNS keys
- Loses data in the process
- Doesn't solve the fundamental isolation problem

---

_Document Status: Draft - Ready for implementation_
_Last Updated: 2026-01-25 - Added TEE infrastructure analysis_

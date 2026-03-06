# External Integrations

**Analysis Date:** 2026-01-20

## Project Status

CipherBox is a **technology demonstrator** with the following integrations implemented:

- **IPFS (Kubo)**: File storage and IPNS publishing (`apps/api/src/ipfs/`)
- **Web3Auth MPC Core Kit**: Authentication and key derivation (`apps/web/src/lib/web3auth/`)
- **PostgreSQL**: User/vault metadata storage (`apps/api/src/`)
- **Redis/BullMQ**: Job queue for background tasks (`apps/api/src/`)
- **TEE (Phala Cloud)**: IPNS republishing (`tee-worker/`)

## APIs & External Services

**IPFS/IPNS (Implemented in PoC):**

- Local IPFS daemon (Kubo) - File storage and IPNS publishing
  - SDK/Client: `ipfs-http-client` 60.0.1
  - Connection: `IPFS_API_URL` env var (default: <http://127.0.0.1:5001>)
  - Gateway: `IPFS_GATEWAY_URL` env var (optional)
  - Usage: `00-Preliminary-R&D/poc/src/index.ts`

**Web3Auth (Implemented):**

- Authentication and key derivation - User identity
  - SDK/Client: `@web3auth/mpc-core-kit` (`apps/web/src/lib/web3auth/`)
  - Auth methods: Email OTP, Google OAuth, Magic Link, External Wallet
  - JWKS endpoint: `https://api-auth.web3auth.io/jwks`
  - Key feature: MPC-based deterministic keypair derivation with device factor MFA
  - Spec: `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` Section 2

**TEE Providers (Implemented — `tee-worker/`):**

- Trusted Execution Environment for IPNS republishing

**Phala Cloud (Primary):**

- TEE-based IPNS key decryption and signing
  - Cost: ~$0.10/hr
  - Features: Intel SGX hardware attestation, on-chain verification
  - Latency: 12-30s per republish
  - Spec: `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` Section 9

**AWS Nitro Enclaves (Fallback):**

- Backup TEE provider
  - Cost: ~$0.17-0.50/hr
  - Features: AWS custom silicon, AWS attestation API
  - Latency: <100ms per republish

## Data Storage

**Databases (Planned):**

- PostgreSQL - User accounts, vaults, tokens, audit logs
  - Tables: users, refresh_tokens, auth_nonces, vaults, volume_audit, pinned_cids, ipns_republish_schedule, tee_key_state, tee_key_rotation_log, ipfs_operations_log
  - Spec: `00-Preliminary-R&D/Documentation/API_SPECIFICATION.md` Section 4

**File Storage:**

- IPFS Network - Encrypted file content (decentralized)
- Kubo - Local IPFS node (pinning and availability)
- Local filesystem (PoC only) - State persistence in `./state/`

**Caching:**

- None implemented in PoC
- Planned: In-memory metadata cache, disk-based encrypted content cache (desktop)

## Authentication & Identity

**Auth Provider (Planned):**

- Web3Auth - Primary authentication
  - Implementation: Two-phase auth (Web3Auth + CipherBox backend)
  - Token types:
    - Web3Auth ID Token (1 hour) - For backend authentication
    - CipherBox Access Token (15 min) - API authorization
    - CipherBox Refresh Token (7 days) - Token renewal
  - Spec: `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` Section 2

**PoC Authentication:**

- Local private key from `.env` - No external auth
- secp256k1 keypair derived locally using `@noble/secp256k1`

## Monitoring & Observability

**Error Tracking:**

- None implemented

**Logs:**

- Console logging only (PoC)
- Planned: `ipfs_operations_log` table for IPFS/IPNS operation tracking

**Monitoring (Planned):**

- Republish success rate monitoring
- TEE response latency tracking
- Epoch rotation lag monitoring

## CI/CD & Deployment

**Hosting:**

- Not deployed (PoC runs locally)
- Planned: Web app hosting TBD, Backend hosting TBD

**CI Pipeline:**

- GitHub Actions (`.github/` directory present, contents not examined)

## Environment Configuration

**Required env vars (PoC):**

- `ECDSA_PRIVATE_KEY` - 32-byte hex string (no 0x prefix)

**Optional env vars (PoC):**

- `IPFS_API_URL` - IPFS daemon endpoint
- `IPFS_GATEWAY_URL` - IPFS gateway URL
- `IPFS_LOCAL_API_URL` - Kubo API endpoint
- `IPFS_LOCAL_GATEWAY_URL` - Kubo gateway endpoint
- `POC_STATE_DIR` - State persistence directory
- `IPNS_POLL_INTERVAL_MS` - Polling interval (default: 1500)
- `IPNS_POLL_TIMEOUT_MS` - Polling timeout (default: 120000)
- `STRESS_CHILDREN_COUNT` - Stress testing (default: 0)
- `STRESS_CHILD_TYPE` - Stress test type (file/folder)

**Secrets location:**

- `.env` file (local development)
- Environment variables (production, planned)

## Webhooks & Callbacks

**Incoming:**

- None

**Outgoing:**

- None

## IPFS/IPNS Integration Details

**IPFS Operations (from PoC):**

```typescript
// Adding content
const { cid } = await ctx.ipfs.add(content, { pin: false });

// Fetching content
const data = await collectChunks(ctx.ipfs.cat(cid));

// Pinning
await ctx.ipfs.pin.add(cid);
await ctx.ipfs.pin.rm(cid);

// Key management
await ctx.ipfs.key.gen(keyName, { type: 'ed25519' });
await ctx.ipfs.key.rm(keyName);
```

**IPNS Operations (from PoC):**

```typescript
// Publishing
await ctx.ipfs.name.publish(`/ipfs/${cid}`, {
  key: ipnsKeyName,
  allowOffline: true,
});

// Resolving
for await (const result of ctx.ipfs.name.resolve(ipnsName, { nocache: true })) {
  // Extract CID from result
}
```

**Production Relay Model (Planned):**

- Client signs IPNS records locally
- Backend relays signed records to IPFS network
- Backend never sees plaintext IPNS private keys
- Spec: `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` Section 5

---

Integration audit: 2026-01-20

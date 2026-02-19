# External Integrations

**Analysis Date:** 2026-01-20

## Project Status

CipherBox is a **technology demonstrator** with integrations split between:
- **Implemented (PoC)**: Local IPFS daemon, optional Pinata
- **Planned (Production)**: Web3Auth, PostgreSQL, Pinata, TEE providers

## APIs & External Services

**IPFS/IPNS (Implemented in PoC):**
- Local IPFS daemon (Kubo) - File storage and IPNS publishing
  - SDK/Client: `ipfs-http-client` 60.0.1
  - Connection: `IPFS_API_URL` env var (default: http://127.0.0.1:5001)
  - Gateway: `IPFS_GATEWAY_URL` env var (optional)
  - Usage: `00-Preliminary-R&D/poc/src/index.ts`

**Pinata (Implemented in PoC, optional):**
- Remote IPFS pinning service - Persistent file storage
  - SDK/Client: Native `fetch` API
  - Auth: `PINATA_API_KEY`, `PINATA_API_SECRET` env vars
  - Toggle: `PINATA_ENABLED=true`
  - Endpoints used:
    - `POST https://api.pinata.cloud/pinning/pinByHash` - Pin CID
    - `DELETE https://api.pinata.cloud/pinning/unpin/{cid}` - Unpin CID
  - Usage: `pinataPin()`, `pinataUnpin()` in `00-Preliminary-R&D/poc/src/index.ts`

**Web3Auth (Planned - Not Implemented):**
- Authentication and key derivation - User identity
  - SDK/Client: `@web3auth/modal` (planned)
  - Auth methods: Google, Apple, GitHub, Email, Magic Link, External Wallet
  - JWKS endpoint: `https://api-auth.web3auth.io/jwks`
  - Key feature: Group connections for deterministic keypair derivation
  - Spec: `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` Section 2

**TEE Providers (Planned - Not Implemented):**
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
- Pinata - Managed pinning (ensures availability)
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
- `PINATA_ENABLED` - Enable Pinata integration
- `PINATA_API_KEY` - Pinata authentication
- `PINATA_API_SECRET` - Pinata authentication
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
await ctx.ipfs.key.gen(keyName, { type: "ed25519" });
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

*Integration audit: 2026-01-20*

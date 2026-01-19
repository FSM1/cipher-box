# External Integrations

**Analysis Date:** 2026-01-19

## APIs & External Services

**IPFS/IPNS:**
- IPFS HTTP API - Content-addressed storage and retrieval
  - SDK/Client: `ipfs-http-client` 60.0.1
  - Connection: `IPFS_API_URL` env var (default: http://127.0.0.1:5001)
  - Operations: add (upload), cat (download), pin.add, pin.rm, name.publish (IPNS), name.resolve (IPNS)
  - Usage: All encrypted file and metadata storage in `poc/src/index.ts`

**Pinata:**
- Pinata Cloud Pinning Service - Remote IPFS pinning for durability
  - SDK/Client: Direct REST API via fetch
  - Auth: `PINATA_API_KEY` and `PINATA_API_SECRET` env vars
  - Endpoints: `https://api.pinata.cloud/pinning/pinByHash` (pin), `https://api.pinata.cloud/pinning/unpin/{cid}` (unpin)
  - Usage: Optional fallback pinning in `poc/src/index.ts` functions `pinataPin()` and `pinataUnpin()`
  - Toggle: `PINATA_ENABLED` env var (default: false)

**Web3Auth (Planned):**
- Web3Auth Network - OAuth-based key derivation and authentication
  - SDK/Client: @web3auth/modal (not yet implemented)
  - Auth: Group connections configured in Web3Auth dashboard
  - JWKS Endpoint: `https://api-auth.web3auth.io/jwks`
  - Issuer: `https://api-auth.web3auth.io`
  - Purpose: Deterministic ECDSA keypair derivation across auth methods
  - Implementation status: Dashboard setup complete, SDK integration pending

## Data Storage

**Databases:**
- PostgreSQL (planned, not implemented)
  - Connection: TBD
  - Client: TBD
  - Schema: Users, vaults, tokens, audit logs (see `Documentation/API_SPECIFICATION.md`)

**File Storage:**
- IPFS Network (decentralized, content-addressed)
  - Accessed via local Kubo node or Pinata gateway
  - All files encrypted client-side before upload
  - Gateway URL: `IPFS_GATEWAY_URL` env var (read operations)

**Caching:**
- None (IPNS resolution uses nocache option)

**Local Persistence:**
- File system via Node.js `fs/promises`
  - Location: `POC_STATE_DIR` env var (default: ./state)
  - Contents: `state.json` with rootIpnsName, rootIpnsKeyName, rootFolderKey (hex)

## Authentication & Identity

**Auth Provider:**
- Web3Auth (planned)
  - Implementation: Threshold cryptography for key derivation
  - Flow: User authenticates → Web3Auth derives ECDSA keypair → Client sends idToken to backend → Backend issues JWT

**Current PoC:**
- Direct ECDSA private key via `ECDSA_PRIVATE_KEY` env var
  - Public key derived using `@noble/secp256k1` getPublicKey()
  - No backend authentication in PoC

## Monitoring & Observability

**Error Tracking:**
- None

**Logs:**
- Console logging via `console.log()`, `console.warn()`, `console.error()`

## CI/CD & Deployment

**Hosting:**
- None (PoC runs locally)

**CI Pipeline:**
- None

**GitHub:**
- Repository: cipher-box
- PR templates in `.github/` directory

## Environment Configuration

**Required env vars:**
- `ECDSA_PRIVATE_KEY` - secp256k1 private key (hex, no 0x prefix)

**Optional env vars:**
- `IPFS_API_URL` - IPFS HTTP API endpoint
- `IPFS_GATEWAY_URL` - IPFS gateway for read operations
- `PINATA_ENABLED` - Enable Pinata pinning (true/false)
- `PINATA_API_KEY` - Pinata API authentication
- `PINATA_API_SECRET` - Pinata API authentication
- `POC_STATE_DIR` - Directory for state.json persistence
- `IPNS_POLL_INTERVAL_MS` - IPNS resolution polling interval
- `IPNS_POLL_TIMEOUT_MS` - IPNS resolution timeout
- `STRESS_CHILDREN_COUNT` - Stress test parameter (metadata size testing)
- `STRESS_CHILD_TYPE` - Stress test type (file/folder)

**Secrets location:**
- `.env` file in `poc/` directory (not committed, see `poc/.env.example`)

## Webhooks & Callbacks

**Incoming:**
- None

**Outgoing:**
- None

---

*Integration audit: 2026-01-19*

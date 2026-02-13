---
phase: 08-tee-integration
plan: 04
subsystem: infra
tags: [tee, phala, express, eciesjs, ipns, ed25519, secp256k1, docker, cvm]

# Dependency graph
requires:
  - phase: 08-01
    provides: TeeService HTTP client, TeeKeyStateService, RepublishEntry/RepublishResult interfaces
  - phase: 08-02
    provides: RepublishService batch processing that calls TEE worker HTTP API
  - phase: 08-03
    provides: Client-side ECIES encryption of IPNS keys with TEE public key
  - phase: 03-core-encryption
    provides: ECIES wrapKey/unwrapKey patterns, IPNS record creation and marshaling
provides:
  - Standalone TEE worker application (cipherbox-tee-worker) ready for Phala Cloud CVM deployment
  - POST /republish endpoint for batch IPNS record signing with epoch fallback
  - GET /public-key endpoint for epoch-based secp256k1 public key retrieval
  - GET /health endpoint for worker status monitoring
  - Simulator mode for local development without Phala hardware
  - Dockerfile and docker-compose.yml for CVM deployment with tappd.sock mount
affects: [09-desktop-app]

# Tech tracking
tech-stack:
  added:
    [
      express,
      eciesjs,
      '@noble/secp256k1',
      '@noble/ed25519',
      '@noble/hashes',
      '@libp2p/crypto',
      ipns,
      multiformats,
      tsx,
    ]
  patterns:
    - 'Standalone Express microservice outside pnpm workspace for independent deployment'
    - 'HKDF-SHA256 simulator key derivation with deterministic epoch keys'
    - 'ECIES decrypt with epoch fallback and lazy re-encryption for key rotation'
    - 'Immediate key zeroing via .fill(0) after IPNS signing'
    - 'Bearer token shared secret auth with timing-safe comparison'
    - 'Per-entry error handling in batch operations (one failure does not block others)'

key-files:
  created:
    - tee-worker/package.json
    - tee-worker/tsconfig.json
    - tee-worker/.env.example
    - tee-worker/src/index.ts
    - tee-worker/src/middleware/auth.ts
    - tee-worker/src/services/tee-keys.ts
    - tee-worker/src/services/key-manager.ts
    - tee-worker/src/services/ipns-signer.ts
    - tee-worker/src/routes/health.ts
    - tee-worker/src/routes/public-key.ts
    - tee-worker/src/routes/republish.ts
    - tee-worker/src/types/dstack-sdk.d.ts
    - tee-worker/Dockerfile
    - tee-worker/docker-compose.yml
  modified: []

key-decisions:
  - 'Type declarations for @phala/dstack-sdk instead of installing SDK in dev'
  - 'Timing-safe string comparison in auth middleware to prevent timing attacks'
  - '48-hour IPNS record lifetime for TEE-republished records (vs 24h for client)'
  - 'Per-entry try/catch in republish route for independent error handling'
  - 'Public key cache in memory (Map) to avoid repeated derivation for same epoch'
  - 'ESM module type (type: module) with bundler moduleResolution'

patterns-established:
  - 'TEE worker structure: Express entry point, services/, routes/, middleware/'
  - 'Epoch-based key derivation with simulator/CVM mode switch'
  - 'IPNS signing standalone replication from @cipherbox/crypto for independent deployment'
  - 'Docker Compose with tappd.sock volume mount for Phala Cloud CVM'

# Metrics
duration: 5min
completed: 2026-02-07
---

# Phase 8 Plan 04: TEE Worker Deployment Summary

**Standalone Express TEE worker with HKDF-simulated epoch keys, ECIES decrypt, IPNS signing, key zeroing, and Phala Cloud CVM Docker config.**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-07T05:32:11Z
- **Completed:** 2026-02-07T05:36:42Z
- **Tasks:** 2
- **Files modified:** 14

## Accomplishments

- Complete standalone TEE worker application at `tee-worker/` (outside pnpm workspace for independent deployment)
- Epoch-based secp256k1 key derivation with simulator mode (HKDF) and CVM mode (dstack SDK)
- ECIES decrypt with fallback from current to previous epoch, plus lazy re-encryption for key rotation
- IPNS record signing replicating `@cipherbox/crypto` logic with 48h record lifetime
- Immediate key zeroing (.fill(0)) at 3 points: after IPNS signing, after success, and on error
- Shared secret Bearer auth with timing-safe comparison
- Full integration test: encrypt IPNS key -> call /republish -> get signed record with incremented sequence number

## Task Commits

Each task was committed atomically:

1. **Task 1: TEE worker project scaffold with key derivation and ECIES decrypt** - `394215d` (feat)
2. **Task 2: IPNS signing route and Docker deployment config** - `eebdaf3` (feat)

## Files Created/Modified

- `tee-worker/package.json` - Standalone npm package with express, eciesjs, noble crypto, ipns dependencies
- `tee-worker/tsconfig.json` - ES2022 target with bundler moduleResolution
- `tee-worker/.env.example` - PORT, TEE_WORKER_SECRET, TEE_MODE configuration
- `tee-worker/src/index.ts` - Express server entry point with JSON 10mb limit, route mounting, auth middleware
- `tee-worker/src/middleware/auth.ts` - Bearer token auth with timing-safe string comparison
- `tee-worker/src/services/tee-keys.ts` - Epoch-based secp256k1 key derivation (HKDF simulator / dstack CVM)
- `tee-worker/src/services/key-manager.ts` - ECIES decrypt with epoch fallback, re-encryption for rotation
- `tee-worker/src/services/ipns-signer.ts` - IPNS record creation and signing with Ed25519, libp2p format, key zeroing
- `tee-worker/src/routes/health.ts` - GET /health returning status, mode, uptime
- `tee-worker/src/routes/public-key.ts` - GET /public-key?epoch=N returning hex secp256k1 public key
- `tee-worker/src/routes/republish.ts` - POST /republish batch IPNS signing with per-entry error handling
- `tee-worker/src/types/dstack-sdk.d.ts` - Type declarations for @phala/dstack-sdk (not installed in dev)
- `tee-worker/Dockerfile` - node:20-alpine for Phala Cloud CVM deployment
- `tee-worker/docker-compose.yml` - CVM config with tappd.sock mount and TEE_WORKER_SECRET env var

## Decisions Made

- **Type declarations over SDK install:** Created `dstack-sdk.d.ts` type declarations instead of installing @phala/dstack-sdk as dev dependency -- SDK is only available inside CVM at runtime, not needed for compilation
- **Timing-safe auth comparison:** Added constant-time string comparison in auth middleware to prevent timing attacks on shared secret
- **48-hour record lifetime:** TEE-republished IPNS records use 48h lifetime (vs 24h for client-published) to provide comfortable margin with 6-hour republish interval
- **Per-entry error handling:** Each entry in the republish batch is processed independently in try/catch -- one failure does not block others
- **Public key caching:** In-memory Map caches epoch public keys to avoid repeated HKDF derivation for the same epoch
- **ESM module type:** Package uses `"type": "module"` with bundler moduleResolution matching the tee-worker's independent deployment context

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - both tasks executed cleanly. TypeScript compilation passed on first attempt. Integration test (encrypt -> decrypt -> sign -> return) worked end-to-end in simulator mode.

## User Setup Required

None - the TEE worker runs independently with `npm run dev`. For production deployment on Phala Cloud CVM, set `TEE_WORKER_SECRET` and `TEE_MODE=cvm` in the docker-compose environment.

## Next Phase Readiness

- Phase 8 (TEE Integration) is now complete -- all 4 plans delivered
- TEE worker is ready for Phala Cloud CVM deployment with `docker compose up`
- Backend (08-01/02) connects to TEE worker via HTTP at TEE_WORKER_URL
- Client (08-03) encrypts IPNS keys with TEE public key on folder creation
- Worker (08-04) decrypts, signs, and returns signed records with key zeroing
- Full end-to-end TEE flow: client encrypts -> backend schedules -> TEE signs -> backend publishes

---

_Phase: 08-tee-integration_
_Completed: 2026-02-07_

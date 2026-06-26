---
phase: 35-phala-testnet-tee-migration
plan: 06
subsystem: infra
tags: [phala, tee, cvm, docker, ghcr, ecies, ipns]

requires:
  - phase: 35-03
    provides: Phala CVM docker-compose and dstack SDK integration
  - phase: 35-04
    provides: Staging workflow with deploy-tee-phala job
provides:
  - Running Phala Cloud CVM on testnet (prod5 node)
  - Verified epoch key determinism across CVM restarts
  - Verified end-to-end IPNS republish through CVM
  - Republish latency baselines for Phala CVM
  - GitHub staging secrets and variables configured
affects: [staging-deploy, tee-migration, ipns-republish]

tech-stack:
  added: [phala-cli]
  patterns: [cvm-deployment, epoch-persistence-verification]

key-files:
  created: []
  modified:
    - apps/tee-worker/Dockerfile

key-decisions:
  - 'Dockerfile needed @cipherbox/api-client for sdk-core DTS build'
  - 'Image built with --platform linux/amd64 (Docker host is ARM, Phala CVMs are x86_64)'
  - 'Used v35-amd64 tag to force CVM image re-pull (bypassed cached ARM latest)'
  - 'Generated fresh STAGING_TEE_WORKER_SECRET (old secret unavailable locally)'
  - 'Phala Cloud free tier ($20 credit) — no separate testnet exists'

patterns-established:
  - 'CVM deployment: always UPDATE existing CVM (same name), never delete+recreate (preserves app_id and epoch keys)'
  - 'Image tagging: use explicit architecture tags for cross-platform CVM deployments'

requirements-completed: []

duration: 45min
completed: 2026-03-29
---

# Plan 35-06: Initial Phala Cloud CVM Deployment Summary

**Phala Cloud CVM deployed (production infra, free tier — no separate testnet exists), epoch key persistence verified across restarts, IPNS republish cycle validated end-to-end**

## Performance

- **Duration:** ~45 min (across two sessions — dev machine + Docker host)
- **Started:** 2026-03-29T14:00:00Z
- **Completed:** 2026-03-29T16:35:00Z
- **Tasks:** 5
- **Files modified:** 1

## Accomplishments

- CVM running on Phala Cloud prod5 node (production infra, free tier) with hardware-backed key derivation (mode=cvm)
- Epoch 1 public key identical before and after CVM restart (SC-3: deterministic derivation)
- ECIES-encrypted IPNS key successfully decrypted and used for IPNS record signing (SC-2)
- Republish latency baselines: ~1155ms avg (network-bound to remote CVM, not compute-bound)
- GitHub staging environment fully configured: PHALA_CLOUD_API_KEY secret + PHALA_TEE_WORKER_URL variable

## Task Commits

1. **Task 1: Provision Phala Cloud account and API key** - Manual (GitHub secrets set)
2. **Task 2: Initial CVM deployment** - `bd265fa4f` (Dockerfile fix + deployment from Docker host)
3. **Task 3: Verify epoch persistence** - Verified inline (no code changes)
4. **Task 4: Verify IPNS republish cycle** - Verified inline (no code changes)
5. **Task 5: Capture latency baselines** - Verified inline (no code changes)

## CVM Details

| Field | Value |
|-------|-------|
| App ID | `011f138783487e4c43ea104cfcbacf817ac4f31b` |
| CVM ID | `28904e91-4a7f-4b70-904e-9351c84ecf83` |
| Name | `cipherbox-tee-staging` |
| Endpoint | `https://011f138783487e4c43ea104cfcbacf817ac4f31b-3001.dstack-pha-prod5.phala.network` |
| Image | `ghcr.io/fsm1/cipherbox-tee-worker:v35-amd64` |
| Node | prod5 |

## Verification Results

### SC-2: End-to-End IPNS Republish

- POST /republish with ECIES-encrypted key returns `success: true`
- signedRecord is non-empty (valid marshaled IPNS record)
- sequenceNumber correctly incremented from "1" to "2"

### SC-3: Epoch Key Persistence

- Pre-restart epoch 1 public key: `047356c8...28ad7d9`
- Post-restart epoch 1 public key: `047356c8...28ad7d9`
- **Match: identical** — deterministic HKDF derivation from app_id confirmed

### SC-4: Republish Latency Baselines

| Run | Latency | Success |
|-----|---------|---------|
| 1 | 1178ms | true |
| 2 | 1299ms | true |
| 3 | 1092ms | true |
| 4 | 1170ms | true |
| 5 | 1036ms | true |

- **Average:** ~1155ms
- **Verdict:** ACCEPTABLE — latency is network round-trip to Phala Cloud, not TEE compute. Co-located production deployment will be faster.

## Decisions Made

- Dockerfile needed api-client package added (sdk-core DTS build dependency)
- Must build with `--platform linux/amd64` for Phala CVM (x86_64)
- Used `v35-amd64` tag to bypass CVM image cache after initial ARM mismatch
- Phala Cloud free tier ($20 credit) used — no separate testnet exists
- Generated fresh TEE_WORKER_SECRET since old value was unavailable

## Deviations from Plan

None — plan executed as specified, with the expected Docker build issues resolved during Task 2.

## Issues Encountered

- ARM vs x86_64 mismatch: Docker host (macOS ARM) built wrong architecture initially. Resolved with `--platform linux/amd64`.
- CVM image cache: Phala Cloud cached the old ARM image under `latest` tag. Resolved by using explicit `v35-amd64` tag.
- CVM restart takes ~60-80s before health endpoint responds (expected for TEE boot sequence).

## Next Phase Readiness

- CVM is live and healthy, staging environment fully configured
- CI/CD pipeline has deploy-tee-phala job ready for automated deployments
- Next staging deploy (via staging tag) will automatically update the CVM

---

_Phase: 35-phala-testnet-tee-migration_
_Completed: 2026-03-29_

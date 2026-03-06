# Phase 8: TEE Integration - Context

**Gathered:** 2026-02-07
**Status:** Ready for planning

## Phase Boundary

IPNS records auto-republish via Phala Cloud TEE without the user being online. The CipherBox backend manages republish scheduling and sends TEE-encrypted IPNS private keys to the TEE worker for signing. Client encrypts IPNS keys with TEE public key on first publish (already implemented in Phase 5). TEE decrypts in hardware, signs IPNS records, and immediately zeros memory. Backend tracks republish jobs with retry queue and key epoch management.

## Implementation Decisions

### Key enrollment flow

- Automatic for all folders — every folder with an IPNS key gets TEE republishing, no user opt-in
- Client already sends `encryptedIpnsPrivateKey` on first publish (Phase 5) — no new client enrollment step needed
- CipherBox API stores the TEE-encrypted IPNS private key and manages when republishing happens
- Client does NOT talk to the TEE directly — backend mediates all TEE interactions
- When TEE is unavailable for enrollment, failed publishes enter the retry queue

### Republish scheduling

- Republish interval: every 6 hours (4 republishes per day per folder)
- IPNS records have ~48h TTL, so 6-hour interval provides comfortable margin
- Queue-based retry for failures — failed republishes go into a retry queue, backend processes periodically
- Batch processing: backend can batch multiple folder republishes in a single TEE session

### Republish failure handling

- Failed republishes enter retry queue with exponential backoff
- After retry threshold exceeded, folder marked as "stale" in DB
- No user notification for stale folders — completely invisible to user
- Dual recovery path (belt and suspenders):
  1. Backend auto-retries all stale folders when TEE recovers
  2. Client re-publishes stale folders on next login as safety net
- Admin health endpoint: `GET /admin/republish-health` returns aggregate counts (pending, failed, stale jobs) — requires admin authentication

### Key epoch rotation

- Phala Cloud only for v1 — no AWS Nitro fallback
- Key epoch rotation model depends on Phala Cloud's attestation and key lifecycle — **needs research**
- Grace period migration strategy (re-encrypt vs keep old epoch) — **needs research after understanding Phala's model**
- TEE deployment model (standalone Phala worker vs integrated) — **needs research into Phala Cloud deployment patterns**

### User observability

- Invisible to user — TEE republishing "just works" with no UI indicators
- No TEE-related messages shown to users
- Structured backend logging: republish attempts, successes, failures, durations with folder IDs (never log keys)
- Admin health endpoint for operational debugging

### Claude's Discretion

- TEE public key distribution method (API-provided vs bundled) — chose based on epoch rotation needs
- Error surfacing threshold — decide whether critically stale folders (>48h) warrant a subtle user warning
- Retry queue implementation details (table schema, processing interval, max retries)
- Batch size for TEE republish sessions
- Phala Cloud SDK/API integration specifics (after research)

## Specific Ideas

- "Given how catastrophic it would be if IPNS records expire, both backend auto-recovery AND client re-publish on login are good" — implement both recovery paths
- Phala Cloud documentation must be consulted for key epoch rotation model — don't assume time-based vs manual rotation
- TEE key management details depend heavily on Phala Network's architecture — researcher should investigate Phala Cloud deployment model, attestation lifecycle, and key management APIs

## Deferred Ideas

- AWS Nitro as fallback TEE provider — future enhancement if Phala proves unreliable
- User-facing republish status in settings page — add if users request visibility
- Per-folder republish status — too granular for v1

---

_Phase: 08-tee-integration_
_Context gathered: 2026-02-07_

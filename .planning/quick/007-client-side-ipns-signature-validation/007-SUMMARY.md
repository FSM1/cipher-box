---
phase: quick-007
plan: 01
subsystem: api, crypto, security
tags: [ed25519, ipns, signature-verification, protobuf, delegated-routing]

# Dependency graph
requires:
  - phase: 03-core-encryption
    provides: Ed25519 signing/verification, IPNS_SIGNATURE_PREFIX
  - phase: 05-folder-system
    provides: IPNS record parser, resolve endpoint, folder loading
provides:
  - Backend IPNS resolve returns signatureV2, data, pubKey fields
  - Client verifies Ed25519 signature before trusting resolved CID
  - Protection against metadata tampering via IPNS record interception
affects: [10-data-portability, desktop-client-sync]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Client-side IPNS signature verification before CID trust'
    - 'Protobuf field extraction for Ed25519 pubKey from libp2p wrapped key'

key-files:
  created: []
  modified:
    - apps/api/src/ipns/ipns-record-parser.ts
    - apps/api/src/ipns/dto/resolve.dto.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns.controller.ts
    - apps/web/src/services/ipns.service.ts
    - apps/web/src/api/models/resolveIpnsResponseDto.ts
    - packages/api-client/openapi.json

key-decisions:
  - 'Signature fields optional in response DTO - DB-cached fallback has no signature data'
  - 'Extract raw 32-byte Ed25519 key from 36-byte protobuf-wrapped libp2p key in parser'
  - 'Invalid signature throws Error (not CryptoError) - application-level validation'
  - 'signatureVerified boolean in resolve result for caller visibility without breaking changes'

patterns-established:
  - "IPNS signature verification: verify 'ipns-signature:' + CBOR data against pubKey"

# Metrics
duration: 4min
completed: 2026-02-10
---

# Quick Task 007: Client-Side IPNS Signature Validation Summary

Ed25519 signature verification on IPNS records before trusting resolved CID, closing metadata tampering attack vector.

## Performance

- **Duration:** 4 min
- **Started:** 2026-02-10T22:09:32Z
- **Completed:** 2026-02-10T22:13:10Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Extended IPNS protobuf parser to extract signatureV2 (field 8), data (field 9), and pubKey (field 7)
- Backend resolve endpoint now returns base64-encoded signature data from delegated routing responses
- Client verifies Ed25519 signature over "ipns-signature:" + CBOR data before trusting CID
- Invalid signature throws error preventing folder load with potentially tampered metadata
- DB-cached fallback (no signature data) continues to work with a warning log

## Task Commits

Each task was committed atomically:

1. **Task 1: Backend - Extract signature data from IPNS records** - `ac0c5aa` (feat)
2. **Task 2: Client - Verify IPNS signature before trusting CID** - `7411d8f` (feat)

## Files Created/Modified

- `apps/api/src/ipns/ipns-record-parser.ts` - Extended protobuf parser with fields 7/8/9, Ed25519 pubKey extraction from libp2p wrapping
- `apps/api/src/ipns/dto/resolve.dto.ts` - Added optional signatureV2, data, pubKey fields to response DTO
- `apps/api/src/ipns/ipns.service.ts` - Base64-encode signature fields, flow through resolve pipeline
- `apps/api/src/ipns/ipns.controller.ts` - Conditionally spread signature fields into response
- `apps/web/src/services/ipns.service.ts` - verifyIpnsSignature function, signature check in resolveIpnsRecord
- `apps/web/src/api/models/resolveIpnsResponseDto.ts` - Regenerated with new optional fields
- `packages/api-client/openapi.json` - Updated OpenAPI spec

## Decisions Made

- Signature fields are optional in the response DTO because DB-cached fallback resolves do not have signature data from the IPNS record
- Raw 32-byte Ed25519 public key extracted from 36-byte protobuf-wrapped libp2p key format (0x08 0x01 0x12 0x20 prefix) in the parser helper
- Invalid signature throws a plain Error (not CryptoError) since this is application-level validation, not a crypto operation failure
- Added `signatureVerified` boolean to resolve result for caller visibility without changing the existing `cid`/`sequenceNumber` interface
- No changes needed to callers (folder.service, FileBrowser, DetailsDialog) since they only use `cid` and `sequenceNumber`

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- IPNS signature validation active on all resolve paths
- Closes GitHub #71 security gap
- Ready for Phase 10 (Data Portability)

---

_Quick Task: 007-client-side-ipns-signature-validation_
_Completed: 2026-02-10_

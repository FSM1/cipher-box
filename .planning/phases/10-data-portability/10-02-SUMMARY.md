---
phase: 10-data-portability
plan: 02
subsystem: ui
tags: [recovery, ecies, aes-gcm, ipns, ipfs, fflate, noble-curves, standalone-html]

# Dependency graph
requires:
  - phase: 03-core-encryption
    provides: ECIES and AES-256-GCM encryption formats
  - phase: 05-folder-system
    provides: Folder metadata structure and IPNS-based hierarchy
provides:
  - Standalone vault recovery HTML page (no server dependencies)
  - ECIES decrypt reimplementation matching eciesjs@0.4.16
  - Public IPFS/IPNS gateway integration for infrastructure-free recovery
affects: [10-data-portability, documentation]

# Tech tracking
tech-stack:
  added: ['@noble/curves (CDN)', '@noble/hashes (CDN)', 'fflate (CDN)']
  patterns:
    [
      'Standalone static HTML with CDN ESM imports',
      'eciesjs@0.4.16 format reimplementation using noble-* primitives',
    ]

key-files:
  created: ['apps/web/public/recovery.html']
  modified: []

key-decisions:
  - 'Web Crypto API for all AES-256-GCM decryption (ECIES inner and folder/file)'
  - '16-byte nonce for ECIES AES-GCM matching eciesjs@0.4.16 default config'
  - 'Compressed ephemeral PK input to getSharedSecret matching eciesjs internal behavior'
  - 'Protobuf parsing for IPNS record extraction from delegated routing binary responses'
  - 'fflate UMD via non-module script tag, noble-* via ESM module imports'

patterns-established:
  - 'CDN ESM import pattern: jsdelivr.net/npm/@noble/* for crypto in standalone pages'
  - 'ECIES manual reimplementation: ephemeralPK(65) || nonce(16) || tag(16) || ciphertext(N)'

# Metrics
duration: 4min
completed: 2026-02-11
---

# Phase 10 Plan 02: Standalone Vault Recovery HTML Summary

**Self-contained recovery page reimplementing ECIES/AES-GCM crypto with CDN noble-\* libraries for infrastructure-free vault recovery**

## Performance

- **Duration:** 4 min
- **Started:** 2026-02-11T01:23:27Z
- **Completed:** 2026-02-11T01:27:45Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Built complete standalone recovery HTML page (1040 lines) with embedded CSS and JavaScript
- Reimplemented eciesjs@0.4.16 ECIES decrypt algorithm using noble-curves + noble-hashes + Web Crypto API
- 4-step guided walkthrough: load export, provide private key, configure gateways, recover files
- Recursive folder traversal with IPNS resolution, metadata decryption, and file download/decrypt
- Zip creation with folder structure preservation via fflate

## Task Commits

Each task was committed atomically:

1. **Task 1: Standalone recovery HTML page** - `8ea3e28` (feat)

## Files Created/Modified

- `apps/web/public/recovery.html` - Complete vault recovery tool: ECIES decrypt, AES-GCM decrypt, IPNS resolution, recursive folder traversal, zip download

## Decisions Made

- Used Web Crypto API for all AES-256-GCM operations (both ECIES inner decrypt with 16-byte nonce and folder/file decrypt with 12-byte IV). Web Crypto supports non-standard nonce lengths, avoiding need for @noble/ciphers CDN import.
- Compressed ephemeral PK passed to `getSharedSecret` to match eciesjs internal behavior (which calls `pk.toBytes(true)` for ECDH input), with uncompressed output for the shared point.
- Protobuf parser for IPNS record extraction handles binary responses from delegated routing API, with JSON fallback and ipfs.io name resolve as secondary fallback.
- fflate loaded via UMD script tag (non-module) since it needs `window.fflate`, while noble-\* loaded via ESM module imports for tree-shaking.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- `apps/web/public/` directory did not exist (Vite default). Created it; Vite automatically copies public/ contents to dist/ on build. Verified with `pnpm --filter web build`.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Recovery HTML page is complete and ready for integration testing with real vault export data
- Future plans in Phase 10 can add the API export endpoint and settings page button that generates the export JSON this tool consumes
- IPNS gateway reliability is the main runtime risk; multiple fallback gateways are configured

---

_Phase: 10-data-portability_
_Completed: 2026-02-11_

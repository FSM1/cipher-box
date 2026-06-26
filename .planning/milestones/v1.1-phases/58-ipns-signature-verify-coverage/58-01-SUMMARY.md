---
phase: 58-ipns-signature-verify-coverage
plan: 01
subsystem: infra
tags: [ipns, cbor, crypto, fuse, sdk-core, security, ciborium, cborg]

requires:
  - phase: 57-ipns-partial-signature-hardening
    provides: verify_ipns_resolve_signature returning Result<Option<bool>> used in bind_verified

provides:
  - decode_ipns_cbor_data helper in cipherbox-core inverting build_cbor_data
  - resolve_ipns_verified verified chokepoint in crates/fuse/src/verify.rs
  - All 9 FUSE resolve sites routed through verify chokepoint with D-02/D-03/D-04 posture
  - CBOR cid/sequence binding in sdk-core resolveIpnsRecord throwing on mismatch

affects:
  - 58-02 sdk-e2e binding regression pin
  - 58-03 Rust-JS posture dedup
  - 58-04 vector tests for verify/bind

tech-stack:
  added:
    - cborg ^4.5.8 as explicit sdk-core dependency for CBOR decode
  patterns:
    - D-01 single verified chokepoint pattern for IPNS resolves
    - D-02 scoped fail-closed posture for poll/metadata sites
    - D-03 hard fail-closed for security-boundary folder-key descent
    - D-04 legacy allow with warn for all-absent signature fields
    - D-07/D-08 CBOR binding as defense-in-depth after Ed25519 verification

key-files:
  created:
    - crates/fuse/src/verify.rs
  modified:
    - crates/core/src/ipns.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/events.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/publish.rs
    - crates/fuse/src/replay.rs
    - packages/sdk-core/src/ipns/index.ts
    - packages/sdk-core/src/__tests__/ipns.test.ts
    - packages/sdk-core/package.json

key-decisions:
  - 'CBOR import: cborg decode used in sdk-core (parseCborData from ipns unavailable in sdk-core context); cborg ^4.5.8 added as explicit dep'
  - 'VerifyError shape: Api(ApiError), Legacy, Invalid(String) — no extra variants'
  - 'VerifiedResolve.cid is the embedded CBOR value with /ipfs/ stripped per D-08'
  - 'resolve_sequence soft path: Invalid falls back to cache, preserving never-wedge contract'
  - 'resolve_sequence_strict: Invalid returns Err; Legacy proceeds with DB sequence per D-04'
  - 'replay.rs fetch_merge_publish_parent: Invalid retains journal entry for next replay attempt'
  - 'apps/desktop prepopulate.rs and vault.rs are out-of-scope for this plan (9 enumerated sites are all in crates/fuse/src/)'
  - 'bind_verified is a pure testable helper separated from resolve_ipns_verified for unit test coverage without network'

patterns-established:
  - 'CBOR binding pattern: decode signed data, compare Value=/ipfs/<cid> and Sequence==sequenceNumber, throw/Err on mismatch'
  - 'Legacy fallback: re-resolve bare API after VerifyError::Legacy to get raw cid for D-04 path'
  - 'All new FUSE resolve sites default to resolve_ipns_verified; direct resolve_ipns only permitted inside verify.rs and D-04 fallback arms'

requirements-completed: [HARD-09]

duration: 45min
completed: 2026-06-22
---

# Phase 58 Plan 01: IPNS Signature Verify Coverage Summary

**CBOR cid/sequence binding added to all 9 FUSE resolve sites and sdk-core resolveIpnsRecord, closing the CID/sequence-swap MITM gap via resolve_ipns_verified chokepoint and cborg decode**

## Performance

- **Duration:** ~45 min (recovery execution)
- **Started:** 2026-06-22
- **Completed:** 2026-06-22
- **Tasks:** 5 (Task 0 Wave-0 probe + Tasks 1-4)
- **Files modified:** 10

## Accomplishments

- `decode_ipns_cbor_data` helper in cipherbox-core round-trips `build_cbor_data` with full error coverage
- `resolve_ipns_verified` verified chokepoint in `crates/fuse/src/verify.rs` with `bind_verified` unit tests covering all postures
- All 9 FUSE resolve sites routed through the chokepoint with correct D-02/D-03/D-04 posture per site
- sdk-core `resolveIpnsRecord` decodes signed CBOR and throws on cid/sequence mismatch, propagating (not 404-swallowed)
- Task 0: Wave-0 probe confirmed `parseCborData` from `ipns` unavailable in sdk-core context; `cborg` added as explicit dep

## Task Commits

Each task was committed atomically:

1. **Task 0 Wave-0 probe** - `2a5d68fa8` (chore — prior session)
2. **Task 1 RED** - `f3a576c50` (test — prior session)
3. **Task 1 GREEN** - `271eb91f5` (feat — prior session)
4. **Task 2** - `69cbc5fd4` (feat — prior session)
5. **Task 3** - `39160a016` (feat)
6. **Task 4 RED** - `d4921a752` (test)
7. **Task 4 GREEN** - `08cd9c64c` (feat)

## Files Created/Modified

- `crates/fuse/src/verify.rs` - New: VerifyError, VerifiedResolve, bind_verified, resolve_ipns_verified
- `crates/core/src/ipns.rs` - Added decode_ipns_cbor_data helper
- `crates/fuse/src/lib.rs` - Added mod verify declaration
- `crates/fuse/src/events.rs` - spawn_metadata_refresh: D-02 scoped via resolve_ipns_verified
- `crates/fuse/src/fs.rs` - FilePointer resolve: D-02 scoped via resolve_ipns_verified
- `crates/fuse/src/metadata.rs` - remote_merge, bin entry, file-metadata: D-02 scoped
- `crates/fuse/src/publish.rs` - resolve_sequence soft and strict: D-02/D-04 per contract
- `crates/fuse/src/replay.rs` - resolve_folder_key D-03 hard + fetch_merge_publish_parent D-02
- `packages/sdk-core/src/ipns/index.ts` - CBOR binding after signatureVerified=true
- `packages/sdk-core/src/__tests__/ipns.test.ts` - 5 new D-07/D-08 binding tests; existing sig test updated to use real CBOR

## Decisions Made

- **CBOR import:** `cborg` decode used (not `parseCborData` from `ipns` — unavailable at sdk-core resolution path)
- **VerifyError::Legacy posture:** Re-resolve with bare `resolve_ipns` to recover the raw cid for D-04 callers. This is two round-trips for legacy records but keeps the safety boundary clear.
- **resolve_sequence soft path:** `VerifyError::Invalid` falls back to cache (preserves the "never wedge the mount" contract)
- **replay.rs fetch_merge_publish_parent:** `Invalid` returns `Err` so the journal entry is retained for the next replay attempt
- **Tauri desktop app (prepopulate.rs, vault.rs):** Out of scope for the 9 enumerated `crates/fuse/src/` sites; noted as deferred items

## Call-site Audit

Positive check: `grep -rln "resolve_ipns_verified" crates/fuse/src/` returns:

- events.rs, fs.rs, publish.rs, metadata.rs, replay.rs, verify.rs

Residual `resolve_ipns(` calls in those 5 files are exclusively inside `Err(VerifyError::Legacy)` fallback arms (D-04 path). No cid-trusting direct call remains outside `verify.rs`.

## Deviations from Plan

### Auto-fixed Issues

**1. Rule 1 - Bug: Missing 9th site in replay.rs fetch_merge_publish_parent**

- **Found during:** Task 3 verification (reviewing uncommitted diff)
- **Issue:** The uncommitted Task 3 work routed 8 of the 9 enumerated sites; `fetch_merge_publish_parent` at line 466 still used bare `resolve_ipns` directly
- **Fix:** Added `resolve_ipns_verified` routing with D-04 Legacy warn-and-proceed and Invalid returning Err to retain the journal entry
- **Files modified:** `crates/fuse/src/replay.rs`
- **Committed in:** `39160a016` (Task 3 commit)

**2. Rule 1 - Bug: resolve.cid dangling reference after replay.rs rename**

- **Found during:** `cargo check` after Task 3 edit
- **Issue:** Unpin call at line 567 still referenced `resolve.cid` after the variable was renamed to `parent_cid`
- **Fix:** Updated `resolve.cid` to `parent_cid`
- **Files modified:** `crates/fuse/src/replay.rs`
- **Committed in:** `39160a016` (Task 3 commit)

**3. Rule 1 - Bug: Existing "verifies signature" test used fake CBOR data incompatible with binding check**

- **Found during:** Task 4 GREEN implementation
- **Issue:** Test at line 143 passed `data: btoa('fake-cbor-data')` which cborg would fail to decode after binding was added
- **Fix:** Updated test to encode real CBOR matching `cid='QmSignedCid'`, `seq=10`
- **Files modified:** `packages/sdk-core/src/__tests__/ipns.test.ts`
- **Committed in:** `08cd9c64c` (Task 4 GREEN commit)

---

**Total deviations:** 3 auto-fixed (all Rule 1 bugs)
**Impact on plan:** All necessary for correctness. No scope creep.

## Deferred Items

- `apps/desktop/src-tauri/src/fuse/prepopulate.rs` (4 sites) and `apps/desktop/src-tauri/src/commands/vault.rs` (2 sites) still use bare `resolve_ipns`. These are outside the 9 enumerated `crates/fuse/src/` sites for this plan. Tracked for future hardening.

## Issues Encountered

- vi.clearAllMocks() in beforeEach does NOT reset mockImplementation (only clears call history). New D-07/D-08 tests needed explicit `vi.mocked(verifyEd25519).mockResolvedValue(true)` to avoid inheriting `false` from the preceding "throws on bad signature" test.

## Next Phase Readiness

- 58-02: sdk-e2e binding regression pin can now run the full round-trip with real server
- 58-03: Rust/JS postures are aligned (D-05); dedup analysis can proceed
- 58-04: vector test plan can target bind_verified, decode_ipns_cbor_data, and js binding

Phase: 58-ipns-signature-verify-coverage
Completed: 2026-06-22

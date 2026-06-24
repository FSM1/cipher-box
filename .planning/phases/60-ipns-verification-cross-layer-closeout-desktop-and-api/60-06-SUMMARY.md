---
phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
plan: "06"
subsystem: api/ipns
tags: [cache, security, d11, ipns, ed25519, tdd]
dependency_graph:
  requires: ["60-05"]
  provides: ["ipns-verify-cache", "d11-measurement"]
  affects: ["apps/api/src/ipns/ipns.service.ts"]
tech_stack:
  added: ["ipns-verify-cache (in-process Map, TTL 60s)"]
  patterns: ["module-level singleton cache", "TDD RED/GREEN cycle"]
key_files:
  created:
    - apps/api/src/ipns/ipns-verify-cache.ts
    - apps/api/src/ipns/ipns-verify-cache.spec.ts
    - scripts/bench-ipns-verify.ts
  modified:
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns.service.spec.ts
    - tsconfig.scripts.json
    - docs/CAPACITY.md
decisions:
  - "D-11 go decision: per-op verify cost (mean 0.105 ms) justifies a short-TTL cache"
  - "Cache key = ipnsName + base64(recordBytes) — any mutation to signatureV2/seq/CID produces different bytes and a mandatory cache miss"
  - "TEE republish path (publishSignedRecord + syncFolderIpnsSequence) does NOT call verifyIpnsRecordSignature — confirmed by reading republish.service.ts:133-178; cache does not apply to it"
  - "resolveRecord does not verify server-side; cache never populated from resolve path"
  - "No pnpm api:generate required — changes are internal service/cache logic with no OpenAPI surface change"
metrics:
  duration: "14min"
  completed: "2026-06-24"
  tasks: 2
  files: 7
---

# Phase 60 Plan 06: IPNS Verified-Record Cache Summary

Short-TTL in-process verified-record cache (D-11) implemented with full TDD cycle. Per-op Ed25519 verify cost measured (0.105 ms mean), cache wired into `publishRecord` with strict D-11 invariant: untrusted/DHT records always fully verified, cache only populated from successful in-process verifications.

## Tasks Completed

### Task 1: Benchmark per-op verification cost (D-11 measurement)

Created `scripts/bench-ipns-verify.ts` (typechecked via `tsconfig.scripts.json`, runnable via `npx tsx`). Benchmark uses `ipns@10 createIPNSRecord + marshalIPNSRecord` with `@libp2p/crypto@5.1.13` `generateKeyPairFromSeed` to produce a real 397-byte marshalled IPNS record, runs `verifyIpnsRecordSignature` N=200 times after warm-up, and measures Map.get() cache-hit cost.

Measured numbers (Apple M-series, Node.js v22, N=200 iterations):

| Measurement                               | mean (ms) | p50 (ms) | p99 (ms) |
| ----------------------------------------- | --------- | -------- | -------- |
| verifyIpnsRecordSignature (Ed25519+proto) | 0.105     | 0.095    | 0.337    |
| Map.get() cache-hit lookup                | ~0.000    | ~0.000   | ~0.001   |
| Recovery per skipped verify               | ~0.105    | --       | --       |

**Go decision:** 0.105 ms mean is recoverable and justifies the cache. At 50 concurrent clients each resubmitting an identical record, the server pays ~5.25 ms of avoidable Ed25519 overhead per request burst.

**Paths NOT subject to verify cost:** TEE republish path (`processRepublishBatch` → `publishSignedRecord` + `syncFolderIpnsSequence`) never calls `verifyIpnsRecordSignature` — confirmed by reading `republish.service.ts:133-178`. `resolveRecord` also does not verify server-side.

Recorded in `docs/CAPACITY.md` §1.6.

**Commit:** `909bf65e8`

### Task 2: Safe short-TTL verified-record cache wired into publishRecord (D-11) — TDD

#### RED phase

Created `apps/api/src/ipns/ipns-verify-cache.spec.ts` with 12 tests covering:

- Cache miss before first verify (Test 1)
- Cache hit after `recordVerified()` within TTL (Test 2)
- Cache miss after TTL expiry via `Date.now` override (Test 3)
- Different discriminator for same ipnsName is a MISS — full-triple key (Test 4)
- `publishRecord` calls verify on first submission (Test 5)
- `publishRecord` SKIPS verify on second identical submission within TTL, spy count = 0 (Test 6)
- `publishRecord` always verifies when record bytes differ (Test 7)
- `resolveRecord` never populates the cache — DHT records always fully verified (Test 8)

Tests failed at RED (module not found). Commit: `a7386ba54`

#### GREEN phase

Implemented `apps/api/src/ipns/ipns-verify-cache.ts`:

- `IpnsVerifyCache` class: `Map<string, number>` keyed by `${ipnsName}:${sequenceNumber}:${discriminator}`, value = insertion timestamp
- `recordVerified(ipnsName, sequenceNumber, discriminator)` — records successful in-process verify
- `isVerified(ipnsName, sequenceNumber, discriminator)` — checks TTL; evicts expired entries on read
- `clear()` — test helper to reset singleton state between tests
- `CACHE_TTL_MS = 60_000` (60 seconds) exported constant
- Module-level `ipnsVerifyCache` singleton

Wired into `apps/api/src/ipns/ipns.service.ts` `publishRecord`:

```
const recordBytesBase64 = Buffer.from(recordBytes).toString('base64');
const cacheHit = ipnsVerifyCache.isVerified(dto.ipnsName, '', recordBytesBase64);
if (!cacheHit) {
  verify() → throw on failure
  ipnsVerifyCache.recordVerified(dto.ipnsName, '', recordBytesBase64);
}
```

The discriminator is `base64(recordBytes)` — the full record bytes include signatureV2, sequence, CID, and validity. Any mutation to any field produces different bytes, a different cache key, and a mandatory full verify. This is strictly safer than a separate `(seq, sigV2)` extraction since it avoids a redundant `parseIpnsRecord` call that would have disrupted existing test mock sequences.

Added `ipnsVerifyCache.clear()` to `afterEach` in `ipns.service.spec.ts` (Rule 2: correctness fix — the singleton bleeds across tests causing false cache hits on `verifyIpnsRecordSignature` call-count assertions).

All 171 IPNS tests pass. Commit: `f12e681bf`

## Security Invariant Enforcement

| Threat | Mitigation | Verified by |
| ------ | ---------- | ----------- |
| T-60-20: cache skips verify of untrusted record | Cache populated ONLY after successful `verifyIpnsRecordSignature`; `resolveRecord` never calls `recordVerified` | Test 8 |
| T-60-21: CID-collision cache poisoning via different signatureV2 | Cache key = base64(recordBytes); different signatureV2 → different bytes → MISS → verify | Tests 4, 7 |
| T-60-22: TEE skipSigVerify bypass | No `skipSigVerify` in service or republish service (grep confirms); TEE path does not hit verify anchor | grep check |

```
grep skipSigVerify apps/api/src/ipns/ipns.service.ts apps/api/src/republish/republish.service.ts
→ no output (correct)
```

## D-11 Invariant: Untrusted/DHT Always Fully Verified

The D-11 invariant holds across all paths:

- `publishRecord`: cache checked first; MISS → full Ed25519 verify (unchanged behavior for first-time submissions); HIT → skip redundant verify for exact identical bytes only
- `resolveRecord`: no verify called server-side (unchanged)
- TEE republish: no `verifyIpnsRecordSignature` call (confirmed)
- `ipnsVerifyCache.recordVerified` is called in exactly ONE place: after a successful `verifyIpnsRecordSignature` in `publishRecord`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing correctness] Added `ipnsVerifyCache.clear()` to `ipns.service.spec.ts` afterEach**

- Found during: Task 2 GREEN implementation
- Issue: The module-level cache singleton bleeds across test runs in the same suite. After early tests succeeded and populated the cache for `testRecord` bytes, later tests expecting `verifyIpnsRecordSignature` to be called received cache hits instead (spy call count = 0 vs expected >= 1).
- Fix: Added `import { ipnsVerifyCache }` and `ipnsVerifyCache.clear()` to existing `afterEach` in `ipns.service.spec.ts`.
- Files modified: `apps/api/src/ipns/ipns.service.spec.ts`
- Commit: `f12e681bf` (bundled with GREEN implementation)

**2. [Rule 1 - Bug] Fixed bench script path for `@libp2p/crypto@5.1.13` vs `@5.0.10` and API for `generateKeyPairFromSeed`**

- Found during: Task 1 benchmark development
- Issue: Initial script used `@libp2p+crypto@5.0.10` path and `unmarshalPrivateKey` (not in v5 API); correct version is `5.1.13` and API is `keys.generateKeyPairFromSeed('Ed25519', seedBytes)`.
- Fix: Updated path constant and switched to `generateKeyPairFromSeed`.
- Files modified: `scripts/bench-ipns-verify.ts`
- Commit: `909bf65e8`

**3. [Rule 1 - Bug] ipns@10 `createIPNSRecord` expects string path not `Uint8Array`**

- Found during: Task 1 benchmark development
- Issue: Initial call passed `new TextEncoder().encode('/ipfs/...')` — ipns@10 expects the value as a plain string.
- Fix: Changed argument to `/ipfs/${TEST_CID}` string literal.
- Files modified: `scripts/bench-ipns-verify.ts`
- Commit: `909bf65e8`

## OpenAPI Surface

No change. The cache is internal to `ipns.service.ts`. No DTO, controller, or endpoint was modified. `pnpm api:generate` not required (decision recorded in plan).

## Known Stubs

None.

## Threat Flags

None beyond the plan's existing threat model. No new network endpoints, auth paths, or schema changes introduced.

## Self-Check: PASSED

- [x] `scripts/bench-ipns-verify.ts` exists and runs
- [x] `apps/api/src/ipns/ipns-verify-cache.ts` exists
- [x] `apps/api/src/ipns/ipns-verify-cache.spec.ts` exists
- [x] `docs/CAPACITY.md` §1.6 has measured numbers
- [x] All 171 IPNS tests pass
- [x] `npx tsc -p tsconfig.scripts.json --noEmit` clean
- [x] Commits: 909bf65e8 (task 1), a7386ba54 (RED), f12e681bf (GREEN)

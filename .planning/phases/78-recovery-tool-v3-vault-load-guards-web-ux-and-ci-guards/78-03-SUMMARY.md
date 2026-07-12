---
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
plan: 03
subsystem: testing
tags: [recovery, e2e, playwright, ipns, ecies, eciesjs, browser-bundle, cors, buffer-polyfill]

requires:
  - phase: 78-02
    provides: "shipped apps/web/public/recovery.html (v3 walk + DOM wiring) driven via stable data-testids"
provides:
  - "tests/web-e2e/tests/recovery.spec.ts un-fixme'd — now an active permanent regression test (SC1 exit-grep clean)"
  - "Airtight root-cause diagnosis of TWO blockers preventing the browser recovery tool from recovering a v3 vault"
affects: [78-02, recovery-tool, web-e2e]

tech-stack:
  added: []
  patterns: [gateway-only-recovery-walk, node-vs-browser-crypto-isolation-probe]

key-files:
  created:
    - .planning/phases/78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards/78-03-SUMMARY.md
  modified:
    - tests/web-e2e/tests/recovery.spec.ts

key-decisions:
  - "Left recovery.spec.ts ACTIVE (never re-deferred) per D-01 — it now correctly RED-flags a real, previously-hidden recovery-tool defect."
  - "Did NOT fix recovery-src (build.ts / eciesjs Buffer polyfill) — explicitly out of this plan's file scope (orchestrator anchor: only file is recovery.spec.ts)."

patterns-established:
  - "Node-vs-browser crypto isolation: reproduce the exact recovery read-chain in node to prove data/crypto correctness, isolating a failure to the browser bundle."

requirements-completed: []

coverage:
  - id: D1
    description: "recovery.spec.ts un-fixme'd — deferred marker removed, v2->v3 wording, FIXME(recovery-v3) block deleted; phase exit grep for test.fixme/test.skip is clean."
    requirement: "SC1"
    verification:
      - kind: other
        ref: "grep -rnE 'test\\.(fixme|skip)\\(' tests/web-e2e/tests/*.spec.ts  => (empty); grep -c 'FIXME(recovery-v3)' recovery.spec.ts => 0"
        status: pass
    human_judgment: false
  - id: D2
    description: "Un-fixme'd recovery.spec.ts passes GREEN — the shipped browser recovery tool recovers the seeded v3 vault from privateKey via the gateway-only walk."
    requirement: "SC1"
    verification:
      - kind: e2e
        ref: "pnpm --filter @cipherbox/web-e2e test -- recovery.spec.ts"
        status: fail
    human_judgment: true
    rationale: "Deterministic RED. Two root-caused blockers (stale-CORS docker mock [infra] + missing Buffer polyfill in the recovery esbuild bundle breaking eciesjs unwrapKey in-browser [recovery-src defect, out of this plan's scope]). Requires a recovery-src fix before it can go green — see Issues Encountered."

duration: 55min
completed: 2026-07-12
status: blocked
---

# Phase 78 Plan 03: Un-fixme Recovery E2E and SC1 Integration Gate Summary

**recovery.spec.ts is now an active regression test (SC1 exit-grep clean), and it deterministically catches a real, previously-hidden recovery-tool defect: the browser bundle's ECIES key-unwrap throws because the esbuild bundle ships no `Buffer` polyfill.**

## Performance

- **Duration:** ~55 min
- **Completed:** 2026-07-12
- **Tasks:** 1 of 2 complete (Task 2 blocked by an out-of-scope recovery-src defect)
- **Files modified:** 1 (`tests/web-e2e/tests/recovery.spec.ts`)

## Accomplishments

- **Task 1 (DONE):** Un-fixme'd `recovery.spec.ts` — promoted the single `test.fixme(...)` to an active `test(...)`, refreshed the v2-blob header/inline comments to describe the v3 read chain, and deleted the stale `FIXME(recovery-v3)` porting-gap block. The phase exit grep is clean: `grep -rnE 'test\.(fixme|skip)\(' tests/web-e2e/tests/*.spec.ts` returns nothing, and `grep -c "FIXME(recovery-v3)"` is 0.
- **Task 2 (BLOCKED, fully diagnosed):** The un-fixme'd spec deterministically fails. Two independent root causes were isolated to airtight certainty (node-side proof that data + crypto are correct; browser is the sole failing surface). SC1 is NOT satisfied — the shipped recovery tool cannot recover a v3 vault in the browser without a `recovery-src` fix. The spec is left ACTIVE (not re-deferred), which is exactly its job as a permanent regression guard.

## Task Commits

1. **Task 1: Un-defer recovery.spec.ts and refresh its stale v2 header** - `a13f44ae5` (test)

**Plan metadata:** this SUMMARY commit (docs)

## Files Created/Modified

- `tests/web-e2e/tests/recovery.spec.ts` - Removed `.fixme`, updated title to "recovers vault files via IPFS-direct v3 read chain", rewrote header + inline comments for the v3 chain, deleted the FIXME(recovery-v3) block. Fixture/`beforeAll` seeding and all `data-testid` locators unchanged; 90s `RECOVERY_TIMEOUT_MS` preserved.

## Decisions Made

- Kept the spec ACTIVE and RED rather than papering over or re-deferring — the failure is a genuine recovery-tool defect, exactly what SC1's exit gate exists to surface.
- Did not touch `apps/web/recovery-src` (the actual defect location) — the orchestrator anchor scopes this plan to `recovery.spec.ts` only, and 78-02's recovery-src typecheck/rebuild is an explicit deferred follow-up.

## Deviations from Plan

None to the in-scope file. The plan anticipated a possible blocker ("if genuinely infra-blocked, document ... spec left active"); the actual blocker is a mix of infra + a real recovery-src defect, documented below.

## Issues Encountered

Task 2 fails deterministically (retried across multiple runs — not a flake). Diagnosis, in the order the failures surfaced:

### 0. Test harness env gap (worked around, not a code change)

`tests/web-e2e/.env` sets `TEST_LOGIN_SECRET` but NOT `SDK_E2E_SECRET`. The seeding harness (`tests/sdk-e2e/src/fixtures/test-harness.ts:19`) reads `SDK_E2E_SECRET` (falling back to a public default), so `beforeAll` seeding got `401 Invalid test login secret`. Worked around by exporting `SDK_E2E_SECRET=$TEST_LOGIN_SECRET` for the run. Not committed. (Follow-up candidate: add `SDK_E2E_SECRET` to the web-e2e env, or have the harness also read `TEST_LOGIN_SECRET`.)

### 1. INFRA — stale docker `cipherbox-mock-ipns-routing` predates the committed CORS hook

- **Symptom:** browser `fetch('http://localhost:3001/routing/v1/ipns/<name>')` blocked: "No 'Access-Control-Allow-Origin' header is present". `OPTIONS` preflight returned `404`.
- **Root cause:** `tools/mock-ipns-routing/src/index.ts` has a CORS `onRequest` hook (committed 2026-03-26, #365), but the running docker container (image `docker-mock-ipns-routing:latest`, up 14h) was built before that and emits no CORS headers. The image builds from a baked Dockerfile (no volume mount), so the container never picked up the source change.
- **Status:** WORKED AROUND for verification by running a dependency-free CORS-enabled replica of the mock on :3001 (docker container stopped, then restored). A proper fix is `docker compose build mock-ipns-routing && docker compose up -d mock-ipns-routing` — which could NOT be run now because Docker Hub metadata for `node:22-alpine` is unreachable from this host (`DeadlineExceeded` pulling the base image; it is not cached locally).
- **Node proof:** the same IPNS name resolves at :3001 from node (CORS-exempt) in ~3ms with `verify=true` and a valid `/ipfs/<cid>` value — so publish/propagation and the record are correct.

### 2. RECOVERY-SRC DEFECT (blocking, out of this plan's scope) — missing `Buffer` polyfill breaks eciesjs in-browser

- **Symptom:** with CORS fixed, the browser tool advances past IPNS resolve + vault-blob fetch, then fails at "Recovery failed: Key unwrapping failed" (from `unwrapKey` in `packages/crypto/src/ecies/decrypt.ts:52`).
- **Root cause:** `unwrapKey` uses the `eciesjs` library, which calls `Buffer.from(...)` internally (6 refs in `eciesjs/dist/index.js`). The shipped `apps/web/public/recovery.html` esbuild bundle references `globalThis.Buffer` but provides NO `Buffer` polyfill. On the page, `typeof Buffer === 'undefined'` (and `typeof process === 'undefined'`), so every ECIES key-unwrap throws — the error is swallowed by `unwrapKey`'s oracle-safe generic `catch` into "Key unwrapping failed".
- **Node proof (identical inputs):** in node the full chain — resolve -> fetch v3 blob (263 bytes, version byte `0x03`) -> `deserializeVaultBlobV3` (encRootReadKey 129 bytes) -> `unwrapKey` -> 32-byte `rootReadKey` — succeeds and the unwrapped key byte-matches `account.rootFolderKey`. So the data, the codec, and the crypto are all correct; the browser bundle is the sole failing surface.
- **Fix location (NOT this plan — recovery-src / 78-02 territory):** teach the recovery esbuild build (`apps/web/recovery-src/build.ts`) to inject a `Buffer` polyfill (bundle the `buffer` shim and `define`/`inject` `globalThis.Buffer`, likely `process` too), then re-run `recovery:build` so `public/recovery.html` carries a working `Buffer`. This plan's anchor explicitly forbids touching `recovery-src`.

## SC1 status

NOT satisfied. Task 1's exit-grep criterion is met and the spec is active, but the SC1 integration proof (a passing recovery walk) cannot go green until the `recovery-src` `Buffer`-polyfill defect (Issue 2) is fixed, and — for the e2e to run against the standard docker stack — the stale mock-ipns-routing image is rebuilt with the CORS hook (Issue 1). Neither is in this plan's file scope.

## Next Phase Readiness

- **Blocker for SC1:** a `recovery-src` fix is required (Issue 2). Recommend a follow-up plan (78-04 or a 78-02 rework) that: (a) adds the `Buffer` polyfill to `apps/web/recovery-src/build.ts` and re-runs `recovery:build`; (b) rebuilds the docker `mock-ipns-routing` image so its committed CORS hook is live; and optionally (c) wires `SDK_E2E_SECRET` into the web-e2e env. The now-active `recovery.spec.ts` will verify the fix end-to-end.
- The spec itself is production-ready and correctly gates the recovery path — it is intentionally RED until the tool is fixed.

## Self-Check: PASSED

- `tests/web-e2e/tests/recovery.spec.ts` — present, active `test(`, exit grep clean.
- `78-03-SUMMARY.md` — present.
- Task 1 commit `a13f44ae5` — present in git log.

---
*Phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards*
*Completed: 2026-07-12*

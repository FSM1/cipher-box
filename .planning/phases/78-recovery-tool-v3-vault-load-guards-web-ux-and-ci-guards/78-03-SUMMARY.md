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
        status: pass
    human_judgment: true
    rationale: "Now GREEN. The two root-caused blockers were fixed by the orchestrator (commit ac12fea04: Buffer polyfill injected into the recovery esbuild bundle + a splice-corruption fix). Re-run against a CORS-enabled mock-ipns-routing passes: recovery.spec.ts is GREEN (1 passed, recovery walk 589ms). SC1 proven end-to-end — see SC1 status."

duration: 55min
completed: 2026-07-12
status: complete
---

# Phase 78 Plan 03: Un-fixme Recovery E2E and SC1 Integration Gate Summary

**recovery.spec.ts is now an active regression test (SC1 exit-grep clean). It deterministically caught a real, previously-hidden recovery-tool defect (the browser bundle's ECIES key-unwrap threw because the esbuild bundle shipped no `Buffer` polyfill); the orchestrator fixed it (commit `ac12fea04`) and the spec now passes GREEN — SC1 is proven end-to-end.**

## Performance

- **Duration:** ~55 min
- **Completed:** 2026-07-12
- **Tasks:** 2 of 2 complete (Task 2's SC1 proof went GREEN after the orchestrator's out-of-scope recovery-src fix, commit `ac12fea04`)
- **Files modified:** 1 (`tests/web-e2e/tests/recovery.spec.ts`)

## Accomplishments

- **Task 1 (DONE):** Un-fixme'd `recovery.spec.ts` — promoted the single `test.fixme(...)` to an active `test(...)`, refreshed the v2-blob header/inline comments to describe the v3 read chain, and deleted the stale `FIXME(recovery-v3)` porting-gap block. The phase exit grep is clean: `grep -rnE 'test\.(fixme|skip)\(' tests/web-e2e/tests/*.spec.ts` returns nothing, and `grep -c "FIXME(recovery-v3)"` is 0.
- **Task 2 (DONE — GREEN):** The un-fixme'd spec originally failed deterministically; two independent root causes were isolated to airtight certainty (node-side proof that data + crypto are correct; browser was the sole failing surface). The orchestrator then fixed the browser-bundle defect (`Buffer` polyfill + a splice-corruption fix, commit `ac12fea04`). Re-running the spec against a CORS-enabled mock-ipns-routing now passes: **`1 passed (10.4s)`**, recovery walk `589ms`. SC1 is satisfied — the shipped recovery tool recovers a seeded v3 vault from `privateKey` alone via the gateway-only walk. The spec stays ACTIVE as a permanent regression guard.

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

## SC1 status — SATISFIED (green-run confirmed)

**Update (2026-07-12, post-fix green run):** SC1 is now proven end-to-end. The blocking `recovery-src` `Buffer`-polyfill defect (Issue 2) was fixed by the orchestrator in **commit `ac12fea04`**, which also fixed a re-splice bug that corrupted `recovery.html` on bundles containing `$` sequences:

1. **Buffer polyfill** — added a `buffer` devDep and injected a buffer-shim in `recovery-src/build.ts`; `apps/web/public/recovery.html` was rebuilt (345,761 bytes, single bundle block) so `globalThis.Buffer` is now defined in-browser and `eciesjs`' internal `Buffer.from(...)` works — `unwrapKey` no longer throws.
2. **Splice fix** — replaced the string-replace injection with a function replacement so `$`-bearing bundles are not corrupted.

Neither fix is in this plan's file scope (recovery-src / 78-02 territory); this plan (78-03) only re-runs and documents.

### Green-run record

- **Command:** `pnpm --filter @cipherbox/web-e2e test -- recovery.spec.ts` (from the worktree root; Playwright auto-booted API :3000 + web :5173, reused a CORS-enabled mock-ipns-routing on :3001).
- **Result:** **GREEN — `1 passed (10.4s)`**, recovery walk itself `589ms`. The browser tool recovered the seeded v3 vault file from `privateKey` alone via the gateway-only chain (IPNS resolve → IPFS fetch → v3 vault-blob decrypt → sealed-child walk → file decrypt), with the CipherBox API absent from the recovery loop (D-01/D-02 upheld — the API only appears in `beforeAll` seeding).
- **Infra note (Issue 1 still stands for the standard stack):** the committed CORS hook in `tools/mock-ipns-routing/src/index.ts` is correct, but the running docker `cipherbox-mock-ipns-routing` image predates it and emits no CORS headers. For this run it was temporarily stopped and replaced with a fresh CORS-enabled instance of the same mock on :3001 (`node tools/mock-ipns-routing/dist/index.js`), then the docker container was restored. A durable fix is `docker compose build mock-ipns-routing && docker compose up -d mock-ipns-routing` so the standard stack serves CORS.
- **Env note (Issue 0 still stands):** the run exported `SDK_E2E_SECRET=$TEST_LOGIN_SECRET` because `tests/web-e2e/.env` sets only `TEST_LOGIN_SECRET` (the seeding harness reads `SDK_E2E_SECRET`). Not committed. Follow-up candidate: wire `SDK_E2E_SECRET` into the web-e2e env or have the harness also read `TEST_LOGIN_SECRET`.

## Next Phase Readiness

- **SC1 blocker cleared:** the recovery-tool defect is fixed (`ac12fea04`) and `recovery.spec.ts` is GREEN. The spec is a live permanent regression guard for the recovery path.
- **Remaining infra follow-ups (non-blocking for SC1, needed for CI/standard-stack repeatability):** (a) rebuild the docker `mock-ipns-routing` image so its committed CORS hook is live; (b) optionally wire `SDK_E2E_SECRET` into the web-e2e env.

## Self-Check: PASSED

- `tests/web-e2e/tests/recovery.spec.ts` — present, active `test(`, exit grep clean.
- `78-03-SUMMARY.md` — present.
- Task 1 commit `a13f44ae5` — present in git log.

---
*Phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards*
*Completed: 2026-07-12*

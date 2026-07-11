---
phase: 77
slug: crypto-hygiene-and-terminology-canonicalization
status: verified
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-11
---

# Phase 77 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Derived from `77-RESEARCH.md` § Validation Architecture. Task IDs (`77-NN-MM`) are assigned by the planner; the rows below are keyed to success criteria and are refined into per-task rows during planning.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest (`packages/crypto`, `packages/core`, `packages/sdk-core`, `packages/sdk`, `apps/tee-worker`) + Jest (`apps/api`) |
| **Config file** | per-package `vitest.config.ts`; `apps/api/jest.config.js` |
| **Quick run command** | `pnpm --filter <pkg> test` (e.g. `pnpm --filter @cipherbox/crypto test`) |
| **Full suite command** | root `pnpm typecheck && pnpm test` |
| **Estimated runtime** | quick per-package ~5–30s; full suite (CI `Test` job = api/crypto/core/sdk-core/sdk/api-client) a few minutes |

---

## Sampling Rate

- **After every task commit:** Run the touched package's quick command, `pnpm --filter <pkg> test`.
- **After every plan wave:** Run the quick commands for the whole dependency chain in order — crypto → core → sdk-core → sdk (rebuild dist between each, per RESEARCH Pitfall 5) — plus `apps/api` + `apps/tee-worker` tests for the independent API/TEE wave.
- **Before `/gsd-verify-work`:** root `pnpm typecheck && pnpm test` must be green (cross-package blast radius makes a partial local run insufficient proof).
- **Max feedback latency:** < 30s per-task quick run.

---

## Per-Task Verification Map

| Criterion | Behavior | Wave | Test Type | Automated Command | File Exists | Status |
|-----------|----------|------|-----------|-------------------|-------------|--------|
| SC1 — createSubfolder | Forcing `sealNode`/`addToIpfs`/`createAndPublishIpnsRecord` — and the TEE-wrap step — to throw zeroes `ipnsPrivateKey`/`readKey`/`writeKey` (owned buffers only) | 1 | unit | `pnpm --filter @cipherbox/sdk-core test -- folder.test.ts` | ✅ exists (16 tests incl. 2 forced-throw zeroization tests) | ✅ green |
| SC1 — AES key-buffer zeroization | Internal `keyView` copy `.fill(0)`'d after `crypto.subtle.importKey` (GCM + CTR, 7 fns route through `importAesKey`) | 1 | unit | `pnpm --filter @cipherbox/crypto test -- aes.test.ts aes-ctr.test.ts` | ✅ exists (`importAesKey` extracted; 210 crypto tests pass) | ✅ green |
| SC1 — verify-filepointer.mts | `userPrivateKey` / derived read keys cleared before process exit | 1 | manual/smoke | run script vs local dev stack (script family has no unit harness — matches sibling scripts) | N/A (manual, documented below) | ✅ source-reviewed |
| SC2 — base64 dedup parity | `@cipherbox/crypto` `base64ToBytes`/`bytesToBase64` round-trip golden vectors | 1 | unit (golden vector) | `pnpm --filter @cipherbox/crypto test -- encoding.test.ts` | ✅ exists (8 golden-vector tests) | ✅ green |
| SC2 — node/ codec parity | `sealNode`/`unsealNode` golden vectors still pass byte-for-byte after consolidation | 1 | unit (golden vector) | `pnpm --filter @cipherbox/core test -- node-codec-vectors.test.ts node-codec.test.ts` | ✅ exists (re-run as parity gate) | ✅ green |
| SC3 — canonical names + dead code gone | `encryptedIpnsPrivateKey` everywhere; `ShareCallbacks`/`addShareKeysFn` fully removed, no orphaned refs | all | typecheck + unit | root `pnpm typecheck && pnpm test` | N/A (existing infra, final gate) | ✅ green |
| SC3 — TEE wire round-trip | Renamed `encryptedIpnsPrivateKey` field decodes + re-signs through the real verify-in-enclave path | all | unit (real decrypt) | `pnpm --filter cipherbox-tee-worker test` (`__tests__/republish.test.ts`) + `apps/api` tee/republish specs | ✅ exists (76 tee-worker + api specs; POSTs `encryptedIpnsPrivateKey`, real `decryptWithFallback`) | ✅ green |
| SC12 — assertRootOwnership helper | Extracted helper throws `ForbiddenException` when caller doesn't own the node, in both `createShare` and `createInvite` | 2 | unit | `pnpm --filter cipherbox-api test -- shares.service.spec.ts share-invite.service.spec.ts` | ✅ exists (behavioral, 57 pass) | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] `packages/crypto/src/__tests__/encoding.test.ts` — new file, base64 round-trip golden vectors (SC2)
- [x] New forced-throw zeroization assertion for `createSubfolder` in `packages/sdk-core/src/__tests__/folder.test.ts` (SC1) — extended in ship-phase with a second test covering the TEE-wrap throw path
- [x] New AES key-buffer zeroization test(s) — `importAesKey()` extracted so the owned copy is independently testable (SC1)
- [x] Framework install: none — vitest + jest already present and configured

---

## Manual-Only Verifications

| Behavior | Criterion | Why Manual | Test Instructions |
|----------|-----------|------------|-------------------|
| `verify-filepointer.mts` key zeroization | SC1 | The `.mts` e2e helper-script family has no unit harness (siblings `edit-filepointer.mts` / `rename-folder.mts` have none either); adding one is out of scope | Run the script against a local dev stack, confirm it completes without crash and keys are `.fill(0)`'d before exit (source review + smoke run) |

---

## Validation Sign-Off

- [x] All tasks have an `<automated>` verify or a Wave 0 dependency (except the one documented manual-only smoke)
- [x] Sampling continuity: no 3 consecutive tasks without an automated verify
- [x] Wave 0 covers all MISSING references (3 new test files above)
- [x] No watch-mode flags in any test command
- [x] Feedback latency < 30s per-task
- [x] `nyquist_compliant: true` set in frontmatter — every criterion maps to a green automated verify (one documented manual-only smoke)

**Approval:** verified 2026-07-11

---

## Validation Audit 2026-07-11

| Metric | Count |
|--------|-------|
| Gaps found | 0 |
| Resolved | 7 (all criteria COVERED by existing/passing tests) |
| Escalated | 1 (`verify-filepointer.mts` — documented manual-only smoke, no unit harness in the `.mts` script family) |

State-A audit at ship time: the pre-execution draft's three Wave-0 MISSING tests were all created and pass (`encoding.test.ts` 8, `folder.test.ts` 16, AES via `importAesKey` 210 crypto). Criteria verified directly (crypto 210 pass, sdk-core 392 pass, api shares 57 pass) and by `77-VERIFICATION.md`.

**SDK E2E gate:** `105/106` sdk-e2e round-trips pass locally (real client→API IPNS publish/resolve, rotation, share, bin, batch, data-integrity — all green) against a freshly-rebuilt tee-worker. The single non-pass is `tee-republish.test.ts` Test A (`waitFor` timeout). Root-caused: the republish batch logged `processed=0` and the TEE worker received **zero** `/republish` calls — i.e. the batch found no due schedule row (a local `makeScheduleDue`-vs-enrollment-commit scheduling race on this stack), so the run never reached the renamed wire field. The failure is therefore **orthogonal to phase 77** — the renamed `encryptedIpnsPrivateKey` payload is never exercised by this timeout. The rename's actual decode+re-sign contract is proven by the tee-worker unit suite (76 pass, real `decryptWithFallback`) and the api tee/republish specs. Reproduced identically on a clean (truncated) DB, confirming it is not state pollution. Deferred to the CI `sdk-e2e` gate, which provisions a clean stack.

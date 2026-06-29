---
phase: 64
slug: rotation-soundness-revocation-guarantees
status: final
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-29
---

# Phase 64 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest (sdk-core unit) + sdk-e2e (live API round-trip) |
| **Config file** | `packages/sdk-core/vitest.config.ts`; `tests/sdk-e2e/` |
| **Quick run command** | `pnpm --filter @cipherbox/sdk-core test` |
| **Full suite command** | `pnpm --filter @cipherbox/sdk-core test && pnpm --filter sdk-e2e test` |
| **Estimated runtime** | ~60–180 seconds (unit); sdk-e2e adds live-stack round-trip time |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/sdk-core test`
- **After every plan wave:** Run the full suite command
- **Before `/gsd-verify-work`:** Full suite (incl. sdk-e2e) must be green
- **Max feedback latency:** ~180 seconds

---

## Per-Task Verification Map

Promoted from `64-RESEARCH.md` `## Validation Architecture` → Phase Requirements → Test Map. Plan/Wave per the 8 committed PLAN.md files.

| # | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 1 | 64-01 | 1 | ROT-06 (D-06) | T-64-01 | `updateFolderMetadataAndPublish` called without `nodeId` throws (required field); dest-path navigation succeeds after `moveItem` (AEAD round-trip) | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder/registration.test.ts` | ⚠️ extend | ⬜ pending |
| 2 | 64-02 | 1 | ROT-05 (D-06) | T-64-02 | `mergeChildren` union by `ipnsName`, remote wins, base detects deletes — no concurrent add dropped | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder/merge.test.ts` | ❌ W0 | ⬜ pending |
| 3 | 64-03 | 1 | ROT-03 (D-01/D-05) | T-64-03 | `mintFileKeyOnRotate` mints fresh `fileKey'` + sets `contentRekeyPending`; old readKey/fileKey holder cannot decrypt next published version | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/engine.test.ts` | ⚠️ add test | ⬜ pending |
| 4 | 64-04 | 2 | ROT-06 (D-01/D-02/D-09) | T-64-04 | Fail-closed publish (no placeholder key); parent `SealedChildRef[N].readKeySealed` re-sealed under parent's NEW `readKey'` and parent republished (batched) | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/engine.test.ts` | ⚠️ extend | ⬜ pending |
| 5 | 64-05 | 3 | ROT-04 (D-04) | T-64-05 | Non-revoked grantee's `readDescriptorRef` re-minted under new key/generation; revoked recipient's row deleted (mocked callbacks) | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/grant-remint.test.ts` | ❌ W0 | ⬜ pending |
| 6 | 64-06 | 4 | ROT-05 (D-09) | T-64-06 | On CAS-409, `rotateOne` re-fetches parent, re-decodes read-body, merges concurrently-added `SealedChildRef`s before re-sealing — new child present in completed parent | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/engine.test.ts` | ⚠️ extend | ⬜ pending |
| 7 | 64-07 | 5 | ROT-06 (D-07/D-09) | T-64-07 | `verifySubtreeClean` rebuilds frontier; resume-guard fix; `completedNodeIds` advanced only after re-mint; queue-key zeroization (terminal-owner only); fresh-record resume converges with no double-bump | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/engine.test.ts` | ⚠️ extend | ⬜ pending |
| 8 | 64-08 | 6 | TEST-01 (D-01/D-02/D-03/D-07) | T-64-08 | sdk-e2e abort-and-resume crash-safety suite passes against live stack (depth ≥ 2 tree, throw-after-N, fresh-resume convergence, concurrent-add) | E2E (live) | `pnpm -C tests/sdk-e2e test --run` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky · File Exists: ✅ exists · ⚠️ extend existing · ❌ new (Wave 0)*

*Per-success-criterion detail and the STRIDE threat rows (T-64-xx) live in `64-RESEARCH.md` `## Validation Architecture` / `## Security Domain` and each plan's `<threat_model>`.*

---

## Wave 0 Requirements

- [ ] sdk-e2e crash-safety suite scaffold (TEST-01) — depth ≥2 manual-node tree with known keypairs
- [ ] vitest mocks for `reMintGrantsRootedAt` (mocked `shares` query + mocked persist callback)

*Existing vitest + sdk-e2e infrastructure covers the unit and round-trip requirements; no new framework install.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| sdk-e2e live round-trip | TEST-01 | Needs the live local API stack (docker compose + `pnpm --filter @cipherbox/api dev`, redis on 6380) | Bring up the stack, run `pnpm --filter sdk-e2e test` |

*Live-stack sdk-e2e is automated but gated on operator-provisioned infrastructure.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 180s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

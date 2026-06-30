---
phase: 65
slug: sdk-write-chain-bin-re-link-and-invite-claim
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-30
audited: 2026-06-30
---

# Phase 65 — Validation Strategy

> Retroactively audited by Nyquist validator after phase execution.
> All Wave-0 requirements were met during execution; this document records the final coverage map.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest (sdk-core unit, sdk unit, sdk-e2e integration) |
| **Config files** | `packages/core/vitest.config.ts`, `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts`, `tests/sdk-e2e/vitest.config.ts` |
| **Unit run command** | `pnpm --filter @cipherbox/core test run` / `pnpm --filter @cipherbox/sdk-core test run` / `pnpm --filter @cipherbox/sdk test run` |
| **E2E run command** | `pnpm --filter @cipherbox/sdk-e2e test run -- write-chain-rotation` (requires docker stack + `api dev` on redis 6380) |
| **Full suite** | `pnpm test` |
| **Estimated runtime** | ~seconds for unit; sdk-e2e gated by stack startup |

---

## Sampling Rate

- **After every task commit:** Run the relevant package quick run command
- **After every plan wave:** Run `pnpm test` for the touched packages
- **Before verify-work:** Full suite must be green; D-04 gate must pass against a live API
- **Max feedback latency:** ~30 seconds for unit (sdk-e2e is gated by stack startup, not run every task)

---

## Per-Task Verification Map

| Task ID | Plan | Requirement | Secure Behavior | Test Type | Automated Command | File | Status |
|---------|------|-------------|-----------------|-----------|-------------------|------|--------|
| 65-01-T1 | 65-01 | WRITE-01 | Role-0x04 seal KAT and round-trip test (RED) | unit | `pnpm --filter @cipherbox/core test run` | `packages/core/src/__tests__/seal-write-chain.test.ts` | green |
| 65-01-T2 | 65-01 | WRITE-01 | `sealChildWriteKey` / `unsealChildWriteKey` implemented and exported (GREEN) | unit | `pnpm --filter @cipherbox/core test run` | `packages/core/src/node/seal.ts` | green |
| 65-02-T1 | 65-02 | WRITE-01 | `BinEntry.nodeReadKey` field added; bin re-link tests un-skipped (RED) | unit | `pnpm --filter @cipherbox/sdk test run` | `packages/sdk/src/__tests__/bin.test.ts` | green |
| 65-02-T2 | 65-02 | WRITE-01 | `addToBin` / `restoreFromBin` as pure re-link (GREEN) | unit | `pnpm --filter @cipherbox/sdk test run` | `packages/sdk/src/bin/index.ts` | green |
| 65-03-T1 | 65-03 | WRITE-01 | `claimInvite` service-flow test — single grant, no fan-out (RED) | unit | `pnpm --filter @cipherbox/sdk-core test run` | `packages/sdk-core/src/__tests__/share/grant.test.ts` | green |
| 65-03-T2 | 65-03 | WRITE-01 | `claimInvite` implemented; `encryptedChildKeys` absent from sdk layer (GREEN) | unit | `pnpm --filter @cipherbox/sdk-core test run` | `packages/sdk-core/src/share/grant.ts` | green |
| 65-04-T1 | 65-04 | WRITE-01, WRITE-03 | `SharedWriteContext` reshaped; write-chain helpers; WRITE-01 read-only/write-only security assertion | unit | `pnpm --filter @cipherbox/sdk test run` | `packages/sdk/src/__tests__/shared-write.test.ts` | green |
| 65-04-T2 | 65-04 | WRITE-01 | Six write operations implemented on the write-body model with no `addShareKeysFn` invocations | unit | `pnpm --filter @cipherbox/sdk test run` | `packages/sdk/src/share/shared-write.ts` | green |
| 65-04-T3 | 65-04 | WRITE-03 | `CannotWriteUntilRefetchError` thrown on every write op when write target tombstoned/rotated | unit | `pnpm --filter @cipherbox/sdk test run` | `packages/sdk/src/__tests__/shared-write.test.ts` | green |
| 65-05-T1 | 65-05 | WRITE-01 | Write-body node survives read-rotation with write plane intact; RED test | unit | `pnpm --filter @cipherbox/sdk-core test run` | `packages/sdk-core/src/__tests__/rotation/write-body-reseal.test.ts` | green |
| 65-05-T2 | 65-05 | WRITE-01 | `nodeWriteKey` threaded in engine; `PLACEHOLDER_WRITE_KEY` removed; fail-closed guard added | unit | `pnpm --filter @cipherbox/sdk-core test run` | `packages/sdk-core/src/rotation/engine.ts` | green |
| 65-06-T1 | 65-06 | WRITE-02, WRITE-03, WRITE-04 | `rotateWriteFromNode` contract: new names, child-first cascade, callbacks (RED) | unit | `pnpm --filter @cipherbox/sdk-core test run` | `packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts` | green |
| 65-06-T2 | 65-06 | WRITE-02, WRITE-03, WRITE-04 | `rotateWriteFromNode` implemented: child-first cascade, tombstone-intent, co-writer re-wrap | unit | `pnpm --filter @cipherbox/sdk-core test run` | `packages/sdk-core/src/rotation/engine.ts` | green |
| 65-07-T1 | 65-07 | WRITE-02, WRITE-03, WRITE-04 | D-04 e2e scaffold: build write-capable subtree against live API | integration | `pnpm --filter @cipherbox/sdk-e2e test run -- write-chain-rotation` | `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` | green |
| 65-07-T2 | 65-07 | WRITE-02, WRITE-03, WRITE-04 | D-04 e2e gate: new names, parent re-point, tombstone-intent, co-writer re-wrap/drop | integration | `pnpm --filter @cipherbox/sdk-e2e test run -- write-chain-rotation` | `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` | green |

Status legend: green · red · flaky

---

## Requirements Coverage

| Requirement | Plans | Description | Covered By | Status |
|-------------|-------|-------------|------------|--------|
| WRITE-01 | 65-01..05 | Write-body holds Ed25519 signing material sealed under independent `writeKey` (role 0x04); a read-only holder can never reach signing material | `seal-write-chain.test.ts` (9 tests: round-trip, cross-role rejection, AAD binding, terminal-owner); `shared-write.test.ts` line 161 — `unsealNode(pub, readKey)` returns no `writeBody`; `bin.test.ts` (20 tests — pure re-link, no re-encrypt); `grant.test.ts` (claimInvite single re-wrap, no fan-out) | SATISFIED |
| WRITE-02 | 65-06, 65-07 | Write-revocation mints a new Ed25519 keypair + k51 name + `writeKey` per node (child-first cascade to share root); new names first-published at `sequenceNumber 1n` | `write-revocation.test.ts` Test 3 (child-first cascade), Test 8 (parent re-point); D-04 e2e gate PASSED 2/2 | SATISFIED |
| WRITE-03 | 65-04, 65-06, 65-07 | Surviving co-writers receive the new `writeKey` re-wrapped into `writeDescriptorRef`; an offline co-writer gets a typed `CannotWriteUntilRefetchError` | `shared-write.test.ts` (CannotWriteUntilRefetchError on every write op + tombstoned-target case); `write-revocation.test.ts` co-writer re-wrap assertion; D-04 e2e gate | SATISFIED |
| WRITE-04 | 65-06, 65-07 | Tombstoned name: `teeUnenrollFn` invoked per old name (removed from TEE republish batch); publish-gate reject (403/410) and resolve-410 mock-asserted this phase, live in Phase 66 | `write-revocation.test.ts` (teeUnenrollFn call-count and argument assertions); D-04 e2e gate (teeUnenrollFn mocked, asserted once per old name); live publish-gate cutover → Phase 66 SC (explicitly deferred per D-02) | PARTIALLY SATISFIED — remainder deferred |

---

## Deferred Items

| # | Item | Addressed In | Evidence |
|---|------|-------------|----------|
| 1 | Live publish gate rejects (403/410) and resolve returns 410 for tombstoned names | Phase 66 | Phase 66 SC: "A tombstoned `ipns_records` row is rejected at the publish gate (403/410) and at the EOL-only renewal; resolve returns a 410 marker for tombstoned names." Phase 65 plans explicitly scope this to a mock seam (D-02); TEE unenroll is done and asserted. |

---

## Wave 0 Completion

All Wave-0 items listed in the planning-time draft are done:

- [x] `packages/core/src/__tests__/seal-write-chain.test.ts` — role-0x04 KAT + round-trip + cross-role rejection + AAD-mismatch + terminal-owner (9 tests)
- [x] `packages/sdk/src/__tests__/shared-write.test.ts` — write-body model + WRITE-01 read-only/write-only security assertion + WRITE-03 offline error (29 tests)
- [x] `packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts` — child-first cascade, tombstone-intent, co-writer re-wrap, read-plane invariance (8 tests)
- [x] `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` — D-04 gate PASSED 2/2 against live docker API
- [x] `packages/sdk/src/__tests__/bin.test.ts` — `addToBin` / `restoreFromBin` Phase-65 describe blocks un-skipped and updated (20 tests)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Status |
|----------|-------------|------------|--------|
| Live publish-gate reject (403/410) and resolve-410 for tombstoned names | WRITE-04 | Out of Phase-65 scope per D-02; enforced live in Phase 66 | Deferred — accepted override |

All other in-scope Phase-65 behaviors have automated verification.

---

## Validation Sign-Off

- [x] All tasks have an automated verify command
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all originally-MISSING test references
- [x] No watch-mode flags in any test command
- [x] Feedback latency < 30s for all unit tests
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** green — 0 gaps (1 explicitly deferred item with Phase 66 evidence)

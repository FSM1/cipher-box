---
phase: 67
slug: tee-lease-renewer-contract-rewrite
status: verified
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-01
---

# Phase 67 — Validation Strategy

> Per-phase validation contract. Retroactive audit of a completed phase: every roadmap
> requirement (TEE-01, TEE-02, TEE-03, TEE-06) maps to an automated test that targets the
> behavior and runs green. **0 gaps → `nyquist_compliant: true`.**

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest (tee-worker, sdk-core, sdk-e2e) + jest (apps/api) |
| **Config file** | per-package `vitest.config.*` / `jest` config in `apps/api/package.json` |
| **Quick run command** | `pnpm --filter cipherbox-tee-worker exec vitest run --no-coverage` |
| **Full suite command** | tee-worker + `pnpm --filter @cipherbox/api exec jest` + sdk-core + sdk-e2e `tee-republish` |
| **Estimated runtime** | ~5 seconds unit; ~5 seconds e2e round-trip (live stack) |

---

## Sampling Rate

- **After every task commit:** Run the affected package's quick test command
- **After every plan wave:** Run the full phase suite
- **Before `/gsd-verify-work`:** Full suite green (achieved)
- **Max feedback latency:** ~5 seconds (unit)

---

## Per-Requirement Verification Map

| Requirement | Secure Behavior | Test Type | Test File(s) | Automated Command | Status |
|-------------|-----------------|-----------|--------------|-------------------|--------|
| TEE-01 | TEE re-emits same CID + same seq, later EOL; cannot originate/repoint | unit + e2e | `apps/tee-worker/src/__tests__/ipns-signer.test.ts`, `apps/tee-worker/src/__tests__/republish.test.ts`, `tests/sdk-e2e/src/suites/tee-republish.test.ts` (Test A) | `vitest run` (tee-worker) + sdk-e2e `tee-republish` | ✅ green |
| TEE-02 | Republish never increments sequence (`+1n` path removed) | unit + e2e | `apps/tee-worker/src/__tests__/republish.test.ts`, `apps/tee-worker/src/__tests__/ipns-signer.test.ts`, `tests/sdk-e2e/src/suites/tee-republish.test.ts` (Test A) | `vitest run` (tee-worker) + sdk-e2e `tee-republish` | ✅ green |
| TEE-03 | `ipns_records` sole signing source; 4 schedule columns collapsed | unit + e2e | `apps/api/src/republish/republish.service.spec.ts`, `packages/sdk-core/src/folder/registration.test.ts`, `tests/sdk-e2e/src/suites/tee-republish.test.ts` (beforeAll migration guard) | `jest republish.service.spec` + `vitest run registration` + sdk-e2e | ✅ green |
| TEE-06 | Internal epoch self-derivation; name↔key binding; stale-key guard; tombstone gate | unit + e2e | `apps/tee-worker/src/__tests__/tee-keys.test.ts`, `apps/tee-worker/src/__tests__/key-manager.test.ts`, `apps/tee-worker/src/__tests__/republish.test.ts`, `tests/sdk-e2e/src/suites/tee-republish.test.ts` (Test B) | `vitest run` (tee-worker) + sdk-e2e `tee-republish` | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new framework install needed
(vitest + jest already configured); `bullmq`/`pg` sdk-e2e devDeps added in 67-05 from the
pinned lockfile versions.

---

## Manual-Only Verifications

All phase behaviors have automated verification.

---

## Validation Audit 2026-07-01

| Metric | Count |
|--------|-------|
| Requirements | 4 |
| Covered (automated + green) | 4 |
| Partial | 0 |
| Missing | 0 |

**Test-run evidence (post-rebuild, this ship pass):**

- tee-worker: **74 passed | 8 todo** (6 files) — `vitest run --no-coverage`
- apps/api republish + tee specs: **71 passed** (2 suites) — `jest`
- sdk-core registration: **9 passed** (2 files) — `vitest run registration`
- sdk-e2e `tee-republish`: **2 passed** — live relay→TEE→DB round-trip (Test A equal-CID/equal-seq/later-EOL; Test B tombstone never re-signed)

---

## Validation Sign-Off

- [x] All requirements have automated verification
- [x] Sampling continuity: no coverage gaps
- [x] Wave 0 covers all MISSING references (none)
- [x] No watch-mode flags
- [x] Feedback latency < 10s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-07-01

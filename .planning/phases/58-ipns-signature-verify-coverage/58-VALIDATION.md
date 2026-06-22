---
phase: 58
slug: ipns-signature-verify-coverage
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-22
---

# Phase 58 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                          |
| ---------------------- | -------------------------------------------------------------- |
| **Framework**          | cargo test (Rust) · vitest (sdk-core/web) · jest (apps/api specs) · SDK E2E (tests/sdk-e2e) |
| **Config file**        | per-crate `Cargo.toml` · `vitest.config.ts` · `jest` config in apps/api |
| **Quick run command**  | `cargo test -p cipherbox-core -p cipherbox-api-client` / `pnpm --filter @cipherbox/sdk-core test` |
| **Full suite command** | `cargo test` + apps/api specs + full SDK E2E (local; redis 6380) |
| **Estimated runtime**  | ~minutes (full SDK E2E dominates)                              |

---

## Sampling Rate

- **After every task commit:** Run the relevant quick command (cargo test for Rust tasks, vitest for TS tasks)
- **After every plan wave:** Run the full suite command
- **Before `/gsd-verify-work`:** Full suite must be green (cargo test + apps/api specs + full SDK E2E)
- **Max feedback latency:** quick unit tests < ~60s

---

## Per-Task Verification Map

> Filled during execution / by `/gsd-validate-phase`. See `58-RESEARCH.md` § Validation Architecture for the decision→proof map (D-01..D-13).

| Task ID   | Plan | Wave | Requirement | Threat Ref   | Secure Behavior                     | Test Type | Automated Command | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ------------ | ----------------------------------- | --------- | ----------------- | ----------- | ---------- |
| 58-01-01  | 01   | 1    | HARD-09     | T-51-07 / —  | TBD during planning                 | unit      | `cargo test`      | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Shared cross-language verify vectors fixture (valid / tampered-sig / name-mismatch / cid-swapped / seq-mismatch / partial-fields / legacy-absent) — D-11/D-12 (Plan 58-04)
- [ ] CBOR-decode probe (Rust `ciborium`; JS `parseCborData` import path) — research Open Question #1

_Otherwise existing infrastructure (cargo test, vitest, SDK E2E) covers all phase requirements._

---

## Manual-Only Verifications

| Behavior   | Requirement | Why Manual | Test Instructions |
| ---------- | ----------- | ---------- | ----------------- |

_All phase behaviors target automated verification (cross-language vectors + SDK E2E)._

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

---
phase: 61
slug: aad-bound-seal-primitive-and-cross-language-kat
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-28
---

# Phase 61 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest (TS, `@cipherbox/crypto`) + `cargo test` (Rust, `cipherbox-crypto`) |
| **Config file** | `packages/crypto/vitest.config.ts` (include `src/**/*.ts`) · `crates/crypto/Cargo.toml` |
| **Quick run command** | `pnpm --filter @cipherbox/crypto test` |
| **Full suite command** | `pnpm --filter @cipherbox/crypto test && cargo test -p cipherbox-crypto --test cross_language` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/crypto test`
- **After every plan wave:** Run the full suite (vitest + `cargo test -p cipherbox-crypto --test cross_language`)
- **Before `/gsd-verify-work`:** Full suite must be green, including `scripts/check-vector-parity.sh`
- **Max feedback latency:** ~30 seconds

---

## Per-Task Verification Map

> Filled by the planner from PLAN.md tasks. Each task maps to a requirement (CRYPTO-01/02/03, TEST-02) and an automated command.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | — | — | — | — | — | — | — | — | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

*Filled by the planner. The cross-language KAT (`tests/vectors/crypto/node-aad.json` asserted by both `packages/crypto/src/__tests__/build-node-aad.test.ts` and `crates/crypto/tests/cross_language.rs`) is the first deliverable and merge gate (C-01).*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|

*If none: "All phase behaviors have automated verification."*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

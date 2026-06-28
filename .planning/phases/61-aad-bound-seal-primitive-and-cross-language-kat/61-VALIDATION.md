---
phase: 61
slug: aad-bound-seal-primitive-and-cross-language-kat
status: approved
nyquist_compliant: true
wave_0_complete: true
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
| **Full suite command** | `pnpm --filter @cipherbox/crypto test && cargo test -p cipherbox-crypto --no-default-features && cargo test -p cipherbox-crypto --test cross_language --no-default-features && bash scripts/check-vector-parity.sh` |
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
| 01-T1 | 61-01 | 1 | CRYPTO-01 | T-61-01, T-61-02 | `buildNodeAad`/`uuidToBytes` produce the frozen 45-byte AAD; fail-closed on bad UUID/kind/role/generation (D-03) | unit (vitest) | `pnpm --filter @cipherbox/crypto test` | ❌ Wave 0 (`build-node-aad.test.ts`) | ⬜ pending |
| 01-T2 | 61-01 | 1 | TEST-02 | T-61-03, T-61-04 | `node-aad.json` `aad_vectors` (4 roles) frozen; TS KAT asserts hex(buildNodeAad)==expected_aad; parity script registers the file | unit (vitest) + CI parity | `pnpm --filter @cipherbox/crypto test && bash scripts/check-vector-parity.sh` | ❌ Wave 0 (`node-aad.json`) | ⬜ pending |
| 02-T1 | 61-02 | 2 | CRYPTO-02 | T-61-05, T-61-06 | Rust `build_node_aad` byte-identical to TS; fail-closed `Err(InvalidAadInput)`; `uuid` parsed via `as_bytes()` (D-04) | unit (cargo) | `cargo test -p cipherbox-crypto --lib aes --no-default-features` | ✅ `crates/crypto/src/aes.rs` | ⬜ pending |
| 02-T2 | 61-02 | 2 | CRYPTO-02, TEST-02 | T-61-05, T-61-06 | `node_aad_cross_language` asserts Rust `build_node_aad` == committed `aad_vectors` (all 4 roles); C-01 gate closed | cross-lang KAT (cargo) | `cargo test -p cipherbox-crypto --test cross_language --no-default-features` | ✅ `crates/crypto/tests/cross_language.rs` | ⬜ pending |
| 03-T1 | 61-03 | 3 | CRYPTO-01 | T-61-08, T-61-09 | `seal/unsealAesGcmAad` (fresh IV, `[IV][ct+tag]`) round-trip; `encrypt/decryptAesGcmAad` thread AAD; sub-28-byte/wrong-key reject | unit (vitest) | `pnpm --filter @cipherbox/crypto test` | ✅ (`build-node-aad.test.ts` from 01) | ⬜ pending |
| 03-T2 | 61-03 | 3 | CRYPTO-03, TEST-02 | T-61-07, T-61-10 | `seal_vectors` (fixed-IV `encryptAesGcmAad`) frozen + full-seal KAT; transplant suite rejects wrong nodeId/role/generation/kind/domain + tag-flip + truncation | unit (vitest) + CI parity | `pnpm --filter @cipherbox/crypto test && bash scripts/check-vector-parity.sh` | ✅ (`node-aad.json` from 01) | ⬜ pending |
| 04-T1 | 61-04 | 4 | CRYPTO-02, CRYPTO-03 | T-61-12, T-61-13 | Rust `encrypt/decrypt/seal/unseal_aes_gcm_aad` via `Payload{msg,aad}`; transplant + truncation reject (CRYPTO-03 symmetry) | unit (cargo) | `cargo test -p cipherbox-crypto --lib aes --no-default-features` | ✅ `crates/crypto/src/aes.rs` | ⬜ pending |
| 04-T2 | 61-04 | 4 | CRYPTO-02, TEST-02 | T-61-11 | `node_aad_cross_language` extended: Rust `encrypt_aes_gcm_aad` == committed `seal_vectors` ciphertext; full AEAD-with-AAD path pinned | cross-lang KAT (cargo) | `cargo test -p cipherbox-crypto --test cross_language --no-default-features` | ✅ `crates/crypto/tests/cross_language.rs` | ⬜ pending |
| 05-T1 | 61-05 | 4 | CRYPTO-01 | T-61-14 | ADR 0003 freezes the byte/role/kind tables, AEAD params, and the "every new role byte extends the KAT" rule | doc-existence grep | `test -f docs/adr/0003-aad-bound-node-seal-encoding.md && grep -q "node-seal/v1" docs/adr/0003-aad-bound-node-seal-encoding.md && grep -qi "every new role byte" docs/adr/0003-aad-bound-node-seal-encoding.md` | ❌ new (`docs/adr/0003-…md`) | ⬜ pending |
| 05-T2 | 61-05 | 4 | CRYPTO-02 | T-61-15 | METADATA_SCHEMAS / METADATA_EVOLUTION_PROTOCOL / FILESYSTEM_SPECIFICATION link ADR 0003; no premature Node-schema text | doc-link grep | `grep -q "0003-aad-bound-node-seal-encoding" docs/METADATA_SCHEMAS.md && grep -q "0003-aad-bound-node-seal-encoding" docs/METADATA_EVOLUTION_PROTOCOL.md && grep -q "0003-aad-bound-node-seal-encoding" docs/FILESYSTEM_SPECIFICATION.md` | ✅ (existing docs) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

The cross-language KAT is the first deliverable and merge gate (C-01), delivered entirely within **Wave 1 / plan 61-01** — there is no separate scaffolding wave because the KAT *is* the phase's first work product. The three RESEARCH "Wave 0 Gaps" are created/extended by plan 61-01 before any consumer code, then asserted on both language sides:

| Wave 0 artifact | Created by | First asserted by | Backs |
|-----------------|------------|-------------------|-------|
| `tests/vectors/crypto/node-aad.json` (`aad_vectors`; `seal_vectors` appended in 03) | 61-01 T2 (wave 1) | TS KAT 01-T2; Rust KAT 02-T2 / 04-T2 | TEST-02 |
| `packages/crypto/src/__tests__/build-node-aad.test.ts` (KAT + transplant suite) | 61-01 T1 (wave 1) | 01-T1, 01-T2 (extended 03-T1/T2) | CRYPTO-01/03, TEST-02 |
| `scripts/check-vector-parity.sh` (`node-aad.json` added to `EXPECTED_VECTORS`) | 61-01 T2 (wave 1) | 01-T2, 03-T2 | TEST-02 |

Path note (stale-path correction): the TS KAT lives at `packages/crypto/src/__tests__/build-node-aad.test.ts` (under `src/**`, per the vitest `include`), NOT the `packages/crypto/__tests__/` path written in CONTEXT.md/RESEARCH.md — a file outside `src/**` is never discovered by vitest.

No task has a MISSING automated reference: every task's backing test file is created no later than its own wave (the two ❌ Wave 0 files are created in wave 1, before the waves that depend on them). The Rust `crates/crypto/tests/cross_language.rs` and `crates/crypto/src/aes.rs` already exist and are extended in place.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|

All phase behaviors have automated verification (every task carries a `~30s` `<automated>` verify; the cross-language KAT mechanically pins TS↔Rust byte equality).

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (the 2 new test files are created in wave 1, plan 61-01)
- [x] No watch-mode flags
- [x] Feedback latency < 60s (every command ~30s)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved

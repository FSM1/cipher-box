---
phase: 75
slug: cross-language-ipns-and-node-codec-verification-parity
status: ready
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-11
---

# Phase 75 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework (Rust)** | Cargo built-in `#[test]` harness (`cargo test`), per-crate and workspace-wide |
| **Framework (TS)** | Vitest (`vitest run`), per-package (`@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/sdk-core`) |
| **Config files** | `Cargo.toml` (workspace root); `packages/*/vitest.config.ts` (existing — no changes needed) |
| **Quick run commands** | Per-task commands in the Per-Task Verification Map below (single-crate `cargo test` / filtered `pnpm --filter … test`) |
| **Full suite (Rust)** | `cargo test --workspace` |
| **Full suite (TS)** | `pnpm --filter @cipherbox/crypto test && pnpm --filter @cipherbox/core test && pnpm --filter @cipherbox/sdk-core test` |
| **Estimated runtime** | Quick run ~5-30s warm (Rust single-crate up to ~120s cold on first compile); full Rust workspace ~3-5 min; full TS suites ~60-90s |

No new framework install is required — Cargo and Vitest are already configured across every touched crate and package.

---

## Sampling Rate

- **After every task commit:** Run that task's quick-run command from the Per-Task Verification Map.
- **After every plan wave:** Run `cargo test --workspace` plus the full TS suite (`@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/sdk-core`).
- **Before `/gsd-verify-work`:** Full Rust workspace + full TS suites green; both CI jobs green (`vector-parity` display "Cross-Language Vector Parity" and `cargo-linux`'s `cargo llvm-cov --workspace` step, which is what exercises `ipns_verify_vectors.rs` and `node_codec_vectors.rs`); `sdk-e2e` unaffected (this phase does not touch the API/relay layer).
- **Max feedback latency:** ~120s (cold single-crate `cargo test`).

---

## Per-Task Verification Map

Requirement column uses the Success Criterion (SC1/SC2/SC3) plus the source-todo slug, since Phase 75 maps no `REQUIREMENTS.md` IDs (it is an M4 closeout phase sourced from todos).

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 75-01-01 | 01 | 1 | SC1 / harden-validity-type-and-vector-expiry-lockstep + ts-resolve-strict-rfc3339-validity-parity | T-75-01 / T-75-02 | Shared oracle carries 4 real-signed invalid cases (expired, wrong-validity-type, malformed RFC3339 x2); fail-closed reject domain pinned | unit (generator + fixture) | `npx tsx scripts/gen-ipns-verify-vectors.ts` then structural assert (12 cases, new cases `expected_result: invalid`) | ✅ generated in-plan | ⬜ pending |
| 75-02-01 | 02 | 2 | SC1 / harden-validity-type-and-vector-expiry-lockstep | T-75-03 | `decode_ipns_cbor_validity` reports `ValidityType` with duplicate-key rejection | unit | `cargo test -p cipherbox-core ipns:: -- --nocapture` | ✅ existing | ⬜ pending |
| 75-02-02 | 02 | 2 | SC1 / harden-validity-type-and-vector-expiry-lockstep | T-75-03 | `bind_verified` fails closed unless `ValidityType == 0`; widened to `pub`; expiry intact | unit | `cargo test -p cipherbox-api-client ipns:: -- --nocapture` | ✅ existing | ⬜ pending |
| 75-02-03 | 02 | 2 | SC1 / harden-validity-type-and-vector-expiry-lockstep | T-75-04 / T-75-05 | `classify_vector` delegates to `bind_verified` (no duplicated binding); all 12 cases classify to `expected_result` | unit (cross-language vector) | `cargo test -p cipherbox-fuse --test ipns_verify_vectors -- --nocapture` | ✅ existing (consumes 75-01 fixture) | ⬜ pending |
| 75-03-01 | 03 | 2 | SC1 / ts-resolve-strict-rfc3339-validity-parity + harden-validity-type-and-vector-expiry-lockstep | T-75-06 / T-75-07 | RED: malformed-timestamp + `ValidityType!=0` + 12-case-vector assertions fail against the loose `new Date` path | unit (cross-language vector) | `pnpm --filter @cipherbox/sdk-core test -- ipns` | ✅ existing (consumes 75-01 fixture) | ⬜ pending |
| 75-03-02 | 03 | 2 | SC1 / ts-resolve-strict-rfc3339-validity-parity + harden-validity-type-and-vector-expiry-lockstep | T-75-06 / T-75-07 / T-75-08 | GREEN: `parseRfc3339ToUnixSecs` replaces `new Date`; `ValidityType===0` fail-closed gate; TS rejects the same fixture cases as Rust | unit (cross-language vector) | `pnpm --filter @cipherbox/sdk-core test -- ipns` | ✅ existing | ⬜ pending |
| 75-04-01 | 04 | 1 | SC2 / node-codec-kat-pin-file-iv-encoding | T-75-10 / T-75-11 | `fileIv` samples are valid base64 but invalid hex; `expected_file_iv_len_bytes` pinned; hex-only harness IVs untouched | unit (fixture) | `node -e` structural assert (each `fileIv` base64-decodes to `expected_file_iv_len_bytes` and is not even-length lowercase-hex) | ✅ generated in-plan | ⬜ pending |
| 75-04-02 | 04 | 1 | SC2 / node-codec-kat-pin-file-iv-encoding | T-75-09 | Rust KAT base64-decodes `fileIv` and asserts byte length; a hex decoder would fail | unit (KAT) | `cargo test -p cipherbox-core --test node_codec_vectors -- --nocapture` | ✅ existing | ⬜ pending |
| 75-04-03 | 04 | 1 | SC2 / node-codec-kat-pin-file-iv-encoding | T-75-09 | TS KAT base64-decodes `fileIv` and asserts byte length; byte-identical with the Rust consumer | unit (KAT) | `pnpm --filter @cipherbox/core test -- node-codec-vectors` | ✅ existing | ⬜ pending |
| 75-05-01 | 05 | 1 | SC3 / harden-uuid-acceptance-parity-aad-builder | T-75-12 / T-75-13 | Cross-language acceptance oracle: canonical accepts; simple-32-hex, loose-hyphen, braced, urn, non-hex, wrong-length rejects | unit (fixture) | `node -e` structural assert (>=2 accept, >=6 reject; valid `expected` values) | ✅ generated in-plan | ⬜ pending |
| 75-05-02 | 05 | 1 | SC3 / harden-uuid-acceptance-parity-aad-builder | T-75-12 / T-75-14 | TS `uuidToBytes` canonical-only; agrees with the oracle for every case | unit (cross-language KAT) | `pnpm --filter @cipherbox/crypto test -- build-node-aad` | ✅ existing (consumes 75-05-01 fixture) | ⬜ pending |
| 75-05-03 | 05 | 1 | SC3 / harden-uuid-acceptance-parity-aad-builder | T-75-12 / T-75-14 | Rust `build_node_aad` dependency-free canonical pre-check; agrees with the oracle and the TS side | unit (cross-language KAT) | `cargo test -p cipherbox-crypto build_node_aad && cargo test -p cipherbox-crypto --test cross_language -- --nocapture` | ✅ existing (consumes 75-05-01 fixture) | ⬜ pending |

Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky

---

## Wave 0 Requirements

No separate Wave 0 install or scaffold phase is needed. RESEARCH.md's "Wave 0 Gaps" (extend the IPNS verify-vector generator, add the node-codec `fileIv` decode assertions, add a UUID acceptance-domain fixture) are satisfied **in-plan** by the first task of the fixture-owning plans:

- 75-01 Task 1 extends `scripts/gen-ipns-verify-vectors.ts` and regenerates `tests/vectors/ipns/verify.json` (12 cases) — the shared oracle consumed by 75-02 and 75-03.
- 75-04 Task 1 replaces `tests/vectors/node-codec.json` `fileIv` samples with encoding-unambiguous base64 and adds `expected_file_iv_len_bytes` — consumed by 75-04 Tasks 2-3.
- 75-05 Task 1 authors `tests/vectors/crypto/uuid-acceptance.json` — consumed by 75-05 Tasks 2-3.

Cargo and Vitest are already fully configured across every touched crate/package, so no framework install is required. `wave_0_complete: true` (all gaps are covered by in-plan generation tasks).

---

## Manual-Only Verifications

All phase behaviors have automated verification. This phase edits parsing/validation logic and test vectors only — every Success Criterion is provable by a Rust `#[test]` and/or a Vitest test against a shared JSON vector, with no visual, interactive, or infra-gated behavior.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (satisfied in-plan by fixture-generation Task 1 of 75-01/75-04/75-05)
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-07-11

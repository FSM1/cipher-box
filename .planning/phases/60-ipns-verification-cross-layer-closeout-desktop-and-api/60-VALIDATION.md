---
phase: 60
slug: ipns-verification-cross-layer-closeout-desktop-and-api
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-24
---

# Phase 60 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> This is a polyglot cutover (Rust + TypeScript + NestJS API) — multiple frameworks apply per layer.

---

## Test Infrastructure

| Property                | Value                                                                                          |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| **Framework**           | Rust `cargo test` (FUSE/core/api-client/sdk) · API `jest` · sdk-core/web `vitest` · SDK/desktop E2E |
| **Config file**         | per-crate `Cargo.toml` · `apps/api/jest.config` · `vitest.config.ts` · `tests/sdk-e2e`         |
| **Quick run command**   | `cargo test -p cipherbox-fuse -p cipherbox-api-client verify` + `pnpm --filter @cipherbox/sdk-core test -- ipns` |
| **Full suite command**  | `cargo test --workspace` + `pnpm --filter @cipherbox/api test` + `pnpm --filter @cipherbox/sdk-core test` + SDK-E2E |
| **Estimated runtime**   | ~quick <60s · full several minutes (E2E gated)                                                  |

---

## Sampling Rate

- **After every task commit:** Run the relevant layer quick command (Rust `cargo test` for the crate touched; `vitest`/`jest` for the package touched).
- **After every plan wave:** Run the full suite for affected layers, including the cross-language verify vector (`cargo test -p cipherbox-fuse ipns_verify`).
- **Before `/gsd-verify-work`:** Full suite green + cross-language vector green + SDK-E2E round-trip green.
- **Max feedback latency:** ~60s for unit/quick; E2E is dispatch-gated and runs at wave boundaries.

---

## Per-Task Verification Map

> Planner fills one row per task. The spine below is illustrative; replace with real task IDs during planning.

| Task ID   | Plan | Wave | Requirement | Threat Ref | Secure Behavior                                                       | Test Type   | Automated Command                                       | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ---------- | -------------------------------------------------------------------- | ----------- | ------------------------------------------------------- | ----------- | ---------- |
| 60-XX-YY  | XX   | 1    | HARD-11     | —          | strict verify fails-closed: embedded≠resp, legacy/None, expired record | unit (Rust) | `cargo test -p cipherbox-fuse verify`                   | ❌ W0       | ⬜ pending |
| 60-XX-YY  | XX   | 1    | HARD-11     | —          | TS resolve THROWS on missing-signature / skew / expired               | unit (vitest) | `pnpm --filter @cipherbox/sdk-core test -- ipns`      | ❌ W0       | ⬜ pending |
| 60-XX-YY  | XX   | 1    | HARD-11     | —          | cross-language vector: legacy-absent + first-publish-skew → invalid    | vector      | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | ✅          | ⬜ pending |
| 60-XX-YY  | XX   | 1    | HARD-11     | —          | API rejects publish with embedded seq 0; resolve 404s NULL signed_record | jest       | `pnpm --filter @cipherbox/api test -- ipns`            | ✅          | ⬜ pending |
| 60-XX-YY  | XX   | 1    | HARD-11     | —          | verified-resolve wrapper rejects tampered CID (sdk/desktop sites)      | unit (Rust) | `cargo test -p cipherbox-api-client`                    | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Rust fail-closed unit tests for the strict verifier (embedded≠resp rejected; `None`/legacy rejected; expired record rejected) — replaces the reverted skew/legacy tests in `crates/fuse/src/verify.rs` and `crates/api-client/src/ipns.rs`.
- [ ] TS resolve throw-path tests in `packages/sdk-core/src/ipns/` (missing-signature throws; skew throws; expired throws).
- [ ] api-client verified-resolve wrapper unit tests (valid passes; tampered CID / bad sig / wrong-name fail-closed) for the D-08 shared chokepoint.
- [ ] Cross-language vector regenerated via `npx tsx scripts/gen-ipns-verify-vectors.ts` with `legacy-absent` + `first-publish-skew` reclassified to `invalid`.
- [ ] Stream C benchmark harness to measure per-op publish/resolve verification cost (baseline vs short-circuit) per `docs/CAPACITY.md` §1.5.

---

## Manual-Only Verifications

| Behavior                                  | Requirement | Why Manual                                  | Test Instructions                                                                 |
| ----------------------------------------- | ----------- | ------------------------------------------- | -------------------------------------------------------------------------------- |
| Staging DB wipe + fresh-login bootstrap   | HARD-11     | Operational; needs staging access + a real login | Wipe staging DB (`docs/DATABASE_EVOLUTION_PROTOCOL.md` §reset), redeploy, log in, confirm root folder resolves strict-verified |
| Desktop verified-resolve at runtime       | HARD-11     | Desktop E2E is dispatch-gated               | `gh workflow run "CI E2E Tests" --ref <branch>`; or headless desktop UAT recipe   |
| Local dev DB wipe before testing Wave 1   | HARD-11     | Developer workflow item (embedded-0 local records would fail-closed) | Each dev wipes local DB before running the strict build |

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s for quick runs
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

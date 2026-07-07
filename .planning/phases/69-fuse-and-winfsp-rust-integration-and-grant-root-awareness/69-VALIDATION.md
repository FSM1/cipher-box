---
phase: 69
slug: fuse-and-winfsp-rust-integration-and-grant-root-awareness
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-06
validated: 2026-07-07
---

# Phase 69 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `69-RESEARCH.md` § Validation Architecture. Per-task rows are populated once PLAN.md task IDs exist.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[test]` / `#[tokio::test]`; cross-language KAT via `tests/vectors/*.json` fixtures loaded in `crates/crypto/tests/`-style integration tests. No `proptest`/`quickcheck` in any workspace `Cargo.toml`. |
| **Config file** | None — standard `cargo test` per crate. |
| **Quick run command** | `cargo test -p cipherbox-core node_codec` / `cargo test -p cipherbox-sdk rotation` (once the new modules + tests exist) |
| **Full suite command** | macOS/Linux: `cargo check --workspace && cargo test --workspace` (default `fuse` feature). Windows (CI-authoritative): `cargo check --workspace --no-default-features --features winfsp && cargo test --workspace --no-default-features --features winfsp`. |
| **Estimated runtime** | ~seconds per crate locally; Windows-feature build deferred to CI (`cargo-windows` job). |

---

## Sampling Rate

- **After every task commit:** Run targeted `cargo test -p <crate> <pattern>` for the crate touched.
- **After every plan wave:** Run `cargo check --workspace && cargo test --workspace` (default features) locally; defer the Windows-feature build to CI (D-06 — no fast local Windows iteration assumed).
- **Before `/gsd-verify-work`:** `cargo-windows` CI job green + explicit `gh workflow run "CI E2E Tests" --ref <branch>` desktop-E2E dispatch green (TEST-03 / SC#5) as the LAST step.
- **Max feedback latency:** local per-crate test run (seconds); Windows CI gate is a round-trip (minutes) and gates phase sign-off only, not per-task.

---

## Per-Task Verification Map

> Populated during/after planning. Requirement→behavior anchors below come from RESEARCH.md § Phase Requirements → Test Map.

| SC / Req | Behavior | Test Type | Automated Command | File Exists | Status |
|----------|----------|-----------|-------------------|-------------|--------|
| TEST-03 / SC#5 | WinFsp read-path validated via Windows CI gate + dispatch desktop E2E | integration (CI-gated) | `cargo check/test --workspace --no-default-features --features winfsp`; `gh workflow run "Desktop E2E Tests" --ref <branch>` | ✅ jobs exist (`ci.yml:590` cargo-windows; `desktop-e2e.yml`) | 🔵 CI-gated (required green before merge) |
| SC#1 | `unseal_node`/`unseal_child_read_key` recover the same keys the legacy ECIES path did | unit | `cargo test -p cipherbox-core node_seal` | ✅ `crates/core/tests/node_seal_vectors.rs` | ✅ green |
| SC#2 | Cross-folder move requires zero re-encrypt; grep-verified absence | static (grep gate) | `grep -rn "spawn_file_meta_reencrypt" crates/fuse/src/` returns empty | ✅ CI grep gate `ci.yml:757` | ✅ green |
| SC#3 | Private delete = zero rotation; shared-scope-exit delete = exactly one `rotate_read_from_node` | unit (spy injection) | `cargo test -p cipherbox-sdk scope`; `cargo test -p cipherbox-fuse grant_scope` | ✅ `scope.rs:318,340`; `grant_scope.rs:573,600` | ✅ green |
| SC#4 | KAT vectors pass; durable floor survives simulated daemon restart | unit + KAT | `cargo test -p cipherbox-core --test node_codec_vectors`; `cargo test -p cipherbox-sdk floor_store` | ✅ `node_codec_vectors.rs`; `floor_store.rs:155,204` | ✅ green |
| SC#6 | `crates/fuse`/WinFsp never call raw resolve; single gated entrypoint | static (grep gate) | SC#6 grep gate in `ci.yml:731` (`resolve_ipns_verified`/`resolve_published_node` in `crates/fuse/src`) | ✅ CI grep gate `ci.yml:731` | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky · 🔵 CI-gated*

> Reconciled post-execution 2026-07-07: `cargo test --workspace` = 476 passed, 0 failed (macOS, default `fuse` feature). All locally-verifiable SCs green; SC#5 is the required-green Windows/desktop-E2E CI gate.

---

## Wave 0 Requirements

- [x] `crates/core/src/node/` module + `crates/core/tests/node_codec_vectors.rs` asserting byte-identical output vs `tests/vectors/node-codec.json` and `tests/vectors/crypto/node-aad.json`
- [x] `crates/sdk/src/rotation/high_water.rs` + unit tests mirroring `packages/sdk/src/__tests__/client-rotation.test.ts` floor-regression assertions
- [x] `crates/sdk/src/rotation/scope.rs` + unit tests mirroring `packages/sdk-core/src/__tests__/rotation/scope.test.ts` spy-based zero-rotation assertion (SC#3 signature test — `scope.rs:318,340`)
- [x] `crates/sdk/src/floor_store.rs` (JSON sidecar) + restart-survival test (`floor_store.rs:155 floor_store_restart`, `:204 survives_restart_end_to_end_through_rotation_high_water`)
- [x] Grep-gate script for SC#6 (single gated read entrypoint), CI-wired at `ci.yml:731`
- [x] Framework: none to install — existing `cargo test` infrastructure covers this phase

*Existing `cargo test` + `tests/vectors/*.json` KAT infrastructure covers all phase requirements; only new test files are needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Desktop E2E (dispatch-gated) | TEST-03 / SC#5 | `desktop-e2e.yml` is `workflow_dispatch`-only; not auto-triggered on non-desktop pushes | `gh workflow run "Desktop E2E Tests" --ref <branch>` (NOT "CI E2E Tests" — that name 404s); confirm all matrix legs green before sign-off |
| WinFsp local iteration | SC#2 / SC#5 | Windows platform layer built/verified on the user's Windows machine (D-06) | User runs `cargo check/test --features winfsp` locally; CI `cargo-windows` is objective sign-off |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency acceptable (local per-crate seconds; Windows CI gates sign-off only)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated 2026-07-07 — 476/476 cargo tests green; all locally-verifiable SCs covered; SC#5 (TEST-03) is the required-green Windows/desktop-E2E CI gate (0 fillable local gaps — the sole open requirement is CI-authoritative).

---

## Validation Audit 2026-07-07

| Metric | Count |
|--------|-------|
| Gaps found | 0 (locally fillable) |
| Resolved | all planned Wave-0 tests exist and pass (476/476) |
| Escalated / manual-only | 1 — TEST-03/SC#5 (Windows CI + Desktop E2E, CI-authoritative) |

Nyquist enforcement hook is disabled in this repo's GSD config; audit performed inline by the ship-phase orchestrator. No test-generation needed — every planned validation target (`node_codec_vectors`, `floor_store` restart, `scope`/`grant_scope` zero-rotation spies, SC#6 grep gate) is implemented and green.

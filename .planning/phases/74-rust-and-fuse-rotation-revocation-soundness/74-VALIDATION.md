---
phase: 74
slug: rust-and-fuse-rotation-revocation-soundness
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-11
---

# Phase 74 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `74-RESEARCH.md` → `## Validation Architecture`.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust workspace crates `cipherbox-sdk`, `cipherbox-fuse`) + Vitest (TS `packages/sdk-core`) + desktop-e2e `.mts`/`.ps1` real-mount scripts (Windows leg CI-only) |
| **Config file** | Workspace `Cargo.toml` / `packages/sdk-core/vitest.config.ts` / `tests/desktop-e2e/scripts/run-all.{sh,ps1}` |
| **Quick run command** | `cargo test -p cipherbox-sdk` and `cargo test -p cipherbox-fuse` (scoped, no live network) |
| **Full suite command** | `cargo test --workspace` + `pnpm --filter @cipherbox/sdk-core test` + `tests/desktop-e2e/scripts/run-all.sh` (macOS/Linux) / `run-all.ps1` (Windows, CI-only) |
| **Estimated runtime** | ~60–120 seconds (scoped Rust + TS unit); desktop-e2e + WinFsp deferred to CI |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-sdk` / `cargo test -p cipherbox-fuse` (scoped, fast, no live/full-suite runs — honors the GSD-subagent no-live-suite constraint)
- **After every plan wave:** Run `cargo test --workspace` (excluding `--features winfsp` full test, which is CI-only) + relevant `pnpm --filter @cipherbox/sdk-core test`
- **Before `/gsd-verify-work`:** Rust workspace + sdk-core suites green locally; WinFsp verification via a dispatched `Cargo Check & Test (Windows)` CI run; desktop-e2e (`shared-scope-exit-rotation.mts`, extended) green on all 3 platforms in CI
- **Max feedback latency:** ~120 seconds (local scoped suites)

---

## Per-Task Verification Map

> Populated per plan/task during planning. Success-criteria → test mapping from research:

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 74-XX-XX | XX | 1 | SC1 | Stale key reseal (EoP/Info-Disc) | Every rotated node's read key refreshed before any relink reseals under a stale key | unit (Rust FakeTransport) + desktop-e2e | `cargo test -p cipherbox-sdk rotation::engine::` / `cargo test -p cipherbox-fuse write_ops::rotation_deps::` | ❌ W0 | ⬜ pending |
| 74-XX-XX | XX | 1 | SC2 | Over-broad revocation (DoS) | `query_grants_rooted_at` returns live grants; retained recipients re-minted, revoked cut | unit (Rust FakeTransport) + desktop-e2e (2 recipients) | `cargo test -p cipherbox-fuse write_ops::rotation_deps::` | ❌ W0 | ⬜ pending |
| 74-XX-XX | XX | 1 | SC3 | Ungated destructive mutation (EoP) | WinFsp rename-overwrite dest gated through `run_scope_exit_gate`, validation-before-gating parity with fuser | unit (Rust) + Windows CI | `cargo test -p cipherbox-fuse --features winfsp` (build local; full test CI-only) | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/fuse/src/write_ops/rotation_deps.rs` — `FakeTransport`-based unit tests for `query_grants_rooted_at` / `update_grant` / `delete_grant` (Todo 2)
- [ ] `crates/sdk/src/rotation/engine.rs` — unit test proving the rotated-node key result contains every rotated node's key for a ≥2-level tree, not just the root (Todo 1)
- [ ] `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — TS parity test mirroring the Rust deep-key test (Todo 1, Rust+TS parity)
- [ ] `crates/fuse/src/platform/windows/write_ops.rs` — unit tests mirroring `rename.rs`'s `rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt` and `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit` (Todo 3)
- [ ] `tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts` — extend with a depth≥2 (grant-root → folder → file) leg AND a second recipient to prove retained-vs-revoked distinction (SC1, SC2)
- [ ] `crates/api-client/src/shares.rs` — `update_grant` / `revoke_share` wire functions + unit tests (mirrors existing `revoke_shares_for_items` / `list_sent_shares` test shape) (Todo 2)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| WinFsp overwrite-rename scope-exit gating | SC3 | winfsp crate cannot build/test locally on macOS/Linux; authoritative only on Windows CI | Dispatch `Cargo Check & Test (Windows)` job; assert new `handle_rename` dest-gate tests pass |
| Real-mount retained-vs-revoked cross-client behavior | SC1, SC2 | Requires real FUSE/WinFsp mount + live API + IPNS round-trip | Run extended `shared-scope-exit-rotation.mts` in desktop-e2e CI on all 3 platforms |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

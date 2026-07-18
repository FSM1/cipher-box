---
phase: 80
slug: rotation-write-plane-and-re-mint-durability
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-12
---

# Phase 80 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Derived from 80-RESEARCH.md `## Validation Architecture`.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework (Rust)** | `cargo test` (workspace crates: `cipherbox-core`, `cipherbox-crypto`, `cipherbox-fuse`, `cipherbox-sdk`) |
| **Framework (TS)** | Vitest (`packages/core`, `packages/sdk-core`, `packages/sdk`) |
| **Framework (cross-package)** | `tests/sdk-e2e` (Vitest, live API — the only real client→API IPNS round-trip gate) |
| **Config file** | Standard `Cargo.toml` workspace + each package's `vitest.config.ts` (no new config needed) |
| **Quick run command** | `cargo test -p cipherbox-core -p cipherbox-crypto` / `pnpm --filter @cipherbox/core test` / `pnpm --filter @cipherbox/sdk-core test` |
| **Full suite command** | `cargo test --workspace` + `pnpm test` (root) + `tests/sdk-e2e` live-API run |
| **Estimated runtime** | ~120 seconds (unit); sdk-e2e several minutes (live stack) |

---

## Sampling Rate

- **After every task commit:** Run the relevant crate/package quick command (Rust: `cargo test -p <crate>`; TS: `pnpm --filter <package> test`)
- **After every plan wave:** Run `cargo test --workspace` + `pnpm test` (root)
- **Before `/gsd-verify-work`:** `tests/sdk-e2e` full live-API round-trip must be green — the ONLY suite exercising a real client→API IPNS resolve/publish cycle, and the class of change (D-01, D-03 key-lifecycle/IPNS) this suite exists to gate
- **Max feedback latency:** ~120 seconds (unit tiers)

---

## Per-Task Verification Map

> Populated by the planner / gsd-nyquist-auditor from the SC→test map below. Each task's `<verify>` must map to one automated command.

| SC | Behavior | Test Type | Automated Command | File Exists |
|----|----------|-----------|-------------------|-------------|
| SC1 (D-01) | Rotation republish reconstructs `write_sealed`; owned-walk survives rotation | unit + regression | `cargo test -p cipherbox-fuse rotation_deps` | ✅ module + `#[cfg(test)]` scaffold |
| SC1 (D-01) | `replay.rs::recover_signing_seed` no longer hits "no write_sealed body" for a rotated node | regression | `cargo test -p cipherbox-fuse replay` | ❌ W0 (new rotation-then-replay test) |
| SC2 perf (D-02) | Scope-exit rotation over N nodes performs ≤1 `/shares/sent` fetch | unit (call-count) | `cargo test -p cipherbox-fuse query_grants_rooted_at` | ❌ W0 (new `collect_sent_shares` call-counter on `FakeTransportInner`) |
| SC2 perf (D-02 TS) | `queryGrantsFn` caches `listSentGrants()` across calls | unit | `pnpm --filter @cipherbox/sdk test owner-reconcile` | ✅ test file exists |
| SC2 binding (D-03) | Re-mint fails closed on pin mismatch (simulated relay substitution) | unit | new cases in `rotation_deps.rs` + `packages/sdk-core` engine tests | ❌ W0 |
| SC2 binding (D-03e) | Pin absent at re-mint = hard fail-closed (no-legacy invariant) | unit | same modules, negative case | ❌ W0 |
| SC2 binding (D-03b) | Cross-language wire parity for new `NodeWriteBody` pin field (JSON KAT, NOT CBOR) | KAT | `cargo test -p cipherbox-core node_write_body_vectors` + `pnpm --filter @cipherbox/core test node-codec-vectors` | ✅ harness exists; add `seal_vectors[1]` fixture to `tests/vectors/node-codec.json` (unrelated `crypto/cross_language.rs` guard stays untouched) |
| SC3 (D-04) | `rotatedNodes` values non-aliased with `parentNewReadKey`, non-zero copies | unit | `pnpm --filter @cipherbox/sdk-core test rotation/engine` | ❌ W0 |
| Full round-trip | E2E scope-exit rotation + re-mint against live API | e2e | `tests/sdk-e2e` | ✅ suite exists — mandatory pre-ship gate |

---

## Wave 0 Requirements

- [ ] `crates/fuse/src/replay.rs` — new test exercising a rotation-then-replay signing-seed-recovery sequence (proves D-01 closes the durability hole, not just the flood)
- [ ] `crates/fuse/src/write_ops/rotation_deps.rs` — new `FakeTransportInner` call-counter for `collect_sent_shares` (D-02) + new pin-mismatch / pin-absent fixtures (D-03 fail-closed)
- [ ] `packages/sdk-core/src/rotation/__tests__/` (or co-located engine test) — new assertion that `rotatedNodes` entries are non-aliased with `parentNewReadKey` (D-04)
- [ ] `tests/vectors/node-codec.json` + `packages/core/src/__tests__/node-codec-vectors.test.ts` + `crates/core/tests/node_write_body_vectors.rs` — new `seal_vectors[1]` entry with a non-empty recipient-pin list (D-03b lockstep); pin field conditionally emitted so frozen `seal_vectors[0]` KAT is preserved
- Note: `crates/crypto/tests/cross_language.rs:310` (`seal_vectors.len() == 1`) reads a DIFFERENT oracle (`crypto/node-aad.json`), NOT `tests/vectors/node-codec.json` — it is unrelated to the new pin fixture and must stay untouched/green (locked by an 80-01 acceptance criterion)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Live scope-exit rotation + re-mint IPNS round-trip | SC1, SC2 | Requires live API + IPNS stack (Kubo/someguy) not available in unit tiers | Run `tests/sdk-e2e` against a local stack per `project-sdk-e2e-worktree-live-checkpoint-run` (copy gitignored `.env`, `SDK_E2E_SECRET` == API `TEST_LOGIN_SECRET`, reset DB + restart API from current code) |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s (unit tiers)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

---
phase: 76
slug: fuse-durability-and-tee-write-path-hardening
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-11
---

# Phase 76 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Derived from `76-RESEARCH.md` `## Validation Architecture`.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework (Rust — SC1, SC2)** | `cargo test` (workspace); existing `#[cfg(test)]` modules in `vault.rs`, `metadata.rs`, `fs.rs`, `delete.rs` |
| **Framework (TypeScript — SC3)** | `vitest` (`apps/tee-worker/vitest.config.ts`); `apps/api` uses Jest per its `package.json` test script |
| **Config file** | Rust: workspace `Cargo.toml`; TS: `apps/tee-worker/vitest.config.ts`, `apps/api` Jest config |
| **Quick run (Rust)** | `cargo test -p cipherbox-fuse` / `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml` (macOS/Linux only — NOT the Windows platform module) |
| **Quick run (TS TEE)** | `pnpm --filter cipherbox-tee-worker test` (NOT currently run in CI — see Open Question below) |
| **Quick run (TS API)** | `pnpm --filter cipherbox-api test -- republish.service` |
| **Full suite command** | `cargo test` (workspace) + `pnpm --filter cipherbox-tee-worker test` + `pnpm --filter cipherbox-api test`; Windows leg is CI-only (`Cargo Check & Test (Windows)`, `Desktop E2E (windows-latest)`) |
| **Estimated runtime** | ~2-5 min local (Rust workspace dominates); Windows CI leg is an async round-trip |

---

## Sampling Rate

- **After every task commit:** Run the targeted quick command scoped to the touched file/crate (`cargo test -p cipherbox-fuse` / `cargo test -p cipherbox-desktop` / `pnpm --filter cipherbox-tee-worker test` / `pnpm --filter cipherbox-api test`).
- **After every plan wave:** Run the full suite (workspace `cargo test` + both TS filters).
- **Before `/gsd-verify-work`:** Full suite green, PLUS (SC2 item 3 / Plan D only) the `Cargo Check & Test (Windows)` and `Desktop E2E (windows-latest)` CI jobs must be green — this cannot be sampled locally.
- **Max feedback latency:** ~30s per targeted task run; Windows CI gate is asynchronous.

---

## Per-Task Verification Map

> Populated by the planner from PLAN.md task IDs. Representative row shown; every task must map to an `<automated>` verify or a Wave 0 dependency.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 76-A-01 | A | 1 | SC1 | fail-closed preflight | Transient resolve error aborts init (never treats non-404 as absent) | unit | `cargo test -p cipherbox-desktop` | ❌ W0 | ⬜ pending |
| 76-C-04 | C | 1 | SC3 | later-EOL invariant | `renewIpnsRecord` rejects equal/earlier EOL vs parsed existing record | unit (tdd) | `pnpm --filter cipherbox-tee-worker test` | ❌ W0 | ⬜ pending |
| 76-D-01 | D | 1 | SC2-3 | D-07 dual-keying correctness | Windows write child_id keys by stored `node_id` | unit + E2E | `Cargo Check & Test (Windows)` (CI-only) | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `vault.rs` `#[cfg(test)]` — preflight abort-on-transient-error, preflight abort-on-unrecoverable-conflict, and recovery-path (decrypt-and-resume) round-trip tests (extend the `init_recover_v3_round_trips` pattern)
- [ ] `metadata.rs` `run_publish_retry_seam` — extend with a `max_attempts` param and a 5-attempt-succeeds-on-attempt-5 case (no 5→2 regression); existing `publish_with_cas_retry_*` tests stay green with the updated signature
- [ ] `fs.rs` — cross-cycle global FP-resolve cap test (2+ consecutive refresh cycles asserting `resolving_file_pointers.len() <= MAX_CONCURRENT_FP_RESOLVES`)
- [ ] Windows-only `write_ops.rs` test for `node_id`-keyed `child_id` on cleanup/delete — CI-only, cannot be authored/verified locally (Plan D, `autonomous: false`)
- [ ] `apps/api` — `renewIpnsRecordEol` real-DB-error-vs-CAS-miss log-level test
- [ ] `apps/tee-worker` — `decryptWithFallback` config/infra-error-rethrow test (introduces a typed error, e.g. `TeeKeyUnavailableError`)
- [ ] `apps/tee-worker` — republish route null-entry defense-in-depth test
- [ ] `apps/tee-worker` — `ipns-signer.test.ts` later-EOL invariant test + longer-than-default original-lifetime edge case
- [ ] `apps/tee-worker` — `key-manager.test.ts` genuine-ciphertext-corruption test (currently only exercises the epoch-mismatch branch)
- [ ] Framework install: none — `cargo test` and `vitest` are already configured

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Windows D-07 materialized-node delete/bin round-trip | SC2 item 3 | Windows platform module does not compile under macOS cargo; verification is CI-only | Confirm `Cargo Check & Test (Windows)` + `Desktop E2E (windows-latest)` jobs green on the PR before merging Plan D |
| Desktop vault init for a genuinely fresh user still works end-to-end | SC1 | Full init touches live IPNS relay + Tauri | Desktop init E2E / vault-recovery flow (existing `desktop-e2e.yml`) |

---

## Open Question (planner decision)

- The `apps/tee-worker` unit suite is **not currently wired into any CI `Test` job** (confirmed against `ci.yml`). New/fixed SC3 tests would not be CI-enforced. The planner should decide whether adding `apps/tee-worker` (and, if needed, the API republish test) to CI is in-scope for this phase or a follow-up todo. If deferred, flag it explicitly in the relevant PLAN.md.

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s (local); Windows CI gate acknowledged as async
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

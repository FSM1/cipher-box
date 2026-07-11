---
phase: 76
slug: fuse-durability-and-tee-write-path-hardening
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-11
audited: 2026-07-12
---

> **Retroactive Nyquist audit (2026-07-12):** All Wave 0 requirements confirmed
> covered by committed behavioral tests (static inspection of the delivered test
> files, cited below). 0 genuine gaps. The Windows D-07 test is `#[cfg(feature =
> "winfsp")]` CI-only — an accepted async/CI-deferred verification, not a Nyquist gap.

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

## Wave 0 Requirements — audited coverage (all delivered)

- [x] `vault.rs` `#[cfg(test)]` — abort-on-transient/auth, route aborts, decrypt-and-resume round-trip. Confirmed: `preflight_ipns_absent_fails_closed_on_transient_error` (vault.rs:864), `_on_auth_error` (:882), `vault_init_route_transient_key_blob_error_aborts_before_publish` (:929), `vault_init_route_both_present_aborts` (:912), `vault_init_recovery_recovers_original_keys_and_coherency_unseals` (:1014, asserts recovered==minted byte-for-byte).
- [x] `metadata.rs` retry seam `max_attempts` — `publish_with_cas_retry_fifth_attempt_succeeds_under_budget_5` (metadata.rs:702) + `_exhausts_budget_2` (:738); no 5→2 regression (paths pass 5/2/2 at metadata.rs:347,522 & content_ops.rs:388).
- [x] `fs.rs` cross-cycle global FP cap — `fp_resolve_global_cap_holds_across_two_cycles` (fs.rs:1028), asserts `resolving_file_pointers.len() <= 10` across 2 refresh cycles (budget = CAP − in-flight).
- [x] Windows `write_ops.rs` `node_id`-keyed `child_id` — `bin_child_id_keys_by_stored_node_id_not_local_ino_d07` in `#[cfg(all(test, feature = "winfsp"))]` (write_ops.rs:1671); prod arm `let child_id = inode.node_id.clone()` (:677). CI-only (accepted async verification, see Manual-Only).
- [x] `apps/api` real-DB-error-vs-CAS-miss log-level — `a real DB error logs at error level (distinct from the CAS-miss debug line) but the batch still reports success` (republish.service.spec.ts:1038; asserts "DB write-back failed" error line, no "CAS miss" debug line).
- [x] `apps/tee-worker` `decryptWithFallback` typed-error rethrow — `rethrows TeeKeyUnavailableError from getKeypair ... instead of masking it as a corrupted key` (key-manager.test.ts:260; instanceof + cause preserved).
- [x] `apps/tee-worker` republish route null-entry defense — `null / non-object entries yield per-entry failures and never 500 the batch (T-76-08)` (republish.test.ts:401).
- [x] `apps/tee-worker` later-EOL invariant + long-lifetime edge — `advances the EOL: renewed.validity is strictly later` (ipns-signer.test.ts:98), rejects EQUAL (:122)/EARLIER (:134), `rejects when the original lifetime is LONGER than the default renewal window` (:145). Additive `validity: Date` covered in ipns-record.test.ts:110.
- [x] `apps/tee-worker` genuine-ciphertext-corruption — `genuine ciphertext corruption (byte-flipped wrapKey output) throws a non-ReEnrollRequiredError, non-TeeKeyUnavailableError generic error` (key-manager.test.ts:232).
- [x] Framework install: none — `cargo test` and `vitest` already configured.

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

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (every item confirmed present in committed tests above)
- [x] No watch-mode flags
- [x] Feedback latency < 30s (local); Windows CI gate acknowledged as async
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved (retroactive Nyquist audit 2026-07-12) — 0 genuine gaps; Windows D-07 CI-deferred by design.

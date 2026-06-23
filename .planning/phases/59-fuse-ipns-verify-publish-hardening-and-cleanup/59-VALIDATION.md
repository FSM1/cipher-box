---
phase: 59
slug: fuse-ipns-verify-publish-hardening-and-cleanup
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-23
---

# Phase 59 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                          |
| ---------------------- | ------------------------------------------------------------------------------ |
| **Framework**          | `cargo test` (Rust) — fuse + winfsp feature sets                               |
| **Config file**        | FUSE crate `Cargo.toml` (find exact path; `#[cfg(winfsp)]`-gated windows mods) |
| **Quick run command**  | `cargo test -p <fuse-crate>` (default/fuse feature set)                        |
| **Full suite command** | `cargo test -p <fuse-crate> --all-features` + `cargo clippy -- -D warnings`    |
| **Estimated runtime**  | ~60–120 seconds local                                                          |

> winfsp paths cannot compile on macOS — `Cargo Check & Test (Windows)` CI is authoritative for any `#[cfg(winfsp)]` change. SDK-E2E (local; redis 6380) + desktop-E2E (dispatch-gated) gate durability-critical publish paths.

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <fuse-crate>` (quick)
- **After every plan wave:** Run full suite (`--all-features`) + `cargo clippy -- -D warnings`
- **Before `/gsd-verify-work`:** Full suite green + winfsp Windows CI dispatched for any winfsp-gated change
- **Max feedback latency:** ~120 seconds

---

## Per-Task Verification Map

> Filled by the planner. Behavioural fixes (A swallowed-error propagation, B inode re-resolution, C VerifyError::Legacy carry) get unit tests; pure cleanup (D/E dead-code) is clippy/compile-only.

| Task ID   | Plan | Wave | Requirement | Threat Ref   | Secure Behavior                     | Test Type | Automated Command | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ------------ | ----------------------------------- | --------- | ----------------- | ----------- | ---------- |
| 59-01-01  | 01   | 1    | HARD-10     | —            | {expected secure behavior or "N/A"} | unit      | `{command}`       | ✅ / ❌ W0  | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Confirm existing `cargo test` harness in the FUSE crate covers the touched modules (verify.rs / fs.rs / inode.rs)
- [ ] Add unit-test stubs for behavioural fixes A, B, C if no analog test exists

_If none: "Existing infrastructure covers all phase requirements."_

---

## Manual-Only Verifications

| Behavior                                          | Requirement | Why Manual                              | Test Instructions                                                  |
| ------------------------------------------------- | ----------- | --------------------------------------- | ----------------------------------------------------------------- |
| winfsp-gated counterparts of any fixed FUSE logic | HARD-10     | Cannot compile/run winfsp on macOS      | Dispatch `Cargo Check & Test (Windows)` CI; confirm green         |
| Durability-critical publish path end-to-end       | HARD-10     | Requires live IPNS publish/resolve loop | Run SDK-E2E (redis 6380) + desktop-E2E (`gh workflow run` CI E2E) |

_If none: "All phase behaviors have automated verification."_

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

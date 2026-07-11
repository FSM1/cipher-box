---
status: testing
phase: 74-rust-and-fuse-rotation-revocation-soundness
source: [74-VERIFICATION.md]
started: 2026-07-11T00:00:00Z
updated: 2026-07-11T00:00:00Z
---

## Current Test

number: 1
name: Windows CI compiles WinFsp rename dest-gate and passes the two new tests
expected: |
  `Cargo Check & Test (Windows)` job is green; both new WinFsp rename tests
  (`rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt`,
  `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit`) pass; the
  existing `replace_if_exists=false` collision-rejection scenario is unregressed.
awaiting: user response

## Tests

### 1. Windows CI: `Cargo Check & Test (Windows)` (SC3 / plan 74-06)

expected: Windows CI job green; both new WinFsp rename tests pass; existing collision-rejection scenario unregressed.
why_human: `crates/fuse/src/platform/windows/write_ops.rs` is `#[cfg(feature = "winfsp")]`-only and cannot compile on macOS/Linux (confirmed: `cargo check -p cipherbox-fuse --features winfsp` fails on `windows-future`/`windows_core::imp`, a genuine toolchain limitation, not a code defect). D-15d ordering (collision check -> ENOTEMPTY check -> source gate -> dest gate -> mutate) was source-verified to match the fuser reference verbatim, but only Windows CI can compile/run it.
how: `gh workflow run "Cargo Check & Test (Windows)" --ref feat/rust-and-fuse-rotation-revocation-soundness` (or open the PR and let CI run).
result: [pending]

### 2. Desktop-e2e 3-platform live run (SC1 + SC2 + SC3 integration / plan 74-07)

expected: All legs pass. Part A/B (pre-existing, unchanged) remain green — including Part A's `bobCanReadAfterRotation === false`; Part C (deep decryptability + Carol retained-vs-revoked) passes on macOS/Linux/Windows; Part D (WinFsp overwrite-rename dest-gate) passes (authoritative on Windows).
why_human: Requires a built Tauri desktop binary + live FUSE-T/fuser/WinFsp mount + API + real IPNS round-trip — not feasible in an autonomous session (matches project memory `project-headless-desktop-fuse-uat` / `project-winfsp-build-ci-only-macos`). The `.mts` scenario typechecks clean and run-all wiring is verified; only the live mount run is outstanding. Note: 74-07 self-flagged a risk that Part A's Bob assertion might flip after 74-05's real `query_grants_rooted_at`; static analysis (verifier) found it likely a false alarm because `bobCanReadAfterRotation` decrypts against a stale pre-rotation key captured before rotation, which fails regardless of grant re-mint — but CI is the authoritative confirmation.
how: `gh workflow run "desktop-e2e" --ref feat/rust-and-fuse-rotation-revocation-soundness`.
result: [pending]

## Summary

total: 2
passed: 0
issues: 0
pending: 2
skipped: 0
blocked: 0

## Gaps

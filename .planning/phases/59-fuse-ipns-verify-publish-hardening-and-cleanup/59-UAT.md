---
status: testing
phase: 59-fuse-ipns-verify-publish-hardening-and-cleanup
source: [59-VERIFICATION.md, 59-REVIEW.md]
started: 2026-06-23
updated: 2026-06-23
---

## Current Test

number: 1
name: Windows winfsp CI gate
expected: |
  `cargo check -p cipherbox-fuse --features winfsp` exits 0 on a Windows runner.
awaiting: user response

## Tests

### 1. Windows winfsp CI gate

expected: Dispatch `Cargo Check & Test (Windows)` (or `gh workflow run "CI E2E Tests" --ref feat/fuse-ipns-verify-publish-hardening-and-cleanup`); it passes. All findings touch shared `#[cfg(any(feature = "fuse", feature = "winfsp"))]` code that macOS cargo cannot compile under winfsp.
result: [pending]

### 2. SDK E2E gate

expected: With the local stack up (docker compose + API dev server, redis on 6380), the SDK E2E suite passes against this branch. This exercises the real client→API IPNS publish/resolve round-trip — the integration surface most relevant to the Finding F sequence work and the CR-01 fix (a freshly-created folder must still resolve).
result: [pending]

### 3. Desktop E2E gate

expected: Dispatch `gh workflow run "CI E2E Tests" --ref feat/fuse-ipns-verify-publish-hardening-and-cleanup`; desktop E2E passes (it is dispatch-gated and skipped on main pushes without desktop-path changes).
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps

Finding F is intentionally PARTIAL in this phase (not a gap): the resolve-side strict-equality cutover was reverted (CR-01) and deferred to Phase 60. The forward embed-1 changes in `publish.rs`/`replay.rs` are retained; the skew allowance is restored so existing/new embedded-0 records still resolve. The full unification (mkdir/windows embed 1 + existing-record republish migration + strict equality) is tracked for Phase 60 — see `.planning/todos/pending/2026-06-23-phase60-ipns-first-publish-strict-equality-cutover.md`.

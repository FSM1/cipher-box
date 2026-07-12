---
phase: 76-fuse-durability-and-tee-write-path-hardening
type: learnings
date: 2026-07-12
---

# Phase 76 Learnings

Mined from the five plan SUMMARYs, the verification/validation/security reports, and the ship pass (PR #610).

## Decisions

- **Fail-closed IPNS preflight keys on a confirmed 404 only.** `classify_preflight_outcome` treats
  exclusively `IpnsNotFound` as "absent"; every other `ApiError` (transient, 5xx, auth) returns
  `Err` and aborts before any publish. A partial-init is resolved by decrypting-and-resuming the
  ORIGINAL ECIES-wrapped root keys from the already-published key blob — never by re-minting (a
  second random pair could never match the published blob).
- **One attempt-budgeted publish helper, not per-call retry loops.** `publish_with_cas_retry(max_attempts)`
  centralizes CAS retry; the metadata path passes 5, bin/per-file paths pass 2. A unit seam locks
  both budgets so a future edit can't silently regress 5→2.
- **FP-resolve concurrency cap is derived from the in-flight accounting set**, making it global across
  refresh cycles instead of per-cycle — the only way to bound total concurrency correctly.
- **Strictly-later-EOL invariant compares against the PARSED EXISTING record's validity, never
  `Date.now()`.** This is clock-skew-safe and is the deliberate, tested rollback-prevention behavior:
  an equal/earlier new EOL throws `EolRollbackError` (thrown outside the sanitized try/catch and
  `instanceof`-passed-through so the invariant signal is never remapped).
- **Typed `TeeKeyUnavailableError` rethrown via `instanceof`, never string-matching `error.message`.**
  A config/infra failure (simulator-in-production, unexpected SDK shape) must never be masked as a
  corrupted user key. Mirrors the `ReEnrollRequiredError` convention.

## Lessons

- **The TEE republish SDK-E2E round-trip needs a bespoke stack the default gate doesn't wire up.**
  The API defaults `TEE_WORKER_URL` to `http://localhost:3001` (the mock-ipns-routing) and
  `TEE_WORKER_SECRET` to `''`. The real worker is on host `:3002` and the running docker image may be
  stale. To exercise Phase-76 tee-worker code you must build the worker from source, run it in
  simulator mode with a known `TEE_WORKER_SECRET`, and restart the API with a matching
  `TEE_WORKER_URL`/secret so `TeeService` seeds `tee_key_state` from the Phase-76 worker at boot
  ("TEE worker healthy, current epoch: 1" / "TEE key state validated"). Without this, `tee-republish
  Test A` times out waiting for `signed_record` renewal — an infra-wiring gap, not a code regression.
- **A fresh isolation worktree lacks the gitignored `apps/api/.env`.** Copy it in (or reconstruct it)
  before starting the API for the SDK-E2E gate; `TEST_LOGIN_SECRET` must equal `SDK_E2E_SECRET`.
- **Zeroization hygiene must be consistent across sibling branches.** The `FreshInit` arm wrapped root
  keys in `Zeroizing<[u8;32]>` but the new `RecoverResume` arm materialized bare `[u8;32]` via
  `try_into()`. Two independent audits (crypto + threat-model) flagged it; the fix is a one-line
  `Zeroizing::new(...)` wrap with use-sites unchanged via deref coercion.

## Patterns

- **Unit-testable decision seams for untestable side-effect code.** `route_vault_init` consumes the two
  raw preflight `Result`s and returns a `VaultInitRoute` enum, making the fail-closed routing decision
  a pure, table-tested function — the same testability trick as `run_publish_retry_seam` in
  `metadata.rs`.
- **Windows write-plane parity is CI-only and gated behind `#[cfg(feature = "winfsp")]`.** The module
  and its ported regression test cannot compile/link on macOS/Linux (no WinFsp SDK). Local
  non-compilation is EXPECTED; proof is deferred to the `Cargo Check & Test (Windows)` +
  `Desktop E2E (windows-latest)` CI legs — a blocking pre-merge gate, never merge on a red Windows leg.
- **Additive parsed field over hand-rolled decode.** `ParsedIpnsRecord.validity: Date` is mapped from
  the `ipns` library's RFC3339 `record.validity` via `new Date(...)` rather than a bespoke CBOR
  validity decode.

## Surprises

- **CodeRabbit CLI hangs on the terminal event.** It emitted its full finding set early (6 findings,
  all `.planning/` doc-consistency nits, 0 source-code) then sat on `heartbeat/reviewing` indefinitely.
  Treat the emitted findings as complete and rely on the PR-level CodeRabbit check for the
  authoritative pass; don't wait on the CLI's non-arriving completion.
- **A docs-only `.planning/` push re-runs the entire CI suite**, including the ~50-min Windows Cargo
  leg — batch `.planning` bookkeeping (todos, learnings) into as few pushes as possible to avoid
  resetting long-running gates, and remember the dispatch-gated CI-E2E does NOT auto-run on PR pushes.
- **The strictly-later-EOL guard has a benign no-op edge on `Invalid Date`** (`NaN <= x` is `false`),
  and it over-rejects a legitimately longer-lived existing record (marking it toward stale). Both were
  triaged: the first discarded as unreachable defense-in-depth, the second logged as a material
  follow-up todo (a healthy longer-EOL renewal should skip-as-success, not fail).

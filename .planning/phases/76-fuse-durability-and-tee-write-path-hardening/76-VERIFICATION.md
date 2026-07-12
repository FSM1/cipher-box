---
phase: 76-fuse-durability-and-tee-write-path-hardening
type: verification
method: goal-backward
date: 2026-07-12
verdict: MET
---

# Phase 76 Verification Report

Goal: harden the desktop publish path and the TEE lease-renewer write path against
transient / partial-failure states.

Method: read all 5 SUMMARYs, inspected the actual referenced source to confirm the
delivered behavior (not just that commits landed), and ran the relevant test suites.

## Test Suite Results

| Suite | Command | Result |
| --- | --- | --- |
| crypto | `pnpm --filter @cipherbox/crypto test` | 211 passed / 0 failed (11 files) |
| fuse | `cargo test -p cipherbox-fuse` | 120 passed + 1 cross-language vector / 0 failed |
| tee-worker | `pnpm --filter cipherbox-tee-worker test` | 84 passed / 0 failed (8 todo, 6 files) |
| api republish | `pnpm --filter @cipherbox/api test -- republish.service` | 42 passed / 0 failed |

All 12 phase commits are present on `feat/fuse-durability-and-tee-write-path-hardening`
(5fb06cba0, 9c3696bc5, a188175d9, b48bcbd27, a0033490a, e3840cd81, 8df830ff7,
26c1e1694, 9b6ab2dc4, 8926d0719, f3cb9f4a3, 36b8d24f5).

## SC1 — Vault init aborts atomically + decrypt-and-resume (never re-mint) [76-01]

Verdict: MET

Evidence (`apps/desktop/src-tauri/src/commands/vault.rs`):

- Fail-closed preflight: `classify_preflight_outcome` (line 63) returns `Ok(true)`
  only on a confirmed `IpnsNotFound` 404; any other `ApiError` returns `Err` (line
  70) — never `Ok(true)`.
- Abort-before-publish is structural: `route_vault_init` (line 116) consumes the raw
  preflight `Result`s and `?`-propagates a transient `Err` (lines 120-121) BEFORE any
  route is selected, so no publish is attempted on an unresolvable name.
- Decrypt-and-resume, not re-mint: the `RecoverResume` branch (line 494) calls
  `recover_root_keys_from_key_blob` (line 145), which `resolve_ipns_verified` (D-09
  chokepoint) + `deserialize_vault_blob_v3` + ECIES `unwrap_key` (lines 171, 173) the
  ORIGINAL root keys. No `generate_file_key` in this branch — both occurrences (lines
  455, 457) are in `FreshInit` only.
- Coherency gate: `coherency_check_root_unseal` (line 182) fetches the just-published
  root and `unseal_node`s its read body under the recovered read key before
  `/vault/init` (called at line 527).
- Tests: `cargo test -p cipherbox-desktop vault` covered by the fuse/desktop crate
  suite; round-trip test asserts recovered keys equal the first attempt's minted keys
  byte-for-byte (lines 1009-1070), plus classify/route abort tests (lines 848-1003).

## SC2 — Shared publish retry + global FP-resolve cap + Windows D-07 node_id [76-02, 76-05]

Verdict: MET

Evidence:

- Single attempt-budgeted helper: `publish_with_cas_retry(max_attempts: u32)`
  (`crates/fuse/src/metadata.rs:46,54`) with an attempt-budget loop guarded by
  `if attempt >= max_attempts` (line 124). No 5→2 regression — the metadata path
  passes `5` (`metadata.rs:347`), the bin path passes `2` (`metadata.rs:522`), and
  the per-file path passes `2` (`content_ops.rs:388`). Seam tests lock both budgets:
  5th-attempt succeeds under budget 5 (line 702) and exhausts (Err) under budget 2
  (line 738).
- Global (cross-refresh) FP-resolve cap: `crates/fuse/src/fs.rs:605` derives
  `cycle_budget = MAX_CONCURRENT_FP_RESOLVES.saturating_sub(self.resolving_file_pointers.len())`
  from the in-flight accounting set and feeds BOTH the pending-drain loop (line 624)
  and the fresh-unresolved loop (line 650). A 2-consecutive-cycle test asserts the
  global in-flight count never overshoots the cap (lines 1042-1066).
- Windows D-07 write refs key by stored `node_id`: in the winfsp-gated module
  (`crates/fuse/src/platform/windows/write_ops.rs:6` = `#[cfg(feature = "winfsp")]`),
  `cleanup()`'s bin-capture arm sets `let child_id = inode.node_id.clone();`
  (line 677), mirroring the shipped Unix `delete.rs:180` fix — NOT `uuid_from_ino`.
  A ported regression test `bin_child_id_keys_by_stored_node_id_not_local_ino_d07`
  lives in a `#[cfg(all(test, feature = "winfsp"))]` module (line 1387/1671).

## SC3 — TEE republish surfaces real failures + strictly-later-EOL guard [76-03, 76-04]

Verdict: MET

Evidence:

- Real DB write-back error surfaced (not silent success):
  `apps/api/src/republish/republish.service.ts` — `renewIpnsRecordEol` logs the
  harmless `affected === 0` CAS-miss at `logger.debug` (line 483) but a real
  repository throw at `logger.error` with a distinct "DB write-back failed" message
  (line 495); batch success accounting unchanged. Tests assert both branches
  (republish.service.spec: 42 passed).
- Typed `TeeKeyUnavailableError` rethrow: defined in
  `apps/tee-worker/src/services/tee-keys.ts:28`, thrown at the two real config/infra
  guard sites (simulator-in-production `:94`, unexpected `getKey()` shape `:117`).
  `key-manager.ts` `decryptWithFallback` `instanceof`-rethrows it wrapped with
  `{ cause }` from both trial catches (lines 105-106, 119-120) — no `error.message`
  string-matching; any other error falls through to the next trial.
- Route null/non-object guard: `apps/tee-worker/src/routes/republish.ts:99` guards
  BEFORE the `try` (line 111), pushing a per-entry failure (`ipnsName: 'unknown'`)
  and `continue`ing so the catch never dereferences a null `entry.ipnsName`.
- Strictly-later-EOL guard: `apps/tee-worker/src/services/ipns-signer.ts` compares
  `newValidity.getTime() <= existingValidity.getTime()` (line 77) where
  `existingValidity` is the PARSED existing record validity
  (`parseIpnsRecord(marshaledExistingRecord).validity`, line 54-55) — NOT
  `Date.now()` — and throws `EolRollbackError` (line 78) on equal/earlier. The
  invariant signal is thrown outside / instanceof-passed-through the sanitized
  try/catch (line 68). `ParsedIpnsRecord.validity: Date` is additive, mapped from the
  ipns library's RFC3339 string via `new Date(record.validity)`
  (`packages/crypto/src/ipns/parse-record.ts:62`).
- CI wiring: `.github/workflows/ci.yml:347-348` runs `pnpm --filter
  cipherbox-tee-worker test` in the Test job, so all three SC3 regressions turn CI
  red on breakage.

## winfsp / D-07 CI-Deferred Note

The Windows write-plane fix (76-05, commit 36b8d24f5) and its ported regression test
live behind `#[cfg(feature = "winfsp")]`, which does not compile or link on
macOS/Linux (no WinFsp SDK). Non-compilation locally is EXPECTED, not a failure. The
code parity and the gated test EXIST and were confirmed by source inspection. Final
proof is deferred to the CI legs `Cargo Check & Test (Windows)` and
`Desktop E2E (windows-latest)` on the phase PR — a blocking merge gate recorded in
STATE.md. Do not merge on a red Windows leg.

## Recorded Deviations (confirmed non-breaking)

- 76-04: `ipns@10.1.3` `IPNSRecord.validity` is an RFC3339 string, not a Date; mapped
  to `Date` via `new Date(record.validity)`. Sub-ms truncation is harmless (renewal
  EOL deltas are seconds-to-hours). Does not affect the strictly-later comparison.
- 76-03: null-entry route test added to existing `republish.test.ts` (not a new
  `republish.route.test.ts`); tee-worker CI wired as a discrete Test-job step. No
  coverage lost.
- 76-02: helper no longer unpins the just-published CID (latent over-unpin fix);
  Windows `MkdirJournalResult` consumer edit is compile-only for the shared struct.
- 76-05: used `inode.node_id.clone()` directly (tighter mirror of the Unix
  `delete.rs:180` site) instead of the fs.rs re-fetch+fallback pattern; equivalent
  net behavior.

## Overall Phase Verdict: MET

All three success criteria are delivered in code and backed by passing tests
(crypto 211, fuse 120+1, tee-worker 84, api republish 42; 0 failures). The only
open item is the winfsp/D-07 Windows CI confirmation, which is CI-deferred by design
and cannot be run on this macOS worktree — the code and its gated regression test are
present and correct on inspection.

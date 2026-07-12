---
phase: 76-fuse-durability-and-tee-write-path-hardening
audit: gsd-secure-phase
asvs_level: 2
block_on: high
threats_total: 13
threats_closed: 13
threats_open: 0
verdict: SECURED
audited_at: 2026-07-12
---

# Phase 76 — Security Audit (FUSE durability and TEE write-path hardening)

**Verdict: SECURED.** All 13 declared threat mitigations (T-76-01 … T-76-13, all
disposition `mitigate`) are present in the implemented code and verified at the
correct trust boundary. No blocking gaps. No unregistered attack surface.

- **ASVS level:** 2 (no explicit `asvs_level` in project config; defaulted to L2
  given the crypto/key-handling surface — verification confirmed each mitigation
  addresses its threat vector at the correct boundary, not merely a grep hit).
- **Block threshold:** `high` (spec default; no `block_on` in project config).
- **Scope:** threats introduced/mitigated by this phase's diff
  (`git diff origin/main...HEAD`), 37 files. Pre-existing issues out of scope.
- **Root `SECURITY.md`:** untouched — it is a pre-existing tracked file, not part
  of the phase diff. Only this phase doc was written.

## Threat Verification

| Threat ID | Category               | Severity | Disposition | Status | Evidence (file:line)                                                                                                                                             |
| --------- | ---------------------- | -------- | ----------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-76-01   | Tampering              | high     | mitigate    | CLOSED | `vault.rs:70` fail-closed `Err` arm in `classify_preflight_outcome`; `vault.rs:120-121,449` `route_vault_init(...)?` propagates before any publish; preflight of both names at `vault.rs:446-447` precedes the publish match at `449` |
| T-76-02   | Tampering              | high     | mitigate    | CLOSED | `vault.rs:494-527` RecoverResume ECIES-unwraps original keys via `recover_root_keys_from_key_blob` (`vault.rs:171-174`); NO `generate_file_key` in recovery branch (only `vault.rs:454-457` FreshInit); coherency gate `coherency_check_root_unseal` at `vault.rs:527` / defined `182-210` |
| T-76-03   | Information Disclosure  | medium   | mitigate    | CLOSED | Recovered keys returned as `Zeroizing<Vec<u8>>` (`vault.rs:149`); `unwrap_key` returns `Zeroizing`; error strings carry operation context + lib error only, no key bytes (`vault.rs:154-174`). See Observation 1 (non-blocking hygiene note). |
| T-76-04   | Denial of Service      | medium   | mitigate    | CLOSED | `metadata.rs:54` `max_attempts: u32` param; `spawn_metadata_publish` delegates with `5` (`metadata.rs:339,347`, inline loop deleted); bin path passes `2` (`metadata.rs:522`); regression test `publish_with_cas_retry_fifth_attempt_succeeds_under_budget_5` (`metadata.rs:702`) + budget-2-exhaustion test (`738`) |
| T-76-05   | Denial of Service      | low      | mitigate    | CLOSED | `fs.rs:605-606` cycle budget = `MAX_CONCURRENT_FP_RESOLVES.saturating_sub(resolving_file_pointers.len())`; both drain + fresh loops honor `spawned >= cycle_budget` (`fs.rs:624,650`); dedup guards `contains(&fp_ino)` untouched (`fs.rs:619,639`); 2-cycle global-cap test (`fs.rs:1042-1066`) |
| T-76-06   | Information Disclosure  | medium   | mitigate    | CLOSED | `content_ops.rs:152,156,275,277` `clear_bytes` on success AND error paths; caller-owned borrows explicitly excluded (`content_ops.rs:251-253`); `mkdir.rs:172,221` bare `[u8;32]` wrapped in `Zeroizing`; `fuse/mod.rs:211-218` strict `try_from` narrowing; `journal_helpers.rs:122` parent seed `Zeroizing<Vec<u8>>`, dead clone removed (`138-140`); `prepopulate.rs` verified-clean, no change (per 76-02-SUMMARY) |
| T-76-07   | Repudiation            | medium   | mitigate    | CLOSED | `republish.service.ts:495` catch logs at `logger.error` with distinct message; `affected===0` CAS-miss stays `logger.debug` (`480-486`); non-fatal (returns, no rethrow, `487-496`); `totalSucceeded` accounting untouched |
| T-76-08   | Denial of Service      | medium   | mitigate    | CLOSED | `republish.ts:99-107` per-entry `entry === null \|\| typeof entry !== 'object'` guard pushes a failure result + `continue` BEFORE the `try` (`try` at ~111); catch dereferences of `entry.ipnsName` are unreachable for malformed entries |
| T-76-09   | Tampering              | medium   | mitigate    | CLOSED | `tee-keys.ts:28` `TeeKeyUnavailableError extends Error`, thrown at both real guard sites — simulator-in-production (`94`) and unexpected `getKey()` shape (`117`); `key-manager.ts:105-106,119-120` `instanceof` rethrow with `{ cause }`; no MIN/MAX epoch throw added; no `error.message` string-matching |
| T-76-10   | Information Disclosure  | high     | mitigate    | CLOSED | `TeeKeyUnavailableError` messages name config/infra conditions only, no key bytes (`tee-keys.ts:26` doc, `95`, `117`); rethrow reuses `err.message` + typed `cause` (`key-manager.ts:106,120`); generic fallback `key-manager.ts:126` no key bytes; route guard error `republish.ts:103` no key material; EOL error log `republish.service.ts:495` DB message only |
| T-76-11   | Tampering              | high     | mitigate    | CLOSED | `ipns-signer.ts:77-81` rejects `newValidity <= existingValidity` via `EolRollbackError`; compared against PARSED EXISTING validity (`ipns-signer.ts:55,65`), never `Date.now()`; additive `validity: Date` on `ParsedIpnsRecord` (`parse-record.ts:32`) sourced from `unmarshalIPNSRecord().validity` (`parse-record.ts:62`) |
| T-76-12   | Information Disclosure  | medium   | mitigate    | CLOSED | `ipns-signer.ts:53-71` parse/sign/marshal wrapped in try/catch; sanitized rethrow `new Error('Failed to renew IPNS record', { cause: err })` (`70`) — no key bytes; `EolRollbackError` passed through cleanly (`68`) |
| T-76-13   | Tampering              | high     | mitigate    | CLOSED (code present; final proof Windows-CI-gated) | `platform/windows/write_ops.rs:677` `child_id = inode.node_id.clone()` at bin_capture with `SECURITY-REVIEW: D-07 dual-keying` comment (`670-676`), mirroring `delete.rs:180,419`; non-delete publish path uses `node_id`/`uuid_from_ino` fallback (`write_ops.rs:962-966`); ported regression test `bin_child_id_keys_by_stored_node_id_not_local_ino_d07` (`write_ops.rs:1671`) |

## Unregistered Flags

None. Every SUMMARY "Threat Model Mitigations Applied" entry maps 1:1 to a
registered threat ID (T-76-01 … T-76-13). No new attack surface appeared during
implementation without a threat mapping. `prepopulate.rs` was correctly handled as
verify-only (no un-zeroed bare-key copy found; no change made).

## Verification depth (ASVS L2 notes)

- **T-76-01 (fail-closed):** confirmed the abort propagates via `?` at the router
  BEFORE the publish `match` — the check is at the correct boundary (pre-write),
  not merely present somewhere in the file.
- **T-76-04 (budget):** confirmed the metadata path passes `5` and the bin path
  passes `2` — verified the delegation actually preserves the 5-attempt budget at
  the specific call site, not just that the parameter exists.
- **T-76-08 (null guard):** confirmed the guard is positioned before the `try`, so
  the catch-block `entry.ipnsName` dereference genuinely cannot hit a null.
- **T-76-11 (EOL):** confirmed the comparison operand is the parsed existing
  record's validity (clock-skew safe), not wall-clock — the exact prohibition
  (`Date.now()` arithmetic) is absent from the function and its evidence path.

## Observations (non-blocking, not counted in threats_open)

1. **Defense-in-depth hygiene — vault.rs RecoverResume bare `[u8;32]` copies
   (`vault.rs:507-514`).** On the recovery branch, the recovered keys are copied
   out of their `Zeroizing<Vec<u8>>` source buffers into bare, un-`Zeroizing`
   `[u8;32]` stack locals (`root_read_key`, `root_write_key`), whereas the
   FreshInit branch uses `Zeroizing<[u8;32]>` (`vault.rs:454-457`). The primary
   source buffers (`root_read_vec`/`root_write_vec`) still zero on drop, there is
   no logging or transmission of these copies, and this is not exploitable — but
   it is inconsistent with the same-phase zeroization standard applied to the
   analogous bare `[u8;32]` copies in `mkdir.rs:172,221` and `content_ops.rs`.
   T-76-03 (severity medium) is substantively mitigated; wrapping these two
   copies in `Zeroizing` would fully align the recovery branch. Below the `high`
   block threshold — non-blocking, does not gate ship. Optional follow-up.

## Result

- Threats total: 13 — Closed: 13 — Open (blocking): 0 — Open (non-blocking): 0
- `threats_open: 0` (no OPEN threat at or above the `high` block threshold)
- **Verdict: SECURED.** Phase 76 may ship on the threat-mitigation axis.

### Merge-gate reminder (not a security gap)

Plan 76-05 is `autonomous:false` with a blocking human/CI checkpoint: the Windows
platform module (`crates/fuse/src/platform/windows/*`) compiles only under the
`winfsp` feature on the Windows CI runner. T-76-13's mitigation **code and test
are present and correct in source** (verified above), which is what this audit
asserts. Final runtime proof — `Cargo Check & Test (Windows)` GREEN and
`Desktop E2E (windows-latest)` GREEN — is delivered by CI, not this audit, and
must be confirmed before merge per the plan checkpoint.

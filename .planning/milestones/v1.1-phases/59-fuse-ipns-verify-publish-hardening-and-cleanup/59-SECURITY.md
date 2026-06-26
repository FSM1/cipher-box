---
phase: 59
slug: fuse-ipns-verify-publish-hardening-and-cleanup
audit: retroactive-security
asvs_level: 1
result: SECURED
threats_closed: 13
threats_total: 13
threats_open: 0
audited: 2026-06-23
---

# Phase 59 — Security Audit

Retroactive verification that every declared threat mitigation in the four
`59-0N-PLAN.md` `<threat_model>` blocks is present in the implemented FUSE code.
Diff range inspected: `git diff origin/main...HEAD -- crates/fuse/src/` (8 changed
source files). Static analysis only — no test/build execution.

## Result: SECURED

**Threats Closed:** 13/13 · **Open:** 0 · **ASVS Level:** 1 (V6 Cryptography)

All declared mitigations are present in code at the cited locations. No new attack
surface was introduced (all four SUMMARY `## Threat Flags` sections declare "None"),
so there are zero unregistered flags. No key material is logged on any error path
touched this phase.

## Threat Verification

| Threat ID | Plan | Category                   | Disposition | Evidence (verified location)                                                                                  |
| --------- | ---- | -------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------- |
| T-59-01   | 01   | Tampering / DoS            | mitigate    | `fs.rs:227-228` File arm now `wrap_key(...).map_err(\|e\| format!("Wrap IPNS key: {}", e))?`; `.ok()` swallow removed. CLOSED |
| T-59-02   | 01   | Spoofing / Tampering       | mitigate    | `inode.rs:588-611` `same_pointer` compares `file_meta_ipns_name.as_deref()`; returns `(true, None)` when pointer differs. CLOSED |
| T-59-03   | 01   | Information Disclosure     | accept      | `crypto/error.rs` `CryptoError` Display strings are all static; "Wrap IPNS key: {e}" carries no key bytes. Accepted-risk holds. CLOSED |
| T-59-04   | 02   | Tampering (TOCTOU)         | mitigate    | All 9 Legacy arms consume carried `cid`/`sequence_number`; grep shows **zero** `resolve_ipns(` calls in events/fs/publish/metadata/replay. CLOSED |
| T-59-05   | 02   | Spoofing                   | mitigate    | `verify.rs:69` `Legacy { cid, sequence_number }` struct variant; every real match arm uses `{ ... }` pattern (compiler-enforced exhaustiveness, no bare arm). CLOSED |
| T-59-06   | 02   | Repudiation / downgrade    | accept      | D-04 unchanged: all-absent legacy record proceeds with DB CID under `log::warn!`; only the redundant second resolve removed. CLOSED |
| T-59-07   | 03   | Tampering (borrow)         | mitigate    | `content_ops.rs:164-176` `record_b64`/`marshaled`/`record` scoped into `is_first_publish` branch; `ipns_key_arr`/`new_seq`/`value` kept outside (Pitfall 2). Update-publish `None` guard preserved (now direct `if`). CLOSED |
| T-59-08   | 03   | Information Disclosure     | accept      | `grep signature_verified crates/fuse/src/` returns **zero** — field removed; it was never read by any call site, so no live verification decision lost. CLOSED |
| T-59-09   | 03   | Tampering (test fixture)   | accept      | Vector filler `public_key`/`private_key` removed; never deserialized by Rust struct, parity gate consumes real fields. CLOSED |
| T-59-10   | 04   | Tampering (rollback)       | mitigate*   | **Strict-equality cutover REVERTED in `0256ea486`.** Skew allowance `resp_seq == 1 && embedded_seq == 0` RESTORED at `verify.rs:124`. See "Finding F deferral" below — verify path remains fail-closed. CLOSED (deferred to Phase 60) |
| T-59-11   | 04   | DoS (durability)           | accept      | TEE republish bypasses `upsertFolderIpns` (confirmed by RESEARCH source analysis); no API change needed. CLOSED |
| T-59-12   | 04   | Tampering (partial update) | mitigate    | First-publish embeds 1: `publish.rs:18` `next_file_publish_sequence` returns `Ok(1)`; `replay.rs:628` embeds `1`. Zero `create_ipns_record(.*, 0,` sites remain in changed code. CLOSED |
| T-59-SC   | all  | Tampering (supply chain)   | accept      | No new dependencies in any of the 4 plans (RESEARCH "Standard Stack"). CLOSED |

`*` T-59-10's declared mitigation (strict `embedded_seq == resp_seq`) was intentionally
reverted; the **threat it guards (anti-rollback) stays mitigated** by the surrounding
signature gate. See deferral note.

## Security Invariants Confirmed

1. **No key material logged on any touched error path.** Grep across all 8 changed
   files for `log::*`/`println!`/`eprintln!` adjacent to `private_key`/`ipns_key`/
   `folder_key`/`file_key`/`secret`/`*_key_arr` returns empty. The new `fs.rs`
   `map_err` interpolates only `CryptoError` Display (static text). All Legacy-arm
   `log::warn!` calls log only the IPNS name / display name, never carried keys.

2. **IPNS verify path stays fail-closed (with skew allowance restored).** The skew
   tolerance `(resp_seq == 1 && embedded_seq == 0)` at `verify.rs:124` is reachable
   **only inside the `Some(true)` verdict branch** — i.e. after `verify_ipns_resolve_signature`
   (`api-client/src/ipns.rs:66`) has already (a) confirmed all three sig fields present,
   (b) passed Ed25519 verification, and (c) bound the derived IPNS name to the resolved
   name. A forged/unsigned record yields `None` → `Legacy` (DB-CID path, no trust
   uplift); a partial/invalid/name-mismatched record yields `Some(false)` → `Invalid`
   (hard fail). The cid binding at `verify.rs:93` remains strict equality. The skew
   therefore only ever tolerates a *cryptographically-signed, name-bound* first-publish
   record (embedded 0 vs DB 1). It does **not** open a fail-open hole.

3. **Removed `signature_verified` field removed no signature CHECK.** The field was a
   never-read bool on `VerifiedResolve`; the actual Ed25519 + name-binding check lives
   in `verify_ipns_resolve_signature` and `bind_verified`, both untouched in their
   decision logic. Zero residual references.

4. **`VerifyError::Legacy { cid, sequence_number }` does not bypass verification.** The
   carried values are clones of the *same* resolve response that was classified Legacy
   (all sig fields absent → pre-existing D-04 accepted-risk where DB CID is already
   authoritative). They replace a redundant second `resolve_ipns` round-trip (closing
   the TOCTOU window) and introduce no new trust decision — they are not
   attacker-controlled inputs to any check that was previously stricter.

## Finding F deferral (T-59-10) — fail-closed reasoning

The user-flagged revert (`0256ea486`) is internally consistent and safe:

- The resolve-side strict-equality cutover was reverted because the **publish-side
  interactive folder-create paths still embed sequence 0** — confirmed at
  `write_ops/implementation/mkdir.rs:174` (`create_ipns_record(..., 0, ...)`) and
  `platform/windows/write_ops.rs`, neither touched this phase.
- Tightening the resolve side to strict equality *before* those publish sites are
  unified to 1 (and existing embedded-0 records are republished) would fail-close
  resolution of every freshly-created folder — a self-inflicted DoS.
- The skew allowance is documented at `verify.rs:113-119` as deferred to Phase 60,
  which lands the publish-side change plus a republish migration.
- Because the allowance sits behind the signature gate (invariant 2), keeping it does
  not weaken anti-rollback: an attacker still cannot present an unsigned/forged record,
  and a signed record can only carry embedded 0 against DB 1 in the legitimate
  first-publish window.

FUSE-side first-publish was unified to 1 (`publish.rs`, `replay.rs`) so the FUSE and
replay paths are mutually consistent; only the cross-layer (mkdir/windows + republish)
unification remains for Phase 60.

## Unregistered Flags

None. All four `59-0N-SUMMARY.md` `## Threat Flags` sections declare "None — no new
network endpoints, auth paths, schema changes, or dependencies." The phase is a
hardening/cleanup phase that *removes* network surface (eliminated second resolves)
and dead code rather than adding any.

## Method

- Threat register extracted from the `<threat_model>` block of each of the four
  `59-0N-PLAN.md` files (13 threats incl. shared `T-59-SC`).
- Each `mitigate` threat verified by grepping the declared pattern in the cited file
  and reading the surrounding match-arm / branch.
- Each `accept` threat verified by reading the code it claims is benign (Display impls,
  field-removal grep, fixture removal) — not by accepting the plan's assertion.
- Implementation files were treated as read-only; this report is the only artifact
  written.

---
phase: 45
slug: desktop-fuse-write-durability-cleanup
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-15
---

# Phase 45 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
>
> No-behavior-change Rust refactor of the FUSE write-journal + crash-recovery replay code. No new attack surface introduced; the security-relevant surface is crash-recovery correctness and key handling in the consolidated journal builders.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
| -------- | ----------- | ------------- |
| old on-disk journal (pre-Phase-45) → new replay loader | a `JournalEntry` serialized by the old build (with the `""` sentinel) must still deserialize and replay under the new `Option<String>` type | possibly-corrupt/truncated persisted JSON; wrapped key material |
| FUSE callback (plaintext temp file + keys) → shared journal builder | the shared `build_*_journal_entry` handles plaintext + file/parent key material; must emit only ciphertext + once-wrapped keys | plaintext bytes, file key, file/parent IPNS private keys |
| process → local filesystem | journal-dir path resolution shared by FUSE mount + sync daemon; a wrong path would split durable state | journal directory path |
| in-process folder-key cache | decrypted folder keys held in memory for one `replay_for_vault` call; must not be persisted/shared | decrypted folder keys (in-memory only) |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
| --------- | -------- | --------- | ----------- | ---------- | ------ |
| T-45-03-INT | Tampering/Integrity (crash-recovery) | serde wire-format `""`→`Option` for `file_meta_ipns_name` | mitigate | `deser_opt_string` (`queue.rs:22`) maps legacy `""`/absent → `None`; tests `legacy_empty_string_ipns_loads_as_none` (queue.rs:951) + round-trip | closed |
| T-45-06-INT | Tampering/Integrity (crash-recovery) | shared `build_*_journal_entry` byte-identical to old inline closures | mitigate | All 9 `JournalOp::UploadFile` fields populated identically (`journal_helpers.rs:315-329`); `is_first_publish` threaded (line 360); Plan-01 safety net green | closed |
| T-45-06-CRYPTO | Information disclosure | shared helper handling plaintext + file/parent keys | mitigate | Journal stores `ciphertext_b64` only (never plaintext); file key zeroized via `clear_bytes` (`journal_helpers.rs:142`); each key ECIES-wrapped exactly once, no double-wrap (lines 290-310) | closed |
| T-45-03-DUR | Integrity (durability) | replay skip-when-absent semantics | mitigate | `replay_upload_entry` guards per-file publish on `Some(name)` (`lib.rs:1738-1740`); parent-merge still proceeds | closed |
| T-45-04-INT | Tampering/Integrity | not-found classification driving `is_first_publish` | mitigate | `resolve_ipns_for_replay` preserves `contains("not found") || contains("404")` (`lib.rs:219`); NotFound→seq-0, Error→retain; test T-45-05 | closed |
| T-45-05-INT | Tampering/Integrity | replay publish via shared `publish_file_metadata` | mitigate | ECIES-unwrap + `is_first_publish` stay local (`lib.rs:1747,1775`); no key re-wrap (`operations.rs:129` takes `&Zeroizing`) | closed |
| T-45-05-DUR | Integrity (durability) | TEE-enrollment reached on first publish | mitigate | `publish_file_metadata` TEE wrap/enroll on first-publish (`operations.rs:170-181`); tee key/epoch threaded through replay | closed |
| T-45-01-DOS | Denial of Service | truncated/partial journal on load | mitigate | `load_all_for_vault` skips malformed/partial JSON with `warn` + `continue`, no panic (`queue.rs:243-255`); tests T-45-01/02 | closed |
| T-45-01-INT | Tampering/Integrity | crash-mid-write durability | mitigate | `put`-but-not-`remove`d entry survives reload; `Failed` entries retained (`queue.rs:290-293`); tests T-45-01/03 | closed |
| T-45-02-INT | Tampering/Integrity | journal-dir path drift between mount + sync daemon | mitigate | Single `default_journal_dir()` source of truth (`fuse/mod.rs:62`); both call sites import it; tail-path test (line 378) | closed |
| T-45-04-DUR | Integrity (durability) | `Error(_)` entry-retention path | mitigate | Error arm returns `Err` → `record_failure` retains entry (`lib.rs:1788-1793,1259`) | closed |
| T-45-05-INFO | Information disclosure | in-memory folder-key cache | mitigate | `folder_key_cache` local to one `replay_for_vault` call (`lib.rs:1204-1206`); `&mut` only, not stored in any struct, dropped on return | closed |
| T-45-06-DUR | Integrity (durability) | platform reply/spawn kept local | mitigate | Only entry-build shared; fuser `reply.error(EIO)` + winfsp return + spawn remain per-platform | closed |

_Status: open · closed_
_Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)_

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
| ------- | ---------- | --------- | ----------- | ---- |
| AR-45-01 | T-45-01-SC, T-45-02-SC, T-45-03-SC, T-45-04-SC, T-45-05-SC, T-45-06-SC | Package Legitimacy Gate N/A — phase adds zero new cargo dependencies (refactor + `#[cfg(test)]` code + internal module only) | gsd-security-auditor | 2026-06-15 |
| AR-45-02 | T-45-02-DUR | `temp_dir` fallback when `data_local_dir` unavailable is behavior-preserved exactly (same `warn` + fallback as pre-refactor); not regressed | gsd-security-auditor | 2026-06-15 |
| AR-45-03 | T-45-03-CRYPTO | The `Option<String>` change touches only an IPNS-name string field; `wrapped_key_hex`/`parent_ipns_key_hex` untouched, no double-wrap introduced (V6) | gsd-security-auditor | 2026-06-15 |

_Accepted risks do not resurface in future audit runs._

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
| ---------- | ------------- | ------ | ---- | ------ |
| 2026-06-15 | 18 | 18 | 0 | gsd-security-auditor (ASVS L1, block_on: high) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-15

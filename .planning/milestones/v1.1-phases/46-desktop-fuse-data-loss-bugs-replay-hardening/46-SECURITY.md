<!-- generated-by: gsd-security-auditor -->

# Phase 46 Security Audit — desktop-fuse-data-loss-bugs-replay-hardening

**ASVS Level:** 1
**block_on:** high
**Audited diff:** `4b539b445..HEAD`
**Result:** SECURED — 10/10 mitigate threats CLOSED, 2/2 accept threats logged.

Implementation files are read-only; this audit only verifies declared mitigations
from the phase threat register exist in the implemented code.

## Threat Verification

| Threat ID | Category               | Disposition | Status | Evidence |
| --------- | ---------------------- | ----------- | ------ | -------- |
| T-46-01   | Information Disclosure | mitigate    | CLOSED | `journal_helpers.rs:535-539` — test asserts decoded `ciphertext_b64 != plaintext`; only `ciphertext_b64` journalled (`:286,311`) |
| T-46-02   | Information Disclosure | mitigate    | CLOSED | `journal_helpers.rs:497-503` real secp256k1 keypair via `ecies::utils::generate_keypair`; `:541-548,591-598` assert wrapped hex fields present, never raw |
| T-46-03   | Denial of Service      | mitigate    | CLOSED | `platform/linux.rs:141-187` `recover_stale_mount` reads `/proc/self/mountinfo` (not `exists()`), `fusermount3 -u` then lazy `-z -u`; `:217-226` `create_mount_point_dir` retries `create_dir_all` once on EEXIST. Wired at `fuse/mod.rs:98-99,105-106` |
| T-46-04   | Tampering              | mitigate    | CLOSED | `test_support.rs:40-49` per-test dir keyed by `process::id()`+`AtomicU64`; comment + code confirm never `default_journal_dir()` |
| T-46-05   | Tampering              | accept      | LOGGED | See accepted-risks AR-46-05 — `platform/linux.rs:191-199` fixed argv `fusermount3` + app-derived `mount_point()` path; no user-controlled command string |
| T-46-06   | Tampering              | mitigate    | CLOSED | `lib.rs:308-321` `resolve_sequence_strict` errs on any resolve failure (no cache fallback); live cache-resilient `resolve_sequence` kept separate at `:266-303`; replay routes through strict via `:215-221` |
| T-46-07   | Information Disclosure | mitigate    | CLOSED | `lib.rs:1882-1887` `replay_upload_entry` returns Err when `file_meta_ipns_name.is_none()` (parks entry → retained), before any publish; no new key material |
| T-46-08   | Information Disclosure | mitigate    | CLOSED | `test_support.rs:72` isolated temp dir + unroutable API (`:95`); replay/release tests reference `ciphertext_b64` + ECIES-wrapped keys only (`lib.rs:2957-2974,3004-3058`) |
| T-46-09   | Repudiation/Data Loss  | mitigate    | CLOSED | `lib.rs:2905-2996` `release_journals_before_cleanup` asserts (1) journalled `ciphertext_b64` non-empty, (2) temp file deleted, (3) reply ok, (4) entry retained — a `reply.ok` before `journal.put` reorder fails (1)/(3) |
| T-46-10   | Tampering              | mitigate    | CLOSED | Only republish-parent path (debounce conflict retry) fetch-and-merges remote children via `merge_folder_children` at `lib.rs:485`; no blind overwrite. A2 traced in 46-04-SUMMARY |
| T-46-SC   | Tampering              | accept      | LOGGED | See accepted-risks AR-46-SC — no `Cargo.toml`/`Cargo.lock` changes in audited diff; `ecies` is `[dev-dependencies]` (`crates/fuse/Cargo.toml:40-41`), `libc` pre-existing |

## Accepted Risks Log

### AR-46-05 — fusermount3 shell-out in recover_stale_mount

`recover_stale_mount` / `try_fusermount3_unmount` invoke `fusermount3` via
`std::process::Command`. Accepted: argv is fixed (`fusermount3`, `-u` / `-z -u`)
and the only path argument is the app-derived `mount_point()` (`~/CipherBox`), not
a user-controlled string. No shell interpolation (`Command::new` + `.arg`, not a
shell). Verified `crates/fuse/src/platform/linux.rs:191-199`.

### AR-46-SC — no new third-party dependencies

Accepted: this phase adds no package installs. The audited diff
(`4b539b445..HEAD`) contains no `Cargo.toml` or `Cargo.lock` changes. The only
crypto/process primitives used are the existing `ecies` dev-dependency
(`crates/fuse/Cargo.toml:40-41`, test-only), `std::process`, and the pre-existing
`libc` Unix target dependency.

## Unregistered Flags

None. No `## Threat Flags` section is present in any 46-0x-SUMMARY.md; the
summaries' `## Threat Model Compliance` notes map 1:1 to the registered threat IDs.
No new attack surface appeared during implementation without a threat mapping.

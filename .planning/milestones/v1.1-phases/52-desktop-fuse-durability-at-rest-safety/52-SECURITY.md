# Phase 52 Security Audit — desktop-fuse-durability-at-rest-safety

Verdict: SECURED. All 16 declared threat mitigations (T-52-01 … T-52-16) are present in
the implemented code. No HIGH-severity threat is left open. Phase 51 hardening (Zeroizing
wrappers, fail-closed signature handling, key zeroization) is intact — Phase 52 reverted
none of it.

Branch: `feat/desktop-fuse-durability-at-rest-safety`
Worktree: `.`
ASVS Level: not declared in plan config; verified against the plan threat registers (STRIDE).
block_on: not declared; treated as informational (no `<config>` block in the plans).

## SECURED

Phase: 52 — desktop-fuse-durability-at-rest-safety
Threats Closed: 16/16

### Threat Verification

| Threat ID | Category | Disposition | Evidence (file:line) |
| --------- | -------- | ----------- | -------------------- |
| T-52-01 | Information Disclosure (D-05 host-path scrub) | mitigate | `crates/sdk/src/sync.rs:266-291` — `regex_replace_paths` scrubs `/Users/`, `/home/`, `/var/`, `/tmp/`, `/private/` (`:272-276`) and Windows drive-letter `:\\Users\\` (`:286-291`) to `[path]`; test `sanitize_error_extended_paths` `:356-398` |
| T-52-02 | Tampering (D-06 swallowed remove) | mitigate | All three `let _ = journal.remove` replaced with `if let Err(e) { log::warn!(... "may replay again on next mount") }`: `crates/fuse/src/lib.rs:1516`, `:1598`, `crates/fuse/src/write_ops.rs:679`. No `let _ = journal.remove` remains |
| T-52-03 | Information Disclosure (D-01 in-JSON ciphertext / WR-06, HIGH) | mitigate | `crates/sdk/src/queue.rs:48-67` — `UploadFile` carries `sidecar_path` + `sidecar_sha256`, no `ciphertext_b64`; `put_with_sidecar` streams ciphertext to a 0600 `.bin` (`:273-312`); zero `ciphertext_b64`/`base64` in `journal_helpers.rs` |
| T-52-04 | Information Disclosure (D-04 plaintext name at rest) | mitigate | `queue.rs:92-103` `filename_encrypted_hex` (`#[serde(alias="filename")]`), `:129-135` `name_encrypted_hex` (`#[serde(alias="name")]`); write-side encryption `journal_helpers.rs:311-314` (file) and `:454-457` (dir), both fail-closed |
| T-52-05 | Information Disclosure (D-01 orphaned `.bin`) | mitigate | `queue.rs:321-..` sidecar-aware `remove` deletes both `.json` + `.bin`; `put_with_sidecar:277-282` pre-cleans stale `.bin` and `:306-309` removes `.bin` on `.json` write failure; GC orphan pass `:506-523` is the backstop |
| T-52-06 | Denial of Service (D-01 unbounded payload, constant) | mitigate | `queue.rs:20` `MAX_JOURNAL_PAYLOAD_BYTES = 2 GiB`, re-exported `crates/sdk/src/lib.rs:16-18` |
| T-52-07 | Denial of Service (D-01 heavy write on FS thread / WR-06, HIGH) | mitigate | `crates/fuse/src/read_ops.rs:825-848` — `put_with_sidecar` runs on a separate OS thread; callback thread blocks on a BOUNDED `recv_timeout(NETWORK_TIMEOUT*18 ≈ 180s)`; timeout/disconnect → `Err` → EIO (`:838-848`, `:995-1004`) |
| T-52-08 | Denial of Service (D-01 OOM size cap) | mitigate | `crates/fuse/src/journal_helpers.rs:140-147` — `file_size > MAX_JOURNAL_PAYLOAD_BYTES` returns `Err("File too large for journal ...")`; flows to the EIO arm in release |
| T-52-09 | Information Disclosure (D-04 plaintext filename / IN-03) | mitigate | `journal_helpers.rs:311-314` ECIES `wrap_key(file_name, public_key)` → `filename_encrypted_hex`, fail-closed; mkdir name `:454-457` |
| T-52-10 | Spoofing/Tampering — false durability ack (Phase-43 CR-04 regression) | mitigate | `read_ops.rs:854-920` — inode mutations, `pending_content.insert`, `queue_publish`, `handle.cleanup()` and `reply.ok()` are ALL deferred until AFTER the bounded recv resolves `Ok(Ok(()))`. `reply.ok()` (`:920`) is strictly after durability. Err/timeout → `reply.error(EIO)` with zero mutations (`:995-1004`) |
| T-52-11 | Denial of Service (D-03 replay blocking mount / WR-07) | mitigate | Per-entry `tokio::time::timeout`: mkdir `NETWORK_TIMEOUT*3` (`lib.rs:1483-1509`), upload `NETWORK_TIMEOUT*18` (`:1560-1591`), timeout → `Err` → `record_failure`. Replay spawned concurrently with mount: `apps/desktop/src-tauri/src/fuse/mod.rs:309` and `fuse/windows/mod.rs:376` (`rt.spawn`, mount no longer awaits) |
| T-52-12 | Tampering (D-01 corrupt/swapped sidecar re-uploaded) | mitigate | `lib.rs:2254-2267` — replay reads `.bin`, recomputes SHA-256, compares to `sidecar_sha256`; mismatch or missing/empty path → `Err` (entry retained, no bad CID published) |
| T-52-13 | Information Disclosure (D-04 decrypted name leaked/persisted) | mitigate | `lib.rs:2153-2180` `decrypt_journal_name` ECIES-unwraps with the user private key; result used transiently for `FilePointer.name`/`FolderEntry.name` only; never written back to the journal |
| T-52-14 | Tampering — legacy plaintext name stranding in-flight writes (D-04) | mitigate | `decrypt_journal_name:2154-2179` — non-hex / undecryptable value triggers a `log::warn!` and passthrough-once of the legacy plaintext; entry replays then is removed; never re-persisted |
| T-52-15 | Information Disclosure (D-02 cross-vault journal retention) | mitigate | `queue.rs:403-411` `purge_vault` removes every `.json` + `.bin` for a vault; wired into `apps/desktop/src-tauri/src/commands/auth.rs:521-533` in `logout()`, BEFORE `clear_keys()` (`:536`) |
| T-52-16 | Denial of Service (D-02 unbounded Failed entries + orphans) | mitigate | `queue.rs:430-526` `gc_failed_entries` — age purge (`:473-487`), oldest-first size-trim incl. `.bin` bytes (`:489-504`), `.bin` orphan cleanup (`:506-523`), Failed-only, best-effort. Run at mount: `apps/desktop/src-tauri/src/fuse/mod.rs:280-287` |

### Implementation deviations reviewed (not gaps)

- Durable-ack mechanism (T-52-07/T-52-10): plan 52-03 specified `rt.block_on` +
  `tokio::sync::oneshot`; the implementation uses `std::thread::spawn` +
  `std::sync::mpsc::recv_timeout` (`read_ops.rs:825-848`). Documented in 52-03-SUMMARY as a
  deliberate fix for the nested-runtime panic (`rt.block_on` inside a tokio runtime). The
  security-relevant contract — a BOUNDED blocking wait that must resolve `Ok` before
  `reply.ok()` — is preserved with the identical `NETWORK_TIMEOUT*18` bound. No false-ack;
  this is semantically equivalent and runtime-agnostic. CLOSED.
- Upload-replay idempotency (T-52-12): plan 52-04 referenced an `already_present`
  short-circuit "before the sidecar read." In the upload path the idempotency guarantee is
  the content-addressed CID (re-pin is a no-op) plus the empty-sidecar-path / hash-mismatch
  guards (`lib.rs:2248-2267`) that retain the entry rather than re-uploading bad ciphertext.
  The `already_present` check (`lib.rs:1828-1835`) is on the mkdir/metadata path. No data-
  integrity gap. CLOSED.

### At-rest permission invariants

- Journal dir: `std::fs::create_dir_all` + `set_permissions(0o700)` —
  `apps/desktop/src-tauri/src/fuse/mod.rs:152-157`.
- `.json` and `.bin` sidecars: atomic `OpenOptionsExt::mode(0o600)` at create time —
  `crates/sdk/src/queue.rs:229` and `:288`; test asserts 0600 (`:1531`).
- Pre-existing dir create→chmod window (umask default until `set_permissions`) is consistent
  across mount/temp/journal dirs and is NOT introduced by Phase 52; files are created 0600
  atomically. Informational, not a Phase-52 finding.

### Phase 51 hardening regression check

`git diff main...HEAD` removed ZERO lines mentioning `zeroize`, `signature`, `verify`,
`sign`, or `signedRecord` in `crates/` or `apps/desktop/src-tauri/src/`. The Phase 52 diff
touches only the planned durability/at-rest files (queue.rs, sync.rs, lib.rs, read_ops.rs,
journal_helpers.rs, write_ops.rs, auth.rs, fuse/mod.rs, windows/mod.rs + Cargo deps); no
crypto/TEE/signing module was modified. `unwrap_key` continues to return `Zeroizing` and
new key material in the touched paths is wrapped in `Zeroizing`. Phase 51 hardening intact.

### Unregistered Flags

None. No `## Threat Flags` section is present in any 52-0N-SUMMARY.md, and no new attack
surface appeared during implementation that lacks a threat mapping (the diff is scoped
entirely to the declared mitigation files).

## Notes

- No `<config>` block (asvs_level / block_on) was present in the phase plans; verification
  was performed against the per-plan STRIDE threat registers.
- Repo-root `SECURITY.md` was NOT modified by
  this audit. Git tree was clean before and after writing this phase doc.

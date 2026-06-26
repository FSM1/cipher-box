---
phase: 52-desktop-fuse-durability-at-rest-safety
verified: 2026-06-20T05:00:00Z
status: passed
score: 16/16 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: none
  previous_score: n/a
---

# Phase 52: Desktop FUSE Durability & At-Rest Safety — Verification Report

**Phase Goal:** Harden the desktop FUSE write-journal and its replay path under HARD-03 —
close the Phase 43 review warnings WR-06 (large-file journal write path / OOM / FS-thread
stall), WR-07 (replay timeout + concurrent mount), IN-03 (at-rest plaintext names), IN-04
(error path scrub), and IN-05 (swallowed journal-remove errors). Cross-platform Rust in
`crates/sdk` + `crates/fuse` + the Tauri shell.

**Verified:** 2026-06-20
**Status:** passed
**Re-verification:** No — initial verification
**Method:** Static analysis + reading only (combined tree pre-verified GREEN by developer:
`cargo test -p cipherbox-fuse` 64/64, `cargo test -p cipherbox-sdk` 57/57,
`cargo check -p cipherbox-desktop --features fuse` clean). The `--features winfsp` failure in
upstream `windows_core` on macOS and the by-design non-compilability of intermediate Wave-2
commits are documented non-defects and were NOT treated as gaps.

## Goal Achievement

### Observable Truths

| # | Plan | Truth | Status | Evidence |
| - | ---- | ----- | ------ | -------- |
| 1 | 52-01 | Tray/notification error copy never contains a real host path prefix (`/Users`, `/home`, `/var`, `/tmp`, `/private`, `C:\Users\`) | ✓ VERIFIED | `crates/sdk/src/sync.rs:271-301` — `regex_replace_paths` scrubs all five Unix prefixes (`:272-276`) + a Windows drive-letter branch `c.is_ascii_uppercase() && input[i+1..].starts_with(":\\Users\\")` (`:286-288`), each pushing `[path]` and skipping to the next whitespace/quote boundary. Test `sanitize_error_extended_paths` (`sync.rs:356`) covers all six. |
| 2 | 52-01 | A failed `journal.remove()` after a successful replay/publish emits `log::warn!` instead of being silently swallowed | ✓ VERIFIED | All three sites converted to `if let Err(e) { log::warn!(... "may replay again on next mount") }`: `lib.rs:1516` (MkdirPublish), `lib.rs:1598` (UploadFile), `write_ops.rs:679` (mkdir parent-publish). No `let _ = journal*.remove(` remains (grep = 0). Test `remove_failure_is_logged` (`lib.rs:3466`). |
| 3 | 52-02 | A journaled file upload stores its ciphertext in a 0600 sidecar `<id>.bin`, never inside the JSON | ✓ VERIFIED | `queue.rs:273-312` `put_with_sidecar` streams ciphertext in 1 MiB chunks to `<id>.bin` opened with `mode(0o600)` (`:288`) + `sync_all` (`:300`), then writes the `.json`. `JournalOp::UploadFile` carries `sidecar_path`/`sidecar_sha256` (`:56,:67`), `ciphertext_b64` removed. Test `sidecar_ciphertext_not_in_json` (`queue.rs:1493`). |
| 4 | 52-02 | Serialized JSON entry contains no base64 ciphertext blob and no plaintext filename | ✓ VERIFIED | `filename_encrypted_hex` replaces `filename` (`queue.rs:103`), `name_encrypted_hex` replaces `name` (`:136`). Test `journal_no_plaintext_filename` (`queue.rs:1446`) asserts serialized JSON has no `ciphertext_b64` key and carries `filename_encrypted_hex`. |
| 5 | 52-02 | Removing a journal entry deletes BOTH `<id>.json` and `<id>.bin` (no orphaned ciphertext) | ✓ VERIFIED | `queue.rs:321-345` `remove` deletes `.bin` (NotFound tolerated) then `.json`, fsyncs parent dir. Test `sidecar_ciphertext_not_in_json` asserts `!bin_path.exists()` after remove (`queue.rs:1536`). |
| 6 | 52-02 | An old pre-Phase-52 entry with a plaintext `filename` field still deserializes (legacy compat, replayed once) | ✓ VERIFIED | `#[serde(alias = "filename")]` on `filename_encrypted_hex` (`queue.rs:102`), `#[serde(alias = "name")]` on `name_encrypted_hex` (`:135`), `#[serde(default)]` on sidecar fields (`:55,:66`). Test `legacy_plaintext_filename_compat` (`queue.rs:1375`) deserializes the old `ciphertext_b64`+plaintext shape. |
| 7 | 52-03 | A file larger than the per-entry payload cap fails `release()` with EIO instead of OOMing/stalling | ✓ VERIFIED | `journal_helpers.rs:140-147` rejects `file_size > MAX_JOURNAL_PAYLOAD_BYTES` (2 GiB, `queue.rs:20`) BEFORE any encryption, returning `Err`; the release path Err arm replies `libc::EIO` (`read_ops.rs:994-1003`). Test `payload_size_cap_returns_err` (`journal_helpers.rs:680`). |
| 8 | 52-03 | Journaled filename is ECIES-encrypted at write time using the user public key | ✓ VERIFIED | `journal_helpers.rs:311-313` `hex::encode(ecies::wrap_key(file_name.as_bytes(), &self.public_key))` → `filename_encrypted_hex`; mkdir name analog at `:454-468`. Test `build_upload_journal_entry_round_trips` (`journal_helpers.rs:541`) asserts valid ECIES hex. |
| 9 | 52-03 | `release()` does not `reply.ok()` until sidecar `.bin` + `.json` are both fsynced (CR-04 durable-ack preserved) | ✓ VERIFIED | `read_ops.rs:817-851` writes the sidecar on a separate OS thread and blocks the callback thread on a bounded `recv_timeout(NETWORK_TIMEOUT*18)` (`:838`); in-memory mutations + `reply.ok()` (`:920`) happen only on durable `Ok`; failure/timeout replies EIO with no mutation (`:996-1003`). Tested by `release_journals_before_cleanup` (`lib.rs:3262`) which asserts the `.bin` exists and hashes to `sidecar_sha256` BEFORE the ack. |
| 10 | 52-04 | Replay reads ciphertext from the `<id>.bin` sidecar and verifies its sha256 | ✓ VERIFIED | `replay_upload_entry` (`lib.rs:2187`) reads `sidecar_path` (`:2254`), recomputes SHA-256 (`:2256-2261`), returns Err on empty path or mismatch (`:2248,:2262`) → entry retained via record_failure. |
| 11 | 52-04 | Replay decrypts `filename_encrypted_hex`/`name_encrypted_hex` transiently (never re-persisted) and still replays a legacy plaintext entry once | ✓ VERIFIED | `decrypt_journal_name` (`lib.rs:2153-2180`) hex-decodes + `ecies::unwrap_key`; on any failure logs once and returns the input verbatim (passthrough-once legacy compat). Used at `:2216` (upload) and `:2029` (mkdir). |
| 12 | 52-04 | Each replay entry's network ops are bounded by `tokio::time::timeout`; a hung entry returns Err → record_failure | ✓ VERIFIED | `replay_for_vault` wraps mkdir in `timeout(NETWORK_TIMEOUT*3, …)` (`lib.rs:1483`) and upload in `timeout(NETWORK_TIMEOUT*18, …)` (`:1560`); timeout Err routed through `record_failure` (`:1527,:1611`). Test `replay_entry_timeout` (`lib.rs:3524`). |
| 13 | 52-04 | Mount returns immediately; replay runs concurrently via `rt.spawn` (macOS/Linux and Windows) | ✓ VERIFIED | `fuse/mod.rs:309-323` spawns `replay_for_vault` via `rt.spawn` BEFORE `CipherBoxFS` construction/mount; Windows analog at `windows/mod.rs:376`. Mount never awaits replay. |
| 14 | 52-05 | `purge_vault` removes every journal entry (`.json` + `.bin`) for one `vault_root_ipns` | ✓ VERIFIED | `queue.rs:403-411` loads all entries for the vault and calls sidecar-aware `remove` per entry. Test `purge_vault_removes_all` (`queue.rs:1601`) asserts vault-A `.json`+`.bin` gone, vault-B survives. |
| 15 | 52-05 | Logout purges the current vault's journal entries so they don't persist past the session | ✓ VERIFIED | `auth.rs:521-533` reads `root_ipns_name` from sdk state (BEFORE `clear_keys()` at `:536` zeroes it), reconstructs `WriteQueue` from `default_journal_dir()`, calls `purge_vault`. Failure logs warn and continues logout. |
| 16 | 52-05 | `gc_failed_entries` removes parked Failed entries older than age window, trims oldest-first to size budget, cleans `.bin` orphans | ✓ VERIFIED | `queue.rs:430-526` — Pass 1 age purge vs `JOURNAL_GC_MAX_AGE_DAYS` (`:473-487`), Pass 2 oldest-first size trim vs budget counting `.json`+`.bin` (`:489-504`), Pass 3 orphan `.bin` cleanup (`:506-521`); only `Failed` entries touched. Wired at mount: `fuse/mod.rs:280-282`. Tests `gc_purges_old_failed` (`queue.rs:1631`), `gc_purges_to_size_budget` (`queue.rs:1664`). |

**Score:** 16/16 truths verified

### Required Artifacts

| Artifact | Provides | Status | Details |
| -------- | -------- | ------ | ------- |
| `crates/sdk/src/sync.rs` | Extended scrub list (D-05) | ✓ VERIFIED | 5 Unix prefixes + Windows drive-letter branch (`:272-288`) |
| `crates/fuse/src/lib.rs` | Logged removals + replay sidecar/timeout/decrypt (D-06/D-03/D-04) | ✓ VERIFIED | `:1516,:1598`; `:1483,:1560` timeout; `:2153` decrypt; `:2254-2262` sidecar verify |
| `crates/fuse/src/write_ops.rs` | Logged mkdir removal (D-06) | ✓ VERIFIED | `:679` |
| `crates/sdk/src/queue.rs` | sidecar shape + put_with_sidecar + remove + GC/cap + compat + purge_vault/gc (D-01/D-02/D-04) | ✓ VERIFIED | `:56-136,:273,:321,:403,:430`; constants `:20,:23,:27` |
| `crates/fuse/src/journal_helpers.rs` | size cap + ECIES name encryption + sidecar entry build (D-01/D-04) | ✓ VERIFIED | `:140,:311,:454` |
| `crates/fuse/src/read_ops.rs` | off-thread durable-ack (D-01) | ✓ VERIFIED | `:817-851,:920,:996-1003` |
| `apps/desktop/src-tauri/src/fuse/mod.rs` | concurrent replay + mount-time GC (D-03/D-02) | ✓ VERIFIED | `:280,:309` |
| `apps/desktop/src-tauri/src/fuse/windows/mod.rs` | concurrent replay on Windows (D-03) | ✓ VERIFIED | `:376` |
| `apps/desktop/src-tauri/src/commands/auth.rs` | logout purge (D-02) | ✓ VERIFIED | `:521-533` |

### Key Link Verification

| From | To | Via | Status |
| ---- | -- | --- | ------ |
| `sanitize_error` | `regex_replace_paths` | six-prefix scrub branch | ✓ WIRED (`sync.rs:259,:271-288`) |
| `put_with_sidecar` | `<id>.bin` + `<id>.json` | stream+fsync .bin, then .json; remove .bin on .json failure | ✓ WIRED (`queue.rs:284-309`) |
| `WriteQueue::remove` | `<id>.bin` | delete sidecar alongside .json | ✓ WIRED (`queue.rs:326`) |
| `release` path | `put_with_sidecar` (off-thread) | OS thread + bounded recv before `reply.ok()` | ✓ WIRED (`read_ops.rs:829-848,:920`) |
| `build_upload_journal_entry` | `ecies::wrap_key` | encrypt filename → `filename_encrypted_hex` | ✓ WIRED (`journal_helpers.rs:311`) |
| `replay_for_vault` | replay_*_entry | `tokio::time::timeout(... )` → Err → record_failure | ✓ WIRED (`lib.rs:1483,:1560,:1527,:1611`) |
| `replay_upload_entry` | `<id>.bin` | read + verify sidecar_sha256 | ✓ WIRED (`lib.rs:2254-2262`) |
| `mount_filesystem` (Unix+Win) | `replay_for_vault` | `rt.spawn(async { … })` before FS construction | ✓ WIRED (`fuse/mod.rs:309`, `windows/mod.rs:376`) |
| `logout()` | `purge_vault` | reconstruct WriteQueue; purge before `clear_keys()` | ✓ WIRED (`auth.rs:523-528,:536`) |
| `mount_filesystem` | `gc_failed_entries` | GC constants | ✓ WIRED (`fuse/mod.rs:280-282`) |

### Behavioral Spot-Checks (test existence proof — enumerated, not run)

11 of 12 VALIDATION-map test names found by exact name (`grep fn <name>`):
`sidecar_ciphertext_not_in_json`, `payload_size_cap_returns_err`, `purge_vault_removes_all`,
`gc_purges_old_failed`, `gc_purges_to_size_budget`, `replay_entry_timeout`,
`journal_no_plaintext_filename`, `filename_encryption_round_trips`,
`legacy_plaintext_filename_compat`, `sanitize_error_extended_paths`, `remove_failure_is_logged`.
The 12th (`durable_ack_with_sidecar`, D-01-b) was folded into the pre-existing
`release_journals_before_cleanup` (`lib.rs:3262`), which drives a real `handle_release`,
asserts `reply.ok()`, then asserts the sidecar `.bin` exists and hashes to `sidecar_sha256`
BEFORE the ack — the exact durable-ack-with-sidecar behavior (documented in 52-03-SUMMARY).
Cosmetic name deviation only; behavior is covered. Full suites pre-verified GREEN by developer.

### Requirements Coverage

| Requirement | Source Plans | Status | Evidence |
| ----------- | ------------ | ------ | -------- |
| HARD-03 | 52-01..52-05 | ✓ SATISFIED | All five review warnings (WR-06, WR-07, IN-03, IN-04, IN-05) closed by the 16 verified truths above. |

### Anti-Patterns Found

None. No `TBD`/`FIXME`/`XXX` debt markers in any modified file. No stub returns, no empty
handlers. The single `TODO`-substring match is a doc comment describing a past root cause, not
a debt marker.

### Noted Deviations (non-blocking)

- **`oneshot` → `std::sync::mpsc`:** The 52-03 PLAN named the durable-ack channel
  `tokio::sync::oneshot` (artifact `contains: "oneshot"`, key_link `pattern: "oneshot"`). The
  implementation uses `std::thread::spawn` + `std::sync::mpsc::recv_timeout`
  (`read_ops.rs:825-848`); the word `oneshot` survives only in a comment (`:803`). This is an
  intentional, documented choice (52-03-SUMMARY: a `tokio` `block_on` would panic
  "Cannot start a runtime from within a runtime" under `#[tokio::test]` and any on-runtime
  caller). The **observable truth** — release blocks on a bounded durable-ack before
  `reply.ok()` — is fully satisfied. Pattern-string mismatch only, not a behavioral gap.
- **D-01-b test name:** `durable_ack_with_sidecar` folded into `release_journals_before_cleanup`
  (covered above). Cosmetic.

### Human Verification Required

None required for goal-backward verification — all truths are statically confirmed in code and
the combined tree was pre-verified GREEN. (The two manual FUSE-mount items in 52-VALIDATION.md —
off-thread write not blocking concurrent FS callbacks, and mount-returns-instantly-during-replay —
are runtime-observability confirmations of already-verified code paths, deferred to live UAT per
the standard headless-desktop FUSE recipe; they are not blockers for phase completion.)

### Gaps Summary

No gaps. All 16 must-have truths across the five plans map to substantive, wired code with
matching tests. The two noted deviations (mpsc-vs-oneshot mechanism, one folded test name) are
documented intentional choices that preserve every observable truth.

---

_Verified: 2026-06-20T05:00:00Z_
_Verifier: Claude (gsd-verifier)_

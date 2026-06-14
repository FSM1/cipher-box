---
status: complete
phase: 43-fuse-write-durability
source: [43-VERIFICATION.md]
started: 2026-06-13T05:30:00Z
updated: 2026-06-14T00:10:00Z
platform: windows (WinFsp); mount C:\Users\<user>\CipherBox; journal %LOCALAPPDATA%\cipherbox\cb-journal
run_environment: |
  Fresh local build of apps/desktop (cargo --no-default-features --features winfsp, debug),
  dev-key headless auth against a local API stack: Docker (postgres, ipfs/kubo, redis, someguy),
  local mock-ipns-routing on :3001, API on :3000 (Node 22). Each test SIGKILLs via
  `taskkill /IM cipherbox-desktop.exe /F` and relaunches the same vault (deterministic
  dev-key@cipherbox.local keypair).
---

## Current Test

number: 4
name: complete
expected: |
  All four human-verification items exercised on a live Windows/WinFsp build.
awaiting: none — run complete

## Tests

### 1. Journal survival after SIGKILL

expected: Copy a file into the vault, SIGKILL desktop before upload completes, relaunch. File replays on mount and is present remotely; the cb-journal entry disappears after successful replay.
result: PASS
evidence: |
  Copied a 20 MB file into C:\Users\<user>\CipherBox, then `taskkill /F` on the desktop
  immediately after the copy ack'd. The journal entry (9552611c…json, 26.6 MB of base64
  ciphertext) was already fsync'd to disk before the kill — confirming release() journals
  before acking. On relaunch the log shows `replay_for_vault: UploadFile 9552611c… ('uat1-mid.bin')
  replayed successfully`, the journal entry was removed, and the file is present in the mount
  with byte-identical content to the original (cmp -s passed). 
  Note: the live root listing took one ~30 s sync-poll cycle to show the replayed file and the
  readdir cache briefly reported size 0 before a per-file getattr resolved 20,000,000 bytes —
  eventual-consistency in the directory cache, not a data-integrity problem.
  Aside: an initial attempt with a 120 MB file surfaced that the API caps uploads at 100 MB
  (HTTP 413); replay correctly retried and RETAINED the entry ("will retry on next mount"),
  which independently confirms the retry-retention branch.

### 2. Park notification render

expected: Force upload failure, copy a file, let retries exhaust. An OS notification with the failed-upload count appears, the tray shows the WriteParked status, and the journal entry remains on disk with Failed status.
result: PASS (after fix — see "Fixes applied" / G-43-UAT-01)
evidence: |
  First run FAILED on a blocking integration gap: the SyncDaemon that emits WriteParked was
  never started (`start_sync_daemon` had zero call sites — see G-43-UAT-01). The journal park
  transition itself already worked: a >100 MB file (persistent HTTP 413) with the retry counter
  at max_retries(5) parked on the next replay — `replay_for_vault: UploadFile … parked as Failed
  after 5 retries: … 413`, on-disk status `Failed{last_error:"…413…"}` — but no notification
  could render because nothing turned the daemon on.
  After the fix (auto-start the daemon from complete_auth_setup), the retest passed end-to-end:
  the log shows `Filesystem mounted …` → `Starting background sync daemon` → `Sync daemon spawned`
  → `Sync daemon started (interval: 30s)`; the parked entry reached `Failed` on disk; the daemon's
  poll reached `Sync cycle complete — checking journal for parked writes` (failed=1); and the
  Windows OS toast "CipherBox Upload Failed — 1 pending upload(s) failed and require attention."
  rendered (visually confirmed by the user), with the tray set to WriteParked. All three
  sub-assertions (OS notification + tray WriteParked + on-disk Failed entry) now hold.
  Note: the retry counter was fast-forwarded to 5 to avoid five real remounts; the per-attempt
  increment and park-at-max transition are independently covered by record_failure + its unit test.

### 3. Mkdir orphan survival

expected: mkdir under a parent with an induced parent-publish conflict; the folder survives an app restart, the parent publishes correctly on retry/replay, and no orphan remains.
result: PASS (crash-before-publish path); live-conflict trigger not artificially induced
evidence: |
  `mkdir C:\Users\<user>\CipherBox\uat3-folder` then immediate `taskkill /F` before the 1.5 s
  debounced publish. The journal held a MkdirPublish entry (5bc7b18e…json, status Pending,
  folder uat3-folder) — mkdir is journaled before the publish. On relaunch:
  `replay_for_vault: MkdirPublish 5bc7b18e… replayed successfully`, the journal entry was removed,
  and uat3-folder is present in the mount as a valid directory after restart — no orphan.
  The specific trigger tested was crash-before-publish (the durability path the journal protects).
  The live in-session MkdirConflict re-arm path (a real IPNS sequence conflict) was not
  artificially induced at runtime; it remains code-verified (D-11a, lib.rs:686-691) only.

### 4. Ciphertext-only journal check

expected: Open any cb-journal/*.json file; it contains only base64/hex ciphertext, wrapped keys, IVs, and IPNS names — never readable file content or plaintext paths.
result: ISSUE (content protected; plaintext filenames/sizes present) — see Gaps
evidence: |
  Inspected real entries created during tests 1–3. File CONTENT is encrypted: `ciphertext_b64`
  is AES-GCM ciphertext (not the known plaintext), `wrapped_key_hex` is ECIES-wrapped, `iv_hex`
  is the IV, and IPNS names/keys are hex/CID strings — all as expected.
  BUT each UploadFile entry stores `"filename":"uat-probe.txt"` and `"size":21` in PLAINTEXT, and
  each MkdirPublish entry stores the folder name (`uat3-folder`) in plaintext. The struct field
  (crates/sdk/src/queue.rs:43-44, doc-commented "Original filename") is written verbatim. The
  D-05 unit test `journal_no_plaintext` (queue.rs:431) only asserts the absence of file CONTENT
  and of the literal keys "plaintext"/"parent_ino" — it does NOT assert filenames are absent.
  So the strict UAT wording "never … plaintext paths" is not met: file/folder NAMES and sizes
  are readable in the on-disk journal (local to the user's device).

## Summary

total: 4
passed: 3
issues: 1
pending: 0
skipped: 0
blocked: 0

## Fixes applied

- **G-43-UAT-01 fix (commits pending): auto-start the sync daemon after mount.** Extracted the
  daemon-spawn logic from the `start_sync_daemon` IPC command into a reusable
  `commands::sync::spawn_sync_daemon(app, &AppState)` and call it from `complete_auth_setup`'s
  mount-success arm (apps/desktop/src-tauri/src/commands/auth.rs). Because every auth flow
  (OAuth, email, session-restore, dev-key test-login) funnels through `complete_auth_setup` and
  it is the only `mount_filesystem` call site, this single point guarantees the daemon runs.
  Verified by retest: daemon start logs appear and the park notification renders (Test 2 PASS).

## Gaps

- **G-43-UAT-01 (RESOLVED — Test 2 now PASS): SyncDaemon was never started.** `start_sync_daemon`
  had no caller (frontend or Rust), so parked writes never surfaced. Fixed by auto-starting the
  daemon from `complete_auth_setup` after a successful mount (see "Fixes applied"). Retest
  confirmed the WriteParked path fires and the OS toast renders.

- **G-43-UAT-02 (Test 4): Journal stores plaintext filenames/folder names and sizes.** File
  content, keys, and IVs are encrypted, but `filename`/folder name and `size` are persisted in
  cleartext in cb-journal/*.json. Triage against the threat model: if local-only plaintext names
  are acceptable, update the D-05 invariant + UAT wording to say "no plaintext file *content*";
  otherwise encrypt the name/size fields. Either way the current behavior contradicts the
  test-as-written.

- **OBSERVATION (from Test 2 setup): a file whose content upload fails (413) is still listed in
  the parent folder.** `uat2-big.bin` appeared in the mount listing even though its content was
  never stored (only the parent metadata published, not the content) — a listed-but-unreadable
  entry. Worth confirming whether parent-listing publish should be gated on content-upload
  success to avoid transient ghost entries.

## Notes

- Build/run friction encountered (environment, not phase-43 code): local API requires Node ≥20.19/≥22
  (jose@6 is ESM-only) — Node was upgraded to 22; stale `packages/*/dist` had to be rebuilt
  (the libp2p-crypto v5 ESM bump broke the old CJS crypto bundle); CORS had to allow the Tauri
  webview origins (http://localhost:1420 + tauri://localhost / tauri.localhost) — added to
  apps/api/.env and .env.example; and the Windows desktop build needs
  `--no-default-features --features winfsp` (default `fuse` feature pulls unix libfuse).

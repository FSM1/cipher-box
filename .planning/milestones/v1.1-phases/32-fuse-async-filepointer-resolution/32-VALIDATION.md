---
phase: 32
slug: fuse-async-filepointer-resolution
status: draft
nyquist_compliant: false
wave_0_complete: true
created: 2026-06-19
---

# Phase 32 — Validation Strategy

> Per-phase validation contract for feedback sampling. Authored retroactively
> (2026-06-19) for an already-shipped phase. Statuses reflect ACTUAL current
> coverage, not pending wave-0 stubs.

---

## Test Infrastructure

| Property               | Value                                            |
| ---------------------- | ------------------------------------------------ |
| **Framework**          | cargo test (Rust workspace)                      |
| **Config file**        | `crates/fuse/Cargo.toml`                         |
| **Quick run command**  | `cargo test -p cipherbox-fuse --features fuse`   |
| **Full suite command** | `cargo test --workspace`                         |
| **E2E command**        | `bash tests/desktop-e2e/scripts/run-all.sh` (CI: `desktop-e2e.yml`) |
| **Estimated runtime**  | ~30 seconds (unit) · several minutes (E2E)       |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p cipherbox-fuse --features fuse`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full unit suite green; desktop E2E green on main push
- **Max feedback latency:** 30 seconds (unit tier)

---

## Per-Task / Per-SC Verification Map

| Task ID  | Plan | SC   | Requirement                                                                 | Test Type   | Automated Command                                                  | File Exists                                                  | Status  |
| -------- | ---- | ---- | -------------------------------------------------------------------------- | ----------- | ----------------------------------------------------------------- | ----------------------------------------------------------- | ------- |
| 32-01-01 | 01   | SC-1 | `PendingFilePointer` channel + dedup-guard infrastructure on `CipherBoxFS` | unit        | `cargo test -p cipherbox-fuse --features fuse`                     | No direct test (compile-gated; symbols exist in lib.rs)     | partial |
| 32-01-02 | 01   | SC-1 | `drain_filepointer_completions()` applies resolved metadata to inodes      | unit        | `cargo test -p cipherbox-fuse --features fuse inode::tests`        | Indirect: `inode::tests::test_populate_folder_resets_resolved_file_on_modified_at_change` exercises `resolve_file_pointer` (the inode mutation the drain invokes) | partial |
| 32-02-01 | 02   | SC-1 | `drain_refresh_completions` spawns async resolution via `rt.spawn` (no block_with_timeout) | integration | `bash tests/desktop-e2e/scripts/test-cross-client-sync.sh`        | Yes: `test-cross-client-sync.sh` drives the refresh→re-resolve path | green   |
| 32-02-02 | 02   | SC-1 | Resolution scoped per-parent via `get_unresolved_file_pointers_for_parent` | unit        | `cargo test -p cipherbox-fuse --features fuse`                     | No direct test of the scoping helper                        | missing |
| 32-03-01 | 03   | SC-2 | Finder ls/open/read/copy do not stall during background refresh           | manual / E2E | `bash tests/desktop-e2e/scripts/test-fuse-operations.sh`          | E2E exercises create/read/overwrite/nested; stall-during-refresh is UX | manual  |
| 32-03-02 | 03   | SC-3 | Resolution latency bounded by timeout (`FILEPOINTER_POLL_TIMEOUT` 5s, `NETWORK_TIMEOUT` 10s) not O(N*network) | unit        | `cargo test -p cipherbox-fuse --features fuse`                     | No direct test asserting the bound                          | missing |
| 32-03-03 | 03   | SC-3 | open/read poll-wait fallback returns EIO on poll-timeout miss             | unit        | `cargo test -p cipherbox-fuse --features fuse read_ops`            | No test module in `read_ops.rs`                             | missing |
| 32-04-01 | —    | SC-4 | Desktop E2E passes with the async resolution path                          | integration | `bash tests/desktop-e2e/scripts/run-all.sh` (CI `desktop-e2e.yml`) | Yes: full E2E suite incl. cross-client-sync runs on main push | green   |

_Status: pending · green · red · flaky · partial · missing · manual_

---

## Coverage Detail by Success Criterion

### SC-1 — Async dispatch via channel pair (no blocking FUSE thread)

- **Implementation present:** `PendingFilePointer` enum (`crates/fuse/src/lib.rs:99`),
  `filepointer_tx`/`filepointer_rx`/`resolving_file_pointers` fields
  (`lib.rs:918-920`), `drain_filepointer_completions()` (`lib.rs:1351`), and
  `drain_refresh_completions` spawning via `rt.spawn` with the dedup guard
  (`lib.rs:1249-1278`).
- **Automated coverage:** PARTIAL. The inode mutation the drain applies
  (`InodeTable::resolve_file_pointer`) is unit-tested by
  `inode::tests::test_populate_folder_resets_resolved_file_on_modified_at_change`.
  The drain method, dedup-guard insert/remove, and the channel round-trip have no
  dedicated unit test. The end-to-end async re-resolution flow IS exercised by
  the `test-cross-client-sync.sh` E2E scenario (edits a file via SDK, then loops
  `ls`/`cat` on the mount until the FUSE side re-resolves the FilePointer to the
  new CID — the exact async path).

### SC-2 — Finder operations do not stall during refresh

- **Automated coverage:** MANUAL / E2E. `test-fuse-operations.sh` validates
  create/read/overwrite/mkdir/nested/binary round-trip succeed on the live mount.
  "Does not stall during background metadata refresh" is a UX/timing property of
  Finder against a mounted volume and is not asserted by an automated timing
  probe. Listed Manual-Only.

### SC-3 — Latency bounded by timeout

- **Implementation present:** `FILEPOINTER_POLL_TIMEOUT = 5s` /
  `FILEPOINTER_POLL_INTERVAL = 100ms` (`read_ops.rs:19-20`); per-task
  `NETWORK_TIMEOUT` (10s) replaces the prior O(N*10s) sequential block.
- **Automated coverage:** MISSING. No unit test asserts the poll deadline, the
  EIO-on-miss fallback, or that concurrent spawns bound total latency. `read_ops.rs`
  has no test module.

### SC-4 — Desktop E2E passes with async path

- **Automated coverage:** GREEN. `desktop-e2e.yml` runs `run-all.sh` on
  macOS/Linux/Windows (main push), which includes the cross-client-sync scenario
  that depends on the async resolution path completing correctly.

---

## Wave 0 Requirements (retroactive — no outstanding stubs)

This phase shipped before adopting wave-0 stub discipline; `wave_0_complete: true`
records that there are no outstanding wave-0 stubs to author. The following unit
tests WOULD close the open gaps and are recommended (not yet present):

- [ ] `lib.rs` test: `drain_filepointer_completions` applies a `Success` message
      to an inode and clears the dedup guard; a `Failure` message clears the guard
      without mutating the inode. (closes SC-1 partial → green)
- [ ] `inode.rs` test: `get_unresolved_file_pointers_for_parent` returns only the
      empty-CID children of the given parent. (closes 32-02-02 missing)
- [ ] `read_ops.rs` test: poll-wait returns the resolved attrs when a `Success`
      arrives before the deadline, and returns EIO when it does not. (closes SC-3)

---

## Manual-Only Verifications

| Behavior                                       | Requirement | Why Manual                                              | Test Instructions                                                                                          |
| ---------------------------------------------- | ----------- | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| Finder does not stall/disconnect during refresh| SC-2        | Requires Finder + live mounted FUSE volume + IPNS poll | Mount FUSE drive, trigger a 30s metadata-refresh cycle while running `ls`/open/copy in Finder; verify no "connection lost" and operations stay responsive |
| Resolution latency feels bounded               | SC-3        | Requires real IPNS/IPFS resolution latency             | Mount a folder with many unresolved FilePointers; `ls` and confirm the callback returns promptly (sub-second) while resolution proceeds in background |

_Desktop E2E (`test-cross-client-sync.sh`, `test-fuse-operations.sh`) covers
automated regression of the async path; the above checks verify the UX property._

---

## Validation Sign-Off

- [x] Implementation present for all four success criteria (symbols enumerated above)
- [x] SC-1 (end-to-end) and SC-4 covered by desktop E2E (`run-all.sh` / `desktop-e2e.yml`)
- [x] SC-1 inode-application step covered by `inode.rs` unit test
- [ ] SC-1 drain/dedup, SC-2 scoping helper, SC-3 timeout/EIO have direct automated unit tests
- [x] No watch-mode flags
- [ ] `nyquist_compliant: true` — NOT set; direct unit coverage absent for SC-1 drain/dedup and all of SC-3

**Approval:** draft — retroactive documentation pass. Not nyquist-compliant: the
async drain/dedup logic (SC-1) and the timeout-bounded poll-wait/EIO fallback
(SC-3) rely solely on desktop E2E (main-push only) plus one indirect inode unit
test; they lack the fast-feedback unit tests the contract requires.

## Validation Audit 2026-06-19

| Metric        | Count |
| ------------- | ----- |
| Success criteria | 4  |
| Covered (green)  | 2  (SC-1 end-to-end via E2E, SC-4) |
| Partial          | 1  (SC-1 unit tier — inode-application only) |
| Missing          | 1  (SC-3 — no timeout/EIO/poll-wait unit test) |
| Manual-only      | 1  (SC-2) |
| Map rows green   | 2/8 |
| Map rows partial | 2/8 |
| Map rows missing | 3/8 |
| Map rows manual  | 1/8 |

Audit notes: Retroactive documentation pass on a docs branch — STATIC ANALYSIS
ONLY, no suites executed. Implementation for all four SCs verified by symbol
enumeration: `PendingFilePointer`/`drain_filepointer_completions`/dedup guard
(`crates/fuse/src/lib.rs`), `resolve_file_pointer` +
`get_unresolved_file_pointers_for_parent` (`crates/fuse/src/inode.rs`), poll-wait
constants and EIO fallback (`crates/fuse/src/read_ops.rs`). The async
re-resolution flow is genuinely exercised by `tests/desktop-e2e/scripts/test-cross-client-sync.sh`
(SC-1 end-to-end + SC-4). However, the `crates/fuse` unit tier has NO test that
directly targets `drain_filepointer_completions`, the `resolving_file_pointers`
dedup guard, `get_unresolved_file_pointers_for_parent`, or the
`FILEPOINTER_POLL_TIMEOUT`/EIO poll-wait path — `read_ops.rs`/`dir_ops.rs` have no
test modules at all. SC-1 is therefore PARTIAL at the unit tier (only the inode
mutation `resolve_file_pointer` is unit-covered) and SC-3 is MISSING. Because
fast-feedback unit coverage is absent for SC-1 drain/dedup and all of SC-3, and
desktop E2E runs only on main push, `nyquist_compliant` is honestly set to
`false` and status remains `draft`. Three recommended Wave-0 unit tests are
listed above to reach compliance.

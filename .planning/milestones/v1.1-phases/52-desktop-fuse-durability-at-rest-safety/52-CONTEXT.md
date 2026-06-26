# Phase 52: Desktop FUSE Durability & At-Rest Safety - Context

**Gathered:** 2026-06-19
**Status:** Ready for planning
**Source:** Discuss-phase. Scope is one re-verified captured todo (#9) under requirement HARD-03 —
the open warnings from the Phase 43 FUSE-write-durability review (criticals already fixed; phases
45/46 closed most warnings). Four implementation forks discussed and locked; two trivial items
pre-locked by the todo.

<domain>

## Phase Boundary

Harden the desktop FUSE write-journal and its replay path under requirement **HARD-03**. All work is
Rust in the shared `crates/sdk` + `crates/fuse` (and the desktop Tauri shell), so fixes are
cross-platform: the same code blocks the single FUSE callback thread on macOS/Linux and runs under
the global WinFsp mutex on Windows.

In scope (todo #9, re-verified 2026-06-18, post phases 45/46):

- **WR-06 (high)** — Each `UploadFile` journal entry embeds the entire file ciphertext as base64
  inside the JSON (`crates/sdk/src/queue.rs:36`). A 2 GB file → ~2.7 GB `serde_json` allocation +
  multi-GB write + `F_FULLFSYNC` on the shared FS thread → blocks the whole filesystem and can OOM.
  No size cap, no GC of parked `Failed` entries, and other vaults' entries persist forever (shared
  journal dir, only filtered).
- **WR-07 (med)** — `replay_for_vault` awaits raw `resolve_ipns` / `fetch_content` /
  `upload_content` per entry with no `NETWORK_TIMEOUT` discipline, and runs BEFORE mount
  (`apps/desktop/src-tauri/src/fuse/mod.rs:278`) → a hung link stalls the mount indefinitely.
- **IN-03 (low)** — plaintext `filename`/`name` persisted in journal JSON (`crates/sdk/src/queue.rs:62`).
- **IN-04 (low)** — `sanitize_error` only scrubs `/Users/` and `/home/` (`crates/sdk/src/sync.rs:271`).
- **IN-05 (low)** — `let _ = journal.remove(...)` swallows removal errors (`crates/fuse/src/lib.rs:1494,:1558`;
  `write_ops.rs:679`) → silent later replay / double-publish risk.

Out of scope: the HARD-02 / HARD-04..06 items (Phases 51, 53–55); any redesign of the journal
format beyond what these fixes require; and the desktop-fuse data-loss bugs already closed in Phase
46. This phase pays down the Phase 43 review warnings only.

</domain>

<decisions>

## Implementation Decisions

### WR-06 — Large-file journal write path

- **D-01 (WR-06, fork):** **Sidecar + off-thread.** Store ciphertext in a sidecar `<id>.bin`
  streamed to disk; the JSON entry holds only the path + hash (+ size). Perform the heavy write +
  `F_FULLFSYNC` **off the shared FS callback thread** (background/journal-writer task) so concurrent
  filesystem operations are never blocked. The originating `release()` must STILL await its own
  entry's durability before acking — do not reintroduce the Phase-43 false-durability-ack bug.
  Add a per-entry payload size cap. (Eliminates both the OOM/2.7 GB allocation and the FS-thread
  stall.)

### Journal retention / GC

- **D-02 (GC, fork):** **GC + logout + cross-vault purge.** Add age + size-budget GC of parked
  `Failed` entries; purge the current vault's entries on logout; and purge a vault's entries on
  account switch / account deletion — closing the cross-vault leak (today the shared journal dir is
  only filtered, never cleaned). The planner proposes concrete default caps (age window + total-size
  budget) consistent with existing desktop constants.

### WR-07 — Replay durability

- **D-03 (WR-07, fork):** **Timeout + concurrent with mount.** Wrap each entry's network ops in a
  `tokio::time::timeout` (mirror the `NETWORK_TIMEOUT` discipline used elsewhere in the desktop
  stack, with a sensible multiplier for large uploads) AND run replay concurrently with mount so the
  mount returns immediately and never waits on replay. A hung entry can neither stall the mount nor
  spin forever.

### IN-03 — At-rest journaled names

- **D-04 (IN-03, fork):** **Omit the plaintext name if replay doesn't need it.** During planning,
  determine whether replay can reconstruct the name from `FileMetadata` / the entry's path. If it
  can, drop the plaintext `filename`/`name` from the journal entry entirely (leak-free, simplest).
  **Fallback:** if the name IS required for replay, encrypt it in the entry instead (the key is
  available at write/replay time). Either way, no plaintext item name persists at rest.

### Locked by the todo (no fork)

- **D-05 (IN-04):** Extend `sanitize_error`'s scrub list beyond `/Users/` and `/home/` to cover
  `C:\Users\…` (drive-letter pattern), `/var`, `/tmp`, `/private` so paths don't leak into
  tray/notification copy.
- **D-06 (IN-05):** Replace `let _ = journal.remove(...)` with `log::warn!` on removal errors at
  `crates/fuse/src/lib.rs:1494,:1558` and `write_ops.rs:679`, so a failed removal can't silently
  cause a later replay / double-publish.

### Suggested sequencing (planner may refine)

WR-06 (the high-severity blocker, biggest change) → WR-07 (replay) → IN-03 (names) → IN-04/IN-05
(trivial, can land alongside any of the above).

### Folded Todos

- **[#9]** `2026-06-18-fuse-journal-growth-and-replay-timeout.md` — WR-06/WR-07 + IN-03/04/05
  (re-verified 2026-06-18, post phases 45/46). Maps to D-01..D-06.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & source findings

- `.planning/todos/pending/2026-06-18-fuse-journal-growth-and-replay-timeout.md` — todo #9 with
  current line numbers, fixes, and acceptance. The primary ref.
- `.planning/phases/43-fuse-write-durability/43-REVIEW.md` — origin of WR-06/WR-07 and IN-03/04/05
  (criticals fixed 2026-06-14; these warnings remain).
- `.planning/REQUIREMENTS.md` — HARD-03.
- `.planning/ROADMAP.md` §"Phase 52" — scope checkboxes.

### Journal / write path (WR-06, GC, IN-03, IN-05)

- `crates/sdk/src/queue.rs` — journal entry struct: ciphertext-in-JSON (`:36`), plaintext name
  (`:62`). WriteQueue is the home for the sidecar + GC + size-cap work.
- `crates/fuse/src/lib.rs` (`:1494`, `:1558`) and `crates/fuse/src/write_ops.rs` (`:679`) — swallowed
  `journal.remove(...)` errors (IN-05).
- `crates/fuse/src/read_ops.rs` — referenced in the todo's file list; relevant to journal/sidecar
  reads.

### Replay (WR-07)

- `apps/desktop/src-tauri/src/fuse/mod.rs` (`:278`) — `replay_for_vault`; add timeout + run
  concurrently with mount.
- Mirror the existing `NETWORK_TIMEOUT` pattern used elsewhere in the desktop stack (researcher to
  locate the canonical definition/usages).

### Error scrubbing (IN-04)

- `crates/sdk/src/sync.rs` (`:271`) — `sanitize_error` prefix list.

### Background

- `docs/FILESYSTEM_SPECIFICATION.md` — FUSE write/durability model and journal semantics.

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- The `NETWORK_TIMEOUT` discipline already used elsewhere in the desktop stack is the pattern to
  mirror for WR-07 — wrap replay ops the same way rather than inventing a new timeout scheme.
- Phase 43/45/46 already built the durable write-journal + crash-recovery replay; this phase hardens
  that existing machinery (sidecar/GC/timeout/scrub), it does not rebuild it.

### Established Patterns

- Single FUSE callback thread (macOS/Linux) / global WinFsp mutex (Windows) — any synchronous heavy
  work on the journal path blocks the WHOLE filesystem; D-01's off-thread requirement follows from
  this.
- Durable-ack contract from Phase 43: `release()` must not ack until the write is durable. D-01's
  off-thread write must preserve this — the originating call still awaits its own entry's fsync.
- Journal dir is shared across vaults and only filtered at read time — the source of the cross-vault
  retention leak D-02 closes.

### Integration Points

- WR-06 changes the on-disk journal entry shape (ciphertext → sidecar path+hash; name omitted or
  encrypted). Replay (`replay_for_vault`) and any journal reader must be updated in lockstep, and
  crash-recovery of in-flight entries must handle the new shape.
- GC + logout/account-switch purge hook into the desktop session lifecycle (login/logout/account
  switch) in the Tauri shell + `crates/sdk`.

</code_context>

<specifics>

## Specific Ideas

- D-04 is conditional: planning must first establish whether replay needs the plaintext name. Prefer
  omission; encryption is the fallback. Record which path was taken in the plan.

</specifics>

<deferred>

## Deferred Ideas

None — discussion stayed within phase scope (the FUSE-journal review warnings).

</deferred>

---

_Phase: 52-desktop-fuse-durability-at-rest-safety_
_Context gathered: 2026-06-19_

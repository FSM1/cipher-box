# ADR 0040 — The FUSE projection seals its spill files and never logs a name

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#736,
  FSM1/cipher-box#898, FSM1/cipher-box#1156, FSM1/cipher-box#1478, FSM1/cipher-box#1511 and
  FSM1/cipher-box#1577, and the blueprint carries it. This ADR also corrects three
  `blueprint/desktop.md` sentences to match the code (Consequence 5); the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:** [#32](https://github.com/FSM1/cipher-box-next/issues/32) (the macOS driver
  research: FUSE-T on the SMB backend, the push-invalidation callback, the hardware gates),
  [#46](https://github.com/FSM1/cipher-box-next/issues/46) (the desktop blueprint: the
  projection doctrine and the sealed spill file),
  [#33](https://github.com/FSM1/cipher-box-next/issues/33) D2 (the FUSE-op TTL check is the
  desktop trigger source) and D6 (the staging budget fails fast, which is `ENOSPC`),
  [#47](https://github.com/FSM1/cipher-box-next/issues/47) (law 1 and the `FUSE Op Core` gate),
  [ADR 0018](./0018-the-pr-gate-is-grouped-by-area-with-an-adapter-leg-per-desktop-platform.md)
  (the `FUSE Op Core` job in the Rust area and the macOS adapter leg), the `blueprint/desktop.md`
  sections "Component map", "Backends", "Reads, writes, and the never-block law", "Freshness —
  the desktop trigger source" and "Open edges", the `blueprint/testing.md` bullet "`crates/fuse`
  operation core (`FUSE Op Core`)", and the `CONTEXT.md` terms "Focus window", "Sync timing
  profile" and "Op queue"
- **Implemented by:** FSM1/cipher-box#736 (D1, the hardware gates), FSM1/cipher-box#898 (D2),
  FSM1/cipher-box#1156 (D3), FSM1/cipher-box#1478 (D4, the `getattr` trigger),
  FSM1/cipher-box#1785 and FSM1/cipher-box#1802 (D4, the folder-in-view and `lookup` triggers),
  FSM1/cipher-box#1511 (D4, the accepted exposure) and FSM1/cipher-box#1577 (D5)

## Context

The desktop app mounts the vault as a local filesystem. `crates/fuse` is the projection: one
operation core behind a host-adapter trait, with one adapter per mount technology (FUSE-T on
macOS, kernel FUSE through the vendored `fuser` on Linux, WinFsp on Windows). The desktop
blueprint (#46) makes the projection key-free and brain-free. Every trust and sync decision
happens below the engine facade. The mount is the plaintext terminus for the local OS, so the
projection is the one component that holds plaintext names and plaintext bytes in the clear.
Five rules keep that plaintext, and the freshness of what the kernel shows, inside the bounds
the rest of the system sets. Each one came from a defect or a measurement, not from a thread.

**The FUSE-T cache.** #32 chose FUSE-T 1.2.7 on its SMB backend, because the SMB backend is the
only FUSE-T configuration where push invalidation works. It asked for a hardware check before
the build. FSM1/cipher-box#736 ran the five gates on 2026-07-22 (`tools/hw-gates/RESULTS.md`).
Gate 1 passed only with the `noattrcache` mount option. Without it, the smbfs client holds
attributes for a 3 s floor and keeps data it has cached with no limit. The same gate showed
that the smbfs client ignores the TTLs in a FUSE reply. A kernel TTL constant therefore has no
effect on this backend, and push invalidation is the only path by which a remote change reaches
the kernel. `crates/fuse/src/adapters/macos.rs` states the cost of a mistake: a mount that
lands on the NFS backend, or that misses one invalidation, shows a revoked or stale vault with
no end.

**The over-quota errno.** v1 returned no honest errno for a refused write. The first desktop
blueprint mapped the staging-budget refusal and a hosted-quota refusal both to `ENOSPC`.
`ENOSPC` tells the member to free space on this device. That does nothing when the account
quota is the constraint. The map resolution on FSM1/cipher-box#841 (2026-07-28) made the engine
say which budget refused, and named `EDQUOT` as the honest errno for the account. The engine
side and the errno split landed in FSM1/cipher-box#898.

**The spill file.** v1 buffered kernel writes in plaintext temp files (`cb-write-*`) and
zero-overwrote them on cleanup. A crash left user plaintext on disk. #46 replaced them with a
sealed spill file under an ephemeral in-memory key. The same blueprint also said that
`crates/fuse` depends on the engine facade only, with no direct use of `crates/core`. The two
statements contradict each other: the FS core cannot seal a spill file without an AEAD, and the
facade exposes none. FSM1/cipher-box#1156 built the write path, sealed the spill with the
`crates/core` AEAD, and narrowed the dependency statement to allow that one use.

**The file leg of the focus window.** FSM1/cipher-box#1415 reported that a file another device
republished kept its old size in the mount until something opened it. The cause was structural.
A version publish does not change the parent record, and a child ref mirrors no size or mtime.
Only the file's own record carries them, and no tick leg resolved a file's own record.
FSM1/cipher-box#1478 made `getattr` on a file put that file in view, on a queue the tick drains
under a per-pass ceiling. FSM1/cipher-box#1511 then stated the privacy cost in the blueprint: a
listing now resolves the records of its children together, and that co-resolution tells a
routing endpoint which names share a folder.

**The name in a log line.** FSM1/cipher-box#1428 found that the default `Filesystem` trait
bodies in the vendored `fuser` log each unimplemented operation at `warn!`, with the caller's
name in the line. Some of these bodies are reachable: `mknod`, `symlink`, `link`, the xattr
trio, and on macOS `exchange` and `setvolname`. In a zero-knowledge vault a file, link or xattr
name is user plaintext. A mount at `RUST_LOG=warn` would write vault contents to the log. The
issue weighed two shapes and chose neither. FSM1/cipher-box#1577 chose redaction inside the
vendored crate, and its review found the same leak one layer down, in the `Display` and `Debug`
renders of a request.

The blueprint carries the five rules today: `blueprint/desktop.md` "Component map", "Backends",
"Reads, writes, and the never-block law", "Freshness — the desktop trigger source" and "Open
edges", and `blueprint/testing.md` "`crates/fuse` operation core (`FUSE Op Core`)". Three
`desktop.md` sentences state D3 and D4 wider or narrower than the code. The "Doctrine" says that
the FS layer holds no keys, but it holds the spill key. The "Component map" says that the AEAD is
the one direct use of `crates/core`, but `crates/fuse` also imports a redaction type from it.
The "Freshness" bullet names `getattr` as the only trigger of the burst, but a folder in view and
a `lookup` also trigger it. This ADR decides the rules as the code implements them and corrects
the three sentences.

## Decision

**D1 — The FUSE-T SMB mount sets `noattrcache`, and every remote change fires push
invalidation.** The macOS mount selects the SMB backend and always passes the `noattrcache`
option. When a background reconcile lands a snapshot that changes a node the kernel can hold,
the engine event stream drives the push-invalidation callback, and the adapter maps it to the
SMB-backend invalidation for that inode's data, attributes or entries. The FUSE-T SMB backend
has no kernel TTL constant: the smbfs client ignores FUSE reply TTLs, so `noattrcache` and push
invalidation replace the TTL on this backend. The rule landed with FSM1/cipher-box#736, on the
evidence of hardware gate 1 in `tools/hw-gates/RESULTS.md`; this ADR records it.

**D2 — A hosted-quota refusal returns `EDQUOT`.** The engine reports which budget refused a
write (`OverBudgetCause`, and `RefusedBudget` for the host). A refusal of the account's hosted
quota maps to `EDQUOT` at every POSIX mount. It never collapses into `ENOSPC`, which stays the
errno for the device's staging budget (#33 D6 and #46 carry that half). The rule was decided on
2026-07-28 in FSM1/cipher-box#841, a resolution under the FSM1/cipher-box#813 map, and landed
with FSM1/cipher-box#898. FSM1/cipher-box#841 decided a fourth over-budget rejection reason,
"the backlog is blocked on account quota", mapped to `EDQUOT`. The code meets that decision with
the start-of-write pre-flight: `pre_flight_quota_check` refuses the write and the facade returns
`OverBudgetCause::AccountQuota` (`crates/engine/src/facade.rs:10851`-`10857`). A quota hold on
the drain never refuses a later write. This ADR accepts the pre-flight as the way the decision
is met (E4).

**D3 — `crates/fuse` seals each spill file under the `crates/core` AEAD, and that AEAD is its
one cryptographic use of `crates/core`.** A kernel write lands in a per-handle spill file in the
engine data dir. The file is sealed with XChaCha20-Poly1305 from `crates/core` under a random
per-handle key. The key is held only in process memory, is never persisted and never logged,
and is zeroized when the handle ends. A crash leaves ciphertext whose key died with the
process, so a spill is deleted, not overwritten. The spill key is the one key the FS layer
holds. `crates/fuse` implements no cryptography of its own, and it calls no other cryptography
in `crates/core`. It depends on the engine facade for everything else. Its one other import from
`crates/core` is `cipherbox_core::codec::RedactedText` (`crates/fuse/src/adapter.rs:10`,
`crates/fuse/src/ops.rs:15`), which renders a name as its length in a `Debug` render and is not
cryptography. The spill key is not in the KDF catalog, touches no wire format, and never leaves the
process. The rule landed with FSM1/cipher-box#1156; this ADR records it.

**D4 — `getattr` on a file, a folder in view and a `lookup` of a size-less file put files in
view; `MAX_FOCUS_FILES` bounds the burst per tick; the sibling-set exposure is accepted.** A
`getattr` on a file puts the file itself, not its parent, into the focus window's on-access file
queue. The tick also queues every file child that projects no size of a folder in view, and a
stale access to a folder queues the same children (`queue_unprojected_children` and
`note_focus_access` in `crates/engine/src/facade.rs`, since FSM1/cipher-box#1785 and
FSM1/cipher-box#1802). A `lookup` that returns a file with no projected size queues that file
(`crates/fuse/src/ops.rs`). The next tick resolves each queued file's own record, so a size or
mtime another device published reaches the mount with no open. A listing therefore produces a
correlated burst of per-child record resolves, inside one tick: one for each entry the host
stats that is also past the staleness threshold, and one for each size-less file child of the
folder in view, with no stat at all. `MAX_FOCUS_FILES` bounds the
burst per tick (64 today, in `crates/engine/src/facade.rs`). An entry the bound evicts
unresolved is queued again on the next stat, so across a browsing session the full sibling set
of a large folder still reaches the endpoints. This is a new exposure. Child `ipnsName`s ride
the parent's sealed read-body, so co-resolution is the one signal that gives a routing endpoint
a sibling-set fingerprint: a durable link of names to a common folder, and at the CipherBox
accelerator a link to an identity. Names, kinds, sizes and bodies stay sealed. The exposure is
accepted. The bound limits the rate, not the exposure. The `getattr` trigger landed with
FSM1/cipher-box#1478, the folder-in-view and `lookup` triggers with FSM1/cipher-box#1785 and
FSM1/cipher-box#1802, and FSM1/cipher-box#1511 stated the exposure; this ADR records all of them.

**D5 — No default `Filesystem` body in the vendored `fuser` writes a name to a log record, and
the `FUSE Op Core` job asserts it.** A file, link or xattr name is user plaintext. Every site in
the vendored `fuser` that formats such a name, in a default trait body, in the `Display` or
`Debug` of `Operation` or `AnyRequest`, or in the `Debug` of `FilenameInDir`, formats it through
one `redacted` wrapper in `third-party/fuser/src/redact.rs`. The wrapper renders the byte length
and nothing else, in `Display` and in `Debug` alike, so no format mode that a call site picks
can select a second render path. The `Debug` of a name-bearing request payload prints its type
and no field (`opaque_debug`, in the same module). The redaction is one module, and a re-vendor
re-applies it with the socket-read and two-lifetime patches (`third-party/fuser/Cargo.toml`).
The `FUSE Op Core` job runs the vendored crate's tests on Linux, so a revert of any one
redaction that Linux compiles blocks a merge. The gate itself is #47 law 1 and ADR 0018; the
assertion is this rule. The rule landed with FSM1/cipher-box#1577; this ADR records it.

## Trust argument

- **A remote change cannot stay invisible on macOS (D1).** With `noattrcache`, the smbfs client
  keeps no attribute floor, and gate 1 measured coherence under 5 ms at p95 with push
  invalidation. The mount profile declares push invalidation, and the SMB backend is the one
  FUSE-T backend that serves it, so the capability claim and the backend choice are one fact. A
  revoked grant or a newer version reaches the kernel on the event that lands it.
- **The errno sends the member to the right machine (D2).** `EDQUOT` says that the account is
  full. `ENOSPC` says that this device is full. Each points at a remedy that works. The split
  comes from the engine's own classification, not from a guess in the adapter: only the
  command-time quota pre-flight (`pre_flight_quota_check` in
  `crates/engine/src/content/retention.rs`) produces `OverBudgetCause::AccountQuota`.
- **A crash leaves no plaintext on disk (D3).** The key never touches disk, so the spill bytes
  that survive a crash cannot be opened. `SpillArea` sweeps a previous run's debris when it
  opens. Each block seals with the block index in the AAD, so a slot moved to another offset
  fails to open. Nonces are a per-file counter under a fresh key, and the counter refuses to
  wrap. `SpillArea::production` takes the OS CSPRNG and no injected source, because a replayed
  source repeats a key and every nonce under it (`crates/fuse/src/spill.rs`).
- **The AEAD exception adds no crypto surface (D3).** `crates/fuse` calls the one audited AEAD
  in `crates/core` and implements none. The key derives from nothing in the KDF catalog and
  crosses no wire, so the KAT regime and the catalog do not change.
- **The file leg adds no trust decision (D4).** The file leg resolves through the same gate and
  verdict handling as the folder leg (`resolve_focused` in `crates/engine/src/net/focus.rs`),
  so a kind transplant is still a trust violation and a lagged epoch still costs the pass
  nothing. The projection only reports which node an operation was about.
- **The exposure is bounded in rate and named (D4).** No name, kind, size or body leaves the
  seal. What an endpoint learns is which record names a listing resolves together. The
  blueprint names this cost, so a later privacy change starts from a stated baseline.
- **No log sink receives a name from the vendored crate (D5).** A name reaches a log or a render
  only through `redacted`, which prints a length. The request payloads print their type and no
  field. The tests drive every default body that takes a name through a capturing logger and
  render a parsed request in all four format calls.

## Alternatives rejected

**(a) The FUSE-T NFS backend, or macFUSE (D1).** #32 rejected both. The NFS backend serves no
notifications, and attribute churn can panic Apple's NFS kext. macFUSE needs a kext install
with reduced security on Apple Silicon, and `fuser` has an unresolved rename-ABI divergence
from macFUSE 5.

**(b) Short kernel TTLs in place of `noattrcache` (D1).** Gate 1 showed that the smbfs client
ignores FUSE reply TTLs. A TTL has no effect on this backend.

**(c) One errno for both budgets (D2).** This is the v1 and first-blueprint shape. It tells a
member whose account is full to free space on the device, which does not help.

**(d) Host composition of the quota cause (D2).** FSM1/cipher-box#841 rejected a reuse of the
"transient backlog" reason joined by each host with the separate `Blocked` state. Both
platforms would derive one rule again, one of them would turn it into an errno, and the message
would be false until a host overrode it.

**(e) Plaintext write buffers with a zero-overwrite cleanup (D3).** This is v1. A crash leaves
plaintext on disk, and the overwrite only hides what a sealed spill closes by construction.

**(f) A slot generation in the spill AAD (D3).** FSM1/cipher-box#1156 rejected it. It defends
only against an attacker who can write the `0600` spill file. That attacker can read the
plaintext from the mount or from the process, because the local uid is not a boundary this
system defends.

**(g) Put the parent in view on a file `getattr` (D4).** This was the shape before
FSM1/cipher-box#1478. The parent's record does not carry a child's size or mtime, so the
refresh changed everything about the file except what `getattr` returns.

**(h) Implement the reachable methods in the adapter so that no default body runs (D5).**
FSM1/cipher-box#1428 offered this shape. It leaves the `Display` and `Debug` renders of a
request, which print the name whichever body runs. It also has to grow with each operation the
adapter does not override. One redaction module in the vendored crate closes both paths.

**(i) A fixed marker in place of the byte length (D5).** FSM1/cipher-box#1577 rejected it. A
length names no file, and the marker would drop the one diagnostic the line still carries.

## Consequences

1. **`blueprint/desktop.md` already carries D1 and D2, and most of D3 and D4.** The
   "Backends" table (invalidation row), the last bullet of "Freshness — the desktop trigger
   source" and the "Kernel TTL values per backend" open edge carry D1. The "statfs" bullet of
   "Reads, writes, and the never-block law" carries D2. The "write" bullet carries the spill seal
   of D3. The `getattr` bullet of "Freshness — the desktop trigger source" carries the `getattr`
   trigger, the bound and the exposure of D4. Consequence 5 lists the three sentences this ADR
   corrects.

2. **`blueprint/testing.md` already carries D5.** The "`crates/fuse` operation core (`FUSE Op
Core`)" bullet states the assertion.

3. **`CONTEXT.md` already carries the terms.** "Focus window" (everything outside the window
   refreshes on access, which is the file leg of D4), "Sync timing profile" (the staleness
   threshold D4 compares against) and "Op queue" (the journal a spill commits into).

4. **The first desktop blueprint of #46 reads with the D3 exception.** Its "Depends on the
   engine facade only — no direct core, transport, or API access" now reads "the facade only,
   except the `crates/core` AEAD the spill file seals under". No ADR amend is needed, because #46
   is a thread.

5. **`blueprint/desktop.md` changes when this ADR is accepted.** Three sentences are corrected:
   - Section "Doctrine": "it holds no keys, no publish machinery, …" becomes "it holds no key
     except the spill key of its own writes (ADR 0040), no publish machinery, …".
   - Section "Component map", the `crates/fuse` entry: "the one direct use of `crates/core` is
     the AEAD the spill file seals under" becomes "the one cryptographic use of `crates/core` is
     the AEAD the spill file seals under (ADR 0040)".
   - Section "Freshness — the desktop trigger source", the `getattr` bullet, gains: "A folder in
     view also queues every file child that projects no size, and a `lookup` that returns such a
     file queues it, so a listing emits the burst with no stat at all; the same
     `MAX_FOCUS_FILES` bound charges it (ADR 0040)."

6. **Citations the blueprint gains:**
   - `blueprint/desktop.md` section "Backends" gains the citation (ADR 0040) at the invalidation
     row, and section "Freshness — the desktop trigger source" gains it at the `noattrcache`
     bullet.
   - `blueprint/desktop.md` section "Reads, writes, and the never-block law" gains the citation
     (ADR 0040) at the "write" and "statfs" bullets.
   - `blueprint/testing.md` section "`crates/fuse` operation core (`FUSE Op Core`)" gains the
     citation (ADR 0040) at the no-name-in-log sentence.

## Residuals

**E1 — The blueprint named only one trigger of the D4 burst.** Since FSM1/cipher-box#1785 and
FSM1/cipher-box#1802, the tick queues every file child of a folder in view that projects no
size (`queue_unprojected_children` in `crates/engine/src/facade.rs`), a stale access to a folder
queues the same children (`note_focus_access`), and a `lookup` that returns a size-less file
queues it (`crates/fuse/src/ops.rs`). A listing therefore emits the burst with no `getattr` at
all. The exposure is the same class, and the same `MAX_FOCUS_FILES` bound charges it per pass.
D4 decides all three triggers, and this ADR adds the sentence for them to the "Freshness" bullet
(Consequence 5).

**E2 — The blueprint's statements on keys and on `crates/core` did not match the code in two
places.** The "Doctrine" section said that the FS layer holds no keys, but the spill key of D3
lives in FS memory; the "write" bullet ("held only in engine/FS memory") was the precise
statement. The "Component map" said that the AEAD is the one direct use of `crates/core`, but
`crates/fuse/src/adapter.rs` and `crates/fuse/src/ops.rs` also import
`cipherbox_core::codec::RedactedText` for their `Debug` renders. That use is not cryptography,
and it does not weaken D3. D3 decides the narrower rule, "the one cryptographic use", and this
ADR corrects both sentences (Consequence 5). What stays open: no lint holds `crates/fuse` to the
AEAD as its one cryptographic import (Gate, D3).

**E3 — The spill key is not locked in memory.** `Zeroizing` clears the key when the handle
ends. While the handle lives, the OS can page the key to a swap file or write it to a
hibernation image, next to the spill ciphertext it opens. The local uid is not a boundary this
system defends (alternative f), and the mount serves the same plaintext to that uid.

**E4 — A quota refusal after the journal ack is not an errno.** `EDQUOT` fires only at command
time, when `pre_flight_quota_check` refuses the write. FSM1/cipher-box#841 decided a rejection
reason for a backlog blocked on account quota. The code has no producer of that reason: a
`Quota` hold on the drain (`crates/engine/src/sync/drain.rs`) refuses no later write, and only
the start-of-write pre-flight produces `OverBudgetCause::AccountQuota`. This ADR accepts the
pre-flight as the way the FSM1/cipher-box#841 decision is met. A later write that fits the
quota at its pre-flight is accepted while an earlier op holds the queue on quota. A
`QUOTA_EXCEEDED` 413 that the drain meets after the kernel ack becomes the drain's `Blocked`
hold (`queue_hold` on the snapshot, reason `QueueHoldReason::Quota`). The desktop tray does not
render that hold today. The kernel is never failed after an ack, by the blueprint's dead-letter
law.

**E5 — A missed invalidation on the SMB backend has no backstop.** The smbfs client ignores
TTLs, so cached data that no invalidation reaches does not revalidate. D1 depends on the engine
event stream firing for each change. The Linux and WinFsp TTL values stay an open edge of the
blueprint.

**E6 — D5 covers the vendored `fuser` only.** The WinFsp adapter reaches the kernel through
`winfsp-rs` from crates.io, which is not vendored, and no test asserts what it logs.
`crates/fuse` redacts names in its own `Debug` renders, and unit tests cover two of them, but no
gate asserts that the desktop shell's `eprintln!` of an engine error carries no name.
`apps/desktop` installs no `log` backend today, so the records reach no sink. D5 holds for the
day a build installs one.

**E7 — The redaction still prints a byte length.** A length names no file, but it is a small
signal about the name. FSM1/cipher-box#1577 accepted it (alternative i).

## Gate

- **D1:** `the_mount_sets_noattrcache`, `the_backend_pushes_invalidation_and_is_the_one_that_can`
  and `a_suppressed_attribute_cache_is_given_no_lifetime` (`crates/fuse/src/adapters/macos.rs`,
  run by the `Adapter tests (macOS)` leg of the Rust area);
  `a_noattrcache_mount_keeps_its_entry_cache_and_loses_only_the_attribute_one`,
  `a_snapshot_the_mount_did_not_author_invalidates_the_listing_the_kernel_holds`,
  `a_second_change_with_no_kernel_callback_in_between_is_still_pushed`,
  `a_name_rebound_to_a_different_node_invalidates_its_entry` and
  `a_version_the_mount_never_served_repaints_the_kernels_caches_off_the_event_stream`
  (`crates/fuse/tests/fuse_op_core.rs`, `FUSE Op Core`). The smbfs behaviour itself (the 3 s
  floor, the ignored TTLs) is proven only by hardware gate 1 in `tools/hw-gates/RESULTS.md`,
  which is not CI. No CI test mounts FUSE-T.
- **D2:** `every_verdict_maps_to_its_named_errno` and `the_shared_class_rules_hold_for_errno`
  (`crates/fuse/src/errno.rs`); `each_budget_keeps_its_own_cause` and
  `only_the_account_quota_is_an_account_budget` (`crates/fuse/src/error.rs`), all in
  `FUSE Op Core`; `a_hosted_write_over_quota_is_refused_at_command_time`
  (`crates/engine/tests/write_plane.rs`, `Engine simulation tests`). No `FUSE Op Core` test
  drives an over-quota write through a mount operation to `EDQUOT` end to end. That is a
  finding.
- **D3:** `plaintext_never_reaches_the_slot_bytes`, `a_rewritten_block_never_repeats_a_nonce`,
  `a_slot_moved_to_another_index_does_not_open`, `two_files_from_one_area_get_different_keys`,
  `dropping_a_spill_removes_its_file`, `opening_the_area_sweeps_a_previous_runs_debris` and
  `the_production_area_mints_a_fresh_key_per_spill` (`crates/fuse/src/spill.rs`);
  `a_spill_file_holds_no_plaintext`, `two_handles_on_one_node_seal_under_different_keys` and
  `a_released_handle_leaves_no_spill_behind` (`crates/fuse/tests/fuse_op_core.rs`), all in
  `FUSE Op Core`. No test or lint proves that the AEAD is the only cryptographic use of
  `crates/core` in `crates/fuse`. That is a finding.
- **D4:** `a_tick_repaints_a_file_another_device_republished_without_an_open` and
  `every_read_path_operation_runs_the_ttl_check_against_the_node_it_has_in_view`
  (`crates/fuse/tests/fuse_op_core.rs`, `FUSE Op Core`), for the `getattr` trigger;
  `a_lookup_queues_only_the_file_whose_length_is_still_to_arrive`
  (`crates/fuse/tests/fuse_op_core.rs`, `FUSE Op Core`), for the `lookup` trigger;
  `a_tick_paints_a_file_another_device_added_to_the_open_folder`,
  `a_tick_paints_a_file_another_device_added_to_the_open_root` and
  `a_tick_resolves_an_unwritten_row_once_per_staleness_window`
  (`crates/engine/tests/write_plane.rs`, `Engine simulation tests`), for the folder-in-view
  trigger; `a_file_in_view_repaints_from_another_devices_version_on_the_tick` and
  `the_on_access_file_queue_stops_admitting_past_its_ceiling`
  (`crates/engine/tests/write_plane.rs`, `Engine simulation tests`), for the file leg and the
  bound;
  `a_legs_file_share_stays_inside_the_passes_own_budget` and
  `a_legs_file_share_spends_a_bulk_row_before_a_host_queued_row` (`crates/engine/src/facade.rs`,
  `Engine simulation tests`). No test proves that an entry the bound evicts is queued again
  on the next stat. That is a finding. The accepted exposure is a design statement and has no
  test.
- **D5:** `default_filesystem_ops_never_log_a_name` and `redacted_name_renders_only_a_length`
  (`third-party/fuser/src/lib_impl.rs`); `every_render_of_a_request_redacts_the_name`,
  `debug_of_a_request_payload_redacts_the_name` and
  `debug_of_a_filename_in_dir_redacts_the_name` (`third-party/fuser/src/ll/request.rs`), all run
  by the "Vendored fuser patches" step of `FUSE Op Core`. `debug_renders_no_entry_name`
  (`crates/fuse/src/adapter.rs`) and `dir_entry_debug_withholds_the_plaintext_name`
  (`crates/fuse/src/ops.rs`) cover the projection's own renders. The macOS-only arms of
  `default_filesystem_ops_never_log_a_name` (`setvolname`, `exchange`) never run in CI: the
  vendored crate's tests run on `ubuntu-latest` only, and the macOS adapter leg does not test
  `fuser`. That is a finding.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.

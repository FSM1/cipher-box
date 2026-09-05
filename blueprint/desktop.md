# Desktop — v2 blueprint

Resolved by [Blueprint: desktop](https://github.com/FSM1/cipher-box-next/issues/46).
Normative for the v2 build. Upstream inputs: the
[component decomposition](https://github.com/FSM1/cipher-box-next/issues/28)
(D1/D3), the
[sync/refresh/offline](https://github.com/FSM1/cipher-box-next/issues/33)
design, the
[macOS filesystem driver research](https://github.com/FSM1/cipher-box-next/issues/32),
and the seam contracts and facade law in
[`blueprint/engine.md`](engine.md); the
[feature set](https://github.com/FSM1/cipher-box-next/issues/5) keeps the FUSE
mount as the primary desktop UX. This doc covers the two desktop-side units of
the FSM1/cipher-box-next#28 D3 layout — `apps/desktop` (Tauri shell) and `crates/fuse` (FS core +
host adapters). Where the engine blueprint already fixes behavior (adoption
gate, sync core, rotation, grants, durability), this doc adds only the
filesystem projection and native hosting around it, never a second copy of it.

## Doctrine

The desktop app is the engine's **native host**: `apps/desktop` links
`crates/engine` directly in the Tauri process and owns login, lifecycle, tray,
and updater; `crates/fuse` projects the engine's snapshot state as a mounted
filesystem and translates kernel operations into facade commands. The FS layer
is a **projection, not a second brain**: it holds no keys, no publish
machinery, no freshness policy, and no rotation logic — every trust and sync
decision already happened below the facade (engine.md). Key material lives in
engine memory only; the FS core maps inodes to stable node ids and moves
plaintext bytes, which is its job — the mount is the plaintext trust terminus
for the local OS.

What dies relative to v1 — with the design that killed it:

| Gone                                                                                                          | Killed by                                                                                                        |
| ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| The desktop twin engine (`crates/sdk` rotation/sync/queue) and its TS divergence table                        | FSM1/cipher-box-next#28 D1 — one Rust engine, linked natively                                                    |
| Keys in the `InodeTable` (`InodeKind` read/write keys, IPNS seeds, `recipient_pins`)                          | engine facade — keys never cross it; the inode map is key-free                                                   |
| mkdir+uploads-only journal, `Option<()>` durability placeholder, two durability classes                       | FSM1/cipher-box-next#33 D6 — every mutation rides the engine's durable op queue                                  |
| `PublishCoordinator`, debounce queue, `mutated_folders`, `apply_owned_children` merge choreography            | FSM1/cipher-box-next#33 D6 — snapshot ⊕ pending-op overlay computed in the engine; the FS renders it             |
| Scope-exit gate choreography in FUSE (`SentSharesCache`, pin refresh, mark-mutated, keys-after-gate ordering) | FSM1/cipher-box-next#26 D7 / engine.md — full-depth scope-exit detection and rotation are one engine transaction |
| The freshness workaround stack: dir TTL 0, edge-triggered drains, the macOS publish-pump thread               | FSM1/cipher-box-next#32 — host adapters expose push invalidation, driven by the engine event stream              |
| FUSE-T NFS backend and its kext-panic/no-invalidation flake class                                             | FSM1/cipher-box-next#32 — SMB backend unconditionally                                                            |
| Whole-file 120 s content downloads before first byte                                                          | engine content plane — chunk-sealed DAG, ranged fetches                                                          |
| Per-op-type timeout zoo (3 s / 10 s / 120 s / 180 s `block_on` freezes)                                       | never-block law below — callbacks block on local durability only                                                 |
| Duplicated operation logic per platform (`&mut self` fuser vs `Arc<Mutex>` WinFsp twin trees)                 | one FS operation core behind the host-adapter trait (FSM1/cipher-box-next#32)                                    |
| TEE enrollment, device registry epochs, `tee_keys`                                                            | FSM1/cipher-box-next#24 D4 — TEE dropped                                                                         |
| Plaintext temp write buffers on disk (`cb-write-*`)                                                           | sealed spill files under an ephemeral in-memory key (below)                                                      |
| Root-only 30 s `SyncDaemon` and its log-and-hope change detection                                             | FSM1/cipher-box-next#33 D2 — FUSE-op TTL checks drive the shared sync core                                       |
| "No offline mode" — mount unresponsive without connectivity                                                   | FSM1/cipher-box-next#33 D6 — cache-first reads + durable op queue give full offline function                     |

What is deliberately **kept** from v1: the fsync-barrier discipline and
ciphertext-only-at-rest law of the write journal (generalized into the engine's
StagingStore/FloorStore implementations), inode stability across renames (v1
learned reallocation causes stale-handle disconnects), platform-junk name
filtering, the vendored `fuser` MSG_PEEK patch (FUSE-T fragments >256 KB
messages; upstream accepts no PRs — the patch is load-bearing and travels with
the vendored crate, this time with a regression test), and dev-key mode as the
headless e2e seam.

## Component map

- **`apps/desktop`** — the Tauri shell: Web3Auth Core Kit webview and the
  login handoff, engine construction with the desktop seam set, mount
  lifecycle, tray + notifications, updater, deep links, autostart. No vault
  semantics; it wraps the facade and renders its event stream.
- **`crates/fuse`** — the FS core and its host adapters: the inode/handle
  model, the vfs-operation surface, read/write paths over the facade, and one
  adapter per mount technology (FUSE-T SMB, Linux FUSE, WinFsp; FSKit
  successor). Depends on the engine facade only — no transport or API access,
  and the one direct use of `crates/core` is the AEAD the spill file seals
  under, since the FS core never implements crypto of its own.

## Engine wiring

The engine is constructed in-process at login with the desktop seam set
(engine.md table, desktop column). All engine stores live under
`<data_local_dir>/cipherbox/<accountId>/`, ciphertext-only at rest — same law
as web's IndexedDB stores; a stolen disk yields sealed bytes only.

| Seam                | Desktop implementation                                                                                                                                                                                                            |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **FloorStore**      | Fsync-barriered files in the engine data dir (the v1 high-water store discipline: write, `sync_all`, parent-dir fsync). Durable across logout by design                                                                           |
| **RecordTransport** | `reqwest` against the configured `/routing/v1` endpoint set                                                                                                                                                                       |
| **Http**            | `reqwest`; the rotating refresh token is injected from CredentialStore                                                                                                                                                            |
| **Scheduler**       | Tokio — timers, background tasks, wall clock                                                                                                                                                                                      |
| **StagingStore**    | The v1 write journal generalized: one durable record per op (JSON or CBOR row + fsync barrier), sidecar files for staged ciphertext, `.json`-before-`.bin` removal ordering, orphan-sidecar GC. Covers **all** mutations, not two |
| **SnapshotCache**   | Sealed record/metadata cache files in the data dir; unsealed in the engine on read                                                                                                                                                |
| **CredentialStore** | OS keychain (`keyring`), one service name; stores the refresh token, the last-account id, and the key that seals the login SDK's Core Kit store — never a seed, and never a key in the KDF catalog                                |

The facade is called directly (in-process async Rust) — no RPC layer, no
worker, no tab leadership; the single-writer invariant is free on desktop
because there is exactly one engine per running app. The Tauri webview is
login-and-settings chrome only: it renders facade state forwarded over Tauri
events and never holds tokens or keys (the v1 `handle_auth_complete` handoff
survives, but the secret goes straight to `start(secret)` and is zeroized).

## The FS core and host adapters

Per the driver research (FSM1/cipher-box-next#32), the FS core's surface sits at the
**vfs-operation level, not the FUSE wire level**: one platform-neutral
operation core (lookup, getattr, readdir, open/read/write/release, create,
mkdir, unlink, rmdir, rename, statfs) implemented once, with a thin
**host-adapter trait** per mount technology. The v1 lesson is structural: the
duplicated fuser/WinFsp operation trees produced a revocation bypass (T-74-09)
that existed in exactly one of them.

The adapter trait carries, in each direction:

- **Inbound**: the vfs operations, each with platform-normalized names and
  credentials; the adapter owns wire decode, errno/NTSTATUS mapping, and
  platform quirks (readdir single-pass for FUSE-T, case-insensitive lookup on
  Windows).
- **Outbound**: an explicit **push-invalidation callback** — the FS core tells
  the adapter "this inode's data/attrs/entries changed" and the adapter maps
  it to `inval_inode`/`inval_entry` (Linux), SMB-backend invalidation (FUSE-T
  ≥ 1.2.1), WinFsp notifications, or FSKit's `DataCacheHandler`. An adapter
  that cannot invalidate (none shipping) would declare it, and the core would
  fall back to short TTLs for that mount only.

### Backends

|              | macOS                                                                                                                     | Linux                                                     | Windows                  | macOS successor                                                                                                           |
| ------------ | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| Backend      | **FUSE-T ≥ 1.2.7, SMB backend** — NFS abandoned unconditionally (FSM1/cipher-box-next#32)                                 | kernel FUSE via vendored `fuser` (MSG_PEEK patch carried) | **WinFsp** (MSI bundled) | **FSKit** module once macOS 27 is stable: Swift appex shell delegating into the shared FS core                            |
| Invalidation | SMB-backend invalidation (added 1.2.1) — **mount with `noattrcache`**, verified on hardware (`tools/hw-gates/RESULTS.md`) | `inval_inode`/`inval_entry`                               | WinFsp notify API        | `FSVolume.DataCacheHandler`                                                                                               |
| Status       | ship v2.0                                                                                                                 | ship v2.0                                                 | ship v2.0                | designed-for; FSKit spike **passed** on macOS 27 (`tools/hw-gates/fskit-spike/RESULTS.md`) — successor timeline unblocked |

**Windows licensing.** WinFsp and the winfsp-rs binding the adapter is built on
are GPLv3, so the Windows build is a combined work distributed under GPLv3, with
WinFsp's commercial licence as the alternative. Two conditions ride with that and
are part of the backend, not paperwork beside it: the notice **"WinFsp - Windows
File System Proxy, Copyright (C) Bill Zissimopoulos"** and a pointer to
<https://github.com/winfsp/winfsp> are shown in the desktop UI and stated in
`docs/ATTRIBUTION.md`, and no proprietary software is bundled alongside WinFsp.

macFUSE stays rejected (kext install friction, license, fuser ABI divergence);
File Provider stays a fallback-only note (its plaintext replica is an E2EE
regression). The hardware verification gates from FSM1/cipher-box-next#32 — SMB invalidation
round-trip, the v1 cross-client scenario, overwrite-rename atomicity, FUSE-T
commercial license terms, an FSKit beta spike — are pre-build checks owned by
the [testing strategy](https://github.com/FSM1/cipher-box-next/issues/47).

### Names and attributes

- **Uniqueness is the engine's strict comparator** (FSM1/cipher-box-next#33 D5): NFC-normalized +
  case-folded, identical on every platform, names stored as-entered. Adapter
  lookup semantics stay platform-conventional (case-sensitive presentation on
  macOS/Linux, case-insensitive on Windows), but collision behavior is decided
  by the one comparator, so every committed folder mounts everywhere.
- Platform-junk names (`.DS_Store`, `._*`, `Thumbs.db`, …) are rejected on
  create and hidden from listings on all platforms (v1 table carried forward).
  Name-length and reserved-character validation move into the operation core
  (255 bytes, platform-reserved characters rejected at create) — v1 advertised
  `namelen=255` without enforcing it.
- Inodes are allocated per mount session, stable across renames, keyed by the
  engine's stable node id; `kind` comes from the child ref (FSM1/cipher-box-next#27 D7), so
  listings never flip type.

## Reads, writes, and the never-block law

**The law**: a kernel callback may block on **local durability** (op-queue
fsync) and on **content-chunk fetches for uncached reads** — never on IPNS
resolution, publish, rotation, or any API bookkeeping call. Cache-first
resolution (FSM1/cipher-box-next#23 D5) plus the op queue (FSM1/cipher-box-next#33 D6) make everything else
asynchronous by construction; the v1 timeout zoo (3/10/120/180 s) has nothing
left to bound. The FS core is async-native on Tokio with per-op cancellation;
there is no `block_on` freeze of the whole mount behind one slow call.

- **readdir/lookup** — served from the engine snapshot (with pending-op
  overlay already applied). Never a network wait: an uncached folder renders
  from last-known-good and reconciles in the background; a truly cold folder
  (no cache) returns once the first resolve lands, the one cold-start
  exception (FSM1/cipher-box-next#33 D4).
- **read** — the engine maps the range onto sealed chunks, serves cached
  chunks immediately, fetches missing ones (gateway accelerator → public
  fallback), CID-verifies, unseals, returns plaintext. First byte no longer
  waits for the last byte. A bounded in-memory plaintext chunk cache
  (LRU, zeroized on unmount) lives in the FS core for hot-file performance —
  the one place plaintext is cached, memory-only.
- **write** — bytes land in a per-handle **sealed spill file**: XChaCha20
  under a random per-handle key held only in engine/FS memory, in the engine
  data dir. A crash leaves ciphertext whose key died with the process — the v1
  plaintext `cb-write-*` exposure class is gone (judgment; the zero-overwrite
  cleanup papers over what this closes structurally).
- **release** (and create/mkdir/rename/unlink/rmdir) — becomes exactly one
  facade intent op (`updateContent`, `create`, `move`, `delete`). A kernel
  rename is one `move`, which carries the relink, the rename, and the
  destination it replaces, so a replace is never observable half-done.
  The kernel is acked when the op is **journaled durably in the StagingStore**
  — the v1 INV-1 no-false-ack discipline, now uniform across every mutation
  instead of two. Everything after the ack (seal, upload, publish, CAS rebase)
  is the engine's background pipeline.
- **statfs** — quota from the engine's quota state (advisory for BYO).
  **Over-budget becomes honest**: the engine says which budget refused the write
  (`OverBudgetCause`), so the offline staging budget running out (FSM1/cipher-box-next#33 D6
  fail-fast) is `ENOSPC` and a hosted-quota refusal is `EDQUOT` — v1 returned
  neither, and collapsing both into "disk full" tells the user to free space on
  the wrong machine.
- **Deletes** ride the engine's delete op; recycle-bin semantics (FSM1/cipher-box-next#5) are
  vault-level engine behavior. The bin is not projected into the mount in
  v2.0; restore/purge live in the web UI and the tray's "Open CipherBox".

### Conflicts, dead letters, and rotation

- A rebased op that loses a race follows the engine's per-op rules (FSM1/cipher-box-next#33 D5) —
  auto-suffixed add/add collisions and edit-wins deletes simply appear in the
  next snapshot; the FS core renders outcomes, it never merges.
- **Dead-letters** (terminally unrebasable ops — e.g. access revoked while
  offline) surface as a tray notification + a persistent tray section with the
  staged bytes recoverable to a local "recovered files" export; nothing is
  silently dropped and the kernel is never retro-failed (it was acked at
  journal time — the dead-letter surface is the compensation channel).
- **Scope-exit rotation** is invisible to the FS layer: a cross-scope `relink`
  or a delete from a granted scope triggers detection and rotation inside the
  engine's op pipeline (FSM1/cipher-box-next#26 D7), as one transaction with the mutation. The
  refusal path (rotation impossible, fail-closed) rejects the **op at journal
  time** — the one mutation class where the ack waits on more than the fsync:
  the engine must accept the op before the kernel hears success. EIO with a
  tray explanation; v1's four-workaround gate choreography has no v2 home.

## Freshness — the desktop trigger source

Desktop drives the **same sync core** as web, from FUSE traffic instead of
navigation (FSM1/cipher-box-next#33 D2):

- Every lookup/readdir/getattr checks the target's snapshot age against the
  sync timing profile's staleness threshold; a stale hit forces a pass for that
  node — this is the **FUSE-op TTL check**, the desktop analog of route
  navigation. Network reconnect, tray "Sync Now", and wake-from-sleep force one
  the same way, through `Command::ManualRefresh`.
- The **focus window** is derived from the op stream: folders with FUSE
  traffic inside the profile's focus horizon count as "open", and the 30 s
  tick refreshes them plus their ancestor chains and the vault pointer —
  Finder windows behave like browser tabs. Everything else refreshes on
  access.
- `getattr` on a file puts **that file** in view rather than its parent, so a
  listing produces a correlated burst of per-child record resolves — one per
  entry the host stats that is also past the staleness threshold, inside one
  tick. Before this leg existed a child's own name was resolved only when
  someone deliberately opened it, so the resolve pattern distinguished browsing
  from reading; it no longer does. This is a **new** exposure, not a repackaged
  one: child `ipnsName`s ride the parent's sealed read-body, so co-resolution is
  the one signal that hands an endpoint a sibling-set fingerprint — a durable
  linkage of names to a common folder, and at the CipherBox accelerator an
  identity-linked one. Names, kinds, sizes and bodies stay sealed.
  `MAX_FOCUS_FILES` bounds the burst **per tick**; an entry it evicts unresolved
  is re-queued on the next stat, so a large directory's full sibling set still
  reaches the endpoints across a browsing session.
- When a background reconcile lands a new snapshot, the engine event stream
  drives the **push-invalidation callback**, and the kernel's next access
  re-reads through the adapter — replacing dir-TTL-0, drain choreography, and
  the pump thread. Kernel entry/attr TTLs are set from the sync timing
  profile per backend capability, not hardcoded zeros.
- The FUSE-T SMB cache is measured, not a ceiling (#644 gates,
  `tools/hw-gates/RESULTS.md`): with `noattrcache`, invalidation
  round-trips are milliseconds — cross-client latency is dominated by
  poll cadence, not the mount. Two hard requirements fall out: the mount
  must set `noattrcache` (without it the smbfs client imposes a 3 s attr
  floor and unbounded staleness for cached data), and every remote change
  must fire push invalidation (uninvalidated cached data never
  revalidates). The smbfs client ignores FUSE reply TTLs entirely on this
  backend.

## Tauri shell

- **Login**: Web3Auth Core Kit in the webview (its DOM/redirect flows and MFA
  enrollment — chrome-side); the exported secret crosses to
  `start(secret)` once and is zeroized. Challenge-signature login, token
  refresh, and session restore are engine-native (engine.md API client);
  the shell's only credential duty is hosting the keychain seam. Dev-key mode
  survives: a debug flag feeds the staging test-login path through the same
  facade, keychain bypassed — the headless agent/e2e seam.
- **The orchestration is shared through `packages/login`** ([ADR 0008](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0008-cipherbox-issues-the-identity-token.md) D3): the shell
  imports the same host-agnostic package and supplies both its own credential
  collector and its own start facade — `LoginFacade` is `{ start, logout }`, over
  Tauri IPC here. It does **not** take `packages/client` — the worker, leadership
  and Service Worker machinery has no place here.
- **The auth surfaces are shared through `packages/auth-ui`** (ADR 0008 D3): the
  login form, the phrase prompt and the error banner are React components both
  hosts mount, parameterised over the host's own actions. Each host keeps its
  own theme and its own wiring; neither keeps a second implementation of a
  surface. The shell's window chrome — the vault panel and the licence footer —
  stays in `apps/desktop`. The webview compiles JSX with Vite's own transform:
  this window's policy is `default-src 'self'`, and a Fast Refresh plugin serves
  an inline preamble the policy refuses.
- **Google collection is native, not in-webview.** Google Identity Services does
  not run in this webview, and the manual OAuth2 flow it falls back to needs a
  `redirect_uri` a packaged Tauri origin cannot satisfy — `tauri://localhost` is
  refused as a non-`http(s)` scheme. The shell therefore serves the callback from
  a loopback listener on a pre-registered port. This is the one login step that
  is genuinely native (ADR 0008).
- **No wallet method here.** The webview reaches no wallet, so the method is
  absent rather than offered and unable to complete (ADR 0008 D2).
- **Recovery phrase always works here** ([ADR 0009](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0009-device-approval-is-a-bound-rendezvous.md) D2): a member with a factor
  policy signs in on this host with the phrase alone, no second device and no
  rendezvous. A login that reaches the policy is held open rather than ended,
  because the phrase is redeemed against that same login, and the window renders
  a phrase field for it.
- **Device approval is requester-only through the cutover.** Approval itself
  always happens in a web session, so this window offers no approver affordance
  and its copy says where factors and approval are managed. Enrollment is
  web-only for the same reason (ADR 0009 consequence 5). The approver role
  arrives after v2.0 by reusing the web app's components, never by a second
  implementation — v1 shipped a requester UI that could never work beside a
  settings string saying MFA was web-only, and the affordance and the truth have
  to agree.
- **Tray** renders the event stream: the staleness ladder maps to
  `Synced / Reconciling / Stale / Offline`, dead-letters to the parked-writes
  state (edge-triggered notifications, v1's anti-spam watermark kept), trust
  violations and withheld-update escalations to a distinct warning state that
  is never conflated with staleness (FSM1/cipher-box-next#33 D4). "Sync Now" is a manual-refresh
  facade command with nocache semantics.
- **Lifecycle**: menu-bar app; mount failure never fails login (session stays
  up, tray shows the error); logout = facade logout (engine zeroizes),
  unmount, keychain token delete; the durable stores survive logout by design
  and an explicit "forget this device" wipes them — same law as web.
  Unmount/quit ordering: quiesce the adapter (stop accepting kernel ops),
  unmount, then stop the engine — acked-but-unpublished ops are already
  journaled and drain on next mount.
- **Replay on mount** is the engine's op-queue drain — the FS core has no
  replay logic of its own (v1's `replay.rs` key-recovery machinery dies with
  the journal it served). Mount renders from SnapshotCache immediately;
  prepopulation is just the focus-window warming on first traffic.
- **Updater**: Tauri updater over GitHub releases, minisign-verified —
  carried from v1; release mechanics belong to
  [deployment/release management](https://github.com/FSM1/cipher-box-next/issues/48).

## Testing hooks

The FS operation core is unit-testable without a kernel: the host-adapter
trait means tests drive vfs operations directly against an engine with mock
seams (the v1 Windows tree that "only CI can compile" shrinks to a thin
adapter). Cross-platform e2e (mount, mutate, cross-client sync, offline
replay, rotation-under-mount) and the FSM1/cipher-box-next#32 hardware gates are owned by the
[testing strategy](https://github.com/FSM1/cipher-box-next/issues/47);
WinFsp CI remains authoritative for the Windows adapter, and dev-key mode is
the headless harness entry.

## Open edges

- **FSKit spike** — done (#644, `tools/hw-gates/fskit-spike/RESULTS.md`):
  native FSKit builds/mounts on macOS 27 and `FSVolume.DataCacheHandler` +
  `-[FSVolume setCacheStateForItem:…]` (`coherencyAction = 1`) give a reliable
  sub-ms push-invalidation that lands on cached pages — the adapter trait's
  outbound push-invalidation callback maps directly onto it, and coherence is
  strictly better than the shipping FUSE-T SMB backend (gate 1). Remaining
  successor work is the `crates/fuse` FSKit adapter itself, not a feasibility
  question ([#47](https://github.com/FSM1/cipher-box-next/issues/47)).
- **FUSE-T license terms** — verified (#644, `tools/hw-gates/RESULTS.md`
  gate 4): bundling in the app requires a negotiated commercial license
  from the author (no published pricing; <alex@fuse-t.org>); user-installed
  FUSE-T is the free interim path. Negotiation must close before v2.0
  ships with a bundled FUSE-T.
- **Dead-letter recovery UX** — the tray surface and "recovered files" export
  shape; settle alongside the failover/offline e2e work
  ([#47](https://github.com/FSM1/cipher-box-next/issues/47)).
- **Focus-horizon value** — how long FUSE traffic keeps a folder "open" joins
  the sync timing profile.
- **Kernel TTL values per backend** — resolved for FUSE-T SMB (#644,
  `tools/hw-gates/RESULTS.md`): the client ignores FUSE reply TTLs, so
  there is no TTL constant to freeze for this backend — `noattrcache` +
  push invalidation replace it. Linux/WinFsp values still freeze with the
  cross-client measurements
  ([#47](https://github.com/FSM1/cipher-box-next/issues/47)).
- **Designed-for, deliberately unbuilt**: FSKit adapter (above); desktop
  embedded DHT behind RecordTransport (FSM1/cipher-box-next#23 D2); desktop PubSub push, whose
  handler forces a pass through `Command::ManualRefresh` (FSM1/cipher-box-next#33 D1).

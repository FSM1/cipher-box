# Gate 5 — FSKit spike results (issue #644)

The macOS-27 FSKit spike from the #644 pre-build checks (FSM1/cipher-box-next#32
verify list). Gate 5 was blocked on macOS 27 beta hardware; this resolves it.

**Environment:** macOS 27.0 beta (Darwin `26A5388g`), Apple M3 Pro (virtualized,
8 GiB, UTM), SIP disabled + `boot-args=amfi_get_out_of_my_way=1` so an ad-hoc
signed FSKit module with the restricted `com.apple.developer.fskit.fsmodule`
entitlement is allowed to load (no Apple Developer team / Xcode required — the
whole spike builds with the Command Line Tools). Measured 2026-07-22. The
harness in this directory reproduces every number below.

## Verdict

**PASS — FSKit is a viable macOS successor backend, and its coherence story is
strictly better than the shipping FUSE-T SMB backend (gate 1).** FSKit exposes
an explicit, reliable, sub-millisecond **push-invalidation** primitive
(`FSVolume.DataCacheHandler` + `-[FSVolume setCacheStateForItem:…]`) that lands
on already-cached kernel pages — the exact failure mode that made FUSE-T need
`noattrcache` and still left held-open cached data unbounded-stale (gate 1).

The successor timeline in `blueprint/desktop.md` can be committed: the adapter
trait's outbound push-invalidation callback maps cleanly onto
`setCacheStateForItem`.

## What was verified

| #   | Question                                                                    | Result                                                                                                                                                                                |
| --- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 5.1 | Does a native FSKit module build/load/mount on 27 with the tooling we have? | **Yes** — CLT-only build, ad-hoc signed, mounts via `FSClient.mountSingleVolume`; volume is fully usable (readdir, read, write, rename, xattr).                                       |
| 5.2 | Is `FSVolume.DataCacheHandler` real and invoked by the kernel?              | **Yes** — `openItem:modes:cacheMode:context:` / `upgradeItem:` / `closeItem:` are called on every open path, each carrying a `cacheMode` and returning a per-open `grantedCoherency`. |
| 5.3 | Is there a push-invalidation call, and does it reach cached data?           | **Yes** — `setCacheStateForItem:cacheMode:coherencyType:coherencyAction:` with **`coherencyAction = 1`** purges kernel-cached (mmap) pages.                                           |
| 5.4 | Is it reliable and fast?                                                    | **Yes** — 100/100 (and 40/40, 60/60 across runs) invalidations landed; latency p50 ≈ 0.35–1.15 ms, p95 ≈ 0.44–2.22 ms (VM, localhost in-process module).                              |

## Caching model (the gate-1 comparison)

- **`read(2)` / `pread` path:** coherent — the kernel re-invokes the module's
  `readFromFile` rather than serving a stale buffer. A server-side change is
  visible on the next `read` with no invalidation needed.
- **`mmap` path:** the unified page cache **does** cache faulted pages, so a
  server-side change is **not** visible on the mapped page until invalidated —
  this is the caching that matters for coherence, and 40/40–100/100 trials with
  a fresh vnode confirmed the page reliably holds stale data until a
  `setCacheStateForItem` call.

## `setCacheStateForItem` — `coherencyAction` semantics

Fresh vnode per trial (see "vnode-scoped" note), 40 trials each:

| `coherencyAction` | page held stale before call | invalidation landed | latency                  |
| ----------------- | --------------------------- | ------------------- | ------------------------ |
| 0                 | 40/40                       | **0/40 (no-op)**    | —                        |
| 1                 | 40/40                       | **40/40**           | p50 0.37 ms, p95 0.44 ms |
| 2                 | 40/40                       | **40/40**           | p50 0.37 ms, p95 0.63 ms |
| 3                 | 40/40                       | **0/40 (no-op)**    | —                        |

`coherencyAction ∈ {1, 2}` invalidate the read cache; `{0, 3}` are read no-ops
(0 = set-state-only; 3 = a write-side action that leaves read pages intact).
`cacheMode` and `coherencyType` did not change the read-invalidation outcome in
the swept range (mode 0–3, type 0–8) — action is the operative field.

The call **succeeds unconditionally** at the FSKit layer for every triple
(framework logs `Successfully set cache state for item`); "landed" is measured
by observing the mapped page, not the return value. The return object is an
`NSError *` (nil on success).

**vnode-scoped coherency (operational note).** Firing `action = 1/2` transitions
the item's kernel vnode to a no-cache coherency that _persists until the vnode
is reclaimed_ — subsequent maps of the same file read through coherently rather
than re-caching. Measuring the primitive therefore requires a fresh file (fresh
vnode) per trial; reusing a file silently reports "not cached" on the second
pass. This matches a lease/coherency-grant model (invalidate == downgrade the
grant), and is the FSKit analogue of an SMB oplock/lease break.

## API surface (recovered by runtime introspection; not in the 26.5 SDK)

The 27 additions are absent from the Command Line Tools SDK headers, so the
module declares them by hand from live-runtime introspection
(`_protocol_getMethodTypeEncoding`, ObjC class/protocol dumps):

```objc
@protocol FSVolumeDataCacheHandler
  - openItem:(FSItem*)i modes:(NSUInteger)m cacheMode:(long)c
        context:(FSContext*)ctx replyHandler:(void(^)(FSOpenItemResult*, NSError*))r;
  - upgradeItem:(FSItem*)i cacheMode:(long)c
        context:(FSContext*)ctx replyHandler:(void(^)(FSUpgradeItemResult*, NSError*))r;
  - closeItem:(FSItem*)i context:(FSContext*)ctx replyHandler:(void(^)(void))r;
  @optional - (BOOL)isDataCacheInhibited;

@interface FSVolume (DataCacheHandler)
  - (NSError*)setCacheStateForItem:(FSItem*)i cacheMode:(long)c
        coherencyType:(long)t coherencyAction:(long)a;

FSOpenItemResult / FSUpgradeItemResult : FSVolumeHandlerResult
  - initWithGrantedCoherency:(long)coherency;   // per-open coherency grant
```

`FSClient.mountSingleVolumeForResource:bundleID:mountPath:options:completionHandler:`
mounts a single `FSPathURLResource`-backed volume at a path; the completion
handler is `(NSURL* mountedURL, NSError*)`.

## Gotchas found (documented so `crates/fuse`'s FSKit adapter avoids them)

1. **Entry point.** A CLT `swiftc @main` executable calls
   `AppExtension.main()` directly and **crashes** on 27 in
   `ExtensionFoundation` (`MainActor.assumeIsolated` trap) — the ExtensionKit
   run loop is never set up. The working shape (matches fuse-t's shipping
   module) keeps the `@main`/`__swift5_entry` discovery metadata but forces the
   Mach-O entry to `_NSExtensionMain` (`-Xlinker -e -Xlinker _NSExtensionMain`).
2. **Container state.** `FSUnaryFileSystemOperations loadResource` must set the
   container status to **`ready`**, not `active` — returning a volume with
   `containerStatus = .active` is rejected by `FSModuleConnector` as "unexpected
   container state" → `mountSingleVolume` fails `EPROTONOSUPPORT` (43). The
   container becomes `active` only once a volume mounts.
3. **Enablement is privileged.** A third-party module must be enabled before
   `fskitd` will route to it. `FSClient.setEnabledStateForIdentifier` needs
   `com.apple.private.LiveFS.connection` (returns `EPERM` without it); hand-
   editing `~/Library/Group Containers/group.com.apple.fskit.settings/enabledModules.plist`
   is **not** honored by `fskitd`. On real hardware this is the System Settings
   → General → Login Items & Extensions → File System Extensions toggle.
4. **`.smbdelete`-style transients don't apply**, but FSKit renames are a single
   `renameItem:…overItem:` op (cleaner than the SMB two-rename dance from gate 3).

## Reproducing

Requires macOS 27, SIP disabled, `boot-args=amfi_get_out_of_my_way=1`.

```sh
cd tools/hw-gates/fskit-spike
make install                                   # build + register the appex
./build/g5mount enable cc.cipherbox.gate5host.fsmodule
mkdir -p /private/tmp/g5back /private/tmp/g5mnt/vol
./build/g5mount mount /private/tmp/g5back /private/tmp/g5mnt/vol nil

./build/g5probe /private/tmp/g5mnt/vol /private/tmp/g5mnt/vol/data.bin 4   # model overview
./build/g5inval /private/tmp/g5mnt/vol /private/tmp/g5mnt/vol/data.bin 0 0 1 100  # invalidation trial
./build/g5sweep /private/tmp/g5mnt/vol /private/tmp/g5mnt/vol/data.bin 3 8 8      # action brute-force

diskutil unmount force /private/tmp/g5mnt/vol
```

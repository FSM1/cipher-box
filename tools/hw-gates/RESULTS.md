# Hardware verification gate results — issue #644

The five FSM1/cipher-box-next#32 pre-build checks for the macOS desktop
driver decision (`blueprint/testing.md` "Hardware verification gates",
`blueprint/desktop.md` Backends/Freshness). Task-shaped, not CI; the
harness in this directory reproduces every number below.

**Environment:** macOS 26.5.2 (Darwin 25), Apple M3 Pro (virtualized,
8 GiB), FUSE-T 1.2.7 (`org.fuse-t.core.1.2.7`), SMB backend, harness
mounted via the v1 socket-read-patched `fuser` 0.16 (vendored here).
Measured 2026-07-22.

## Verdict summary

| Gate | Check                               | Result                                                                                                                                                                       |
| ---- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | SMB invalidation round-trip latency | **PASS, with `noattrcache` required** — sub-ms coherence with push invalidation; without the option there is a 3 s attr floor and unbounded staleness for client-cached data |
| 2    | v1 cross-client flake replay        | **PASS** — 0/100 flakes (v1/NFS baseline ~15 %); issue-109 churn workload survives with 0 errors                                                                             |
| 3    | Overwrite-rename atomicity          | **PASS** — 0 torn/missing/short reads across 300 overwrite-renames                                                                                                           |
| 4    | Commercial license terms            | **CONDITIONAL** — bundling requires a paid commercial license from the author; free path is user-installed FUSE-T                                                            |
| 5    | FSKit spike (macOS 27 beta)         | **BLOCKED — no macOS 27 beta hardware** (this machine is 26.5.2)                                                                                                             |

No gate failed in a way that reopens the driver decision: FUSE-T ≥ 1.2.7
SMB backend stands, with one new mount-option requirement (`noattrcache`)
and one licensing action item.

## Gate 1 — invalidation round-trip

Reply TTLs handed to the kernel are **ignored** by the stack (confirmed:
FUSE-T wiki "caching attributes returned by the filesystem implementation
are ignored"; measured identically at ttl=3600 s). The macOS smbfs client
imposes its own caches; FUSE-T translates `inval_inode` into SMB
lease/oplock breaks (`LeaseBreak`/`OplockBreakNotification` present in the
1.2.7 server binary).

Default mount options:

| Measurement                               | n   | min     | p50         | p95     | max                        |
| ----------------------------------------- | --- | ------- | ----------- | ------- | -------------------------- |
| data change + `inval_inode`, fresh open   | 30  | 3.2 ms  | 3.8 ms      | 4.1 ms  | 4.2 ms                     |
| size change + `inval_inode` (attr)        | 30  | 3.5 ms  | **3000 ms** | 3002 ms | 3003 ms                    |
| size change, no inval (attr control)      | 5   | 2999 ms | 3000 ms     | 3003 ms | 3003 ms                    |
| new entry + `inval_entry`                 | 30  | 0.4 ms  | 0.5 ms      | 1.7 ms  | 1.9 ms                     |
| data change + `inval_inode`, held-open fd | 30  | 0.3 ms  | —           | —       | **28/30 timeouts (>10 s)** |
| data change, no inval, after pages cached | 5   | —       | —           | —       | **5/5 timeouts (>30 s)**   |

Reading: entry invalidation is effectively instant; attr visibility is
pinned to the smbfs client attr cache (a hard ~3.0 s floor, invalidation
has no effect on it); and once the client has cached data pages,
`inval_inode` fails to reach them — staleness is unbounded.

With `-o noattrcache` (gate 1b):

| Measurement                                    | Result                      |
| ---------------------------------------------- | --------------------------- |
| attr change + inval                            | 0.3–0.6 ms (n=10)           |
| attr change, no inval                          | 0.4–0.5 ms (n=5)            |
| cached data (held-open fd) + one `inval_inode` | **0.0 s**                   |
| cached data, no inval                          | **>300 s, never converged** |

`noattrcache` removes the attr floor entirely and — critically — makes
lease-break invalidation land on already-cached data instantly. Without an
invalidation, cached data never revalidates; that is acceptable because
the engine's push-invalidation contract fires on every remote change
(`blueprint/desktop.md`: host adapters expose push invalidation, driven by
the engine event stream).

Throughput cost of `noattrcache` (gate 1c, 256 MiB sequential):

| Mount       | cold      | warm      |
| ----------- | --------- | --------- |
| default     | 873 MB/s  | 5779 MB/s |
| noattrcache | 1047 MB/s | 6017 MB/s |

None — the data page cache still works; only attr revalidation round-trips
(≈0.3 ms against the localhost server).

### Constants fed to the sync timing profile

- **Kernel entry/attr TTL constants for the FUSE-T SMB backend: none.**
  The open edge in `blueprint/desktop.md` ("Kernel TTL values per
  backend") resolves to _not applicable_ for this backend — the client
  ignores FS-supplied TTLs, so there is no per-backend TTL constant to
  freeze into `SyncTimingProfile`. The backend requirement is instead:
  **mount with `noattrcache` and always fire `inval_inode`/`inval_entry`
  on remote change.**
- **Mount-side invalidation latency budget:** ≤ 5 ms p95 (data, attr, and
  entry). Cross-client staleness is therefore dominated entirely by
  `poll_cadence` (30 s production) + record resolution; the FUSE hop
  contributes nothing material. No profile value changes.

## Gate 2 — v1 cross-client flake replay

Remote create + remote modify, invalidation fired, 2 s visibility
deadline, 100 rounds: **100/100 visible, 0.0 % flake** (v1 on the NFS
backend flaked ~15 %). Run on a default mount — cross-client visibility
via fresh opens does not even need `noattrcache`.

Issue-109 replay (attribute churn + atomic renames, 2 writer threads + 1
reader, 30 s): **103,029 ops, 0 errors, mount alive**. No kext panic
surface — the SMB backend does not touch Apple's NFS client kext.

## Gate 3 — overwrite-rename atomicity

300 overwrite-renames of a 64 KiB target with a concurrent full-file
reader: **7,483 reads — 0 torn, 0 ENOENT, 0 short, 0 errors**.

Mechanics observed at the FUSE layer: the smbfs client implements
overwrite-rename as `rename(target → .smbdeleteXXXX)` + `rename(tmp →
target)` + `unlink(.smbdelete…)` (625 renames / 599 unlinks for 300
user-level renames). Readers never observed an intermediate state. The v1
"rename callback name truncated by 8 bytes" bug did not reproduce on
1.2.7 (0 fallback hits).

Consequence for `crates/fuse`: the projection must tolerate transient
`.smbdelete*` siblings and must not require rename names to arrive as a
single canonical op.

## Gate 4 — FUSE-T commercial license

License (`License.txt` at tag 1.2.7, unchanged since 2022): free for
non-commercial use; **"For commercial use or/and bundling with commercial
software — the software vendor has to obtain a commercial license from
the FUSE-T authors."** No published pricing; contact <alex@fuse-t.org>. The
author has stated (fuse-t issue #1) the license targets exactly our case:
repackaging/re-signing the binaries inside a vendor's app bundle.

- Bundling FUSE-T in CipherBox.app ⇒ requires a negotiated commercial
  license **before v2.0 ships**.
- Free interim path: have users install FUSE-T themselves (official pkg
  or Homebrew) — per the author's stated intent this needs no license.
- `libfuse-t.dylib` (the side we link) is LGPL-2.1: link dynamically,
  ship notices, mirror the library source. No copyleft reaches our code.
- The SMB server component is the author's own dual-licensed code
  (AGPL/commercial); covered by the same negotiation, since he holds the
  copyright.
- Open questions for the author: pricing model; whether auto-downloading
  the unmodified official pkg counts as redistribution; free-tier
  definition of "commercial"; third-party notices for the closed server;
  upgrade rights across 1.x releases.

## Gate 5 — FSKit spike

**Blocked on hardware:** `FSClient.mountSingleVolume` and
`FSVolume.DataCacheHandler` exist only in the macOS 27 beta; this machine
is on 26.5.2. Two notes for when hardware is available:

- FUSE-T 1.2.7 itself now ships an FSKit backend (`org.fuse-t.fskit`
  pkg), but its wiki marks notifications **unsupported** on that backend —
  as shipped it would reintroduce the gate-1 staleness problem, so it is
  not a shortcut around the native-FSKit spike.
- The spike still needs hands-on confirmation of `DataCacheHandler`
  invalidation semantics before the successor timeline in
  `blueprint/desktop.md` is committed.

## Reproducing

```sh
cd tools/hw-gates
cargo run --release -- gate1   # invalidation latency + controls
cargo run --release -- gate1b  # noattrcache + staleness horizon
cargo run --release -- gate1c  # throughput A/B
cargo run --release -- gate2   # flake replay + churn
cargo run --release -- gate3   # rename atomicity
```

Requires FUSE-T ≥ 1.2.7 installed (no kext, no sudo). If macFUSE is also
installed, the vendored fuser's build script prefers `fuse-t.pc` — do not
link `fuse.pc`, it belongs to macFUSE and will trigger its kext.

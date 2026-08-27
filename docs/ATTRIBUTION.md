# Attribution

Third-party components CipherBox ships or links, and the notices their licences
ask for.

CipherBox itself is [MIT](../LICENSE). A component listed here carries its own
licence, and where that licence reaches the combined work, the row says so.

## WinFsp — the Windows mount backend

> WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos

Project: <https://github.com/winfsp/winfsp>

CipherBox's Windows desktop app projects the vault as a filesystem through
[WinFsp](https://github.com/winfsp/winfsp), reached from `crates/fuse`'s WinFsp
host adapter over the [winfsp-rs](https://github.com/SnowflakePowered/winfsp-rs)
binding. WinFsp and winfsp-rs are both **GPLv3**, and the Windows build is a
combined work with them: it is distributed under GPLv3, with WinFsp's
[commercial licence](https://winfsp.dev/) as the alternative for a distribution
that cannot be.

The notice above is shown to the user as well as stated here — the desktop
shell carries it and the project address on every screen
(`apps/desktop/src/frontDoor.ts`).

CipherBox bundles no proprietary software alongside WinFsp.

The mount's access control is this backend's own work rather than the kernel's:
WinFsp asks the filesystem for a security descriptor and grants a caller
whatever it requested when none is reported, so `crates/fuse` serves an
owner-only descriptor for every node. The two Windows calls that cannot be made
in safe Rust live in `crates/win-security`, apart from the projection, which
forbids `unsafe`.

The pinned WinFsp release CI provisions, and the digest it is verified against,
live in [`.github/actions/setup-winfsp/action.yml`](../.github/actions/setup-winfsp/action.yml).

## FUSE-T — the macOS mount backend

Project: <https://github.com/macos-fuse-t/fuse-t>

The macOS app mounts through FUSE-T's SMB backend. FUSE-T ships under its own
terms and is installed by the user's machine rather than bundled; nothing of it
is linked into a CipherBox binary beyond its libfuse ABI.

The pinned release CI provisions lives in
[`.github/actions/setup-fuse-t/action.yml`](../.github/actions/setup-fuse-t/action.yml).

## libfuse / `fuser` — the Linux mount backend

Project: <https://github.com/cberner/fuser>

The Linux app speaks the FUSE wire through a vendored copy of `fuser`
(`third-party/fuser`, MIT), carrying a socket-read patch for the FUSE-T shim the
macOS backend shares with it. Its own licence and notices travel with the
vendored tree.

# FUSE-T SMB Backend and Fuser Socket Patch

**Date:** 2026-02-18

## Original Prompt

> Test FUSE filesystem operations: many small files, 50MB+ file, other useful tests. Fix failures atomically.

## What I Learned

### macOS NFS Client Write Bug (Unfixable)

- macOS Sequoia 15.3 (Darwin 25.3.0) has a kernel bug where the NFS client never sends WRITE RPCs to FUSE-T's NFS server for newly created files. The process hangs permanently.
- FUSE-T author confirmed: "lockups occur in the macos NFS client code before it reaches the server" — reported to Apple, no fix available.
- `FOPEN_DIRECT_IO` flag does NOT help — it's between the FUSE daemon and FUSE-T, not between the macOS NFS client and FUSE-T.
- `noattrcache` mount option breaks file creation entirely (NFS interprets it as `noacc`, disabling access checks).
- **Solution: switch to SMB backend** via `MountOption::CUSTOM("backend=smb".to_string())`.

### FUSE-T SMB Backend Quirks

- Mount shows as `smbfs` instead of `nfs` — functionally equivalent for our purposes.
- `opendir` MUST return non-zero file handles. SMB treats `fh=0` as "no handle", causing `queryDirectory: err bad file descriptor`.
- SMB rename (`mv`) fails with EPERM — the macOS SMB client rejects before the request reaches FUSE-T. Open issue, not yet investigated.
- SMB mount options include `noowners` which changes how permission checks work.

### Fuser Socket Read Incompatibility (The Big One)

- Stock fuser assumes `/dev/fuse` which delivers complete FUSE messages atomically (one `read()` = one message).
- FUSE-T uses a **Unix domain socket** where:
  - **Large messages fragment:** A 1MB write arrives in multiple `read()` calls (e.g., 327KB + 721KB).
  - **Small messages coalesce:** Multiple FUSE requests can be buffered together in one `read()`.
- Stock fuser's single `read()` fails with `Short read of FUSE request (N < M)` and kills the FUSE session.

### The Fix: Peek-Based Receive

Vendored fuser 0.16 with patched `channel.rs:receive()`:

1. **Peek** at first 4 bytes via `recv(fd, buf, 4, MSG_PEEK)` — reads the FUSE header `len` field without consuming socket data.
2. **Read exactly** `len` bytes via loop of `read(fd, buf+offset, remaining)` — prevents both short reads (fragmentation) and over-reads (coalescing).

The first attempt (loop-read without peek) failed because the initial `read()` with `buffer.len()` (16MB) consumed data from the next message, causing stream misalignment. The symptom was a "valid" header with `len=3.3GB` — actually bytes from the middle of a different message.

### What Didn't Work

| Approach                                   | Result                                             |
| ------------------------------------------ | -------------------------------------------------- |
| `FOPEN_DIRECT_IO` (0x1) flag               | No effect on NFS write stall                       |
| `noattrcache` mount option                 | Broke file creation (NFS `noacc`)                  |
| `rwsize=65536` mount option                | FUSE-T ignored it for FUSE-level write sizing      |
| `config.set_max_write(256*1024)` in init() | SMB backend bypasses FUSE init negotiation         |
| Loop-read without peek (first patch)       | Over-read caused stream misalignment on 50MB files |

### Test Results with Final Fix

| Test                       | Result                                             |
| -------------------------- | -------------------------------------------------- |
| Single file write+read     | Pass                                               |
| 20 rapid small files       | Pass                                               |
| 10MB binary write+verify   | Pass (checksum match)                              |
| 50MB binary write+verify   | Pass (checksum match)                              |
| 100MB binary write+verify  | Pass (checksum match, upload 413 — API size limit) |
| File deletion (rm)         | Pass                                               |
| Directory creation (mkdir) | Pass                                               |
| Nested file write          | Pass                                               |
| File rename (mv)           | Fail (SMB EPERM — macOS client issue)              |

## What Would Have Helped

- Knowing upfront that FUSE-T communicates via Unix domain socket (not `/dev/fuse`) would have saved hours of debugging the "Short read" crash.
- A FUSE-T README section explaining the NFS write bug and recommending SMB backend.
- The fuser crate should handle socket-based FUSE transports — this is a general issue for any non-kernel FUSE implementation.

## Implications for Windows/Linux

- **Linux (kernel FUSE):** None of these issues apply. Kernel FUSE uses `/dev/fuse` with atomic message delivery. No need for SMB backend or fuser patching. The vendored fuser with socket patch is harmless on Linux (peek returns the same data, loop-read completes in one iteration).
- **Windows (WinFSP/Dokan):** Different FUSE implementation entirely. WinFSP has its own IPC mechanism. The fuser crate is not used on Windows. However, the same _principle_ applies: verify the IPC transport is reliable for large messages before assuming atomic delivery.
- **Cross-platform strategy:** Keep the fuser vendor patch for macOS. On Linux, consider switching back to upstream fuser (or keep the patch — it's a no-op with `/dev/fuse`). On Windows, use a native filesystem driver library.

## Key Files

- `apps/desktop/src-tauri/vendor/fuser/src/channel.rs` — Patched receive() with peek-based loop-read
- `apps/desktop/src-tauri/src/fuse/mod.rs` — Mount options (SMB backend), debounced publish, pre-populate
- `apps/desktop/src-tauri/src/fuse/operations.rs` — FUSE callbacks (opendir non-zero fh fix)
- `apps/desktop/src-tauri/Cargo.toml` — `[patch.crates-io]` for vendored fuser

# gate-5 FSKit spike

Standalone macOS-27 FSKit spike for issue #644 gate 5 (the FSKit successor-
backend check). Not CI, not shipped — a throwaway harness that answers whether
`FSVolume.DataCacheHandler` gives us a working push-invalidation primitive
before the `blueprint/desktop.md` successor timeline is committed. Findings and
measurements: [`RESULTS.md`](RESULTS.md).

## Layout

| Path       | What it is                                                                                                                                                                                                                                                                    |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `module/`  | The FSKit module: an in-memory unary file system (`Gate5FS`/`Gate5Volume`) conforming to `FSVolumeDataCacheHandler`. Control plane over xattrs: `setxattr("g5.cmd", …)` mutates server-side state or fires `setCacheStateForItem`; `getxattr("g5.log")` drains the event log. |
| `host/`    | Stub container app (`Gate5Host.app`) the appex lives inside.                                                                                                                                                                                                                  |
| `client/`  | `g5mount` — entitled control client (`list` / `enable` / `mount`), declaring the private FSKit + LiveFS entitlements.                                                                                                                                                         |
| `harness/` | `g5probe` (model overview), `g5inval` (single-triple invalidation trial), `g5sweep` (coherency-triple brute force).                                                                                                                                                           |
| `Makefile` | CLT-only build; ad-hoc signs the appex with `com.apple.developer.fskit.fsmodule`.                                                                                                                                                                                             |

## Requirements

macOS 27, SIP disabled, `boot-args=amfi_get_out_of_my_way=1` — so an ad-hoc
signed binary carrying the restricted FSKit entitlements is allowed to load
without an Apple Developer team or Xcode. This is a spike rig for a disposable
beta VM, **not** a template for anything shipped: the real desktop app signs the
FSKit appex with the team cert and the user enables it through System Settings.

See [`RESULTS.md`](RESULTS.md) for the build gotchas (NSExtensionMain entry,
`ready` container state, privileged enablement) that a real `crates/fuse` FSKit
adapter must get right.

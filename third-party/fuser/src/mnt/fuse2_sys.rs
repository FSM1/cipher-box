//! Native FFI bindings to libfuse2.
//!
//! This is a small set of bindings that are required to mount/unmount FUSE filesystems and
//! open/close a fd to the FUSE kernel driver.

#![warn(missing_debug_implementations)]
#![allow(missing_docs)]

use libc::{c_char, c_int};

#[repr(C)]
#[derive(Debug)]
pub struct fuse_args {
    pub argc: c_int,
    pub argv: *const *const c_char,
    pub allocated: c_int,
}

#[cfg(fuser_mount_impl = "libfuse2")]
unsafe extern "C" {
    // *_compat25 functions were introduced in FUSE 2.6 when function signatures changed.
    // Therefore, the minimum version requirement for *_compat25 functions is libfuse-2.6.0.

    #[cfg(not(fuser_fuse_t))]
    pub fn fuse_mount_compat25(mountpoint: *const c_char, args: *const fuse_args) -> c_int;
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    pub fn fuse_unmount_compat22(mountpoint: *const c_char);
}

/// The mount-status callback of FUSE-T's `fuse_kern_mount`: the context, the
/// status, and the monitor socket.
#[cfg(fuser_fuse_t)]
pub type FuseMountCallback = unsafe extern "C" fn(*mut libc::c_void, c_int, c_int);

#[cfg(fuser_fuse_t)]
unsafe extern "C" {
    /// FUSE-T's mount: `fuse_mount_compat25` is this with no callback.
    pub fn fuse_kern_mount(
        mountpoint: *const c_char,
        args: *const fuse_args,
        callback: Option<FuseMountCallback>,
        context: *mut libc::c_void,
    ) -> c_int;
}

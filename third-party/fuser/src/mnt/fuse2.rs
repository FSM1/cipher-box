use super::{MountOption, fuse2_sys::*, with_fuse_args};
use log::warn;
use std::{
    ffi::CString,
    fs::File,
    io,
    os::unix::prelude::{FromRawFd, OsStrExt},
    path::Path,
    sync::Arc,
};

/// Ensures that an os error is never 0/Success
fn ensure_last_os_error() -> io::Error {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(0) => io::Error::other("Unspecified Error"),
        _ => err,
    }
}

#[derive(Debug)]
pub struct Mount {
    mountpoint: CString,
    /// The mount point as the mount table spells it.
    #[cfg(fuser_fuse_t)]
    listed_as: CString,
    #[cfg(fuser_fuse_t)]
    server: super::fuse_t::Server,
}
impl Mount {
    pub fn new(mountpoint: &Path, options: &[MountOption]) -> io::Result<(Arc<File>, Mount)> {
        // Resolved before the mount: a resolve after it reads through the mount.
        #[cfg(fuser_fuse_t)]
        let listed_as =
            CString::new(std::fs::canonicalize(mountpoint)?.as_os_str().as_bytes()).unwrap();
        #[cfg(fuser_fuse_t)]
        super::fuse_t::await_exits(&listed_as, super::fuse_t::EXIT_WITHIN)?;
        let mountpoint = CString::new(mountpoint.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, |args| {
            #[cfg(fuser_fuse_t)]
            let server = super::fuse_t::Server::new();
            #[cfg(fuser_fuse_t)]
            let fd = unsafe {
                fuse_kern_mount(
                    mountpoint.as_ptr(),
                    args,
                    Some(super::fuse_t::delivered),
                    server.context(),
                )
            };
            #[cfg(not(fuser_fuse_t))]
            let fd = unsafe { fuse_mount_compat25(mountpoint.as_ptr(), args) };
            if fd < 0 {
                Err(ensure_last_os_error())
            } else {
                let file = unsafe { File::from_raw_fd(fd) };
                Ok((
                    Arc::new(file),
                    Mount {
                        mountpoint,
                        #[cfg(fuser_fuse_t)]
                        listed_as,
                        #[cfg(fuser_fuse_t)]
                        server,
                    },
                ))
            }
        })
    }
}
impl Drop for Mount {
    fn drop(&mut self) {
        use std::io::ErrorKind::PermissionDenied;

        // fuse_unmount_compat22 unfortunately doesn't return a status. Additionally,
        // it attempts to call realpath, which in turn calls into the filesystem. So
        // if the filesystem returns an error, the unmount does not take place, with
        // no indication of the error available to the caller. So we call unmount
        // directly, which is what osxfuse does anyway, since we already converted
        // to the real path when we first mounted.
        let unmounted = super::libc_umount(&self.mountpoint);
        if let Err(err) = &unmounted {
            // Linux always returns EPERM for non-root users.  We have to let the
            // library go through the setuid-root "fusermount -u" to unmount.
            if err.kind() == PermissionDenied {
                #[cfg(not(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "openbsd",
                    target_os = "netbsd"
                )))]
                unsafe {
                    fuse_unmount_compat22(self.mountpoint.as_ptr());
                    return;
                }
            }
            warn!("umount failed with {err:?}");
        }
        // CipherBox patch: neither unmount above ends the FUSE-T server.
        #[cfg(fuser_fuse_t)]
        self.server.release(
            &self.listed_as,
            unmounted.is_ok(),
            super::fuse_t::mounted_at,
        );
    }
}

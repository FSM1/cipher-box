//! FUSE filesystem trait implementation for CipherBoxFS.
//!
//! Delegates to category-specific modules:
//! - `read_ops`: init, destroy, lookup, getattr, open, read, release, flush, access, getxattr, listxattr
//! - `write_ops`: setattr, write, create, unlink, mkdir, rmdir, rename
//! - `dir_ops`: readdir, opendir, releasedir, statfs

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    use fuser::{
        Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
        ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request,
    };
    use std::ffi::OsStr;
    use std::time::{Duration, SystemTime};

    use crate::CipherBoxFS;

    /// TTL for FUSE attribute/entry cache replies on files.
    pub const FILE_TTL: Duration = Duration::from_secs(60);

    /// TTL for directory attribute/entry cache replies.
    pub const DIR_TTL: Duration = Duration::from_secs(0);

    pub fn ttl_for_is_dir(is_dir: bool) -> Duration {
        if is_dir {
            DIR_TTL
        } else {
            FILE_TTL
        }
    }

    pub fn current_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    pub fn current_gid() -> u32 {
        unsafe { libc::getgid() }
    }

    pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);

    pub fn block_with_timeout<F, T>(rt: &tokio::runtime::Handle, fut: F) -> Result<T, String>
    where
        F: std::future::Future<Output = Result<T, String>>,
    {
        rt.block_on(async {
            match tokio::time::timeout(NETWORK_TIMEOUT, fut).await {
                Ok(result) => result,
                Err(_) => Err("Operation timed out".to_string()),
            }
        })
    }

    /// Synchronous (FUSE-callback-thread) node/v3 content fetch + decrypt.
    ///
    /// SIGNATURE CHANGE (69-09 Slice 5b): the former
    /// `(cid, encrypted_file_key_hex, iv_hex, encryption_mode)` params are gone.
    /// node/v3 recovers the content descriptors + file_key by SYMMETRIC unseal of
    /// the file node's OWN read-body — so this now takes the file's `ipns_name` +
    /// its `read_key` and resolves the node through the gated
    /// [`cipherbox_sdk::fetch_node_gated`] wrapper (SC#6). `read_key` is a
    /// caller-owned borrow (D-09). Bounded by the macOS 3s `NETWORK_TIMEOUT`.
    pub fn fetch_and_decrypt_file_content(
        fs: &CipherBoxFS,
        ipns_name: &str,
        read_key: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let api = fs.api.clone();
        let high_water = fs.high_water.clone();
        let ipns_owned = ipns_name.to_string();
        let read_key_owned = *read_key;
        let rt = fs.rt.clone();

        block_with_timeout(&rt, async move {
            crate::content_ops::fetch_node_and_decrypt_content(
                &api,
                &high_water,
                &ipns_owned,
                &read_key_owned,
            )
            .await
        })
    }

    // Re-export shared async helpers from content_ops (Tier-2 dedup, Plan 55-03).
    // fetch_and_decrypt_file_content is NOT re-exported here: it uses a private
    // NETWORK_TIMEOUT = 3s (vs 10s in crate::block_with_timeout) which is
    // intentional for the macOS sync FUSE callback path (A2 scope narrowing).
    pub use crate::content_ops::{
        fetch_and_decrypt_content_async, fetch_node_and_decrypt_content, publish_file_metadata,
        resolve_file_descriptors,
    };

    impl Filesystem for CipherBoxFS {
        fn init(
            &mut self,
            _req: &Request<'_>,
            config: &mut fuser::KernelConfig,
        ) -> Result<(), libc::c_int> {
            crate::read_ops::implementation::handle_init(self, config)
        }

        fn destroy(&mut self) {
            crate::read_ops::implementation::handle_destroy(self);
        }

        fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
            crate::read_ops::implementation::handle_lookup(self, parent, name, reply);
        }

        fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
            crate::read_ops::implementation::handle_getattr(self, ino, reply);
        }

        fn setattr(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _mode: Option<u32>,
            _uid: Option<u32>,
            _gid: Option<u32>,
            size: Option<u64>,
            _atime: Option<fuser::TimeOrNow>,
            _mtime: Option<fuser::TimeOrNow>,
            _ctime: Option<SystemTime>,
            fh: Option<u64>,
            _crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<u32>,
            reply: ReplyAttr,
        ) {
            crate::write_ops::implementation::handle_setattr(self, ino, size, fh, reply);
        }

        fn readdir(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            reply: ReplyDirectory,
        ) {
            crate::dir_ops::implementation::handle_readdir(self, ino, offset, reply);
        }

        fn create(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            flags: i32,
            reply: ReplyCreate,
        ) {
            crate::write_ops::implementation::handle_create(self, parent, name, flags, reply);
        }

        fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
            crate::read_ops::implementation::handle_open(self, ino, flags, reply);
        }

        fn write(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            offset: i64,
            data: &[u8],
            _write_flags: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyWrite,
        ) {
            crate::write_ops::implementation::handle_write(self, ino, fh, offset, data, reply);
        }

        fn read(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            offset: i64,
            size: u32,
            _flags: i32,
            _lock: Option<u64>,
            reply: ReplyData,
        ) {
            crate::read_ops::implementation::handle_read(self, ino, fh, offset, size, reply);
        }

        fn release(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            _flags: i32,
            _lock_owner: Option<u64>,
            _flush: bool,
            reply: ReplyEmpty,
        ) {
            crate::read_ops::implementation::handle_release(self, ino, fh, reply);
        }

        fn flush(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _fh: u64,
            _lock_owner: u64,
            reply: ReplyEmpty,
        ) {
            crate::read_ops::implementation::handle_flush(reply);
        }

        fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            crate::write_ops::implementation::handle_unlink(self, parent, name, reply);
        }

        fn mkdir(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            reply: ReplyEntry,
        ) {
            crate::write_ops::implementation::handle_mkdir(self, parent, name, reply);
        }

        fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            crate::write_ops::implementation::handle_rmdir(self, parent, name, reply);
        }

        fn rename(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            newparent: u64,
            newname: &OsStr,
            _flags: u32,
            reply: ReplyEmpty,
        ) {
            crate::write_ops::implementation::handle_rename(
                self, parent, name, newparent, newname, reply,
            );
        }

        fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
            crate::dir_ops::implementation::handle_statfs(self, reply);
        }

        fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
            crate::read_ops::implementation::handle_access(self, ino, mask, reply);
        }

        fn getxattr(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _name: &OsStr,
            _size: u32,
            reply: ReplyXattr,
        ) {
            crate::read_ops::implementation::handle_getxattr(reply);
        }

        fn listxattr(&mut self, _req: &Request<'_>, _ino: u64, size: u32, reply: ReplyXattr) {
            crate::read_ops::implementation::handle_listxattr(size, reply);
        }

        fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
            crate::dir_ops::implementation::handle_opendir(self, ino, reply);
        }

        fn releasedir(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _fh: u64,
            _flags: i32,
            reply: ReplyEmpty,
        ) {
            crate::dir_ops::implementation::handle_releasedir(reply);
        }
    }
}

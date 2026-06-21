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
    use zeroize::Zeroizing;

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

    /// Build a `Zeroizing<[u8; 32]>` from a slice without ever materializing a
    /// plain `[u8; 32]` temporary (preallocate-then-copy). A `try_into()` would
    /// briefly leave an un-zeroed copy of sensitive key material on the stack.
    fn zeroizing_32_from_slice(bytes: &[u8], message: &str) -> Result<Zeroizing<[u8; 32]>, String> {
        if bytes.len() != 32 {
            return Err(message.to_string());
        }
        let mut out = Zeroizing::new([0_u8; 32]);
        out.copy_from_slice(bytes);
        Ok(out)
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

    pub fn fetch_and_decrypt_file_content(
        fs: &CipherBoxFS,
        cid: &str,
        encrypted_file_key_hex: &str,
        iv_hex: &str,
        encryption_mode: &str,
    ) -> Result<Vec<u8>, String> {
        let api = fs.api.clone();
        let private_key = fs.private_key.clone();
        let cid_owned = cid.to_string();
        let key_hex = encrypted_file_key_hex.to_string();
        let iv_hex_owned = iv_hex.to_string();
        let mode = encryption_mode.to_string();
        let rt = fs.rt.clone();

        block_with_timeout(&rt, async {
            let encrypted_bytes = cipherbox_api_client::ipfs::fetch_content(&api, &cid_owned)
                .await
                .map_err(|e| format!("{}", e))?;
            let encrypted_file_key =
                hex::decode(&key_hex).map_err(|_| "Invalid file key hex".to_string())?;
            // unwrap_key returns Zeroizing<Vec<u8>> (S3/D-05).
            let file_key = cipherbox_crypto::unwrap_key(&encrypted_file_key, &private_key)
                .map_err(|e| format!("File key unwrap failed: {}", e))?;
            let file_key_arr =
                zeroizing_32_from_slice(file_key.as_slice(), "Invalid file key length")?;

            let plaintext = if mode == "CTR" {
                let iv =
                    hex::decode(&iv_hex_owned).map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 16] = iv
                    .try_into()
                    .map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
                cipherbox_crypto::decrypt_aes_ctr(&encrypted_bytes, &file_key_arr, &iv_arr)
                    .map_err(|e| format!("CTR file decryption failed: {}", e))?
            } else {
                let iv =
                    hex::decode(&iv_hex_owned).map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 12] = iv
                    .try_into()
                    .map_err(|_| "Invalid GCM IV length (expected 12)".to_string())?;
                cipherbox_crypto::decrypt_aes_gcm(&encrypted_bytes, &file_key_arr, &iv_arr)
                    .map_err(|e| format!("GCM file decryption failed: {}", e))?
            };
            Ok(plaintext)
        })
    }

    // Re-export shared async helpers from content_ops (Tier-2 dedup, Plan 55-03).
    // fetch_and_decrypt_file_content is NOT re-exported here: it uses a private
    // NETWORK_TIMEOUT = 3s (vs 10s in crate::block_with_timeout) which is
    // intentional for the macOS sync FUSE callback path (A2 scope narrowing).
    pub use crate::content_ops::{fetch_and_decrypt_content_async, publish_file_metadata};

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

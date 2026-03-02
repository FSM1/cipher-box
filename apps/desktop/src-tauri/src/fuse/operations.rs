//! FUSE filesystem trait implementation for CipherBoxFS.
//!
//! Delegates to category-specific modules:
//! - `read_ops`: init, destroy, lookup, getattr, open, read, release, flush, access, getxattr, listxattr
//! - `write_ops`: setattr, write, create, unlink, mkdir, rmdir, rename
//! - `dir_ops`: readdir, opendir, releasedir, statfs
//!
//! IMPORTANT: All async operations use block_on from the tokio runtime.
//! FUSE requires synchronous replies, so we block on async operations as needed.

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    use fuser::{
        Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
        ReplyEntry, ReplyEmpty, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request,
    };
    use std::ffi::OsStr;
    use std::time::{Duration, SystemTime};

    use crate::fuse::CipherBoxFS;

    // ── Shared constants and helpers ────────────────────────────────────────

    /// TTL for FUSE attribute/entry cache replies on files.
    pub const FILE_TTL: Duration = Duration::from_secs(60);

    /// TTL for directory attribute/entry cache replies.
    pub const DIR_TTL: Duration = Duration::from_secs(0);

    /// Pick the right TTL based on whether the inode is a directory.
    pub fn ttl_for_is_dir(is_dir: bool) -> Duration {
        if is_dir { DIR_TTL } else { FILE_TTL }
    }

    /// Get the current process UID (macOS only).
    pub fn current_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    /// Get the current process GID (macOS only).
    pub fn current_gid() -> u32 {
        unsafe { libc::getgid() }
    }

    /// Maximum time for a network operation before returning EIO.
    pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);

    /// Run an async operation with a timeout, blocking the current thread.
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

    /// Helper: Fetch, decrypt, and populate a folder's children.
    pub fn fetch_and_populate_folder(
        fs: &mut CipherBoxFS,
        ino: u64,
        ipns_name: &str,
        folder_key: &[u8],
    ) -> Result<(), String> {
        let api = fs.api.clone();
        let ipns_name_owned = ipns_name.to_string();
        let folder_key_owned = folder_key.to_vec();
        let private_key = fs.private_key.clone();

        let rt = fs.rt.clone();
        let result = block_with_timeout(&rt, async {
            let resolve_resp =
                crate::api::ipns::resolve_ipns(&api, &ipns_name_owned).await?;
            let encrypted_bytes =
                crate::api::ipfs::fetch_content(&api, &resolve_resp.cid).await?;
            Ok::<(Vec<u8>, String), String>((encrypted_bytes, resolve_resp.cid))
        })?;

        let (encrypted_bytes, cid) = result;

        let metadata = crate::fuse::decrypt::decrypt_metadata_from_ipfs_public(&encrypted_bytes, &folder_key_owned)?;

        fs.metadata_cache.set(&ipns_name.to_string(), metadata.clone(), cid);

        fs.inodes.populate_folder(ino, &metadata, &private_key, &fs.public_key, false)?;

        let unresolved = fs.inodes.get_unresolved_file_pointers();
        if !unresolved.is_empty() {
            log::info!("Resolving {} FilePointer(s) for folder ino {}", unresolved.len(), ino);
            resolve_file_pointers_blocking(fs, &unresolved, &folder_key_owned)?;
        }

        Ok(())
    }

    /// Resolve FilePointer inodes by fetching and decrypting per-file IPNS metadata.
    pub fn resolve_file_pointers_blocking(
        fs: &mut CipherBoxFS,
        unresolved: &[(u64, String)],
        folder_key: &[u8],
    ) -> Result<(), String> {
        let api = fs.api.clone();
        let rt = fs.rt.clone();
        let folder_key_arr: [u8; 32] = folder_key.try_into()
            .map_err(|_| "Invalid folder key length for FilePointer resolution".to_string())?;

        for (ino, ipns_name) in unresolved {
            let resolve_result = block_with_timeout(&rt, async {
                let resp = crate::api::ipns::resolve_ipns(&api, ipns_name).await?;
                let encrypted_bytes = crate::api::ipfs::fetch_content(&api, &resp.cid).await?;
                Ok::<Vec<u8>, String>(encrypted_bytes)
            });

            match resolve_result {
                Ok(encrypted_bytes) => {
                    match crate::fuse::decrypt::decrypt_file_metadata_from_ipfs_public(&encrypted_bytes, &folder_key_arr) {
                        Ok(file_meta) => {
                            fs.inodes.resolve_file_pointer(
                                *ino,
                                file_meta.cid,
                                file_meta.file_key_encrypted,
                                file_meta.file_iv,
                                file_meta.size,
                                file_meta.encryption_mode,
                                file_meta.versions,
                            );
                        }
                        Err(e) => {
                            log::warn!(
                                "FilePointer resolution failed for ino {} ({}): {}",
                                ino, ipns_name, e
                            );
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "FilePointer IPNS resolve failed for ino {} ({}): {}",
                        ino, ipns_name, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Helper: Fetch and decrypt existing file content for editing.
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
            let encrypted_bytes =
                crate::api::ipfs::fetch_content(&api, &cid_owned).await?;
            let encrypted_file_key = hex::decode(&key_hex)
                .map_err(|_| "Invalid file key hex".to_string())?;
            let file_key = zeroize::Zeroizing::new(
                crate::crypto::ecies::unwrap_key(&encrypted_file_key, &private_key)
                    .map_err(|e| format!("File key unwrap failed: {}", e))?,
            );
            let file_key_arr: [u8; 32] = file_key.as_slice().try_into()
                .map_err(|_| "Invalid file key length".to_string())?;

            let plaintext = if mode == "CTR" {
                let iv = hex::decode(&iv_hex_owned)
                    .map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 16] = iv.try_into()
                    .map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
                crate::crypto::aes_ctr::decrypt_aes_ctr(&encrypted_bytes, &file_key_arr, &iv_arr)
                    .map_err(|e| format!("CTR file decryption failed: {}", e))?
            } else {
                let iv = hex::decode(&iv_hex_owned)
                    .map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 12] = iv.try_into()
                    .map_err(|_| "Invalid GCM IV length (expected 12)".to_string())?;
                crate::crypto::aes::decrypt_aes_gcm(
                    &encrypted_bytes, &file_key_arr, &iv_arr,
                )
                .map_err(|e| format!("GCM file decryption failed: {}", e))?
            };

            Ok(plaintext)
        })
    }

    /// Async version of content download + decrypt for use in background prefetch tasks.
    pub async fn fetch_and_decrypt_content_async(
        api: &crate::api::client::ApiClient,
        cid: &str,
        encrypted_file_key_hex: &str,
        iv_hex: &str,
        encryption_mode: &str,
        private_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        let encrypted_bytes =
            crate::api::ipfs::fetch_content(api, cid).await?;
        let encrypted_file_key = hex::decode(encrypted_file_key_hex)
            .map_err(|_| "Invalid file key hex".to_string())?;
        let file_key = zeroize::Zeroizing::new(
            crate::crypto::ecies::unwrap_key(&encrypted_file_key, private_key)
                .map_err(|e| format!("File key unwrap failed: {}", e))?,
        );
        let file_key_arr: [u8; 32] = file_key.as_slice().try_into()
            .map_err(|_| "Invalid file key length".to_string())?;

        let plaintext = if encryption_mode == "CTR" {
            let iv = hex::decode(iv_hex)
                .map_err(|_| "Invalid file IV hex".to_string())?;
            let iv_arr: [u8; 16] = iv.try_into()
                .map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
            crate::crypto::aes_ctr::decrypt_aes_ctr(&encrypted_bytes, &file_key_arr, &iv_arr)
                .map_err(|e| format!("CTR decryption failed: {}", e))?
        } else {
            let iv = hex::decode(iv_hex)
                .map_err(|_| "Invalid file IV hex".to_string())?;
            let iv_arr: [u8; 12] = iv.try_into()
                .map_err(|_| "Invalid GCM IV length (expected 12)".to_string())?;
            crate::crypto::aes::decrypt_aes_gcm(&encrypted_bytes, &file_key_arr, &iv_arr)
                .map_err(|e| format!("GCM decryption failed: {}", e))?
        };

        Ok(plaintext)
    }

    /// Encrypt and publish per-file FileMetadata to the file's own IPNS record.
    pub async fn publish_file_metadata(
        api: &crate::api::client::ApiClient,
        file_meta: &crate::crypto::folder::FileMetadata,
        folder_key: &[u8],
        file_ipns_private_key: &zeroize::Zeroizing<Vec<u8>>,
        file_ipns_name: &str,
        coordinator: &crate::fuse::PublishCoordinator,
    ) -> Result<(), String> {
        let folder_key_arr: [u8; 32] = folder_key
            .try_into()
            .map_err(|_| "Invalid folder key length for FileMetadata encryption".to_string())?;

        let sealed = crate::crypto::folder::encrypt_file_metadata(file_meta, &folder_key_arr)
            .map_err(|e| format!("FileMetadata encryption failed: {}", e))?;

        let iv_hex = hex::encode(&sealed[..12]);
        use base64::Engine;
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
        let json = serde_json::json!({ "iv": iv_hex, "data": data_base64 });
        let json_bytes = serde_json::to_vec(&json)
            .map_err(|e| format!("FileMetadata JSON serialization failed: {}", e))?;

        let file_meta_cid = crate::api::ipfs::upload_content(api, &json_bytes).await?;

        let seq = coordinator.resolve_sequence(api, file_ipns_name).await?;

        let ipns_key_arr: [u8; 32] = file_ipns_private_key.as_slice()
            .try_into()
            .map_err(|_| "Invalid file IPNS private key length".to_string())?;
        let new_seq = seq + 1;
        let value = format!("/ipfs/{}", file_meta_cid);
        let record = crate::crypto::ipns::create_ipns_record(
            &ipns_key_arr,
            &value,
            new_seq,
            86_400_000,
        )
        .map_err(|e| format!("File IPNS record creation failed: {}", e))?;
        let marshaled = crate::crypto::ipns::marshal_ipns_record(&record)
            .map_err(|e| format!("File IPNS record marshal failed: {}", e))?;

        let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

        let req = crate::api::ipns::IpnsPublishRequest {
            ipns_name: file_ipns_name.to_string(),
            record: record_b64,
            metadata_cid: file_meta_cid.clone(),
            encrypted_ipns_private_key: None,
            key_epoch: None,
        };
        crate::api::ipns::publish_ipns(api, &req).await?;

        coordinator.record_publish(file_ipns_name, new_seq);
        log::info!("Per-file IPNS publish succeeded for {}", file_ipns_name);

        Ok(())
    }

    // ── Filesystem trait implementation (delegates to sub-modules) ──────────

    impl Filesystem for CipherBoxFS {
        fn init(
            &mut self,
            _req: &Request<'_>,
            config: &mut fuser::KernelConfig,
        ) -> Result<(), libc::c_int> {
            crate::fuse::read_ops::implementation::handle_init(self, config)
        }

        fn destroy(&mut self) {
            crate::fuse::read_ops::implementation::handle_destroy(self);
        }

        fn lookup(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            reply: ReplyEntry,
        ) {
            crate::fuse::read_ops::implementation::handle_lookup(self, parent, name, reply);
        }

        fn getattr(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: Option<u64>,
            reply: ReplyAttr,
        ) {
            crate::fuse::read_ops::implementation::handle_getattr(self, ino, reply);
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
            crate::fuse::write_ops::implementation::handle_setattr(self, ino, size, fh, reply);
        }

        fn readdir(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            reply: ReplyDirectory,
        ) {
            crate::fuse::dir_ops::implementation::handle_readdir(self, ino, offset, reply);
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
            crate::fuse::write_ops::implementation::handle_create(self, parent, name, flags, reply);
        }

        fn open(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            flags: i32,
            reply: ReplyOpen,
        ) {
            crate::fuse::read_ops::implementation::handle_open(self, ino, flags, reply);
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
            crate::fuse::write_ops::implementation::handle_write(self, ino, fh, offset, data, reply);
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
            crate::fuse::read_ops::implementation::handle_read(self, ino, fh, offset, size, reply);
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
            crate::fuse::read_ops::implementation::handle_release(self, ino, fh, reply);
        }

        fn flush(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _fh: u64,
            _lock_owner: u64,
            reply: ReplyEmpty,
        ) {
            crate::fuse::read_ops::implementation::handle_flush(reply);
        }

        fn unlink(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            reply: ReplyEmpty,
        ) {
            crate::fuse::write_ops::implementation::handle_unlink(self, parent, name, reply);
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
            crate::fuse::write_ops::implementation::handle_mkdir(self, parent, name, reply);
        }

        fn rmdir(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            reply: ReplyEmpty,
        ) {
            crate::fuse::write_ops::implementation::handle_rmdir(self, parent, name, reply);
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
            crate::fuse::write_ops::implementation::handle_rename(self, parent, name, newparent, newname, reply);
        }

        fn statfs(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            reply: ReplyStatfs,
        ) {
            crate::fuse::dir_ops::implementation::handle_statfs(self, reply);
        }

        fn access(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            mask: i32,
            reply: ReplyEmpty,
        ) {
            crate::fuse::read_ops::implementation::handle_access(self, ino, mask, reply);
        }

        fn getxattr(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _name: &OsStr,
            _size: u32,
            reply: ReplyXattr,
        ) {
            crate::fuse::read_ops::implementation::handle_getxattr(reply);
        }

        fn listxattr(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            size: u32,
            reply: ReplyXattr,
        ) {
            crate::fuse::read_ops::implementation::handle_listxattr(size, reply);
        }

        fn opendir(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _flags: i32,
            reply: ReplyOpen,
        ) {
            crate::fuse::dir_ops::implementation::handle_opendir(self, ino, reply);
        }

        fn releasedir(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _fh: u64,
            _flags: i32,
            reply: ReplyEmpty,
        ) {
            crate::fuse::dir_ops::implementation::handle_releasedir(reply);
        }
    }
}

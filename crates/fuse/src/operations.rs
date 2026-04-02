//! FUSE filesystem trait implementation for CipherBoxFS.
//!
//! Delegates to category-specific modules:
//! - `read_ops`: init, destroy, lookup, getattr, open, read, release, flush, access, getxattr, listxattr
//! - `write_ops`: setattr, write, create, unlink, mkdir, rmdir, rename
//! - `dir_ops`: readdir, opendir, releasedir, statfs

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    use fuser::{
        Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
        ReplyEntry, ReplyEmpty, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request,
    };
    use std::ffi::OsStr;
    use std::time::{Duration, SystemTime};

    use crate::CipherBoxFS;

    /// TTL for FUSE attribute/entry cache replies on files.
    pub const FILE_TTL: Duration = Duration::from_secs(60);

    /// TTL for directory attribute/entry cache replies.
    pub const DIR_TTL: Duration = Duration::from_secs(0);

    pub fn ttl_for_is_dir(is_dir: bool) -> Duration {
        if is_dir { DIR_TTL } else { FILE_TTL }
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
                .await.map_err(|e| format!("{}", e))?;
            let encrypted_file_key = hex::decode(&key_hex).map_err(|_| "Invalid file key hex".to_string())?;
            let file_key = zeroize::Zeroizing::new(
                cipherbox_crypto::unwrap_key(&encrypted_file_key, &private_key)
                    .map_err(|e| format!("File key unwrap failed: {}", e))?,
            );
            let file_key_arr: [u8; 32] = file_key.as_slice().try_into()
                .map_err(|_| "Invalid file key length".to_string())?;

            let plaintext = if mode == "CTR" {
                let iv = hex::decode(&iv_hex_owned).map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 16] = iv.try_into().map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
                cipherbox_crypto::decrypt_aes_ctr(&encrypted_bytes, &file_key_arr, &iv_arr)
                    .map_err(|e| format!("CTR file decryption failed: {}", e))?
            } else {
                let iv = hex::decode(&iv_hex_owned).map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| "Invalid GCM IV length (expected 12)".to_string())?;
                cipherbox_crypto::decrypt_aes_gcm(&encrypted_bytes, &file_key_arr, &iv_arr)
                    .map_err(|e| format!("GCM file decryption failed: {}", e))?
            };
            Ok(plaintext)
        })
    }

    pub async fn fetch_and_decrypt_content_async(
        api: &cipherbox_api_client::ApiClient,
        cid: &str,
        encrypted_file_key_hex: &str,
        iv_hex: &str,
        encryption_mode: &str,
        private_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        let encrypted_bytes = cipherbox_api_client::ipfs::fetch_content(api, cid)
            .await.map_err(|e| format!("{}", e))?;
        let encrypted_file_key = hex::decode(encrypted_file_key_hex)
            .map_err(|_| "Invalid file key hex".to_string())?;
        let file_key = zeroize::Zeroizing::new(
            cipherbox_crypto::unwrap_key(&encrypted_file_key, private_key)
                .map_err(|e| format!("File key unwrap failed: {}", e))?,
        );
        let file_key_arr: [u8; 32] = file_key.as_slice().try_into()
            .map_err(|_| "Invalid file key length".to_string())?;

        let plaintext = if encryption_mode == "CTR" {
            let iv = hex::decode(iv_hex).map_err(|_| "Invalid file IV hex".to_string())?;
            let iv_arr: [u8; 16] = iv.try_into().map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
            cipherbox_crypto::decrypt_aes_ctr(&encrypted_bytes, &file_key_arr, &iv_arr)
                .map_err(|e| format!("CTR decryption failed: {}", e))?
        } else {
            let iv = hex::decode(iv_hex).map_err(|_| "Invalid file IV hex".to_string())?;
            let iv_arr: [u8; 12] = iv.try_into().map_err(|_| "Invalid GCM IV length (expected 12)".to_string())?;
            cipherbox_crypto::decrypt_aes_gcm(&encrypted_bytes, &file_key_arr, &iv_arr)
                .map_err(|e| format!("GCM decryption failed: {}", e))?
        };
        Ok(plaintext)
    }

    pub async fn publish_file_metadata(
        api: &cipherbox_api_client::ApiClient,
        file_meta: &cipherbox_core::FileMetadata,
        folder_key: &[u8],
        file_ipns_private_key: &zeroize::Zeroizing<Vec<u8>>,
        file_ipns_name: &str,
        coordinator: &crate::PublishCoordinator,
        tee_public_key: Option<&[u8]>,
        tee_key_epoch: Option<u32>,
        is_first_publish: bool,
    ) -> Result<(), String> {
        let folder_key_arr: [u8; 32] = folder_key.try_into()
            .map_err(|_| "Invalid folder key length for FileMetadata encryption".to_string())?;

        let sealed = cipherbox_core::folder::encrypt_file_metadata(file_meta, &folder_key_arr)
            .map_err(|e| format!("FileMetadata encryption failed: {}", e))?;

        let iv_hex = hex::encode(&sealed[..12]);
        use base64::Engine;
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
        let json = serde_json::json!({ "iv": iv_hex, "data": data_base64 });
        let json_bytes = serde_json::to_vec(&json)
            .map_err(|e| format!("FileMetadata JSON serialization failed: {}", e))?;

        let file_meta_cid = cipherbox_api_client::ipfs::upload_content(api, &json_bytes)
            .await.map_err(|e| format!("{}", e))?;

        let current_seq = if is_first_publish {
            None
        } else {
            Some(coordinator.resolve_sequence(api, file_ipns_name).await?)
        };

        let ipns_key_arr: [u8; 32] = file_ipns_private_key.as_slice().try_into()
            .map_err(|_| "Invalid file IPNS private key length".to_string())?;
        let new_seq = crate::next_file_publish_sequence(is_first_publish, current_seq)?;
        let value = format!("/ipfs/{}", file_meta_cid);
        let record = cipherbox_core::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)
            .map_err(|e| format!("File IPNS record creation failed: {}", e))?;
        let marshaled = cipherbox_core::marshal_ipns_record(&record)
            .map_err(|e| format!("File IPNS record marshal failed: {}", e))?;

        let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

        // TEE enrollment on first publish only (same pattern as folder creation in write_ops.rs)
        let (encrypted_ipns_for_tee, tee_epoch) = match (is_first_publish, tee_public_key, tee_key_epoch) {
            (true, Some(tee_key), Some(epoch)) => {
                let wrapped = cipherbox_crypto::wrap_key(
                    file_ipns_private_key.as_slice(), tee_key
                ).map_err(|e| format!("TEE key wrapping failed: {}", e))?;
                (Some(hex::encode(&wrapped)), Some(epoch))
            }
            (true, Some(_), None) => {
                return Err("TEE public key present but key_epoch missing".to_string());
            }
            _ => (None, None),
        };

        let req = cipherbox_api_client::IpnsPublishRequest {
            ipns_name: file_ipns_name.to_string(),
            record: record_b64,
            metadata_cid: file_meta_cid.clone(),
            encrypted_ipns_private_key: encrypted_ipns_for_tee,
            key_epoch: tee_epoch,
            expected_sequence_number: None,
        };
        match cipherbox_api_client::ipns::publish_ipns(api, &req).await.map_err(|e| format!("{}", e))? {
            cipherbox_api_client::PublishResult::Success => {}
            cipherbox_api_client::PublishResult::Conflict { .. } => {
                log::warn!("Unexpected conflict on per-file IPNS publish for {}", file_ipns_name);
            }
        }

        coordinator.record_publish(file_ipns_name, new_seq);
        log::info!("Per-file IPNS publish succeeded for {}", file_ipns_name);
        Ok(())
    }

    impl Filesystem for CipherBoxFS {
        fn init(&mut self, _req: &Request<'_>, config: &mut fuser::KernelConfig) -> Result<(), libc::c_int> {
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

        fn setattr(&mut self, _req: &Request<'_>, ino: u64, _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>, size: Option<u64>, _atime: Option<fuser::TimeOrNow>, _mtime: Option<fuser::TimeOrNow>, _ctime: Option<SystemTime>, fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, _flags: Option<u32>, reply: ReplyAttr) {
            crate::write_ops::implementation::handle_setattr(self, ino, size, fh, reply);
        }

        fn readdir(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, offset: i64, reply: ReplyDirectory) {
            crate::dir_ops::implementation::handle_readdir(self, ino, offset, reply);
        }

        fn create(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, _mode: u32, _umask: u32, flags: i32, reply: ReplyCreate) {
            crate::write_ops::implementation::handle_create(self, parent, name, flags, reply);
        }

        fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
            crate::read_ops::implementation::handle_open(self, ino, flags, reply);
        }

        fn write(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyWrite) {
            crate::write_ops::implementation::handle_write(self, ino, fh, offset, data, reply);
        }

        fn read(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock: Option<u64>, reply: ReplyData) {
            crate::read_ops::implementation::handle_read(self, ino, fh, offset, size, reply);
        }

        fn release(&mut self, _req: &Request<'_>, ino: u64, fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
            crate::read_ops::implementation::handle_release(self, ino, fh, reply);
        }

        fn flush(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
            crate::read_ops::implementation::handle_flush(reply);
        }

        fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            crate::write_ops::implementation::handle_unlink(self, parent, name, reply);
        }

        fn mkdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
            crate::write_ops::implementation::handle_mkdir(self, parent, name, reply);
        }

        fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            crate::write_ops::implementation::handle_rmdir(self, parent, name, reply);
        }

        fn rename(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, _flags: u32, reply: ReplyEmpty) {
            crate::write_ops::implementation::handle_rename(self, parent, name, newparent, newname, reply);
        }

        fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
            crate::dir_ops::implementation::handle_statfs(self, reply);
        }

        fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
            crate::read_ops::implementation::handle_access(self, ino, mask, reply);
        }

        fn getxattr(&mut self, _req: &Request<'_>, _ino: u64, _name: &OsStr, _size: u32, reply: ReplyXattr) {
            crate::read_ops::implementation::handle_getxattr(reply);
        }

        fn listxattr(&mut self, _req: &Request<'_>, _ino: u64, size: u32, reply: ReplyXattr) {
            crate::read_ops::implementation::handle_listxattr(size, reply);
        }

        fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
            crate::dir_ops::implementation::handle_opendir(self, ino, reply);
        }

        fn releasedir(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _flags: i32, reply: ReplyEmpty) {
            crate::dir_ops::implementation::handle_releasedir(reply);
        }
    }
}

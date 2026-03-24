//! WinFsp FileSystemContext implementation for CipherBoxFS.
//!
//! Delegates to category-specific modules:
//! - `read_ops`: get_volume_info, get_security_by_name, open, close, read, get_file_info, get_security, flush
//! - `write_ops`: create, write, overwrite, cleanup, set_basic_info, set_file_size, set_delete, rename
//! - `dir_ops`: read_directory
//!
//! Uses `Arc<Mutex<CipherBoxFS>>` for interior mutability (WinFsp callbacks
//! receive `&self`, not `&mut self`, because the driver invokes callbacks on
//! any thread).
//!
//! Path resolution: WinFsp is path-based (receives `\folder\file.txt`), while
//! the inode table uses parent_ino + name lookups. `resolve_path()` bridges
//! this by walking the inode table component-by-component from the root.

#[cfg(feature = "winfsp")]
pub(crate) mod implementation {
    use std::ffi::c_void;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use winfsp::filesystem::{
        DirMarker, FileInfo, FileSystemContext, FileSecurity, OpenFileInfo,
    };
    use widestring::U16CStr;
    use winfsp::FspError;

    use crate::inode::{FileAttrs, ROOT_INO};
    use crate::CipherBoxFS;

    // Re-export is_windows_special so sub-modules can import from here
    pub use crate::helpers::is_windows_special;

    // ── NTSTATUS error helpers ─────────────────────────────────────────
    // FspError::IO cannot be used in const context since ErrorKind may not be
    // const-constructible, so we use inline functions.
    pub fn status_object_name_not_found() -> FspError { FspError::NTSTATUS(0xC0000034_u32 as i32) }
    pub fn status_invalid_parameter() -> FspError { FspError::NTSTATUS(0xC000000D_u32 as i32) }
    pub fn status_object_name_collision() -> FspError { FspError::NTSTATUS(0xC0000035_u32 as i32) }
    pub fn status_directory_not_empty() -> FspError { FspError::NTSTATUS(0xC0000101_u32 as i32) }
    pub fn status_invalid_handle() -> FspError { FspError::NTSTATUS(0xC0000008_u32 as i32) }
    pub fn status_io_device_error() -> FspError { FspError::IO(std::io::ErrorKind::Other) }

    /// Permissive self-relative security descriptor granting FILE_ALL_ACCESS
    /// to Everyone (S-1-1-0). CipherBox is single-user; encryption is the real
    /// access control, so we grant full NTFS permissions.
    ///
    /// Layout: 20-byte header, 28-byte DACL (one ACE), 12-byte Owner, 12-byte Group.
    ///
    /// Without a valid descriptor, WinFsp's `FspFileSystemOpenCheck()` strips
    /// DELETE access from `GrantedAccess` when `SecurityDescriptorSize == 0`,
    /// which prevents directory deletion via `Remove-Item` / `RemoveDirectory()`.
    pub static PERMISSIVE_SD: [u8; 72] = [
        // ── SECURITY_DESCRIPTOR header (20 bytes) ──
        0x01,                   // Revision
        0x00,                   // Sbz1
        0x04, 0x80,             // Control: SE_SELF_RELATIVE | SE_DACL_PRESENT
        0x30, 0x00, 0x00, 0x00, // OwnerOffset = 48
        0x3C, 0x00, 0x00, 0x00, // GroupOffset = 60
        0x00, 0x00, 0x00, 0x00, // SaclOffset = 0 (none)
        0x14, 0x00, 0x00, 0x00, // DaclOffset = 20
        // ── ACL header (8 bytes) ──
        0x02,                   // AclRevision
        0x00,                   // Sbz1
        0x1C, 0x00,             // AclSize = 28
        0x01, 0x00,             // AceCount = 1
        0x00, 0x00,             // Sbz2
        // ── ACCESS_ALLOWED_ACE (20 bytes) ──
        0x00,                   // AceType = ACCESS_ALLOWED
        0x00,                   // AceFlags
        0x14, 0x00,             // AceSize = 20
        0xFF, 0x01, 0x1F, 0x00, // Mask = FILE_ALL_ACCESS (0x001F01FF)
        // SID: S-1-1-0 (Everyone)
        0x01, 0x01,             // Revision, SubAuthorityCount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IdentifierAuthority
        0x00, 0x00, 0x00, 0x00, // SubAuthority[0]
        // ── Owner SID: S-1-1-0 (12 bytes) ──
        0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        // ── Group SID: S-1-1-0 (12 bytes) ──
        0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
    ];

    // ── WinFsp Context Types ───────────────────────────────────────────────

    /// WinFsp filesystem context wrapping the shared CipherBoxFS.
    ///
    /// All callbacks receive `&self`, so we use `Arc<Mutex<CipherBoxFS>>` for
    /// interior mutability. The tokio runtime handle is used for blocking on
    /// async operations from WinFsp's synchronous callback threads.
    pub struct WinFspContext {
        pub inner: Arc<Mutex<CipherBoxFS>>,
        pub rt: tokio::runtime::Handle,
    }

    /// Lightweight file context returned from open/create.
    /// References into CipherBoxFS.open_files via file handle ID.
    pub struct WinFspFileContext {
        pub fh: u64,
        pub ino: u64,
        pub is_dir: bool,
    }

    // ── Path Resolution ────────────────────────────────────────────────────

    /// Resolve a Windows-style path (`\folder\subfolder\file.txt`) to (ino, parent_ino).
    /// Returns None if any component is not found.
    pub fn resolve_path(fs: &CipherBoxFS, path: &str) -> Option<(u64, u64)> {
        let path = path.trim_start_matches('\\');
        if path.is_empty() {
            return Some((ROOT_INO, ROOT_INO));
        }
        let mut current_ino = ROOT_INO;
        let mut parent_ino = ROOT_INO;
        for component in path.split('\\').filter(|c| !c.is_empty()) {
            parent_ino = current_ino;
            match fs.inodes.find_child(current_ino, component) {
                Some(child_ino) => current_ino = child_ino,
                None => return None,
            }
        }
        Some((current_ino, parent_ino))
    }

    /// Split a Windows path into (parent_path, file_name).
    /// e.g. `\Documents\hello.txt` -> (`\Documents`, `hello.txt`)
    /// Root path `\` or `\hello.txt` -> (`\`, `hello.txt`)
    pub fn split_path(path: &str) -> (&str, &str) {
        match path.rfind('\\') {
            Some(pos) => {
                let parent = if pos == 0 { "\\" } else { &path[..pos] };
                let name = &path[pos + 1..];
                (parent, name)
            }
            None => ("\\", path),
        }
    }

    // ── FileInfo Conversion ────────────────────────────────────────────────

    /// Convert a SystemTime to Windows FILETIME (100-nanosecond intervals
    /// since 1601-01-01). Returns 0 if the time is before the Unix epoch.
    pub fn systemtime_to_filetime(t: SystemTime) -> u64 {
        // Windows FILETIME epoch: 1601-01-01 00:00:00 UTC
        // Unix epoch: 1970-01-01 00:00:00 UTC
        // Difference: 11644473600 seconds = 116444736000000000 in 100ns intervals
        const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => {
                let hundred_ns = d.as_secs() * 10_000_000 + d.subsec_nanos() as u64 / 100;
                hundred_ns + EPOCH_DIFF
            }
            Err(_) => 0,
        }
    }

    /// Convert Windows FILETIME to SystemTime. Returns UNIX_EPOCH if invalid.
    pub fn filetime_to_systemtime(ft: u64) -> SystemTime {
        const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
        if ft < EPOCH_DIFF {
            return UNIX_EPOCH;
        }
        let hundred_ns = ft - EPOCH_DIFF;
        let secs = hundred_ns / 10_000_000;
        let nanos = (hundred_ns % 10_000_000) * 100;
        UNIX_EPOCH + Duration::new(secs, nanos as u32)
    }

    /// Populate a WinFsp FileInfo from our platform-agnostic FileAttrs.
    pub fn fill_file_info(attrs: &FileAttrs) -> FileInfo {
        let mut info = FileInfo::default();
        info.file_attributes = if attrs.is_dir {
            0x10 // FILE_ATTRIBUTE_DIRECTORY
        } else {
            0x80 // FILE_ATTRIBUTE_NORMAL
        };
        info.file_size = attrs.size;
        info.allocation_size = (attrs.size + 4095) & !4095; // round up to 4K
        info.creation_time = systemtime_to_filetime(attrs.crtime);
        info.last_access_time = systemtime_to_filetime(attrs.atime);
        info.last_write_time = systemtime_to_filetime(attrs.mtime);
        info.change_time = systemtime_to_filetime(attrs.ctime);
        info
    }

    // ── Helper functions ───────────────────────────────────────────────────

    /// Fetch, decrypt, and return file content synchronously.
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

        crate::block_with_timeout(&rt, async {
            let encrypted_bytes =
                cipherbox_api_client::ipfs::fetch_content(&api, &cid_owned).await.map_err(|e| e.to_string())?;
            let encrypted_file_key = hex::decode(&key_hex)
                .map_err(|_| "Invalid file key hex".to_string())?;
            let file_key = zeroize::Zeroizing::new(
                cipherbox_crypto::ecies::unwrap_key(&encrypted_file_key, &private_key)
                    .map_err(|e| format!("File key unwrap failed: {}", e))?,
            );
            let file_key_arr: [u8; 32] = file_key
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid file key length".to_string())?;

            let plaintext = if mode == "CTR" {
                let iv = hex::decode(&iv_hex_owned)
                    .map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 16] = iv
                    .try_into()
                    .map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
                cipherbox_crypto::aes_ctr::decrypt_aes_ctr(
                    &encrypted_bytes,
                    &file_key_arr,
                    &iv_arr,
                )
                .map_err(|e| format!("CTR file decryption failed: {}", e))?
            } else {
                let iv = hex::decode(&iv_hex_owned)
                    .map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 12] = iv
                    .try_into()
                    .map_err(|_| "Invalid GCM IV length (expected 12)".to_string())?;
                cipherbox_crypto::aes::decrypt_aes_gcm(
                    &encrypted_bytes,
                    &file_key_arr,
                    &iv_arr,
                )
                .map_err(|e| format!("GCM file decryption failed: {}", e))?
            };

            Ok(plaintext)
        })
    }

    /// Async version of content download + decrypt for background prefetch tasks.
    pub async fn fetch_and_decrypt_content_async(
        api: &cipherbox_api_client::ApiClient,
        cid: &str,
        encrypted_file_key_hex: &str,
        iv_hex: &str,
        encryption_mode: &str,
        private_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        let encrypted_bytes = cipherbox_api_client::ipfs::fetch_content(api, cid).await.map_err(|e| e.to_string())?;
        let encrypted_file_key = hex::decode(encrypted_file_key_hex)
            .map_err(|_| "Invalid file key hex".to_string())?;
        let file_key = zeroize::Zeroizing::new(
            cipherbox_crypto::ecies::unwrap_key(&encrypted_file_key, private_key)
                .map_err(|e| format!("File key unwrap failed: {}", e))?,
        );
        let file_key_arr: [u8; 32] = file_key
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid file key length".to_string())?;

        let plaintext = if encryption_mode == "CTR" {
            let iv =
                hex::decode(iv_hex).map_err(|_| "Invalid file IV hex".to_string())?;
            let iv_arr: [u8; 16] = iv
                .try_into()
                .map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
            cipherbox_crypto::aes_ctr::decrypt_aes_ctr(
                &encrypted_bytes,
                &file_key_arr,
                &iv_arr,
            )
            .map_err(|e| format!("CTR decryption failed: {}", e))?
        } else {
            let iv =
                hex::decode(iv_hex).map_err(|_| "Invalid file IV hex".to_string())?;
            let iv_arr: [u8; 12] = iv
                .try_into()
                .map_err(|_| "Invalid GCM IV length (expected 12)".to_string())?;
            cipherbox_crypto::aes::decrypt_aes_gcm(
                &encrypted_bytes,
                &file_key_arr,
                &iv_arr,
            )
            .map_err(|e| format!("GCM decryption failed: {}", e))?
        };

        Ok(plaintext)
    }

    /// Encrypt and publish per-file FileMetadata to the file's own IPNS record.
    pub async fn publish_file_metadata(
        api: &cipherbox_api_client::ApiClient,
        file_meta: &cipherbox_core::folder::FileMetadata,
        folder_key: &[u8],
        file_ipns_private_key: &zeroize::Zeroizing<Vec<u8>>,
        file_ipns_name: &str,
        coordinator: &crate::PublishCoordinator,
    ) -> Result<(), String> {
        let folder_key_arr: [u8; 32] = folder_key.try_into().map_err(|_| {
            "Invalid folder key length for FileMetadata encryption".to_string()
        })?;

        // Encrypt FileMetadata with parent folder key
        let sealed =
            cipherbox_core::folder::encrypt_file_metadata(file_meta, &folder_key_arr)
                .map_err(|e| format!("FileMetadata encryption failed: {}", e))?;

        // Package as JSON envelope: { "iv": hex, "data": base64 }
        let iv_hex = hex::encode(&sealed[..12]);
        use base64::Engine;
        let data_base64 =
            base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
        let json = serde_json::json!({ "iv": iv_hex, "data": data_base64 });
        let json_bytes = serde_json::to_vec(&json)
            .map_err(|e| format!("FileMetadata JSON serialization failed: {}", e))?;

        // Upload encrypted file metadata to IPFS
        let file_meta_cid =
            cipherbox_api_client::ipfs::upload_content(api, &json_bytes).await.map_err(|e| e.to_string())?;

        // Resolve current IPNS sequence number
        let seq = coordinator
            .resolve_sequence(api, file_ipns_name)
            .await?;

        // Create and sign IPNS record
        let ipns_key_arr: [u8; 32] = file_ipns_private_key
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid file IPNS private key length".to_string())?;
        let new_seq = seq + 1;
        let value = format!("/ipfs/{}", file_meta_cid);
        let record = cipherbox_core::ipns::create_ipns_record(
            &ipns_key_arr,
            &value,
            new_seq,
            86_400_000,
        )
        .map_err(|e| format!("File IPNS record creation failed: {}", e))?;
        let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)
            .map_err(|e| format!("File IPNS record marshal failed: {}", e))?;

        let record_b64 =
            base64::engine::general_purpose::STANDARD.encode(&marshaled);

        // Per-file IPNS publishes do not use conflict detection -- file metadata
        // is owned by the file's own IPNS keypair and conflicts are inherently
        // avoided by the per-file sequence number management.
        let req = cipherbox_api_client::IpnsPublishRequest {
            ipns_name: file_ipns_name.to_string(),
            record: record_b64,
            metadata_cid: file_meta_cid.clone(),
            encrypted_ipns_private_key: None,
            key_epoch: None,
            expected_sequence_number: None,
        };
        match cipherbox_api_client::ipns::publish_ipns(api, &req).await.map_err(|e| e.to_string())? {
            cipherbox_api_client::PublishResult::Success => {}
            cipherbox_api_client::PublishResult::Conflict { .. } => {
                log::warn!("Unexpected conflict on per-file IPNS publish for {}", file_ipns_name);
            }
        }

        coordinator.record_publish(file_ipns_name, new_seq);
        log::info!("Per-file IPNS publish succeeded for {}", file_ipns_name);

        Ok(())
    }

    // ── FileSystemContext Implementation (delegates to sub-modules) ──────

    impl FileSystemContext for WinFspContext {
        type FileContext = WinFspFileContext;

        fn get_volume_info(
            &self,
            volume_info: &mut winfsp::filesystem::VolumeInfo,
        ) -> Result<(), FspError> {
            super::read_ops::implementation::handle_get_volume_info(
                self, volume_info,
            )
        }

        fn get_security_by_name(
            &self,
            file_name: &U16CStr,
            security_descriptor: Option<&mut [c_void]>,
            _find_reparse_point: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
        ) -> Result<FileSecurity, FspError> {
            super::read_ops::implementation::handle_get_security_by_name(
                self, file_name, security_descriptor,
            )
        }

        fn open(
            &self,
            file_name: &U16CStr,
            create_options: u32,
            granted_access: u32,
            file_info: &mut OpenFileInfo,
        ) -> Result<Self::FileContext, FspError> {
            super::read_ops::implementation::handle_open(
                self, file_name, create_options, granted_access, file_info,
            )
        }

        fn overwrite(
            &self,
            context: &Self::FileContext,
            _file_attributes: u32,
            _replace_file_attributes: bool,
            _allocation_size: u64,
            _extra_buffer: Option<&[u8]>,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::write_ops::implementation::handle_overwrite(
                self, context, file_info,
            )
        }

        fn close(&self, context: Self::FileContext) {
            super::read_ops::implementation::handle_close(
                self, context,
            );
        }

        fn read(
            &self,
            context: &Self::FileContext,
            buffer: &mut [u8],
            offset: u64,
        ) -> Result<u32, FspError> {
            super::read_ops::implementation::handle_read(
                self, context, buffer, offset,
            )
        }

        fn write(
            &self,
            context: &Self::FileContext,
            buffer: &[u8],
            offset: u64,
            write_to_end_of_file: bool,
            _constrained_io: bool,
            file_info: &mut FileInfo,
        ) -> Result<u32, FspError> {
            super::write_ops::implementation::handle_write(
                self, context, buffer, offset, write_to_end_of_file, file_info,
            )
        }

        fn flush(
            &self,
            _context: Option<&Self::FileContext>,
            _file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::read_ops::implementation::handle_flush()
        }

        fn get_file_info(
            &self,
            context: &Self::FileContext,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::read_ops::implementation::handle_get_file_info(
                self, context, file_info,
            )
        }

        fn get_security(
            &self,
            _context: &Self::FileContext,
            security_descriptor: Option<&mut [c_void]>,
        ) -> Result<u64, FspError> {
            super::read_ops::implementation::handle_get_security(
                security_descriptor,
            )
        }

        fn set_basic_info(
            &self,
            context: &Self::FileContext,
            _file_attributes: u32,
            creation_time: u64,
            last_access_time: u64,
            last_write_time: u64,
            change_time: u64,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::write_ops::implementation::handle_set_basic_info(
                self, context, creation_time, last_access_time, last_write_time,
                change_time, file_info,
            )
        }

        fn set_file_size(
            &self,
            context: &Self::FileContext,
            new_size: u64,
            set_allocation_size: bool,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            super::write_ops::implementation::handle_set_file_size(
                self, context, new_size, set_allocation_size, file_info,
            )
        }

        fn cleanup(
            &self,
            context: &Self::FileContext,
            _file_name: Option<&U16CStr>,
            flags: u32,
        ) {
            super::write_ops::implementation::handle_cleanup(
                self, context, flags,
            );
        }

        fn read_directory(
            &self,
            context: &Self::FileContext,
            _pattern: Option<&U16CStr>,
            marker: DirMarker,
            buffer: &mut [u8],
        ) -> Result<u32, FspError> {
            super::dir_ops::implementation::handle_read_directory(
                self, context, marker, buffer,
            )
        }

        fn create(
            &self,
            file_name: &U16CStr,
            create_options: u32,
            granted_access: u32,
            _file_attributes: u32,
            _security_descriptor: Option<&[c_void]>,
            _allocation_size: u64,
            _extra_buffer: Option<&[u8]>,
            _extra_buffer_is_reparse_point: bool,
            file_info: &mut OpenFileInfo,
        ) -> Result<Self::FileContext, FspError> {
            super::write_ops::implementation::handle_create(
                self, file_name, create_options, granted_access,
                _file_attributes, _security_descriptor, _allocation_size,
                _extra_buffer, _extra_buffer_is_reparse_point, file_info,
            )
        }

        fn rename(
            &self,
            _context: &Self::FileContext,
            file_name: &U16CStr,
            new_file_name: &U16CStr,
            replace_if_exists: bool,
        ) -> Result<(), FspError> {
            super::write_ops::implementation::handle_rename(
                self, file_name, new_file_name, replace_if_exists,
            )
        }

        fn set_delete(
            &self,
            context: &Self::FileContext,
            file_name: &U16CStr,
            delete_file: bool,
        ) -> Result<(), FspError> {
            super::write_ops::implementation::handle_set_delete(
                context, file_name, delete_file,
            )
        }
    }
}

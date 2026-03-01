//! WinFsp FileSystemContext implementation for CipherBoxFS.
//!
//! Translates all macOS FUSE callbacks to their WinFsp equivalents.
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
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use winfsp::filesystem::{
        DirInfo, DirMarker, FileInfo, FileSystemContext, FileSecurity, OpenFileInfo,
        WideNameInfo,
    };
    use widestring::{U16CStr, U16CString};
    use winfsp::FspError;

    use crate::fuse::inode::{FileAttrs, InodeData, InodeKind, ROOT_INO};
    use crate::fuse::file_handle::OpenFileHandle;
    use crate::fuse::CipherBoxFS;

    // ── NTSTATUS error helpers ─────────────────────────────────────────
    // FspError::IO cannot be used in const context since ErrorKind may not be
    // const-constructible, so we use inline functions.
    fn status_object_name_not_found() -> FspError { FspError::NTSTATUS(0xC0000034_u32 as i32) }
    fn status_invalid_parameter() -> FspError { FspError::NTSTATUS(0xC000000D_u32 as i32) }
    fn status_object_name_collision() -> FspError { FspError::NTSTATUS(0xC0000035_u32 as i32) }
    fn status_directory_not_empty() -> FspError { FspError::NTSTATUS(0xC0000101_u32 as i32) }
    fn status_invalid_handle() -> FspError { FspError::NTSTATUS(0xC0000008_u32 as i32) }
    fn status_io_device_error() -> FspError { FspError::IO(std::io::ErrorKind::Other) }

    /// Total storage quota in bytes (500 MiB).
    const QUOTA_BYTES: u64 = 500 * 1024 * 1024;

    /// Maximum number of past versions to keep per file.
    const MAX_VERSIONS_PER_FILE: usize = 10;

    /// Cooldown period for desktop FUSE version creation (15 minutes in milliseconds).
    const VERSION_COOLDOWN_MS: u64 = 15 * 60 * 1000;

    /// Maximum time for file content download in open().
    const CONTENT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

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
    fn resolve_path(fs: &CipherBoxFS, path: &str) -> Option<(u64, u64)> {
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
    fn split_path(path: &str) -> (&str, &str) {
        match path.rfind('\\') {
            Some(pos) => {
                let parent = if pos == 0 { "\\" } else { &path[..pos] };
                let name = &path[pos + 1..];
                (parent, name)
            }
            None => ("\\", path),
        }
    }

    // ── Platform Special File Filter ───────────────────────────────────────

    /// Returns true if this filename is a Windows-specific special file
    /// that should never be created, synced, or shown in directory listings.
    fn is_windows_special(name: &str) -> bool {
        let lower = name.to_lowercase();
        matches!(
            lower.as_str(),
            "desktop.ini"
                | "thumbs.db"
                | "$recycle.bin"
                | "system volume information"
                | "recycler"
                | "pagefile.sys"
                | "swapfile.sys"
                | "hiberfil.sys"
        ) || lower.contains(":zone.identifier")
            || lower.starts_with('$')
    }

    // ── FileInfo Conversion ────────────────────────────────────────────────

    /// Convert a SystemTime to Windows FILETIME (100-nanosecond intervals
    /// since 1601-01-01). Returns 0 if the time is before the Unix epoch.
    fn systemtime_to_filetime(t: SystemTime) -> u64 {
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
    fn filetime_to_systemtime(ft: u64) -> SystemTime {
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
    fn fill_file_info(attrs: &FileAttrs) -> FileInfo {
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

    /// Detect MIME type from file extension.
    fn mime_from_extension(filename: &str) -> String {
        let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
        match ext.as_str() {
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "gif" => "image/gif",
            "webp" => "image/webp",
            "svg" => "image/svg+xml",
            "bmp" => "image/bmp",
            "ico" => "image/x-icon",
            "pdf" => "application/pdf",
            "mp4" => "video/mp4",
            "webm" => "video/webm",
            "mov" => "video/quicktime",
            "avi" => "video/x-msvideo",
            "mkv" => "video/x-matroska",
            "mp3" => "audio/mpeg",
            "wav" => "audio/wav",
            "ogg" => "audio/ogg",
            "flac" => "audio/flac",
            "aac" => "audio/aac",
            "txt" => "text/plain",
            "html" | "htm" => "text/html",
            "css" => "text/css",
            "js" => "application/javascript",
            "json" => "application/json",
            "xml" => "application/xml",
            "zip" => "application/zip",
            "gz" | "gzip" => "application/gzip",
            "tar" => "application/x-tar",
            "doc" => "application/msword",
            "docx" => {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            }
            "xls" => "application/vnd.ms-excel",
            "xlsx" => {
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            }
            "ppt" => "application/vnd.ms-powerpoint",
            "pptx" => {
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            }
            "md" => "text/markdown",
            _ => "application/octet-stream",
        }
        .to_string()
    }

    /// Fetch, decrypt, and return file content synchronously.
    fn fetch_and_decrypt_file_content(
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

        crate::fuse::block_with_timeout(&rt, async {
            let encrypted_bytes =
                crate::api::ipfs::fetch_content(&api, &cid_owned).await?;
            let encrypted_file_key = hex::decode(&key_hex)
                .map_err(|_| "Invalid file key hex".to_string())?;
            let file_key = zeroize::Zeroizing::new(
                crate::crypto::ecies::unwrap_key(&encrypted_file_key, &private_key)
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
                crate::crypto::aes_ctr::decrypt_aes_ctr(
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
                crate::crypto::aes::decrypt_aes_gcm(
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
    async fn fetch_and_decrypt_content_async(
        api: &crate::api::client::ApiClient,
        cid: &str,
        encrypted_file_key_hex: &str,
        iv_hex: &str,
        encryption_mode: &str,
        private_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        let encrypted_bytes = crate::api::ipfs::fetch_content(api, cid).await?;
        let encrypted_file_key = hex::decode(encrypted_file_key_hex)
            .map_err(|_| "Invalid file key hex".to_string())?;
        let file_key = zeroize::Zeroizing::new(
            crate::crypto::ecies::unwrap_key(&encrypted_file_key, private_key)
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
            crate::crypto::aes_ctr::decrypt_aes_ctr(
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
            crate::crypto::aes::decrypt_aes_gcm(
                &encrypted_bytes,
                &file_key_arr,
                &iv_arr,
            )
            .map_err(|e| format!("GCM decryption failed: {}", e))?
        };

        Ok(plaintext)
    }

    /// Encrypt and publish per-file FileMetadata to the file's own IPNS record.
    async fn publish_file_metadata(
        api: &crate::api::client::ApiClient,
        file_meta: &crate::crypto::folder::FileMetadata,
        folder_key: &[u8],
        file_ipns_private_key: &zeroize::Zeroizing<Vec<u8>>,
        file_ipns_name: &str,
        coordinator: &crate::fuse::PublishCoordinator,
    ) -> Result<(), String> {
        let folder_key_arr: [u8; 32] = folder_key.try_into().map_err(|_| {
            "Invalid folder key length for FileMetadata encryption".to_string()
        })?;

        // Encrypt FileMetadata with parent folder key
        let sealed =
            crate::crypto::folder::encrypt_file_metadata(file_meta, &folder_key_arr)
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
            crate::api::ipfs::upload_content(api, &json_bytes).await?;

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
        let record = crate::crypto::ipns::create_ipns_record(
            &ipns_key_arr,
            &value,
            new_seq,
            86_400_000,
        )
        .map_err(|e| format!("File IPNS record creation failed: {}", e))?;
        let marshaled = crate::crypto::ipns::marshal_ipns_record(&record)
            .map_err(|e| format!("File IPNS record marshal failed: {}", e))?;

        let record_b64 =
            base64::engine::general_purpose::STANDARD.encode(&marshaled);

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

    /// Decrypt folder metadata fetched from IPFS (v2 only).
    /// Self-contained implementation (does not depend on fuse::operations module).
    fn decrypt_metadata_from_ipfs(
        encrypted_bytes: &[u8],
        folder_key: &[u8],
    ) -> Result<crate::crypto::folder::FolderMetadata, String> {
        #[derive(serde::Deserialize)]
        struct EncryptedFolderMetadata {
            iv: String,
            data: String,
        }

        let encrypted: EncryptedFolderMetadata =
            serde_json::from_slice(encrypted_bytes)
                .map_err(|e| format!("Failed to parse encrypted metadata JSON: {}", e))?;

        let iv_bytes = hex::decode(&encrypted.iv)
            .map_err(|_| "Invalid metadata IV hex".to_string())?;
        if iv_bytes.len() != 12 {
            return Err(format!("Invalid IV length: {} (expected 12)", iv_bytes.len()));
        }
        let iv: [u8; 12] = iv_bytes.try_into().unwrap();

        use base64::Engine;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&encrypted.data)
            .map_err(|e| format!("Invalid metadata base64: {}", e))?;

        let folder_key_arr: [u8; 32] = folder_key
            .try_into()
            .map_err(|_| "Invalid folder key length".to_string())?;

        // Reconstruct sealed format: IV || ciphertext (includes tag)
        let mut sealed = Vec::with_capacity(12 + ciphertext.len());
        sealed.extend_from_slice(&iv);
        sealed.extend_from_slice(&ciphertext);

        crate::crypto::folder::decrypt_folder_metadata(&sealed, &folder_key_arr)
            .map_err(|e| format!("Metadata decryption failed: {}", e))
    }

    /// Decrypt per-file metadata fetched from IPFS.
    /// Self-contained implementation (does not depend on fuse::operations module).
    fn decrypt_file_metadata_from_ipfs(
        encrypted_bytes: &[u8],
        folder_key: &[u8; 32],
    ) -> Result<crate::crypto::folder::FileMetadata, String> {
        #[derive(serde::Deserialize)]
        struct EncryptedFolderMetadata {
            iv: String,
            data: String,
        }

        let encrypted: EncryptedFolderMetadata =
            serde_json::from_slice(encrypted_bytes)
                .map_err(|e| format!("Failed to parse encrypted file metadata JSON: {}", e))?;

        let iv_bytes = hex::decode(&encrypted.iv)
            .map_err(|_| "Invalid file metadata IV hex".to_string())?;
        if iv_bytes.len() != 12 {
            return Err(format!("Invalid IV length: {} (expected 12)", iv_bytes.len()));
        }
        let iv: [u8; 12] = iv_bytes.try_into().unwrap();

        use base64::Engine;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&encrypted.data)
            .map_err(|e| format!("Invalid file metadata base64: {}", e))?;

        // Reconstruct sealed format: IV || ciphertext (includes tag)
        let mut sealed = Vec::with_capacity(12 + ciphertext.len());
        sealed.extend_from_slice(&iv);
        sealed.extend_from_slice(&ciphertext);

        crate::crypto::folder::decrypt_file_metadata(&sealed, folder_key)
            .map_err(|e| format!("File metadata decryption failed: {}", e))
    }

    /// Helper: Fetch, decrypt, and populate a folder's children (blocking).
    fn fetch_and_populate_folder(
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

        let result = crate::fuse::block_with_timeout(&rt, async {
            let resolve_resp =
                crate::api::ipns::resolve_ipns(&api, &ipns_name_owned).await?;
            let encrypted_bytes =
                crate::api::ipfs::fetch_content(&api, &resolve_resp.cid).await?;
            Ok::<(Vec<u8>, String), String>((encrypted_bytes, resolve_resp.cid))
        })?;

        let (encrypted_bytes, cid) = result;
        let metadata =
            decrypt_metadata_from_ipfs(&encrypted_bytes, &folder_key_owned)?;
        fs.metadata_cache
            .set(&ipns_name.to_string(), metadata.clone(), cid);
        fs.inodes.populate_folder(
            ino,
            &metadata,
            &private_key,
            &fs.public_key,
            false,
        )?;

        // Resolve unresolved FilePointers eagerly
        let unresolved = fs.inodes.get_unresolved_file_pointers();
        if !unresolved.is_empty() {
            log::info!(
                "Resolving {} FilePointer(s) for folder ino {}",
                unresolved.len(),
                ino
            );
            resolve_file_pointers_blocking(fs, &unresolved, &folder_key_owned)?;
        }

        Ok(())
    }

    /// Resolve FilePointer inodes by fetching and decrypting per-file IPNS metadata.
    fn resolve_file_pointers_blocking(
        fs: &mut CipherBoxFS,
        unresolved: &[(u64, String)],
        folder_key: &[u8],
    ) -> Result<(), String> {
        let api = fs.api.clone();
        let rt = fs.rt.clone();
        let folder_key_arr: [u8; 32] = folder_key.try_into().map_err(|_| {
            "Invalid folder key length for FilePointer resolution".to_string()
        })?;

        for (ino, ipns_name) in unresolved {
            let resolve_result = crate::fuse::block_with_timeout(&rt, async {
                let resp =
                    crate::api::ipns::resolve_ipns(&api, ipns_name).await?;
                let encrypted_bytes =
                    crate::api::ipfs::fetch_content(&api, &resp.cid).await?;
                Ok::<Vec<u8>, String>(encrypted_bytes)
            });

            match resolve_result {
                Ok(encrypted_bytes) => {
                    match decrypt_file_metadata_from_ipfs(
                        &encrypted_bytes,
                        &folder_key_arr,
                    ) {
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
                                ino,
                                ipns_name,
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "FilePointer IPNS resolve failed for ino {} ({}): {}",
                        ino,
                        ipns_name,
                        e
                    );
                }
            }
        }

        Ok(())
    }

    // ── WinFsp NTSTATUS constants ──────────────────────────────────────────

    // These are used when the winfsp crate expects NTSTATUS values.
    // The winfsp crate provides its own error types via FspError.

    // ── FileSystemContext Implementation ───────────────────────────────────

    impl FileSystemContext for WinFspContext {
        type FileContext = WinFspFileContext;

        // -- get_volume_info --
        fn get_volume_info(
            &self,
            volume_info: &mut winfsp::filesystem::VolumeInfo,
        ) -> Result<(), FspError> {
            let fs = self.inner.lock().unwrap();
            let used_bytes: u64 = fs
                .inodes
                .inodes
                .values()
                .filter_map(|inode| match &inode.kind {
                    InodeKind::File { size, .. } => Some(*size),
                    _ => None,
                })
                .sum();

            volume_info.total_size = QUOTA_BYTES;
            volume_info.free_size = QUOTA_BYTES.saturating_sub(used_bytes);
            Ok(())
        }

        // -- get_security_by_name --
        // Combines lookup + getattr. Return file attributes and security descriptor.
        fn get_security_by_name(
            &self,
            file_name: &U16CStr,
            _security_descriptor: Option<&mut [c_void]>,
            _find_reparse_point: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
        ) -> Result<FileSecurity, FspError> {
            let path = file_name.to_string_lossy();
            let fs = self.inner.lock().unwrap();

            // Check for Windows special files
            let name_only = path.rsplit('\\').next().unwrap_or(&path);
            if is_windows_special(name_only) {
                return Err(status_object_name_not_found());
            }

            let (ino, _parent_ino) = resolve_path(&fs, &path)
                .ok_or(status_object_name_not_found())?;

            let inode = fs
                .inodes
                .get(ino)
                .ok_or(status_object_name_not_found())?;

            let info = fill_file_info(&inode.attr);

            // Use a permissive default security descriptor.
            // CipherBox is single-user, encryption is the real access control.
            Ok(FileSecurity {
                attributes: info.file_attributes,
                reparse: false,
                sz_security_descriptor: 0,
            })
        }

        // -- open --
        fn open(
            &self,
            file_name: &U16CStr,
            create_options: u32,
            granted_access: u32,
            file_info: &mut OpenFileInfo,
        ) -> Result<Self::FileContext, FspError> {
            let path = file_name.to_string_lossy();
            log::info!(
                "open() path={} create_options=0x{:08X} granted_access=0x{:08X}",
                path,
                create_options,
                granted_access
            );
            let mut fs = self.inner.lock().unwrap();

            // Drain pending completions
            fs.drain_upload_completions();
            fs.drain_content_prefetches();

            let (ino, _parent_ino) = resolve_path(&fs, &path)
                .ok_or(status_object_name_not_found())?;

            let inode = fs
                .inodes
                .get(ino)
                .ok_or(status_object_name_not_found())?;
            let is_dir = inode.attr.is_dir;

            // Populate file_info with attributes
            *file_info.as_mut() = fill_file_info(&inode.attr);

            if is_dir {
                // Directory: just return a handle
                let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
                return Ok(WinFspFileContext { fh, ino, is_dir: true });
            }

            // File: determine read vs write
            // FILE_WRITE_DATA = 0x0002, FILE_APPEND_DATA = 0x0004
            let is_write = (granted_access & 0x0006) != 0;

            if is_write {
                // Get file info for content pre-population
                let (cid, encrypted_file_key, iv, encryption_mode) =
                    match &inode.kind {
                        InodeKind::File {
                            cid,
                            encrypted_file_key,
                            iv,
                            encryption_mode,
                            ..
                        } => (
                            cid.clone(),
                            encrypted_file_key.clone(),
                            iv.clone(),
                            encryption_mode.clone(),
                        ),
                        _ => {
                            return Err(status_invalid_parameter());
                        }
                    };

                // Pre-populate with existing content if editing
                let existing_content = if !cid.is_empty() {
                    if let Some(cached) = fs.content_cache.get(&cid) {
                        Some(cached.to_vec())
                    } else {
                        match fetch_and_decrypt_file_content(
                            &fs,
                            &cid,
                            &encrypted_file_key,
                            &iv,
                            &encryption_mode,
                        ) {
                            Ok(content) => Some(content),
                            Err(e) => {
                                log::error!(
                                    "Failed to fetch content for write-open: {}",
                                    e
                                );
                                return Err(status_io_device_error());
                            }
                        }
                    }
                } else {
                    None
                };

                let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
                match OpenFileHandle::new_write(
                    ino,
                    &fs.temp_dir,
                    existing_content.as_deref(),
                ) {
                    Ok(handle) => {
                        fs.open_files.insert(fh, handle);
                        Ok(WinFspFileContext {
                            fh,
                            ino,
                            is_dir: false,
                        })
                    }
                    Err(e) => {
                        log::error!("Failed to create write handle: {}", e);
                        Err(status_io_device_error())
                    }
                }
            } else {
                // Read-only open: fire async prefetch
                let (cid, encrypted_file_key, iv, encryption_mode) =
                    match &inode.kind {
                        InodeKind::File {
                            cid,
                            encrypted_file_key,
                            iv,
                            encryption_mode,
                            ..
                        } => (
                            cid.clone(),
                            encrypted_file_key.clone(),
                            iv.clone(),
                            encryption_mode.clone(),
                        ),
                        _ => {
                            return Err(status_invalid_parameter());
                        }
                    };

                if !cid.is_empty()
                    && fs.content_cache.get(&cid).is_none()
                    && !fs.prefetching.contains(&cid)
                {
                    let api = fs.api.clone();
                    let rt = fs.rt.clone();
                    let tx = fs.content_tx.clone();
                    let cid_clone = cid.clone();
                    let efk = encrypted_file_key.clone();
                    let iv_clone = iv.clone();
                    let enc_mode = encryption_mode.clone();
                    let pk = fs.private_key.clone();
                    fs.prefetching.insert(cid.clone());

                    rt.spawn(async move {
                        let result = tokio::time::timeout(
                            CONTENT_DOWNLOAD_TIMEOUT,
                            fetch_and_decrypt_content_async(
                                &api,
                                &cid_clone,
                                &efk,
                                &iv_clone,
                                &enc_mode,
                                &pk,
                            ),
                        )
                        .await;

                        match result {
                            Ok(Ok(plaintext)) => {
                                let _ =
                                    tx.send(crate::fuse::PendingContent::Success {
                                        cid: cid_clone,
                                        data: plaintext,
                                    });
                            }
                            Ok(Err(e)) => {
                                log::error!(
                                    "Prefetch failed for CID {}: {}",
                                    cid_clone,
                                    e
                                );
                                let _ =
                                    tx.send(crate::fuse::PendingContent::Failure {
                                        cid: cid_clone,
                                    });
                            }
                            Err(_) => {
                                log::error!(
                                    "Prefetch timed out for CID {}",
                                    cid_clone
                                );
                                let _ =
                                    tx.send(crate::fuse::PendingContent::Failure {
                                        cid: cid_clone,
                                    });
                            }
                        }
                    });
                }

                let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
                fs.open_files.insert(fh, OpenFileHandle::new_read(ino));
                Ok(WinFspFileContext {
                    fh,
                    ino,
                    is_dir: false,
                })
            }
        }

        // -- overwrite --
        // Called when Windows opens an existing file with FILE_OVERWRITE or
        // FILE_OVERWRITE_IF disposition (e.g., PowerShell Set-Content, CreateFile
        // with CREATE_ALWAYS). Truncates the file to zero length.
        fn overwrite(
            &self,
            context: &Self::FileContext,
            _file_attributes: u32,
            _replace_file_attributes: bool,
            _allocation_size: u64,
            _extra_buffer: Option<&[u8]>,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            log::info!(
                "overwrite() called for ino={} fh={}",
                context.ino,
                context.fh
            );
            let mut fs = self.inner.lock().unwrap();

            // Truncate the open file handle to zero length
            if let Some(handle) = fs.open_files.get_mut(&context.fh) {
                let has_temp = handle.temp_path.is_some();
                log::info!(
                    "overwrite: handle found, has_temp_path={}",
                    has_temp
                );
                if has_temp {
                    handle
                        .truncate(0)
                        .map_err(|_| status_io_device_error())?;
                    handle.dirty = true;
                    log::info!("overwrite: truncated to 0");
                }
            } else {
                log::warn!(
                    "overwrite: no handle found for fh={}",
                    context.fh
                );
            }

            // Update inode size to 0
            if let Some(inode) = fs.inodes.get_mut(context.ino) {
                inode.attr.size = 0;
                inode.attr.mtime = SystemTime::now();
                inode.attr.ctime = SystemTime::now();
                *file_info = fill_file_info(&inode.attr);
            }

            Ok(())
        }

        // -- close --
        fn close(&self, context: Self::FileContext) {
            log::info!("close() ino={} fh={}", context.ino, context.fh);
            // close() (IRP_MJ_CLOSE) may be deferred indefinitely by the Windows
            // cache manager. All data flushing happens in cleanup() (IRP_MJ_CLEANUP)
            // which fires immediately when the user-mode handle is closed.
            // Here we just remove the handle from open_files if it wasn't already
            // removed during cleanup flush.
            let mut fs = self.inner.lock().unwrap();
            fs.drain_upload_completions();

            if let Some(handle) = fs.open_files.remove(&context.fh) {
                // Handle survived cleanup without being flushed (e.g., read-only handle)
                handle.cleanup();
            }
        }

        // -- read --
        fn read(
            &self,
            context: &Self::FileContext,
            buffer: &mut [u8],
            offset: u64,
        ) -> Result<u32, FspError> {
            let mut fs = self.inner.lock().unwrap();
            fs.drain_upload_completions();
            fs.drain_content_prefetches();

            let fh = context.fh;
            let ino = context.ino;

            // Check if handle has a temp file (writable)
            let has_temp = fs
                .open_files
                .get(&fh)
                .map(|h| h.temp_path.is_some())
                .unwrap_or(false);

            if has_temp {
                match fs.open_files.get(&fh) {
                    Some(handle) => {
                        match handle.read_at(offset as i64, buffer.len() as u32) {
                            Ok(data) => {
                                let len =
                                    std::cmp::min(data.len(), buffer.len());
                                buffer[..len].copy_from_slice(&data[..len]);
                                return Ok(len as u32);
                            }
                            Err(e) => {
                                log::error!("Temp file read failed: {}", e);
                                return Err(status_io_device_error());
                            }
                        }
                    }
                    None => return Err(status_invalid_handle()),
                }
            }

            // Read-only path: get file metadata
            let (cid, encrypted_file_key_hex, iv_hex, encryption_mode) = {
                match fs.inodes.get(ino) {
                    Some(inode) => match &inode.kind {
                        InodeKind::File {
                            cid,
                            encrypted_file_key,
                            iv,
                            encryption_mode,
                            ..
                        } => (
                            cid.clone(),
                            encrypted_file_key.clone(),
                            iv.clone(),
                            encryption_mode.clone(),
                        ),
                        _ => return Err(status_invalid_parameter()),
                    },
                    None => return Err(status_object_name_not_found()),
                }
            };

            // Empty CID means upload in flight -- serve from pending cache
            if cid.is_empty() {
                if let Some(content) = fs.pending_content.get(&ino) {
                    let start = offset as usize;
                    if start >= content.len() {
                        return Ok(0);
                    }
                    let end =
                        std::cmp::min(start + buffer.len(), content.len());
                    let len = end - start;
                    buffer[..len].copy_from_slice(&content[start..end]);
                    return Ok(len as u32);
                }
                return Ok(0);
            }

            // Check open file handle cached content
            if let Some(handle) = fs.open_files.get(&fh) {
                if let Some(ref content) = handle.cached_content {
                    let start = offset as usize;
                    if start >= content.len() {
                        return Ok(0);
                    }
                    let end =
                        std::cmp::min(start + buffer.len(), content.len());
                    let len = end - start;
                    buffer[..len].copy_from_slice(&content[start..end]);
                    return Ok(len as u32);
                }
            }

            // Check content cache -- clone to release immutable borrow before
            // mutably borrowing open_files below.
            let cached_owned = fs.content_cache.get(&cid).map(|c| c.to_vec());
            if let Some(cached_owned) = cached_owned {
                let start = offset as usize;
                if start >= cached_owned.len() {
                    return Ok(0);
                }
                let end = std::cmp::min(start + buffer.len(), cached_owned.len());
                let len = end - start;
                buffer[..len].copy_from_slice(&cached_owned[start..end]);

                // Store in handle for subsequent reads
                if let Some(handle) = fs.open_files.get_mut(&fh) {
                    handle.cached_content = Some(cached_owned);
                }
                return Ok(len as u32);
            }

            // Content not cached: start prefetch and poll
            if !fs.prefetching.contains(&cid) {
                let api = fs.api.clone();
                let rt = fs.rt.clone();
                let tx = fs.content_tx.clone();
                let cid_clone = cid.clone();
                let efk = encrypted_file_key_hex.clone();
                let iv_clone = iv_hex.clone();
                let enc_mode = encryption_mode.clone();
                let pk = fs.private_key.clone();
                fs.prefetching.insert(cid.clone());

                rt.spawn(async move {
                    let result = tokio::time::timeout(
                        CONTENT_DOWNLOAD_TIMEOUT,
                        fetch_and_decrypt_content_async(
                            &api,
                            &cid_clone,
                            &efk,
                            &iv_clone,
                            &enc_mode,
                            &pk,
                        ),
                    )
                    .await;

                    match result {
                        Ok(Ok(plaintext)) => {
                            let _ =
                                tx.send(crate::fuse::PendingContent::Success {
                                    cid: cid_clone,
                                    data: plaintext,
                                });
                        }
                        Ok(Err(e)) => {
                            log::error!(
                                "Read prefetch failed for CID {}: {}",
                                cid_clone,
                                e
                            );
                            let _ =
                                tx.send(crate::fuse::PendingContent::Failure {
                                    cid: cid_clone,
                                });
                        }
                        Err(_) => {
                            let _ =
                                tx.send(crate::fuse::PendingContent::Failure {
                                    cid: cid_clone,
                                });
                        }
                    }
                });
            }

            // Poll for content (up to 5s -- WinFsp is more tolerant than NFS)
            let poll_start = std::time::Instant::now();
            let max_wait = Duration::from_secs(5);
            loop {
                // Must drop the lock while sleeping
                drop(fs);
                std::thread::sleep(Duration::from_millis(100));
                fs = self.inner.lock().unwrap();
                fs.drain_content_prefetches();

                if let Some(cached) = fs.content_cache.get(&cid) {
                    let start = offset as usize;
                    if start >= cached.len() {
                        return Ok(0);
                    }
                    let end =
                        std::cmp::min(start + buffer.len(), cached.len());
                    let len = end - start;
                    buffer[..len].copy_from_slice(&cached[start..end]);
                    return Ok(len as u32);
                }
                if poll_start.elapsed() > max_wait {
                    break;
                }
            }

            Err(status_io_device_error())
        }

        // -- write --
        fn write(
            &self,
            context: &Self::FileContext,
            buffer: &[u8],
            offset: u64,
            write_to_end_of_file: bool,
            _constrained_io: bool,
            file_info: &mut FileInfo,
        ) -> Result<u32, FspError> {
            let mut fs = self.inner.lock().unwrap();
            let fh = context.fh;
            let ino = context.ino;

            // Read file size before getting mutable handle (avoids borrow conflict)
            let current_file_size = fs
                .inodes
                .get(ino)
                .map(|i| i.attr.size)
                .unwrap_or(0);

            // Determine actual write offset
            let actual_offset = if write_to_end_of_file {
                log::info!(
                    "write() ino={} fh={} len={} write_to_end_of_file=true offset_param={} using file_size={}",
                    ino, fh, buffer.len(), offset, current_file_size
                );
                current_file_size
            } else {
                log::info!(
                    "write() ino={} fh={} len={} offset={} write_to_end_of_file=false",
                    ino, fh, buffer.len(), offset
                );
                offset
            };

            let handle = match fs.open_files.get_mut(&fh) {
                Some(h) => h,
                None => return Err(status_invalid_handle()),
            };

            match handle.write_at(actual_offset as i64, buffer) {
                Ok(written) => {
                    // Update inode size if write extends the file
                    let new_end = actual_offset + buffer.len() as u64;
                    if let Some(inode) = fs.inodes.get_mut(ino) {
                        if new_end > inode.attr.size {
                            inode.attr.size = new_end;
                            inode.attr.blocks = (new_end + 511) / 512;
                        }
                        inode.attr.mtime = SystemTime::now();
                        *file_info = fill_file_info(&inode.attr);
                    }
                    Ok(written as u32)
                }
                Err(e) => {
                    log::error!(
                        "Write failed for ino {} fh {}: {}",
                        ino,
                        fh,
                        e
                    );
                    Err(status_io_device_error())
                }
            }
        }

        // -- flush --
        fn flush(
            &self,
            _context: Option<&Self::FileContext>,
            _file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            Ok(())
        }

        // -- get_file_info --
        fn get_file_info(
            &self,
            context: &Self::FileContext,
            file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            let fs = self.inner.lock().unwrap();
            let inode = fs
                .inodes
                .get(context.ino)
                .ok_or(status_object_name_not_found())?;
            *file_info = fill_file_info(&inode.attr);
            Ok(())
        }

        // -- set_basic_info --
        fn set_basic_info(
            &self,
            context: &Self::FileContext,
            _file_attributes: u32,
            creation_time: u64,
            last_access_time: u64,
            last_write_time: u64,
            change_time: u64,
            _file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            let mut fs = self.inner.lock().unwrap();
            if let Some(inode) = fs.inodes.get_mut(context.ino) {
                if creation_time != 0 {
                    inode.attr.crtime = filetime_to_systemtime(creation_time);
                }
                if last_access_time != 0 {
                    inode.attr.atime = filetime_to_systemtime(last_access_time);
                }
                if last_write_time != 0 {
                    inode.attr.mtime = filetime_to_systemtime(last_write_time);
                }
                if change_time != 0 {
                    inode.attr.ctime = filetime_to_systemtime(change_time);
                }
                *_file_info = fill_file_info(&inode.attr);
            }
            Ok(())
        }

        // -- set_file_size --
        fn set_file_size(
            &self,
            context: &Self::FileContext,
            new_size: u64,
            set_allocation_size: bool,
            _file_info: &mut FileInfo,
        ) -> Result<(), FspError> {
            log::info!(
                "set_file_size() ino={} fh={} new_size={} set_allocation_size={}",
                context.ino,
                context.fh,
                new_size,
                set_allocation_size
            );
            let mut fs = self.inner.lock().unwrap();

            // WinFsp calls set_file_size for both end-of-file changes
            // (set_allocation_size=false) and allocation size changes
            // (set_allocation_size=true). For overwrite operations (e.g.,
            // PowerShell Set-Content), WinFsp sends set_allocation_size=true
            // with new_size=0 to signal file truncation. We must handle both.
            //
            // For non-zero allocation size changes on a file that's already
            // large enough, we skip (no sparse file support). But for
            // truncation to 0, we always apply it.
            let should_truncate = !set_allocation_size
                || (set_allocation_size && new_size == 0);

            if should_truncate {
                // Truncate the temp file if writable handle exists
                if let Some(handle) = fs.open_files.get_mut(&context.fh) {
                    if handle.temp_path.is_some() {
                        handle
                            .truncate(new_size)
                            .map_err(|_| status_io_device_error())?;
                        handle.dirty = true;
                        log::info!(
                            "set_file_size: truncated temp file to {} bytes",
                            new_size
                        );
                    }
                }

                // Update inode size
                if let Some(inode) = fs.inodes.get_mut(context.ino) {
                    inode.attr.size = new_size;
                    inode.attr.blocks = (new_size + 511) / 512;
                    inode.attr.mtime = SystemTime::now();
                    if let InodeKind::File {
                        size: ref mut s,
                        cid: ref mut c,
                        ..
                    } = inode.kind
                    {
                        *s = new_size;
                        // Clear CID when truncating to 0 so that subsequent
                        // open() calls don't re-download stale IPFS content
                        // into the temp file.
                        if new_size == 0 {
                            c.clear();
                        }
                    }
                    *_file_info = fill_file_info(&inode.attr);
                }
            }

            Ok(())
        }

        // -- cleanup --
        // Called when a file handle is being cleaned up (IRP_MJ_CLEANUP).
        // This is called immediately when the user closes the Win32 handle,
        // BEFORE close() which may be deferred by the cache manager.
        // If FspCleanupDelete flag is set, this is the actual delete.
        fn cleanup(
            &self,
            context: &Self::FileContext,
            _file_name: Option<&U16CStr>,
            flags: u32,
        ) {
            log::info!(
                "cleanup() ino={} fh={} flags=0x{:08X}",
                context.ino,
                context.fh,
                flags
            );
            let mut fs = self.inner.lock().unwrap();
            let ino = context.ino;
            let fh = context.fh;

            // FspCleanupDelete = 0x01
            if flags & 0x01 != 0 {
                // Get parent and CID info before removal
                let (parent_ino, cid_to_unpin) =
                    match fs.inodes.get(ino) {
                        Some(inode) => {
                            let parent = inode.parent_ino;
                            let cid = match &inode.kind {
                                InodeKind::File { cid, .. } => {
                                    if cid.is_empty() {
                                        None
                                    } else {
                                        Some(cid.clone())
                                    }
                                }
                                InodeKind::Folder { ipns_name, .. } => {
                                    // Get CID from metadata cache for unpinning
                                    fs.metadata_cache
                                        .get(ipns_name)
                                        .map(|cached| cached.cid.clone())
                                }
                                _ => None,
                            };
                            (parent, cid)
                        }
                        None => return,
                    };

                // Remove inode from table
                fs.inodes.remove(ino);

                // Bump parent mtime
                if let Some(parent_inode) = fs.inodes.get_mut(parent_ino) {
                    parent_inode.attr.mtime = SystemTime::now();
                    parent_inode.attr.ctime = SystemTime::now();
                }

                // Update parent folder metadata
                if let Err(e) = fs.update_folder_metadata(parent_ino) {
                    log::error!(
                        "Failed to update folder metadata after delete: {}",
                        e
                    );
                }

                // Fire-and-forget unpin
                if let Some(cid) = cid_to_unpin {
                    let api = fs.api.clone();
                    fs.rt.spawn(async move {
                        let _ =
                            crate::api::ipfs::unpin_content(&api, &cid).await;
                    });
                }
            } else {
                // Non-delete cleanup: flush dirty file handles.
                // On WinFsp, close() (IRP_MJ_CLOSE) may be deferred indefinitely by
                // the Windows cache manager. cleanup() (IRP_MJ_CLEANUP) fires immediately
                // when the user-mode handle is closed, so we must flush data here.
                fs.drain_upload_completions();

                let needs_flush = fs.open_files.get(&fh)
                    .map(|h| {
                        let has_temp = h.temp_path.is_some();
                        let is_new = has_temp && fs.inodes.get(ino)
                            .map(|i| match &i.kind {
                                InodeKind::File { cid, .. } => cid.is_empty(),
                                _ => false,
                            })
                            .unwrap_or(false);
                        has_temp && (h.dirty || is_new)
                    })
                    .unwrap_or(false);

                if needs_flush {
                    // Remove the handle so we own it for read_all + cleanup
                    let handle = fs.open_files.remove(&fh).unwrap();

                    let prepare_result = (|| -> Result<(), String> {
                        let plaintext = handle.read_all()?;
                        let mut file_key =
                            crate::crypto::utils::generate_file_key();
                        let iv = crate::crypto::utils::generate_iv();
                        let ciphertext = crate::crypto::aes::encrypt_aes_gcm(
                            &plaintext, &file_key, &iv,
                        )
                        .map_err(|e| format!("File encryption failed: {}", e))?;
                        let wrapped_key = crate::crypto::ecies::wrap_key(
                            &file_key,
                            &fs.public_key,
                        )
                        .map_err(|e| format!("Key wrapping failed: {}", e))?;
                        crate::crypto::utils::clear_bytes(&mut file_key);

                        let (
                            old_file_cid,
                            _old_encrypted_key,
                            _old_iv,
                            old_size,
                            old_mode,
                            existing_versions,
                            file_ipns_private_key,
                            file_meta_ipns_name,
                        ) = fs
                            .inodes
                            .get(ino)
                            .map(|inode| match &inode.kind {
                                InodeKind::File {
                                    cid,
                                    encrypted_file_key,
                                    iv,
                                    size,
                                    encryption_mode,
                                    versions,
                                    file_ipns_private_key,
                                    file_meta_ipns_name,
                                    ..
                                } => (
                                    if cid.is_empty() {
                                        None
                                    } else {
                                        Some(cid.clone())
                                    },
                                    encrypted_file_key.clone(),
                                    iv.clone(),
                                    *size,
                                    encryption_mode.clone(),
                                    versions.clone(),
                                    file_ipns_private_key.clone(),
                                    file_meta_ipns_name.clone(),
                                ),
                                _ => (
                                    None,
                                    String::new(),
                                    String::new(),
                                    0,
                                    "GCM".to_string(),
                                    None,
                                    None,
                                    None,
                                ),
                            })
                            .unwrap_or((
                                None,
                                String::new(),
                                String::new(),
                                0,
                                "GCM".to_string(),
                                None,
                                None,
                                None,
                            ));

                        let encrypted_file_key_hex = hex::encode(&wrapped_key);
                        let iv_hex = hex::encode(&iv);
                        let file_size = plaintext.len() as u64;
                        let file_name = fs
                            .inodes
                            .get(ino)
                            .map(|i| i.name.clone())
                            .unwrap_or_default();
                        let mime_type = mime_from_extension(&file_name);

                        // Version creation with cooldown
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;

                        let should_version =
                            if let Some(ref versions) = existing_versions {
                                if let Some(newest) = versions.first() {
                                    now_ms.saturating_sub(newest.timestamp)
                                        >= VERSION_COOLDOWN_MS
                                } else {
                                    old_file_cid
                                        .as_ref()
                                        .is_some_and(|c| !c.is_empty())
                                }
                            } else {
                                old_file_cid
                                    .as_ref()
                                    .is_some_and(|c| !c.is_empty())
                            };

                        let (new_versions, pruned_cids) = if should_version {
                            if let Some(ref old_c) = old_file_cid {
                                if !old_c.is_empty() {
                                    let version_entry =
                                        crate::crypto::folder::VersionEntry {
                                            cid: old_c.clone(),
                                            file_key_encrypted: _old_encrypted_key
                                                .clone(),
                                            file_iv: _old_iv.clone(),
                                            size: old_size,
                                            timestamp: now_ms,
                                            encryption_mode: old_mode.clone(),
                                        };
                                    let mut versions = vec![version_entry];
                                    versions.extend(
                                        existing_versions.unwrap_or_default(),
                                    );
                                    let pruned: Vec<String> =
                                        if versions.len() > MAX_VERSIONS_PER_FILE {
                                            versions
                                                .split_off(MAX_VERSIONS_PER_FILE)
                                                .into_iter()
                                                .map(|v| v.cid)
                                                .collect()
                                        } else {
                                            vec![]
                                        };
                                    (Some(versions), pruned)
                                } else {
                                    (existing_versions, vec![])
                                }
                            } else {
                                (existing_versions, vec![])
                            }
                        } else {
                            (existing_versions, vec![])
                        };

                        let versions_for_meta = new_versions
                            .as_ref()
                            .filter(|v| !v.is_empty())
                            .cloned();

                        if let Some(inode) = fs.inodes.get_mut(ino) {
                            let cached_hex = match &inode.kind {
                                InodeKind::File {
                                    file_ipns_key_encrypted_hex,
                                    ..
                                } => file_ipns_key_encrypted_hex.clone(),
                                _ => None,
                            };
                            inode.kind = InodeKind::File {
                                cid: String::new(),
                                encrypted_file_key: encrypted_file_key_hex.clone(),
                                iv: iv_hex.clone(),
                                size: file_size,
                                encryption_mode: "GCM".to_string(),
                                file_meta_ipns_name: file_meta_ipns_name.clone(),
                                file_meta_resolved: true,
                                file_ipns_private_key: file_ipns_private_key
                                    .clone(),
                                file_ipns_key_encrypted_hex: cached_hex,
                                versions: versions_for_meta.clone(),
                            };
                            inode.attr.size = file_size;
                            inode.attr.blocks = (file_size + 511) / 512;
                            inode.attr.mtime = SystemTime::now();
                        }

                        fs.pending_content.insert(ino, plaintext);

                        let parent_ino = fs
                            .inodes
                            .get(ino)
                            .map(|i| i.parent_ino)
                            .unwrap_or(ROOT_INO);

                        let folder_key_for_file_meta =
                            fs.get_folder_key(parent_ino);

                        fs.queue_publish(parent_ino, true);

                        let api = fs.api.clone();
                        let rt = fs.rt.clone();
                        let upload_tx = fs.upload_tx.clone();
                        let coordinator = fs.publish_coordinator.clone();

                        let file_meta =
                            crate::crypto::folder::FileMetadata {
                                version: "v1".to_string(),
                                cid: String::new(),
                                file_key_encrypted: encrypted_file_key_hex,
                                file_iv: iv_hex,
                                size: file_size,
                                mime_type,
                                encryption_mode: "GCM".to_string(),
                                created_at: now_ms,
                                modified_at: now_ms,
                                versions: versions_for_meta,
                            };

                        std::thread::spawn(move || {
                            let result = rt.block_on(async {
                                let file_cid =
                                    crate::api::ipfs::upload_content(
                                        &api,
                                        &ciphertext,
                                    )
                                    .await?;
                                log::info!(
                                    "File uploaded: ino {} -> CID {}",
                                    ino,
                                    file_cid
                                );

                                let _ = upload_tx.send(
                                    crate::fuse::UploadComplete {
                                        ino,
                                        new_cid: file_cid.clone(),
                                        parent_ino,
                                        old_file_cid,
                                        pruned_cids,
                                        write_generation: 0, // TODO: pass actual generation for Windows
                                    },
                                );

                                if let (
                                    Some(ipns_key),
                                    Some(ipns_name),
                                    Some(folder_key),
                                ) = (
                                    &file_ipns_private_key,
                                    &file_meta_ipns_name,
                                    &folder_key_for_file_meta,
                                ) {
                                    let mut file_meta_with_cid = file_meta;
                                    file_meta_with_cid.cid = file_cid;
                                    if let Err(e) = publish_file_metadata(
                                        &api,
                                        &file_meta_with_cid,
                                        folder_key,
                                        ipns_key,
                                        ipns_name,
                                        &coordinator,
                                    )
                                    .await
                                    {
                                        log::warn!(
                                            "Per-file IPNS publish failed for ino {}: {}",
                                            ino,
                                            e
                                        );
                                    }
                                }

                                Ok::<(), String>(())
                            });

                            if let Err(e) = result {
                                log::error!(
                                    "Background upload failed for ino {}: {}",
                                    ino,
                                    e
                                );
                            }
                        });

                        Ok(())
                    })();

                    if let Err(e) = prepare_result {
                        log::error!(
                            "File upload preparation failed for ino {}: {}",
                            ino,
                            e
                        );
                    }

                    handle.cleanup();
                }
            }
        }

        // -- read_directory --
        fn read_directory(
            &self,
            context: &Self::FileContext,
            _pattern: Option<&U16CStr>,
            marker: DirMarker,
            buffer: &mut [u8],
        ) -> Result<u32, FspError> {
            let mut fs = self.inner.lock().unwrap();
            let ino = context.ino;

            // Drain pending operations
            fs.drain_refresh_completions();
            fs.drain_upload_completions();

            let inode = fs
                .inodes
                .get(ino)
                .ok_or(status_object_name_not_found())?;

            // Check if metadata is stale and fire background refresh
            let stale_info: Option<(String, zeroize::Zeroizing<Vec<u8>>)> =
                match &inode.kind {
                    InodeKind::Root { ipns_name, .. } => {
                        ipns_name.as_ref().and_then(|name| {
                            if fs.metadata_cache.get(name).is_none() {
                                Some((name.clone(), fs.root_folder_key.clone()))
                            } else {
                                None
                            }
                        })
                    }
                    InodeKind::Folder {
                        ipns_name,
                        folder_key,
                        ..
                    } => {
                        if fs.metadata_cache.get(&ipns_name).is_none() {
                            Some((ipns_name.clone(), folder_key.clone()))
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

            // Fire background refresh (non-blocking)
            if let Some((ipns_name, folder_key)) = stale_info {
                let api = fs.api.clone();
                let rt = fs.rt.clone();
                let tx = fs.refresh_tx.clone();
                let refresh_ino = ino;
                rt.spawn(async move {
                    match crate::api::ipns::resolve_ipns(&api, &ipns_name).await
                    {
                        Ok(resolve_resp) => {
                            match crate::api::ipfs::fetch_content(
                                &api,
                                &resolve_resp.cid,
                            )
                            .await
                            {
                                Ok(encrypted_bytes) => {
                                    match decrypt_metadata_from_ipfs(
                                        &encrypted_bytes,
                                        &folder_key,
                                    ) {
                                        Ok(metadata) => {
                                            let _ = tx.send(
                                                crate::fuse::PendingRefresh {
                                                    ino: refresh_ino,
                                                    ipns_name,
                                                    metadata,
                                                    cid: resolve_resp.cid,
                                                },
                                            );
                                        }
                                        Err(e) => log::warn!(
                                            "Refresh decrypt failed: {}",
                                            e
                                        ),
                                    }
                                }
                                Err(e) => log::warn!(
                                    "Refresh fetch failed: {}",
                                    e
                                ),
                            }
                        }
                        Err(e) => log::warn!(
                            "Refresh resolve failed for {}: {}",
                            ipns_name,
                            e
                        ),
                    }
                });
            }

            // Return current entries
            let parent_ino = inode.parent_ino;
            let children = inode.children.clone().unwrap_or_default();

            // Collect all directory entries into a Vec
            let mut entries: Vec<(U16CString, FileInfo)> = Vec::new();

            // "." entry
            if let Ok(name) = U16CString::from_str(".") {
                entries.push((name, fill_file_info(&inode.attr)));
            }

            // ".." entry
            if let Some(parent) = fs.inodes.get(parent_ino) {
                if let Ok(name) = U16CString::from_str("..") {
                    entries.push((name, fill_file_info(&parent.attr)));
                }
            }

            // Child entries
            for &child_ino in &children {
                if let Some(child) = fs.inodes.get(child_ino) {
                    if is_windows_special(&child.name) {
                        continue;
                    }
                    if let Ok(name) = U16CString::from_str(&child.name) {
                        entries.push((name, fill_file_info(&child.attr)));
                    }
                }
            }

            // Write entries into buffer, respecting the marker (resume point).
            // DirMarker wraps the name of the last entry from the previous call.
            // If marker.is_none(), this is the first call -- return all entries.
            // Otherwise, skip entries up to and including the marker name.
            let mut past_marker = marker.is_none();
            let mut bytes_written: u32 = 0;

            for (entry_name, entry_info) in &entries {
                if !past_marker {
                    // Compare entry name with marker to find resume point.
                    let entry_str = entry_name.to_string_lossy();
                    let is_match = if marker.is_current() {
                        entry_str == "."
                    } else if marker.is_parent() {
                        entry_str == ".."
                    } else if let Some(marker_cstr) = marker.inner_as_cstr() {
                        // Compare using string lossy conversion
                        entry_str == marker_cstr.to_string_lossy()
                    } else {
                        false
                    };
                    if is_match {
                        past_marker = true;
                    }
                    continue;
                }

                let mut dir_info = DirInfo::<255>::new();
                *dir_info.file_info_mut() = entry_info.clone();
                let _ = dir_info.set_name_cstr(entry_name);
                if !dir_info.append_to_buffer(buffer, &mut bytes_written) {
                    break; // buffer full
                }
            }

            // Proactive content prefetch for child files
            fs.drain_content_prefetches();
            for &child_ino in &children {
                // Clone fields from inode to release the immutable borrow on fs
                let file_info = fs.inodes.get(child_ino).and_then(|child| {
                    if let InodeKind::File {
                        cid,
                        encrypted_file_key,
                        iv,
                        encryption_mode,
                        ..
                    } = &child.kind
                    {
                        if !cid.is_empty() {
                            Some((cid.clone(), encrypted_file_key.clone(), iv.clone(), encryption_mode.clone()))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                });
                if let Some((cid_clone, efk, iv_clone, enc_mode)) = file_info {
                    if fs.content_cache.get(&cid_clone).is_none()
                        && !fs.prefetching.contains(&cid_clone)
                    {
                        let api = fs.api.clone();
                        let rt = fs.rt.clone();
                        let tx = fs.content_tx.clone();
                        let pk = fs.private_key.clone();
                        fs.prefetching.insert(cid_clone.clone());

                        rt.spawn(async move {
                            let result = tokio::time::timeout(
                                CONTENT_DOWNLOAD_TIMEOUT,
                                fetch_and_decrypt_content_async(
                                    &api,
                                    &cid_clone,
                                    &efk,
                                    &iv_clone,
                                    &enc_mode,
                                    &pk,
                                ),
                            )
                            .await;

                            match result {
                                Ok(Ok(plaintext)) => {
                                    let _ = tx.send(
                                        crate::fuse::PendingContent::Success {
                                            cid: cid_clone,
                                            data: plaintext,
                                        },
                                    );
                                }
                                Ok(Err(_e)) => {
                                    let _ = tx.send(
                                        crate::fuse::PendingContent::Failure {
                                            cid: cid_clone,
                                        },
                                    );
                                }
                                Err(_) => {
                                    let _ = tx.send(
                                        crate::fuse::PendingContent::Failure {
                                            cid: cid_clone,
                                        },
                                    );
                                }
                            }
                        });
                        }
                    }
                }

            Ok(bytes_written)
        }

        // -- create --
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
            let path = file_name.to_string_lossy();
            log::info!(
                "create() path={} create_options=0x{:08X} granted_access=0x{:08X}",
                path,
                create_options,
                granted_access
            );
            let (parent_path, name) = split_path(&path);

            if name.is_empty() {
                return Err(status_invalid_parameter());
            }

            // Reject Windows special files
            if is_windows_special(name) {
                return Err(status_object_name_not_found());
            }

            let mut fs = self.inner.lock().unwrap();

            // Resolve parent
            let (parent_ino, _) = resolve_path(&fs, parent_path)
                .ok_or(status_object_name_not_found())?;

            // Check parent is a directory
            let parent_is_dir = fs.inodes.get(parent_ino).map(|inode| {
                matches!(
                    inode.kind,
                    InodeKind::Root { .. } | InodeKind::Folder { .. }
                )
            });
            if parent_is_dir != Some(true) {
                return Err(status_object_name_not_found());
            }

            // FILE_DIRECTORY_FILE = 0x00000001
            let is_dir = (create_options & 0x00000001) != 0;

            if is_dir {
                // Create directory (equivalent to mkdir)
                let result = (|| -> Result<(FileAttrs, u64), String> {
                    let folder_key =
                        crate::crypto::utils::generate_file_key();
                    let (ipns_public_key, ipns_private_key) =
                        crate::crypto::ed25519::generate_ed25519_keypair();
                    let ipns_pub_arr: [u8; 32] =
                        ipns_public_key.clone().try_into().map_err(|_| {
                            "Invalid IPNS public key length".to_string()
                        })?;
                    let ipns_name =
                        crate::crypto::ipns::derive_ipns_name(&ipns_pub_arr)
                            .map_err(|e| {
                                format!("Failed to derive IPNS name: {}", e)
                            })?;
                    let wrapped_folder_key = crate::crypto::ecies::wrap_key(
                        &folder_key,
                        &fs.public_key,
                    )
                    .map_err(|e| {
                        format!("Folder key wrapping failed: {}", e)
                    })?;
                    let encrypted_folder_key_hex =
                        hex::encode(&wrapped_folder_key);

                    let ino = fs.inodes.allocate_ino();
                    let now = SystemTime::now();

                    let attr = FileAttrs {
                        ino,
                        size: 0,
                        blocks: 0,
                        atime: now,
                        mtime: now,
                        ctime: now,
                        crtime: now,
                        is_dir: true,
                        perm: 0o755,
                        nlink: 2,
                    };

                    let inode = InodeData {
                        ino,
                        parent_ino,
                        name: name.to_string(),
                        kind: InodeKind::Folder {
                            ipns_name: ipns_name.clone(),
                            encrypted_folder_key: encrypted_folder_key_hex,
                            folder_key: zeroize::Zeroizing::new(
                                folder_key.to_vec(),
                            ),
                            ipns_private_key: Some(zeroize::Zeroizing::new(
                                ipns_private_key.clone(),
                            )),
                            children_loaded: true,
                        },
                        attr: attr.clone(),
                        children: Some(vec![]),
                        write_generation: 0,
                    };

                    fs.inodes.insert(inode);
                    if let Some(parent_inode) =
                        fs.inodes.get_mut(parent_ino)
                    {
                        if let Some(ref mut children) =
                            parent_inode.children
                        {
                            children.push(ino);
                        }
                        parent_inode.attr.mtime = SystemTime::now();
                        parent_inode.attr.ctime = SystemTime::now();
                    }

                    // Prepare background network I/O
                    let metadata =
                        crate::crypto::folder::FolderMetadata {
                            version: "v2".to_string(),
                            children: vec![],
                        };
                    let json_bytes =
                        crate::fuse::encrypt_metadata_to_json(
                            &metadata,
                            &folder_key,
                        )?;
                    let encrypted_ipns_for_tee =
                        if let Some(ref tee_key) = fs.tee_public_key {
                            let wrapped = crate::crypto::ecies::wrap_key(
                                &ipns_private_key,
                                tee_key,
                            )
                            .map_err(|e| {
                                format!("TEE key wrapping failed: {}", e)
                            })?;
                            Some(hex::encode(&wrapped))
                        } else {
                            None
                        };
                    let tee_key_epoch = fs.tee_key_epoch;
                    let (
                        parent_metadata,
                        parent_folder_key,
                        parent_ipns_key,
                        parent_ipns_name,
                        parent_old_cid,
                    ) = fs.build_folder_metadata(parent_ino)?;

                    let api = fs.api.clone();
                    let rt = fs.rt.clone();
                    let ipns_name_clone = ipns_name.clone();
                    let coordinator = fs.publish_coordinator.clone();

                    std::thread::spawn(move || {
                        let result = rt.block_on(async {
                            let initial_cid =
                                crate::api::ipfs::upload_content(
                                    &api,
                                    &json_bytes,
                                )
                                .await?;
                            let ipns_key_arr: [u8; 32] = ipns_private_key
                                .try_into()
                                .map_err(|_| {
                                    "Invalid IPNS key length".to_string()
                                })?;
                            let value =
                                format!("/ipfs/{}", initial_cid);
                            let record =
                                crate::crypto::ipns::create_ipns_record(
                                    &ipns_key_arr,
                                    &value,
                                    0,
                                    86_400_000,
                                )
                                .map_err(|e| {
                                    format!(
                                        "IPNS record creation failed: {}",
                                        e
                                    )
                                })?;
                            let marshaled =
                                crate::crypto::ipns::marshal_ipns_record(
                                    &record,
                                )
                                .map_err(|e| {
                                    format!("IPNS marshal failed: {}", e)
                                })?;

                            use base64::Engine;
                            let record_b64 =
                                base64::engine::general_purpose::STANDARD
                                    .encode(&marshaled);

                            let req =
                                crate::api::ipns::IpnsPublishRequest {
                                    ipns_name: ipns_name_clone.clone(),
                                    record: record_b64,
                                    metadata_cid: initial_cid,
                                    encrypted_ipns_private_key:
                                        encrypted_ipns_for_tee,
                                    key_epoch: tee_key_epoch,
                                };
                            crate::api::ipns::publish_ipns(&api, &req)
                                .await?;
                            coordinator
                                .record_publish(&ipns_name_clone, 0);

                            // Publish parent folder metadata
                            let lock = coordinator
                                .get_lock(&parent_ipns_name);
                            let _guard = lock.lock().await;
                            let parent_json =
                                crate::fuse::encrypt_metadata_to_json(
                                    &parent_metadata,
                                    &parent_folder_key,
                                )?;
                            let seq = coordinator
                                .resolve_sequence(
                                    &api,
                                    &parent_ipns_name,
                                )
                                .await?;
                            let parent_meta_cid =
                                crate::api::ipfs::upload_content(
                                    &api,
                                    &parent_json,
                                )
                                .await?;
                            let parent_key_arr: [u8; 32] =
                                parent_ipns_key.try_into().map_err(
                                    |_| {
                                        "Invalid parent IPNS key length"
                                            .to_string()
                                    },
                                )?;
                            let new_seq = seq + 1;
                            let parent_value = format!(
                                "/ipfs/{}",
                                parent_meta_cid
                            );
                            let parent_record =
                                crate::crypto::ipns::create_ipns_record(
                                    &parent_key_arr,
                                    &parent_value,
                                    new_seq,
                                    86_400_000,
                                )
                                .map_err(|e| {
                                    format!(
                                        "Parent IPNS record failed: {}",
                                        e
                                    )
                                })?;
                            let parent_marshaled =
                                crate::crypto::ipns::marshal_ipns_record(
                                    &parent_record,
                                )
                                .map_err(|e| {
                                    format!(
                                        "Parent IPNS marshal failed: {}",
                                        e
                                    )
                                })?;
                            let parent_record_b64 =
                                base64::engine::general_purpose::STANDARD
                                    .encode(&parent_marshaled);
                            let parent_req =
                                crate::api::ipns::IpnsPublishRequest {
                                    ipns_name: parent_ipns_name.clone(),
                                    record: parent_record_b64,
                                    metadata_cid: parent_meta_cid,
                                    encrypted_ipns_private_key: None,
                                    key_epoch: None,
                                };
                            crate::api::ipns::publish_ipns(
                                &api,
                                &parent_req,
                            )
                            .await?;
                            coordinator.record_publish(
                                &parent_ipns_name,
                                new_seq,
                            );
                            if let Some(old) = parent_old_cid {
                                let _ =
                                    crate::api::ipfs::unpin_content(
                                        &api, &old,
                                    )
                                    .await;
                            }
                            Ok::<(), String>(())
                        });
                        if let Err(e) = result {
                            log::error!(
                                "Background mkdir publish failed: {}",
                                e
                            );
                        }
                    });

                    Ok((attr, ino))
                })();

                match result {
                    Ok((attr, ino)) => {
                        *file_info.as_mut() = fill_file_info(&attr);
                        let fh =
                            fs.next_fh.fetch_add(1, Ordering::SeqCst);
                        Ok(WinFspFileContext {
                            fh,
                            ino,
                            is_dir: true,
                        })
                    }
                    Err(e) => {
                        log::error!("create dir failed: {}", e);
                        Err(status_io_device_error())
                    }
                }
            } else {
                // Create file (equivalent to create)
                let ino = fs.inodes.allocate_ino();
                let now = SystemTime::now();

                let attr = FileAttrs {
                    ino,
                    size: 0,
                    blocks: 0,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    crtime: now,
                    is_dir: false,
                    perm: 0o644,
                    nlink: 1,
                };

                // Generate random IPNS keypair for this file
                let signing_key = ed25519_dalek::SigningKey::generate(
                    &mut rand::rngs::OsRng,
                );
                let verifying_key = signing_key.verifying_key();
                let file_ipns_private_key =
                    signing_key.to_bytes().to_vec();
                let file_ipns_public_key_bytes: [u8; 32] =
                    verifying_key.to_bytes();
                let file_ipns_name =
                    match crate::crypto::ipns::derive_ipns_name(
                        &file_ipns_public_key_bytes,
                    ) {
                        Ok(name) => name,
                        Err(e) => {
                            log::error!(
                                "create: IPNS name derivation failed: {}",
                                e
                            );
                            return Err(status_io_device_error());
                        }
                    };

                let ipns_key_encrypted_hex =
                    match crate::crypto::ecies::wrap_key(
                        &file_ipns_private_key,
                        &fs.public_key,
                    ) {
                        Ok(wrapped) => Some(hex::encode(&wrapped)),
                        Err(e) => {
                            log::error!(
                                "create: failed to ECIES-wrap IPNS key: {}",
                                e
                            );
                            return Err(status_io_device_error());
                        }
                    };

                let inode = InodeData {
                    ino,
                    parent_ino,
                    name: name.to_string(),
                    kind: InodeKind::File {
                        cid: String::new(),
                        encrypted_file_key: String::new(),
                        iv: String::new(),
                        size: 0,
                        encryption_mode: "GCM".to_string(),
                        file_meta_ipns_name: Some(file_ipns_name),
                        file_meta_resolved: true,
                        file_ipns_private_key: Some(
                            zeroize::Zeroizing::new(file_ipns_private_key),
                        ),
                        file_ipns_key_encrypted_hex: ipns_key_encrypted_hex,
                        versions: None,
                    },
                    attr: attr.clone(),
                    children: None,
                    write_generation: 0,
                };

                fs.inodes.insert(inode);
                if let Some(parent_inode) =
                    fs.inodes.get_mut(parent_ino)
                {
                    if let Some(ref mut children) =
                        parent_inode.children
                    {
                        children.push(ino);
                    }
                    parent_inode.attr.mtime = SystemTime::now();
                    parent_inode.attr.ctime = SystemTime::now();
                }

                let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
                match OpenFileHandle::new_write(
                    ino,
                    &fs.temp_dir,
                    None,
                ) {
                    Ok(handle) => {
                        fs.open_files.insert(fh, handle);
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to create temp file for new file: {}",
                            e
                        );
                        fs.inodes.remove(ino);
                        return Err(status_io_device_error());
                    }
                }

                fs.mutated_folders
                    .insert(parent_ino, std::time::Instant::now());

                *file_info.as_mut() = fill_file_info(&attr);
                Ok(WinFspFileContext {
                    fh,
                    ino,
                    is_dir: false,
                })
            }
        }

        // -- rename --
        fn rename(
            &self,
            _context: &Self::FileContext,
            file_name: &U16CStr,
            new_file_name: &U16CStr,
            replace_if_exists: bool,
        ) -> Result<(), FspError> {
            let old_path = file_name.to_string_lossy();
            let new_path = new_file_name.to_string_lossy();

            let mut fs = self.inner.lock().unwrap();

            let (source_ino, old_parent_ino) = resolve_path(&fs, &old_path)
                .ok_or(status_object_name_not_found())?;

            let (new_parent_path, new_name) = split_path(&new_path);
            let (new_parent_ino, _) = resolve_path(&fs, new_parent_path)
                .ok_or(status_object_name_not_found())?;

            // Handle existing destination
            if let Some(dest_ino) =
                fs.inodes.find_child(new_parent_ino, new_name)
            {
                if !replace_if_exists {
                    return Err(status_object_name_collision());
                }
                // Check if destination is a non-empty directory
                if let Some(dest_inode) = fs.inodes.get(dest_ino) {
                    match &dest_inode.kind {
                        InodeKind::Folder { .. } => {
                            if let Some(ref children) = dest_inode.children
                            {
                                if !children.is_empty() {
                                    return Err(
                                        status_directory_not_empty(),
                                    );
                                }
                            }
                        }
                        InodeKind::File { cid, .. } => {
                            if !cid.is_empty() {
                                let cid_clone = cid.clone();
                                let api = fs.api.clone();
                                fs.rt.spawn(async move {
                                    let _ =
                                        crate::api::ipfs::unpin_content(
                                            &api,
                                            &cid_clone,
                                        )
                                        .await;
                                });
                            }
                        }
                        _ => {}
                    }
                }
                fs.inodes.remove(dest_ino);
            }

            // Remove source from old parent's name index
            let old_name = fs
                .inodes
                .get(source_ino)
                .map(|i| i.name.clone())
                .unwrap_or_default();
            fs.inodes.name_to_ino.remove(&(
                old_parent_ino,
                crate::fuse::inode::normalize_name(&old_name),
            ));

            // Update source inode
            if let Some(inode) = fs.inodes.get_mut(source_ino) {
                inode.name = new_name.to_string();
                inode.parent_ino = new_parent_ino;
                inode.attr.ctime = SystemTime::now();
            }

            // Update name index for new location
            fs.inodes.name_to_ino.insert(
                (
                    new_parent_ino,
                    crate::fuse::inode::normalize_name(new_name),
                ),
                source_ino,
            );

            if old_parent_ino != new_parent_ino {
                // Cross-folder move
                if let Some(old_parent) =
                    fs.inodes.get_mut(old_parent_ino)
                {
                    if let Some(ref mut children) = old_parent.children {
                        children.retain(|&c| c != source_ino);
                    }
                    old_parent.attr.mtime = SystemTime::now();
                    old_parent.attr.ctime = SystemTime::now();
                }
                if let Some(new_parent) =
                    fs.inodes.get_mut(new_parent_ino)
                {
                    if let Some(ref mut children) = new_parent.children {
                        children.push(source_ino);
                    }
                    new_parent.attr.mtime = SystemTime::now();
                    new_parent.attr.ctime = SystemTime::now();
                }
                if let Err(e) =
                    fs.update_folder_metadata(old_parent_ino)
                {
                    log::error!(
                        "Failed to update old parent metadata after rename: {}",
                        e
                    );
                }
                if let Err(e) =
                    fs.update_folder_metadata(new_parent_ino)
                {
                    log::error!(
                        "Failed to update new parent metadata after rename: {}",
                        e
                    );
                }
            } else {
                // Same-folder rename
                if let Some(parent_inode) =
                    fs.inodes.get_mut(old_parent_ino)
                {
                    parent_inode.attr.mtime = SystemTime::now();
                    parent_inode.attr.ctime = SystemTime::now();
                }
                if let Err(e) =
                    fs.update_folder_metadata(old_parent_ino)
                {
                    log::error!(
                        "Failed to update parent metadata after rename: {}",
                        e
                    );
                }
            }

            Ok(())
        }

        // -- set_delete --
        fn set_delete(
            &self,
            _context: &Self::FileContext,
            _file_name: &U16CStr,
            _delete_file: bool,
        ) -> Result<(), FspError> {
            // Mark for deletion. Actual deletion happens in cleanup().
            // WinFsp handles the pending-delete semantics for us.
            Ok(())
        }
    }
}

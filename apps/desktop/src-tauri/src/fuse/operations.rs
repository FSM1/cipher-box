//! FUSE filesystem trait implementation for CipherBoxFS.
//!
//! Implements read operations: init, lookup, getattr, readdir, open, read, release, statfs, access.
//! Write operations: create, write, open-write, release-with-upload, unlink, setattr, flush.
//!
//! IMPORTANT: All async operations use block_on from the tokio runtime.
//! FUSE requires synchronous replies, so we block on async operations as needed.

#[cfg(feature = "fuse")]
mod implementation {
    use fuser::{
        FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
        ReplyEntry, ReplyEmpty, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request,
    };
    use std::ffi::OsStr;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, SystemTime};

    use crate::fuse::CipherBoxFS;
    use crate::fuse::file_handle::OpenFileHandle;
    use crate::fuse::inode::{InodeData, InodeKind, ROOT_INO, BLOCK_SIZE};

    /// TTL for FUSE attribute/entry cache replies on files.
    /// Longer TTL = fewer kernel callbacks = less FUSE-T NFS thread contention.
    const FILE_TTL: Duration = Duration::from_secs(60);

    /// TTL for directory attribute/entry cache replies.
    /// Must be short (or zero) so the NFS client re-validates directory attributes
    /// after mutations (rename, create, unlink, etc.) and sees updated mtime,
    /// which triggers readdir cache invalidation.
    const DIR_TTL: Duration = Duration::from_secs(0);

    /// Pick the right TTL based on file type.
    fn ttl_for(kind: FileType) -> Duration {
        if kind == FileType::Directory { DIR_TTL } else { FILE_TTL }
    }

    /// Total storage quota in bytes (500 MiB).
    const QUOTA_BYTES: u64 = 500 * 1024 * 1024;

    /// Returns true if this filename is a platform-specific special file
    /// that should never be created, synced, or shown in directory listings.
    fn is_platform_special(name: &str) -> bool {
        name.starts_with("._")
            || name == ".DS_Store"
            || name == ".Trashes"
            || name == ".fseventsd"
            || name == ".Spotlight-V100"
            || name == ".hidden"
            || name == ".localized"
            || name == ".metadata_never_index"
            || name == ".metadata_never_index_unless_rootfs"
            || name == ".metadata_direct_scope_only"
            || name == ".ql_disablecache"
            || name == ".ql_disablethumbnails"
            || name == "DCIM"
            || name == "Thumbs.db"
            || name == "desktop.ini"
            || name == ".directory"
    }

    /// Maximum time for a network operation before returning EIO.
    /// FUSE-T runs NFS callbacks on a single thread; blocking too long
    /// causes ALL subsequent operations (including ls) to hang.
    /// Keep this SHORT for non-read operations.
    const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);

    /// Maximum time for file content download in open().
    /// Large files (e.g., 64MB) can take 30-60s from staging IPFS.
    /// This blocks the NFS thread, but since the content is cached after
    /// open(), all subsequent reads are instant.
    const CONTENT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

    /// Run an async operation with a timeout, blocking the current thread.
    /// Returns Err if the operation fails or times out.
    fn block_with_timeout<F, T>(rt: &tokio::runtime::Handle, fut: F) -> Result<T, String>
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

    /// Encrypted folder metadata format from IPFS (JSON with iv + data).
    #[derive(serde::Deserialize)]
    struct EncryptedFolderMetadata {
        /// Hex-encoded 12-byte IV for AES-GCM.
        iv: String,
        /// Base64-encoded AES-GCM ciphertext (includes 16-byte auth tag).
        data: String,
    }

    /// Decrypt folder metadata fetched from IPFS (v2 only).
    ///
    /// The IPFS content is JSON: `{ "iv": "<hex>", "data": "<base64>" }`.
    /// Decode IV from hex, decode ciphertext from base64, then AES-256-GCM decrypt.
    /// Rejects non-v2 metadata.
    fn decrypt_metadata_from_ipfs(
        encrypted_bytes: &[u8],
        folder_key: &[u8],
    ) -> Result<crate::crypto::folder::FolderMetadata, String> {
        let encrypted: EncryptedFolderMetadata = serde_json::from_slice(encrypted_bytes)
            .map_err(|e| format!("Failed to parse encrypted metadata JSON: {}", e))?;

        // Decode IV from hex
        let iv_bytes = hex::decode(&encrypted.iv)
            .map_err(|_| "Invalid metadata IV hex".to_string())?;
        if iv_bytes.len() != 12 {
            return Err(format!("Invalid IV length: {} (expected 12)", iv_bytes.len()));
        }
        let iv: [u8; 12] = iv_bytes.try_into().unwrap();

        // Decode ciphertext from base64
        use base64::Engine;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&encrypted.data)
            .map_err(|e| format!("Invalid metadata base64: {}", e))?;

        // Decrypt with AES-256-GCM
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

    /// Helper: Fetch, decrypt, and populate a folder's children.
    ///
    /// Resolves the folder's IPNS name to CID, fetches encrypted metadata,
    /// decrypts with the folder key, and populates the inode table.
    /// For FilePointers, resolves per-file IPNS metadata eagerly.
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
        let result = block_with_timeout(&rt, async {
            let resolve_resp =
                crate::api::ipns::resolve_ipns(&api, &ipns_name_owned).await?;
            let encrypted_bytes =
                crate::api::ipfs::fetch_content(&api, &resolve_resp.cid).await?;
            Ok::<(Vec<u8>, String), String>((encrypted_bytes, resolve_resp.cid))
        })?;

        let (encrypted_bytes, cid) = result;

        // Decrypt metadata (v2 only)
        let metadata = decrypt_metadata_from_ipfs(&encrypted_bytes, &folder_key_owned)?;

        // Cache metadata directly
        fs.metadata_cache.set(&ipns_name.to_string(), metadata.clone(), cid);

        // Populate inode table with children.
        // First load for this folder -- replace mode (merge_only=false).
        fs.inodes.populate_folder(ino, &metadata, &private_key, false)?;

        // Resolve unresolved FilePointers eagerly
        let unresolved = fs.inodes.get_unresolved_file_pointers();
        if !unresolved.is_empty() {
            log::info!("Resolving {} FilePointer(s) for folder ino {}", unresolved.len(), ino);
            resolve_file_pointers_blocking(fs, &unresolved, &folder_key_owned)?;
        }

        Ok(())
    }

    /// Resolve FilePointer inodes by fetching and decrypting per-file IPNS metadata.
    ///
    /// This is called eagerly during populate_folder to ensure all files have correct
    /// CID/key/IV/size BEFORE the first READDIR (NFS stability requirement).
    fn resolve_file_pointers_blocking(
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
                    // Decrypt file metadata JSON (same format as folder metadata: { iv, data })
                    match decrypt_file_metadata_from_ipfs(&encrypted_bytes, &folder_key_arr) {
                        Ok(file_meta) => {
                            fs.inodes.resolve_file_pointer(
                                *ino,
                                file_meta.cid,
                                file_meta.file_key_encrypted,
                                file_meta.file_iv,
                                file_meta.size,
                                file_meta.encryption_mode,
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

    /// Decrypt per-file metadata fetched from IPFS.
    ///
    /// The IPFS content is JSON: `{ "iv": "<hex>", "data": "<base64>" }`.
    /// Uses the parent folder's key for decryption.
    fn decrypt_file_metadata_from_ipfs(
        encrypted_bytes: &[u8],
        folder_key: &[u8; 32],
    ) -> Result<crate::crypto::folder::FileMetadata, String> {
        let encrypted: EncryptedFolderMetadata = serde_json::from_slice(encrypted_bytes)
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

    /// Helper: Fetch and decrypt existing file content for editing.
    ///
    /// Used when opening an existing file for writing -- need to pre-populate
    /// the temp file with the current decrypted content.
    /// Dispatches to AES-GCM or AES-CTR based on encryption_mode.
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
                // AES-CTR: 16-byte IV, no auth tag
                let iv = hex::decode(&iv_hex_owned)
                    .map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 16] = iv.try_into()
                    .map_err(|_| "Invalid CTR IV length (expected 16)".to_string())?;
                crate::crypto::aes_ctr::decrypt_aes_ctr(&encrypted_bytes, &file_key_arr, &iv_arr)
                    .map_err(|e| format!("CTR file decryption failed: {}", e))?
            } else {
                // AES-GCM: 12-byte IV, 16-byte auth tag appended
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
    /// Does not require a reference to CipherBoxFS — takes all needed params by value.
    async fn fetch_and_decrypt_content_async(
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

    impl Filesystem for CipherBoxFS {
        /// Initialize the filesystem.
        ///
        /// Root folder is pre-populated in mount_filesystem() before the FUSE
        /// event loop starts. No network I/O happens here — FUSE-T's NFS layer
        /// requires fast init() responses to avoid connection timeouts.
        fn init(
            &mut self,
            _req: &Request<'_>,
            _config: &mut fuser::KernelConfig,
        ) -> Result<(), libc::c_int> {
            log::info!("CipherBoxFS::init (root pre-populated, no network I/O)");
            log::info!("Root IPNS name: {}", self.root_ipns_name);
            log::info!("Inode count: {}", self.inodes.inodes.len());
            Ok(())
        }

        /// Clean up all caches and zeroize sensitive data on unmount.
        fn destroy(&mut self) {
            use zeroize::Zeroize;

            self.content_cache.clear();
            self.metadata_cache.clear();

            // Zeroize pending_content values
            for (_, content) in self.pending_content.iter_mut() {
                content.zeroize();
            }
            self.pending_content.clear();

            // Zeroize open file handles' cached content
            for (_, handle) in self.open_files.iter_mut() {
                if let Some(ref mut c) = handle.cached_content {
                    c.zeroize();
                }
            }
            self.open_files.clear();

            log::info!("CipherBoxFS destroyed: all caches zeroized");
        }

        /// Look up a child by name within a parent directory.
        fn lookup(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            reply: ReplyEntry,
        ) {
            self.drain_upload_completions();
            self.drain_refresh_completions();

            let name_str = match name.to_str() {
                Some(n) => n,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            // Handle "." and ".." — NFS clients rely on these working.
            // Returning ENOENT for ".." causes the NFS client to disconnect.
            if name_str == "." {
                if let Some(inode) = self.inodes.get(parent) {
                    reply.entry(&ttl_for(inode.attr.kind), &inode.attr, 0);
                    return;
                }
            }
            if name_str == ".." {
                let parent_ino = self.inodes.get(parent)
                    .map(|i| i.parent_ino)
                    .unwrap_or(1); // root's parent is itself
                if let Some(inode) = self.inodes.get(parent_ino) {
                    reply.entry(&ttl_for(inode.attr.kind), &inode.attr, 0);
                    return;
                }
            }

            // Quick-reject platform special names — these never exist in the vault
            // and would otherwise trigger blocking lazy-load of subfolder children.
            if is_platform_special(name_str) {
                reply.error(libc::ENOENT);
                return;
            }

            // Check if parent is a folder with unloaded children (lazy loading)
            let needs_load = {
                if let Some(parent_inode) = self.inodes.get(parent) {
                    match &parent_inode.kind {
                        InodeKind::Folder {
                            children_loaded,
                            ipns_name,
                            folder_key,
                            ..
                        } => {
                            if !children_loaded {
                                Some((ipns_name.clone(), folder_key.clone()))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                } else {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            // Non-blocking lazy load: fire background fetch instead of blocking
            // the FUSE-T NFS thread. Return ENOENT now; the NFS client retries
            // shortly and the children will be populated by then.
            if let Some((ipns_name, folder_key)) = needs_load {
                let api = self.api.clone();
                let rt = self.rt.clone();
                let tx = self.refresh_tx.clone();
                let private_key = self.private_key.clone();
                let refresh_ino = parent;
                rt.spawn(async move {
                    match crate::api::ipns::resolve_ipns(&api, &ipns_name).await {
                        Ok(resolve_resp) => {
                            match crate::api::ipfs::fetch_content(&api, &resolve_resp.cid).await {
                                Ok(encrypted_bytes) => {
                                    match crate::fuse::operations::decrypt_metadata_from_ipfs_public(
                                        &encrypted_bytes, &folder_key,
                                    ) {
                                        Ok(metadata) => {
                                            let _ = tx.send(crate::fuse::PendingRefresh {
                                                ino: refresh_ino,
                                                ipns_name,
                                                metadata,
                                                cid: resolve_resp.cid,
                                            });
                                        }
                                        Err(e) => log::warn!("Lookup prefetch decrypt failed: {}", e),
                                    }
                                }
                                Err(e) => log::warn!("Lookup prefetch fetch failed: {}", e),
                            }
                        }
                        Err(e) => log::debug!("Lookup prefetch resolve failed for {}: {}", ipns_name, e),
                    }
                });
                reply.error(libc::ENOENT);
                return;
            }

            // Now look up the child
            if let Some(child_ino) = self.inodes.find_child(parent, name_str) {
                if let Some(inode) = self.inodes.get(child_ino) {
                    reply.entry(&ttl_for(inode.attr.kind), &inode.attr, 0);
                    return;
                }
            }

            reply.error(libc::ENOENT);
        }

        /// Return file attributes for an inode.
        fn getattr(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: Option<u64>,
            reply: ReplyAttr,
        ) {
            self.drain_upload_completions();

            if let Some(inode) = self.inodes.get(ino) {
                reply.attr(&ttl_for(inode.attr.kind), &inode.attr);
            } else {
                reply.error(libc::ENOENT);
            }
        }

        /// Set file attributes (handles truncate via size parameter).
        ///
        /// Per RESEARCH.md pitfall 4: don't try to independently set atime/mtime
        /// on FUSE-T -- only handle the size (truncate) operation.
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
            // Handle truncate if size is specified
            if let Some(new_size) = size {
                // Truncate temp file if file handle exists
                if let Some(fh_id) = fh {
                    if let Some(handle) = self.open_files.get_mut(&fh_id) {
                        if handle.temp_path.is_some() {
                            if let Err(e) = handle.truncate(new_size) {
                                log::error!("Truncate failed for ino {}: {}", ino, e);
                                reply.error(libc::EIO);
                                return;
                            }
                            handle.dirty = true;
                        }
                    }
                }

                // Update inode size
                if let Some(inode) = self.inodes.get_mut(ino) {
                    inode.attr.size = new_size;
                    inode.attr.blocks = (new_size + 511) / 512;
                    inode.attr.mtime = SystemTime::now();

                    // Also update InodeKind::File size
                    if let InodeKind::File { size: ref mut s, .. } = inode.kind {
                        *s = new_size;
                    }

                    reply.attr(&ttl_for(inode.attr.kind), &inode.attr);
                    return;
                }
            }

            // For other setattr calls, just return current attributes
            if let Some(inode) = self.inodes.get(ino) {
                reply.attr(&ttl_for(inode.attr.kind), &inode.attr);
            } else {
                reply.error(libc::ENOENT);
            }
        }

        /// List directory entries.
        ///
        /// IMPORTANT: Returns ALL entries in a single pass (FUSE-T requirement per pitfall 1).
        /// Never paginate readdir results.
        fn readdir(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            mut reply: ReplyDirectory,
        ) {
            // 1. Drain any pending background refresh results (non-blocking)
            self.drain_refresh_completions();

            // 2. Check if metadata is stale — fire background refresh if so
            let stale_info: Option<(String, zeroize::Zeroizing<Vec<u8>>)> = {
                let inode = match self.inodes.get(ino) {
                    Some(i) => i,
                    None => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                };

                match &inode.kind {
                    InodeKind::Root { ipns_name, .. } => {
                        ipns_name.as_ref().and_then(|name| {
                            if self.metadata_cache.get(name).is_none() {
                                Some((name.clone(), self.root_folder_key.clone()))
                            } else {
                                None
                            }
                        })
                    }
                    InodeKind::Folder { ipns_name, folder_key, .. } => {
                        if self.metadata_cache.get(ipns_name).is_none() {
                            Some((ipns_name.clone(), folder_key.clone()))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            };

            // Fire background refresh (non-blocking, results applied on next readdir)
            // Only on offset=0 to avoid duplicate refreshes (NFS calls readdir twice)
            if let Some((ipns_name, folder_key)) = stale_info.filter(|_| offset == 0) {
                let api = self.api.clone();
                let rt = self.rt.clone();
                let tx = self.refresh_tx.clone();
                let refresh_ino = ino;
                rt.spawn(async move {
                    match crate::api::ipns::resolve_ipns(&api, &ipns_name).await {
                        Ok(resolve_resp) => {
                            match crate::api::ipfs::fetch_content(&api, &resolve_resp.cid).await {
                                Ok(encrypted_bytes) => {
                                    match crate::fuse::operations::decrypt_metadata_from_ipfs_public(
                                        &encrypted_bytes, &folder_key,
                                    ) {
                                        Ok(metadata) => {
                                            let _ = tx.send(crate::fuse::PendingRefresh {
                                                ino: refresh_ino,
                                                ipns_name,
                                                metadata,
                                                cid: resolve_resp.cid,
                                            });
                                        }
                                        Err(e) => log::warn!("Refresh decrypt failed: {}", e),
                                    }
                                }
                                Err(e) => log::warn!("Refresh fetch failed: {}", e),
                            }
                        }
                        Err(e) => log::warn!("Refresh resolve failed for {}: {}", ipns_name, e),
                    }
                });
            }

            // 3. Return current (possibly stale) entries immediately — no blocking
            let (parent_ino, children) = {
                let inode = match self.inodes.get(ino) {
                    Some(i) => i,
                    None => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                };
                (inode.parent_ino, inode.children.clone().unwrap_or_default())
            };

            let mut entries: Vec<(u64, FileType, String)> = Vec::new();
            entries.push((ino, FileType::Directory, ".".to_string()));
            entries.push((parent_ino, FileType::Directory, "..".to_string()));

            for &child_ino in &children {
                if let Some(child) = self.inodes.get(child_ino) {
                    // Filter out platform special files — readdir must be
                    // consistent with lookup or Finder/NFS will hang retrying.
                    if is_platform_special(&child.name) {
                        continue;
                    }
                    let file_type = match &child.kind {
                        InodeKind::Root { .. } | InodeKind::Folder { .. } => {
                            FileType::Directory
                        }
                        InodeKind::File { .. } => FileType::RegularFile,
                    };
                    entries.push((child_ino, file_type, child.name.clone()));
                }
            }

            for (i, (ino, file_type, name)) in
                entries.iter().enumerate().skip(offset as usize)
            {
                if reply.add(*ino, (i + 1) as i64, *file_type, &name) {
                    break;
                }
            }

            reply.ok();

            // Proactive content prefetch: start downloading file content for
            // all children so it's cached by the time the user reads them.
            // Only on offset=0 to avoid duplicate prefetches.
            if offset == 0 {
                self.drain_content_prefetches();
                for &child_ino in &children {
                    if let Some(child) = self.inodes.get(child_ino) {
                        if let InodeKind::File { cid, encrypted_file_key, iv, encryption_mode, .. } = &child.kind {
                            if !cid.is_empty()
                                && self.content_cache.get(cid).is_none()
                                && !self.prefetching.contains(cid)
                            {
                                let api = self.api.clone();
                                let rt = self.rt.clone();
                                let tx = self.content_tx.clone();
                                let cid_clone = cid.clone();
                                let efk = encrypted_file_key.clone();
                                let iv_clone = iv.clone();
                                let enc_mode = encryption_mode.clone();
                                let pk = self.private_key.clone();
                                self.prefetching.insert(cid.clone());

                                rt.spawn(async move {
                                    let result = tokio::time::timeout(
                                        CONTENT_DOWNLOAD_TIMEOUT,
                                        fetch_and_decrypt_content_async(
                                            &api, &cid_clone, &efk, &iv_clone, &enc_mode, &pk,
                                        ),
                                    )
                                    .await;

                                    match result {
                                        Ok(Ok(plaintext)) => {
                                            log::debug!(
                                                "prefetch(readdir): cached {} bytes for CID {}",
                                                plaintext.len(),
                                                &cid_clone[..cid_clone.len().min(12)]
                                            );
                                            let _ = tx.send(crate::fuse::PendingContent::Success {
                                                cid: cid_clone,
                                                data: plaintext,
                                            });
                                        }
                                        Ok(Err(e)) => {
                                            log::error!("Prefetch(readdir) failed for CID {}: {}", cid_clone, e);
                                            let _ = tx.send(crate::fuse::PendingContent::Failure { cid: cid_clone });
                                        }
                                        Err(_) => {
                                            log::error!("Prefetch(readdir) timed out for CID {}", cid_clone);
                                            let _ = tx.send(crate::fuse::PendingContent::Failure { cid: cid_clone });
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
            }
        }

        /// Create a new file in a directory.
        ///
        /// Allocates a new inode, creates a temp file for write buffering,
        /// and adds the file to the parent's children list.
        /// The file isn't uploaded until release() -- it exists only locally.
        fn create(
            &mut self,
            req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            flags: i32,
            reply: ReplyCreate,
        ) {
            let name_str = match name.to_str() {
                Some(n) => n,
                None => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            // Reject platform-specific files — never sync .DS_Store, ._ etc.
            if is_platform_special(name_str) {
                reply.error(libc::EACCES);
                return;
            }

            // Check parent exists and is a directory
            let parent_exists = self.inodes.get(parent).map(|inode| {
                matches!(inode.kind, InodeKind::Root { .. } | InodeKind::Folder { .. })
            });
            if parent_exists != Some(true) {
                reply.error(libc::ENOENT);
                return;
            }

            // Allocate new inode
            let ino = self.inodes.allocate_ino();
            let now = SystemTime::now();
            let uid = req.uid();
            let gid = req.gid();

            let attr = FileAttr {
                ino,
                size: 0,
                blocks: 0,
                atime: now,
                mtime: now,
                ctime: now,
                crtime: now,
                kind: FileType::RegularFile,
                perm: 0o644,
                nlink: 1,
                uid,
                gid,
                rdev: 0,
                blksize: BLOCK_SIZE,
                flags: 0,
            };

            // Create inode with empty CID (not yet uploaded)
            let inode = InodeData {
                ino,
                parent_ino: parent,
                name: name_str.to_string(),
                kind: InodeKind::File {
                    cid: String::new(),
                    encrypted_file_key: String::new(),
                    iv: String::new(),
                    size: 0,
                    encryption_mode: "GCM".to_string(),
                    file_meta_ipns_name: None,
                    file_meta_resolved: true,
                },
                attr,
                children: None,
            };

            self.inodes.insert(inode);

            // Add to parent's children list and bump mtime for NFS cache invalidation
            if let Some(parent_inode) = self.inodes.get_mut(parent) {
                if let Some(ref mut children) = parent_inode.children {
                    children.push(ino);
                }
                parent_inode.attr.mtime = SystemTime::now();
                parent_inode.attr.ctime = SystemTime::now();
            }

            // Create writable file handle with temp file
            let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
            match OpenFileHandle::new_write(ino, flags, &self.temp_dir, None) {
                Ok(handle) => {
                    self.open_files.insert(fh, handle);
                }
                Err(e) => {
                    log::error!("Failed to create temp file for new file: {}", e);
                    // Remove the inode we just created
                    self.inodes.remove(ino);
                    reply.error(libc::EIO);
                    return;
                }
            }

            // Mark parent as locally mutated to prevent background refreshes
            // from overwriting this new file before IPNS publish propagates.
            self.mutated_folders.insert(parent, std::time::Instant::now());

            log::debug!("create: {} in parent {} -> ino {} fh {}", name_str, parent, ino, fh);
            reply.created(&FILE_TTL, &attr, 0, fh, 0);
        }

        /// Open a file for reading or writing.
        ///
        /// For read-only: creates a lightweight handle.
        /// For write: creates a temp file, pre-populated with existing content if editing.
        fn open(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            flags: i32,
            reply: ReplyOpen,
        ) {
            // Get file info
            let file_info = match self.inodes.get(ino) {
                Some(inode) => match &inode.kind {
                    InodeKind::File { cid, encrypted_file_key, iv, encryption_mode, .. } => {
                        Some((cid.clone(), encrypted_file_key.clone(), iv.clone(), encryption_mode.clone()))
                    }
                    _ => {
                        reply.error(libc::EISDIR);
                        return;
                    }
                },
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            let (cid, encrypted_file_key, iv, encryption_mode) = file_info.unwrap();
            let access_mode = flags & libc::O_ACCMODE;

            if access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR {
                // Writable open: create temp file
                // If existing file (has CID), pre-populate with decrypted content.
                // Try content cache first (populated by readdir proactive prefetch).
                let existing_content = if !cid.is_empty() {
                    self.drain_content_prefetches();
                    if let Some(cached) = self.content_cache.get(&cid) {
                        Some(cached.to_vec())
                    } else {
                        match fetch_and_decrypt_file_content(self, &cid, &encrypted_file_key, &iv, &encryption_mode) {
                            Ok(content) => Some(content),
                            Err(e) => {
                                log::error!("Failed to fetch content for write-open: {}", e);
                                reply.error(libc::EIO);
                                return;
                            }
                        }
                    }
                } else {
                    None
                };

                let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
                match OpenFileHandle::new_write(
                    ino,
                    flags,
                    &self.temp_dir,
                    existing_content.as_deref(),
                ) {
                    Ok(handle) => {
                        self.open_files.insert(fh, handle);
                        reply.opened(fh, 0);
                    }
                    Err(e) => {
                        log::error!("Failed to create write handle: {}", e);
                        reply.error(libc::EIO);
                    }
                }
            } else {
                // Read-only open — return IMMEDIATELY to avoid blocking the
                // FUSE-T NFS thread. FUSE-T uses NFSv4 with a 1-second timeout
                // (timeo=10); blocking here causes "not responding" mount state.
                //
                // Instead, start an async background prefetch so content is
                // likely cached by the time read() is called. If it's not ready
                // yet, read() will do a synchronous fallback download.
                self.drain_content_prefetches();

                if !cid.is_empty()
                    && self.content_cache.get(&cid).is_none()
                    && !self.prefetching.contains(&cid)
                {
                    let api = self.api.clone();
                    let rt = self.rt.clone();
                    let tx = self.content_tx.clone();
                    let cid_clone = cid.clone();
                    let efk = encrypted_file_key.clone();
                    let iv_clone = iv.clone();
                    let enc_mode = encryption_mode.clone();
                    let pk = self.private_key.clone();
                    self.prefetching.insert(cid.clone());

                    rt.spawn(async move {
                        let result = tokio::time::timeout(
                            CONTENT_DOWNLOAD_TIMEOUT,
                            fetch_and_decrypt_content_async(
                                &api, &cid_clone, &efk, &iv_clone, &enc_mode, &pk,
                            ),
                        )
                        .await;

                        match result {
                            Ok(Ok(plaintext)) => {
                                log::debug!(
                                    "prefetch: cached {} bytes for CID {}",
                                    plaintext.len(),
                                    &cid_clone[..cid_clone.len().min(12)]
                                );
                                let _ = tx.send(crate::fuse::PendingContent::Success {
                                    cid: cid_clone,
                                    data: plaintext,
                                });
                            }
                            Ok(Err(e)) => {
                                log::error!("Prefetch failed for CID {}: {}", cid_clone, e);
                                let _ = tx.send(crate::fuse::PendingContent::Failure { cid: cid_clone });
                            }
                            Err(_) => {
                                log::error!(
                                    "Prefetch timed out for CID {} ({}s)",
                                    cid_clone,
                                    CONTENT_DOWNLOAD_TIMEOUT.as_secs()
                                );
                                let _ = tx.send(crate::fuse::PendingContent::Failure { cid: cid_clone });
                            }
                        }
                    });
                }

                let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
                self.open_files.insert(fh, OpenFileHandle::new_read(ino, flags));
                reply.opened(fh, 0);
            }
        }

        /// Write data to an open file.
        ///
        /// Writes to the temp file at the given offset. The actual
        /// encrypt + upload happens on release().
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
            let handle = match self.open_files.get_mut(&fh) {
                Some(h) => h,
                None => {
                    reply.error(libc::EBADF);
                    return;
                }
            };

            match handle.write_at(offset, data) {
                Ok(written) => {
                    // Update inode size if write extends the file
                    let new_end = offset as u64 + data.len() as u64;
                    if let Some(inode) = self.inodes.get_mut(ino) {
                        if new_end > inode.attr.size {
                            inode.attr.size = new_end;
                            inode.attr.blocks = (new_end + 511) / 512;
                        }
                        inode.attr.mtime = SystemTime::now();
                    }

                    reply.written(written as u32);
                }
                Err(e) => {
                    log::error!("Write failed for ino {} fh {}: {}", ino, fh, e);
                    reply.error(libc::EIO);
                }
            }
        }

        /// Read file content.
        ///
        /// For writable handles with a temp file, reads from the temp file.
        /// For read-only handles, checks content cache first, then fetches from IPFS.
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
            // Drain any pending content prefetches into the cache
            self.drain_content_prefetches();

            // Check if the handle has a temp file (writable handle)
            let has_temp = self.open_files.get(&fh)
                .map(|h| h.temp_path.is_some())
                .unwrap_or(false);

            if has_temp {
                // Read from temp file
                match self.open_files.get(&fh) {
                    Some(handle) => {
                        match handle.read_at(offset, size) {
                            Ok(data) => {
                                reply.data(&data);
                                return;
                            }
                            Err(e) => {
                                log::error!("Temp file read failed: {}", e);
                                reply.error(libc::EIO);
                                return;
                            }
                        }
                    }
                    None => {
                        reply.error(libc::EBADF);
                        return;
                    }
                }
            }

            // Read-only path: get file metadata
            let (cid, encrypted_file_key_hex, iv_hex, encryption_mode) = {
                match self.inodes.get(ino) {
                    Some(inode) => match &inode.kind {
                        InodeKind::File {
                            cid,
                            encrypted_file_key,
                            iv,
                            encryption_mode,
                            ..
                        } => (cid.clone(), encrypted_file_key.clone(), iv.clone(), encryption_mode.clone()),
                        _ => {
                            reply.error(libc::EISDIR);
                            return;
                        }
                    },
                    None => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                }
            };

            // Empty CID means file upload is in flight — serve from pending cache
            if cid.is_empty() {
                if let Some(content) = self.pending_content.get(&ino) {
                    let start = offset as usize;
                    if start >= content.len() {
                        reply.data(&[]);
                    } else {
                        let end = std::cmp::min(start + size as usize, content.len());
                        reply.data(&content[start..end]);
                    }
                    return;
                }
                reply.data(&[]);
                return;
            }

            // Check open file handle for cached content
            if let Some(handle) = self.open_files.get(&fh) {
                if let Some(ref content) = handle.cached_content {
                    let start = offset as usize;
                    if start >= content.len() {
                        reply.data(&[]);
                        return;
                    }
                    let end = std::cmp::min(start + size as usize, content.len());
                    reply.data(&content[start..end]);
                    return;
                }
            }

            // Check content cache
            if let Some(cached) = self.content_cache.get(&cid) {
                let start = offset as usize;
                if start >= cached.len() {
                    reply.data(&[]);
                    return;
                }
                let end = std::cmp::min(start + size as usize, cached.len());

                // Store in open file handle for subsequent reads
                let data_slice = cached[start..end].to_vec();
                if let Some(handle) = self.open_files.get_mut(&fh) {
                    // Clone entire cached data for the handle
                    handle.cached_content = Some(cached.to_vec());
                }
                reply.data(&data_slice);
                return;
            }

            // Content not in cache. Download it on-demand:
            //
            // 1. Ensure a background prefetch is running (async download+decrypt)
            // 2. Poll the prefetch channel in 100ms increments (up to 3s)
            // 3. Serve data once it arrives, or EIO if still downloading
            //
            // We limit blocking to 3s to avoid corrupting NFSv4 client state.
            // FUSE-T's single NFS thread means longer blocks prevent ALL other
            // ops, causing the NFS client to time out queued requests and get
            // confused about file state. 3s is enough for small files; large
            // files use proactive prefetch from readdir to be cached ahead of time.

            // Start prefetch if not already in progress
            if !self.prefetching.contains(&cid) {
                let api = self.api.clone();
                let rt = self.rt.clone();
                let tx = self.content_tx.clone();
                let cid_clone = cid.clone();
                let efk = encrypted_file_key_hex.clone();
                let iv_clone = iv_hex.clone();
                let enc_mode = encryption_mode.clone();
                let pk = self.private_key.clone();
                self.prefetching.insert(cid.clone());

                rt.spawn(async move {
                    let result = tokio::time::timeout(
                        CONTENT_DOWNLOAD_TIMEOUT,
                        fetch_and_decrypt_content_async(
                            &api, &cid_clone, &efk, &iv_clone, &enc_mode, &pk,
                        ),
                    )
                    .await;

                    match result {
                        Ok(Ok(plaintext)) => {
                            log::debug!(
                                "prefetch(read): cached {} bytes for CID {}",
                                plaintext.len(),
                                &cid_clone[..cid_clone.len().min(12)]
                            );
                            let _ = tx.send(crate::fuse::PendingContent::Success {
                                cid: cid_clone,
                                data: plaintext,
                            });
                        }
                        Ok(Err(e)) => {
                            log::error!("Read prefetch failed for CID {}: {}", cid_clone, e);
                            let _ = tx.send(crate::fuse::PendingContent::Failure { cid: cid_clone });
                        }
                        Err(_) => {
                            log::error!("Read prefetch timed out for CID {}", cid_clone);
                            let _ = tx.send(crate::fuse::PendingContent::Failure { cid: cid_clone });
                        }
                    }
                });
            }

            // Poll the prefetch channel (up to 3s in 100ms increments).
            // Keep this SHORT to avoid blocking the single NFS thread too long.
            let poll_start = std::time::Instant::now();
            let max_wait = Duration::from_secs(3);
            loop {
                std::thread::sleep(Duration::from_millis(100));
                self.drain_content_prefetches();
                if let Some(cached) = self.content_cache.get(&cid) {
                    log::debug!(
                        "FUSE read: content ready after {:.1}s for CID {}",
                        poll_start.elapsed().as_secs_f64(),
                        &cid[..cid.len().min(12)]
                    );
                    let start = offset as usize;
                    if start >= cached.len() {
                        reply.data(&[]);
                    } else {
                        let end = std::cmp::min(start + size as usize, cached.len());
                        reply.data(&cached[start..end]);
                    }
                    return;
                }
                if poll_start.elapsed() > max_wait {
                    break;
                }
            }

            // Content still downloading — return EIO. The prefetch continues
            // in background. Next open+read will find it cached.
            reply.error(libc::EIO);
        }

        /// Release (close) a file handle.
        ///
        /// If the handle is dirty (has been written to), encrypts the temp file
        /// content and spawns a background upload to IPFS. Metadata publish is
        /// debounced — handled by flush_publish_queue() after uploads settle.
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
            // Drain any completed uploads from previous operations
            self.drain_upload_completions();

            let handle = self.open_files.remove(&fh);

            if let Some(handle) = handle {
                // Upload if: (a) file was written to (dirty), OR
                // (b) file was just created and never existed on IPFS (CID empty).
                // Case (b) handles `touch newfile` which creates + releases without writing.
                let is_new_file = handle.temp_path.is_some() && {
                    self.inodes.get(ino).map(|i| match &i.kind {
                        InodeKind::File { cid, .. } => cid.is_empty(),
                        _ => false,
                    }).unwrap_or(false)
                };
                let needs_upload = handle.temp_path.is_some() && (handle.dirty || is_new_file);
                if needs_upload {
                    // Dirty or new file: do CPU work synchronously, spawn network I/O
                    log::debug!("release: uploading ino {} (dirty={}, new={})", ino, handle.dirty, is_new_file);

                    let prepare_result = (|| -> Result<(), String> {
                        // Read complete temp file content (local I/O, fast)
                        let plaintext = handle.read_all()?;

                        // Generate new random file key and IV
                        let mut file_key = crate::crypto::utils::generate_file_key();
                        let iv = crate::crypto::utils::generate_iv();

                        // Encrypt content with AES-256-GCM
                        let ciphertext = crate::crypto::aes::encrypt_aes_gcm(
                            &plaintext, &file_key, &iv,
                        )
                        .map_err(|e| format!("File encryption failed: {}", e))?;

                        // Wrap file key with user's public key (ECIES)
                        let wrapped_key = crate::crypto::ecies::wrap_key(
                            &file_key, &self.public_key,
                        )
                        .map_err(|e| format!("Key wrapping failed: {}", e))?;

                        // Zero file key from memory
                        crate::crypto::utils::clear_bytes(&mut file_key);

                        // Get the old file CID for unpinning
                        let old_file_cid = self.inodes.get(ino).and_then(|inode| {
                            match &inode.kind {
                                InodeKind::File { cid, .. } if !cid.is_empty() => {
                                    Some(cid.clone())
                                }
                                _ => None,
                            }
                        });

                        // Update local inode (CID="" for now — drain_upload_completions will fix it)
                        let encrypted_file_key_hex = hex::encode(&wrapped_key);
                        let iv_hex = hex::encode(&iv);
                        let file_size = plaintext.len() as u64;

                        if let Some(inode) = self.inodes.get_mut(ino) {
                            inode.kind = InodeKind::File {
                                cid: String::new(),
                                encrypted_file_key: encrypted_file_key_hex,
                                iv: iv_hex,
                                size: file_size,
                                encryption_mode: "GCM".to_string(),
                                file_meta_ipns_name: None,
                                file_meta_resolved: true,
                            };
                            inode.attr.size = file_size;
                            inode.attr.blocks = (file_size + 511) / 512;
                            inode.attr.mtime = SystemTime::now();
                        }

                        // Cache plaintext so reads work before upload completes
                        self.pending_content.insert(ino, plaintext);

                        // Get parent inode for metadata publish queue
                        let parent_ino = self.inodes.get(ino)
                            .map(|i| i.parent_ino)
                            .unwrap_or(ROOT_INO);

                        // Queue debounced metadata publish (with pending upload)
                        self.queue_publish(parent_ino, true);

                        // Clone data for background thread
                        let api = self.api.clone();
                        let rt = self.rt.clone();
                        let upload_tx = self.upload_tx.clone();

                        // Spawn background OS thread for file upload ONLY
                        // Metadata publish is handled by the debounced publish queue
                        std::thread::spawn(move || {
                            let result = rt.block_on(async {
                                let file_cid = crate::api::ipfs::upload_content(
                                    &api, &ciphertext,
                                ).await?;

                                log::info!("File uploaded: ino {} -> CID {}", ino, file_cid);

                                // Notify main thread of completed upload
                                let _ = upload_tx.send(crate::fuse::UploadComplete {
                                    ino,
                                    new_cid: file_cid,
                                    parent_ino,
                                    old_file_cid,
                                });

                                Ok::<(), String>(())
                            });

                            if let Err(e) = result {
                                log::error!("Background upload failed for ino {}: {}", ino, e);
                            }
                        });

                        Ok(())
                    })();

                    if let Err(e) = prepare_result {
                        log::error!("File upload preparation failed for ino {}: {}", ino, e);
                    }

                    // Cleanup temp file
                    handle.cleanup();
                }
                // Non-dirty handles: just drop (cleanup happens via Drop impl)
            }

            reply.ok();
        }

        /// Flush file data (no-op -- actual upload happens on release).
        fn flush(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _fh: u64,
            _lock_owner: u64,
            reply: ReplyEmpty,
        ) {
            reply.ok();
        }

        /// Delete a file from a directory.
        fn unlink(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            reply: ReplyEmpty,
        ) {
            let name_str = match name.to_str() {
                Some(n) => n,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            // Find child inode
            let child_ino = match self.inodes.find_child(parent, name_str) {
                Some(ino) => ino,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            // Verify it's a file (not a directory)
            let cid_to_unpin = match self.inodes.get(child_ino) {
                Some(inode) => match &inode.kind {
                    InodeKind::File { cid, .. } => {
                        if cid.is_empty() { None } else { Some(cid.clone()) }
                    }
                    _ => {
                        reply.error(libc::EISDIR);
                        return;
                    }
                },
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            log::debug!("unlink: {} from parent {}", name_str, parent);

            // Remove inode from table (also removes from parent's children)
            self.inodes.remove(child_ino);

            // Bump parent mtime so NFS client invalidates its directory cache
            if let Some(parent_inode) = self.inodes.get_mut(parent) {
                parent_inode.attr.mtime = SystemTime::now();
                parent_inode.attr.ctime = SystemTime::now();
            }

            // Update parent folder metadata
            if let Err(e) = self.update_folder_metadata(parent) {
                log::error!("Failed to update folder metadata after unlink: {}", e);
                // Don't fail -- the local state is already updated
            }

            // Fire-and-forget unpin of file CID
            if let Some(cid) = cid_to_unpin {
                let api = self.api.clone();
                self.rt.spawn(async move {
                    if let Err(e) = crate::api::ipfs::unpin_content(&api, &cid).await {
                        log::debug!("Background unpin failed for {}: {}", cid, e);
                    }
                });
            }

            reply.ok();
        }

        /// Create a new directory.
        ///
        /// Generates a new Ed25519 IPNS keypair, derives the IPNS name,
        /// creates initial empty folder metadata, encrypts and uploads to IPFS,
        /// creates and publishes IPNS record, enrolls for TEE republishing,
        /// and updates the parent folder metadata.
        fn mkdir(
            &mut self,
            req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            reply: ReplyEntry,
        ) {
            let name_str = match name.to_str() {
                Some(n) => n,
                None => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            // Reject platform-specific directories — never sync .Trashes, .fseventsd etc.
            if is_platform_special(name_str) {
                reply.error(libc::EACCES);
                return;
            }

            // Check parent exists and is a directory
            let parent_exists = self.inodes.get(parent).map(|inode| {
                matches!(inode.kind, InodeKind::Root { .. } | InodeKind::Folder { .. })
            });
            if parent_exists != Some(true) {
                reply.error(libc::ENOENT);
                return;
            }

            log::debug!("mkdir: {} in parent {}", name_str, parent);

            let result = (|| -> Result<FileAttr, String> {
                // Generate new folder key (32 random bytes)
                let folder_key = crate::crypto::utils::generate_file_key();

                // Generate new Ed25519 keypair for this folder's IPNS
                let (ipns_public_key, ipns_private_key) =
                    crate::crypto::ed25519::generate_ed25519_keypair();

                // Derive IPNS name from public key
                let ipns_pub_arr: [u8; 32] = ipns_public_key.clone().try_into()
                    .map_err(|_| "Invalid IPNS public key length".to_string())?;
                let ipns_name = crate::crypto::ipns::derive_ipns_name(&ipns_pub_arr)
                    .map_err(|e| format!("Failed to derive IPNS name: {}", e))?;

                // Wrap folder key with user's public key (ECIES) for parent metadata
                let wrapped_folder_key = crate::crypto::ecies::wrap_key(
                    &folder_key, &self.public_key,
                )
                .map_err(|e| format!("Folder key wrapping failed: {}", e))?;
                let encrypted_folder_key_hex = hex::encode(&wrapped_folder_key);

                // Allocate inode and create InodeData (locally, no network I/O)
                let ino = self.inodes.allocate_ino();
                let now = SystemTime::now();
                let uid = req.uid();
                let gid = req.gid();

                let attr = FileAttr {
                    ino,
                    size: 0,
                    blocks: 0,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    crtime: now,
                    kind: FileType::Directory,
                    perm: 0o755,
                    nlink: 2,
                    uid,
                    gid,
                    rdev: 0,
                    blksize: BLOCK_SIZE,
                    flags: 0,
                };

                let inode = InodeData {
                    ino,
                    parent_ino: parent,
                    name: name_str.to_string(),
                    kind: InodeKind::Folder {
                        ipns_name: ipns_name.clone(),
                        encrypted_folder_key: encrypted_folder_key_hex,
                        folder_key: zeroize::Zeroizing::new(folder_key.to_vec()),
                        ipns_private_key: Some(zeroize::Zeroizing::new(ipns_private_key.clone())),
                        children_loaded: true, // empty folder, so "loaded"
                    },
                    attr,
                    children: Some(vec![]),
                };

                self.inodes.insert(inode);

                // Add to parent's children and bump mtime for NFS cache invalidation
                if let Some(parent_inode) = self.inodes.get_mut(parent) {
                    if let Some(ref mut children) = parent_inode.children {
                        children.push(ino);
                    }
                    parent_inode.attr.mtime = SystemTime::now();
                    parent_inode.attr.ctime = SystemTime::now();
                }

                // Create initial empty folder metadata (CPU-only)
                let metadata = crate::crypto::folder::FolderMetadata {
                    version: "v2".to_string(),
                    children: vec![],
                };

                // Encrypt metadata (CPU-only)
                let json_bytes = crate::fuse::encrypt_metadata_to_json(
                    &metadata, &folder_key,
                )?;

                // Encrypt IPNS private key with TEE public key for republishing
                let encrypted_ipns_for_tee = if let Some(ref tee_key) = self.tee_public_key {
                    let wrapped = crate::crypto::ecies::wrap_key(&ipns_private_key, tee_key)
                        .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
                    Some(hex::encode(&wrapped))
                } else {
                    None
                };
                let tee_key_epoch = self.tee_key_epoch;

                // Build parent folder metadata for background publish
                let (parent_metadata, parent_folder_key, parent_ipns_key, parent_ipns_name, parent_old_cid) =
                    self.build_folder_metadata(parent)?;

                // Spawn background thread for ALL network I/O:
                // 1. Upload new folder's initial metadata to IPFS
                // 2. Create + publish IPNS record for new folder
                // 3. Encrypt + upload + publish parent folder metadata
                let api = self.api.clone();
                let rt = self.rt.clone();
                let ipns_name_clone = ipns_name.clone();
                let coordinator = self.publish_coordinator.clone();

                std::thread::spawn(move || {
                    let result = rt.block_on(async {
                        // Upload new folder's encrypted metadata to IPFS
                        let initial_cid = crate::api::ipfs::upload_content(
                            &api, &json_bytes,
                        ).await?;

                        // Create and sign IPNS record for new folder (seq 0 is correct for brand new folder)
                        let ipns_key_arr: [u8; 32] = ipns_private_key.try_into()
                            .map_err(|_| "Invalid IPNS key length".to_string())?;
                        let value = format!("/ipfs/{}", initial_cid);
                        let record = crate::crypto::ipns::create_ipns_record(
                            &ipns_key_arr, &value, 0, 86_400_000,
                        ).map_err(|e| format!("IPNS record creation failed: {}", e))?;
                        let marshaled = crate::crypto::ipns::marshal_ipns_record(&record)
                            .map_err(|e| format!("IPNS marshal failed: {}", e))?;

                        use base64::Engine;
                        let record_b64 = base64::engine::general_purpose::STANDARD
                            .encode(&marshaled);

                        let req = crate::api::ipns::IpnsPublishRequest {
                            ipns_name: ipns_name_clone.clone(),
                            record: record_b64,
                            metadata_cid: initial_cid,
                            encrypted_ipns_private_key: encrypted_ipns_for_tee,
                            key_epoch: tee_key_epoch,
                        };
                        crate::api::ipns::publish_ipns(&api, &req).await?;

                        // Record new folder's initial publish
                        coordinator.record_publish(&ipns_name_clone, 0);
                        log::info!("New folder IPNS published: {}", ipns_name_clone);

                        // Now publish parent folder metadata
                        // Acquire per-folder publish lock for parent
                        let lock = coordinator.get_lock(&parent_ipns_name);
                        let _guard = lock.lock().await;

                        let parent_json = crate::fuse::encrypt_metadata_to_json(
                            &parent_metadata, &parent_folder_key,
                        )?;

                        // Resolve parent seq (monotonic cache fallback)
                        let seq = coordinator.resolve_sequence(&api, &parent_ipns_name).await?;

                        let parent_meta_cid = crate::api::ipfs::upload_content(
                            &api, &parent_json,
                        ).await?;

                        let parent_key_arr: [u8; 32] = parent_ipns_key.try_into()
                            .map_err(|_| "Invalid parent IPNS key length".to_string())?;
                        let new_seq = seq + 1;
                        let parent_value = format!("/ipfs/{}", parent_meta_cid);
                        let parent_record = crate::crypto::ipns::create_ipns_record(
                            &parent_key_arr, &parent_value, new_seq, 86_400_000,
                        ).map_err(|e| format!("Parent IPNS record failed: {}", e))?;
                        let parent_marshaled = crate::crypto::ipns::marshal_ipns_record(
                            &parent_record,
                        ).map_err(|e| format!("Parent IPNS marshal failed: {}", e))?;
                        let parent_record_b64 = base64::engine::general_purpose::STANDARD
                            .encode(&parent_marshaled);

                        let parent_req = crate::api::ipns::IpnsPublishRequest {
                            ipns_name: parent_ipns_name.clone(),
                            record: parent_record_b64,
                            metadata_cid: parent_meta_cid,
                            encrypted_ipns_private_key: None,
                            key_epoch: None,
                        };
                        crate::api::ipns::publish_ipns(&api, &parent_req).await?;

                        // Record successful parent publish
                        coordinator.record_publish(&parent_ipns_name, new_seq);

                        if let Some(old) = parent_old_cid {
                            let _ = crate::api::ipfs::unpin_content(&api, &old).await;
                        }

                        log::info!("Parent metadata published after mkdir");
                        Ok::<(), String>(())
                    });

                    if let Err(e) = result {
                        log::error!("Background mkdir publish failed: {}", e);
                    }
                });

                Ok(attr)
            })();

            match result {
                Ok(attr) => {
                    reply.entry(&DIR_TTL, &attr, 0);
                }
                Err(e) => {
                    log::error!("mkdir failed: {}", e);
                    reply.error(libc::EIO);
                }
            }
        }

        /// Remove an empty directory.
        fn rmdir(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            reply: ReplyEmpty,
        ) {
            let name_str = match name.to_str() {
                Some(n) => n,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            // Find child inode
            let child_ino = match self.inodes.find_child(parent, name_str) {
                Some(ino) => ino,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            // Verify it's a folder and get CID for unpinning
            let cid_to_unpin = match self.inodes.get(child_ino) {
                Some(inode) => {
                    match &inode.kind {
                        InodeKind::Folder { ipns_name, .. } => {
                            // Check not empty
                            if let Some(ref children) = inode.children {
                                if !children.is_empty() {
                                    reply.error(libc::ENOTEMPTY);
                                    return;
                                }
                            }
                            // Get CID from metadata cache for unpinning
                            self.metadata_cache.get(ipns_name)
                                .map(|cached| cached.cid.clone())
                        }
                        _ => {
                            reply.error(libc::ENOTDIR);
                            return;
                        }
                    }
                }
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            log::debug!("rmdir: {} from parent {}", name_str, parent);

            // Remove inode from table (also removes from parent's children)
            self.inodes.remove(child_ino);

            // Bump parent mtime so NFS client invalidates its directory cache
            if let Some(parent_inode) = self.inodes.get_mut(parent) {
                parent_inode.attr.mtime = SystemTime::now();
                parent_inode.attr.ctime = SystemTime::now();
            }

            // Update parent folder metadata
            if let Err(e) = self.update_folder_metadata(parent) {
                log::error!("Failed to update folder metadata after rmdir: {}", e);
            }

            // Fire-and-forget unpin of folder's IPNS CID
            if let Some(cid) = cid_to_unpin {
                let api = self.api.clone();
                self.rt.spawn(async move {
                    if let Err(e) = crate::api::ipfs::unpin_content(&api, &cid).await {
                        log::debug!("Background unpin failed for {}: {}", cid, e);
                    }
                });
            }

            reply.ok();
        }

        /// Rename or move a file/folder.
        ///
        /// Handles both same-folder renames and cross-folder moves.
        /// For cross-folder moves, updates both parent folders' metadata.
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
            log::debug!(
                "rename: {:?} (parent {}) -> {:?} (parent {})",
                name, parent, newname, newparent,
            );
            let name_str = match name.to_str() {
                Some(n) => n,
                None => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };
            let newname_str = match newname.to_str() {
                Some(n) => n,
                None => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            // Find source inode.
            // Workaround: FUSE-T (NFS-based) may pass truncated names
            // to the rename callback (first N bytes stripped). If exact
            // match fails, fall back to suffix match among children.
            let (source_ino, actual_name) = match self.inodes.find_child(parent, name_str) {
                Some(ino) => (ino, name_str.to_string()),
                None => {
                    // Suffix-match fallback for FUSE-T truncated names
                    let parent_inode = match self.inodes.get(parent) {
                        Some(i) => i,
                        None => {
                            reply.error(libc::ENOENT);
                            return;
                        }
                    };
                    let children = parent_inode.children.clone().unwrap_or_default();
                    let mut matches: Vec<(u64, String)> = Vec::new();
                    for &child_ino in &children {
                        if let Some(child) = self.inodes.get(child_ino) {
                            // Skip platform special files
                            if is_platform_special(&child.name) {
                                continue;
                            }
                            if child.name.ends_with(name_str) && child.name.len() > name_str.len() {
                                matches.push((child_ino, child.name.clone()));
                            }
                        }
                    }
                    if matches.len() == 1 {
                        log::debug!(
                            "rename suffix-match: truncated {:?} matched full name {:?}",
                            name_str, matches[0].1
                        );
                        (matches[0].0, matches[0].1.clone())
                    } else {
                        log::debug!(
                            "rename failed: {:?} not found (suffix matches: {})",
                            name_str, matches.len()
                        );
                        reply.error(libc::ENOENT);
                        return;
                    }
                }
            };

            // Use actual_name for name_to_ino removal (may differ from truncated name_str)
            let name_str = &actual_name;

            log::debug!(
                "rename: {} (ino {}) in parent {} -> {} in parent {}",
                name_str, source_ino, parent, newname_str, newparent,
            );

            // If destination exists, handle replacement
            if let Some(dest_ino) = self.inodes.find_child(newparent, newname_str) {
                // Check if destination is a non-empty directory
                if let Some(dest_inode) = self.inodes.get(dest_ino) {
                    match &dest_inode.kind {
                        InodeKind::Folder { .. } => {
                            if let Some(ref children) = dest_inode.children {
                                if !children.is_empty() {
                                    reply.error(libc::ENOTEMPTY);
                                    return;
                                }
                            }
                        }
                        InodeKind::File { cid, .. } => {
                            // Fire-and-forget unpin of replaced file
                            if !cid.is_empty() {
                                let cid_clone = cid.clone();
                                let api = self.api.clone();
                                self.rt.spawn(async move {
                                    let _ = crate::api::ipfs::unpin_content(
                                        &api, &cid_clone,
                                    ).await;
                                });
                            }
                        }
                        _ => {}
                    }
                }
                // Remove destination inode
                self.inodes.remove(dest_ino);
            }

            // Remove source from old parent's name index (NFC-normalized)
            {
                use unicode_normalization::UnicodeNormalization;
                let nfc_key: String = name_str.nfc().collect();
                self.inodes.name_to_ino.remove(&(parent, nfc_key));
            }

            // Update the source inode's name and parent
            if let Some(inode) = self.inodes.get_mut(source_ino) {
                inode.name = newname_str.to_string();
                inode.parent_ino = newparent;
                inode.attr.ctime = SystemTime::now();
            }

            // Update the name lookup index for the new location (NFC-normalized)
            {
                use unicode_normalization::UnicodeNormalization;
                let nfc_key: String = newname_str.nfc().collect();
                self.inodes.name_to_ino.insert(
                    (newparent, nfc_key),
                    source_ino,
                );
            }

            if parent != newparent {
                // Cross-folder move: update both parent children lists
                // Remove from old parent
                if let Some(old_parent) = self.inodes.get_mut(parent) {
                    if let Some(ref mut children) = old_parent.children {
                        children.retain(|&c| c != source_ino);
                    }
                    old_parent.attr.mtime = SystemTime::now();
                    old_parent.attr.ctime = SystemTime::now();
                }
                // Add to new parent
                if let Some(new_parent) = self.inodes.get_mut(newparent) {
                    if let Some(ref mut children) = new_parent.children {
                        children.push(source_ino);
                    }
                    new_parent.attr.mtime = SystemTime::now();
                    new_parent.attr.ctime = SystemTime::now();
                }

                // Update both folders' metadata
                if let Err(e) = self.update_folder_metadata(parent) {
                    log::error!("Failed to update old parent metadata after rename: {}", e);
                }
                if let Err(e) = self.update_folder_metadata(newparent) {
                    log::error!("Failed to update new parent metadata after rename: {}", e);
                }
            } else {
                // Same-folder rename: update parent mtime + metadata
                if let Some(parent_inode) = self.inodes.get_mut(parent) {
                    parent_inode.attr.mtime = SystemTime::now();
                    parent_inode.attr.ctime = SystemTime::now();
                }
                if let Err(e) = self.update_folder_metadata(parent) {
                    log::error!("Failed to update parent metadata after rename: {}", e);
                }
            }

            reply.ok();
        }

        /// Return filesystem statistics.
        fn statfs(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            reply: ReplyStatfs,
        ) {
            let block_size = BLOCK_SIZE as u64;
            let total_blocks = QUOTA_BYTES / block_size;

            // Estimate used blocks from known file sizes
            let used_bytes: u64 = self
                .inodes
                .inodes
                .values()
                .filter_map(|inode| match &inode.kind {
                    InodeKind::File { size, .. } => Some(*size),
                    _ => None,
                })
                .sum();
            let used_blocks = (used_bytes + block_size - 1) / block_size;
            let free_blocks = total_blocks.saturating_sub(used_blocks);

            let total_files: u64 = self.inodes.inodes.len() as u64;

            reply.statfs(
                total_blocks,   // total blocks
                free_blocks,    // free blocks
                free_blocks,    // available blocks (same as free for non-quota)
                total_files,    // total inodes
                total_files,    // free inodes (unlimited)
                block_size as u32,  // block size
                255,            // max name length
                block_size as u32,  // fragment size
            );
        }

        /// Check file access permissions.
        ///
        /// Enforces owner-only access based on inode permission bits.
        fn access(
            &mut self,
            req: &Request<'_>,
            ino: u64,
            mask: i32,
            reply: ReplyEmpty,
        ) {
            let Some(inode) = self.inodes.get(ino) else {
                reply.error(libc::ENOENT);
                return;
            };

            // F_OK: just check existence
            if mask == libc::F_OK {
                reply.ok();
                return;
            }

            let attr = &inode.attr;
            // Owner-only check: only the mounting user should access files
            if req.uid() != attr.uid {
                reply.error(libc::EACCES);
                return;
            }

            let owner_bits = (attr.perm >> 6) & 0o7;
            let mut granted = true;
            if mask & libc::R_OK != 0 && owner_bits & 0o4 == 0 { granted = false; }
            if mask & libc::W_OK != 0 && owner_bits & 0o2 == 0 { granted = false; }
            if mask & libc::X_OK != 0 && owner_bits & 0o1 == 0 { granted = false; }

            if granted {
                reply.ok();
            } else {
                reply.error(libc::EACCES);
            }
        }

        /// Get extended attribute value.
        ///
        /// Finder calls this for resource forks, Spotlight metadata, etc.
        /// Return ENODATA (no such xattr) instead of ENOSYS so Finder
        /// treats the directory as readable rather than broken.
        fn getxattr(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _name: &OsStr,
            _size: u32,
            reply: ReplyXattr,
        ) {
            // ENODATA = attribute not found (expected for files with no xattrs)
            #[cfg(target_os = "macos")]
            { reply.error(libc::ENOATTR); }
            #[cfg(not(target_os = "macos"))]
            { reply.error(libc::ENODATA); }
        }

        /// List extended attribute names.
        ///
        /// Return empty list (size 0) so Finder knows there are no xattrs
        /// rather than getting ENOSYS which it treats as an error.
        fn listxattr(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            size: u32,
            reply: ReplyXattr,
        ) {
            if size == 0 {
                // Caller wants to know the buffer size needed — 0 bytes.
                reply.size(0);
            } else {
                // Return empty xattr data.
                reply.data(&[]);
            }
        }

        /// Open a directory handle.
        ///
        /// Finder calls opendir before readdir. Return success for any
        /// known directory inode. Must return a non-zero fh for FUSE-T's
        /// SMB backend (fh=0 is treated as "no handle").
        fn opendir(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _flags: i32,
            reply: ReplyOpen,
        ) {
            if self.inodes.get(ino).is_some() {
                let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
                reply.opened(fh, 0);
            } else {
                reply.error(libc::ENOENT);
            }
        }

        /// Release (close) a directory handle.
        fn releasedir(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _fh: u64,
            _flags: i32,
            reply: ReplyEmpty,
        ) {
            reply.ok();
        }
    }
}

/// Public wrapper for decrypt_metadata_from_ipfs, used by mod.rs for pre-population.
/// Returns FolderMetadata (v2 only). Rejects non-v2 metadata.
#[cfg(feature = "fuse")]
pub fn decrypt_metadata_from_ipfs_public(
    encrypted_bytes: &[u8],
    folder_key: &[u8],
) -> Result<crate::crypto::folder::FolderMetadata, String> {
    #[derive(serde::Deserialize)]
    struct EncryptedFolderMetadata {
        iv: String,
        data: String,
    }

    let encrypted: EncryptedFolderMetadata = serde_json::from_slice(encrypted_bytes)
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

/// Public wrapper for decrypt_file_metadata_from_ipfs, used by mod.rs for FilePointer resolution.
#[cfg(feature = "fuse")]
pub fn decrypt_file_metadata_from_ipfs_public(
    encrypted_bytes: &[u8],
    folder_key: &[u8; 32],
) -> Result<crate::crypto::folder::FileMetadata, String> {
    #[derive(serde::Deserialize)]
    struct EncryptedFolderMetadata {
        iv: String,
        data: String,
    }

    let encrypted: EncryptedFolderMetadata = serde_json::from_slice(encrypted_bytes)
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

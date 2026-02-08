//! FUSE filesystem trait implementation for CipherVaultFS.
//!
//! Implements read operations: init, lookup, getattr, readdir, open, read, release, statfs, access.
//! Write operations are deferred to plan 09-06.
//!
//! IMPORTANT: All async operations spawn tasks on the tokio runtime and never block the FUSE thread.
//! This prevents Finder from hanging during network operations (RESEARCH.md pitfall 3).

#[cfg(feature = "fuse")]
mod implementation {
    use fuser::{
        FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
        ReplyOpen, ReplyEmpty, ReplyStatfs, Request,
    };
    use std::ffi::OsStr;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use crate::fuse::CipherVaultFS;
    use crate::fuse::file_handle::OpenFileHandle;
    use crate::fuse::inode::{InodeKind, ROOT_INO, BLOCK_SIZE};

    /// TTL for FUSE attribute/entry cache replies (1 second).
    const FUSE_TTL: Duration = Duration::from_secs(1);

    /// Total storage quota in bytes (500 MiB).
    const QUOTA_BYTES: u64 = 500 * 1024 * 1024;

    /// Encrypted folder metadata format from IPFS (JSON with iv + data).
    #[derive(serde::Deserialize)]
    struct EncryptedFolderMetadata {
        /// Hex-encoded 12-byte IV for AES-GCM.
        iv: String,
        /// Base64-encoded AES-GCM ciphertext (includes 16-byte auth tag).
        data: String,
    }

    /// Decrypt folder metadata fetched from IPFS.
    ///
    /// The IPFS content is JSON: `{ "iv": "<hex>", "data": "<base64>" }`.
    /// Decode IV from hex, decode ciphertext from base64, then AES-256-GCM decrypt.
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
        let folder_key_arr: &[u8; 32] = folder_key
            .try_into()
            .map_err(|_| "Invalid folder key length".to_string())?;
        let plaintext = crate::crypto::aes::decrypt_aes_gcm(&ciphertext, folder_key_arr, &iv)
            .map_err(|e| format!("Metadata decryption failed: {}", e))?;

        // Parse JSON to FolderMetadata
        serde_json::from_slice(&plaintext)
            .map_err(|e| format!("Failed to parse decrypted metadata: {}", e))
    }

    /// Helper: Fetch, decrypt, and populate a folder's children.
    ///
    /// Resolves the folder's IPNS name to CID, fetches encrypted metadata,
    /// decrypts with the folder key, and populates the inode table.
    fn fetch_and_populate_folder(
        fs: &mut CipherVaultFS,
        ino: u64,
        ipns_name: &str,
        folder_key: &[u8],
    ) -> Result<(), String> {
        let api = fs.api.clone();
        let ipns_name_owned = ipns_name.to_string();
        let folder_key_owned = folder_key.to_vec();
        let private_key = fs.private_key.clone();

        // Use the tokio runtime to run the async fetch synchronously
        // This is called during init (before FUSE event loop) so blocking is acceptable here
        let rt = fs.rt.clone();
        let result = rt.block_on(async {
            // Resolve IPNS name to CID
            let resolve_resp =
                crate::api::ipns::resolve_ipns(&api, &ipns_name_owned).await?;

            // Fetch encrypted metadata from IPFS
            let encrypted_bytes =
                crate::api::ipfs::fetch_content(&api, &resolve_resp.cid).await?;

            Ok::<(Vec<u8>, String), String>((encrypted_bytes, resolve_resp.cid))
        })?;

        let (encrypted_bytes, cid) = result;

        // Decrypt metadata
        let metadata = decrypt_metadata_from_ipfs(&encrypted_bytes, &folder_key_owned)?;

        // Cache metadata
        fs.metadata_cache
            .set(&ipns_name.to_string(), metadata.clone(), cid);

        // Populate inode table with children
        fs.inodes
            .populate_folder(ino, &metadata, &private_key)?;

        Ok(())
    }

    impl Filesystem for CipherVaultFS {
        /// Initialize the filesystem: populate root folder from IPNS.
        fn init(
            &mut self,
            _req: &Request<'_>,
            _config: &mut fuser::KernelConfig,
        ) -> Result<(), libc::c_int> {
            log::info!("CipherVaultFS::init - populating root folder");

            let root_ipns_name = self.root_ipns_name.clone();
            let root_folder_key = self.root_folder_key.clone();

            match fetch_and_populate_folder(self, ROOT_INO, &root_ipns_name, &root_folder_key)
            {
                Ok(()) => {
                    log::info!("Root folder populated successfully");
                    Ok(())
                }
                Err(e) => {
                    log::error!("Failed to populate root folder: {}", e);
                    // Still allow mount -- empty filesystem until sync fixes it
                    Ok(())
                }
            }
        }

        /// Look up a child by name within a parent directory.
        fn lookup(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            reply: ReplyEntry,
        ) {
            let name_str = match name.to_str() {
                Some(n) => n,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

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

            // Load children if needed
            if let Some((ipns_name, folder_key)) = needs_load {
                if let Err(e) =
                    fetch_and_populate_folder(self, parent, &ipns_name, &folder_key)
                {
                    log::warn!("Failed to load folder children: {}", e);
                    // Continue -- the child might not exist
                }
            }

            // Now look up the child
            if let Some(child_ino) = self.inodes.find_child(parent, name_str) {
                if let Some(inode) = self.inodes.get(child_ino) {
                    reply.entry(&FUSE_TTL, &inode.attr, 0);
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
            if let Some(inode) = self.inodes.get(ino) {
                reply.attr(&FUSE_TTL, &inode.attr);
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
            let (parent_ino, children, ipns_stale) = {
                let inode = match self.inodes.get(ino) {
                    Some(i) => i,
                    None => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                };

                let parent_ino = inode.parent_ino;
                let children = inode.children.clone().unwrap_or_default();

                // Check if metadata is stale for background refresh
                let ipns_stale = match &inode.kind {
                    InodeKind::Root { ipns_name, .. } => {
                        ipns_name.as_ref().and_then(|name| {
                            if self.metadata_cache.get(name).is_none() {
                                Some(name.clone())
                            } else {
                                None
                            }
                        })
                    }
                    InodeKind::Folder { ipns_name, .. } => {
                        if self.metadata_cache.get(ipns_name).is_none() {
                            Some(ipns_name.clone())
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                (parent_ino, children, ipns_stale)
            };

            // Build complete entry list: ".", "..", then children
            let mut entries: Vec<(u64, FileType, String)> = Vec::new();
            entries.push((ino, FileType::Directory, ".".to_string()));
            entries.push((parent_ino, FileType::Directory, "..".to_string()));

            for &child_ino in &children {
                if let Some(child) = self.inodes.get(child_ino) {
                    let file_type = match &child.kind {
                        InodeKind::Root { .. } | InodeKind::Folder { .. } => {
                            FileType::Directory
                        }
                        InodeKind::File { .. } => FileType::RegularFile,
                    };
                    entries.push((child_ino, file_type, child.name.clone()));
                }
            }

            // Return entries starting at offset (ALL in one pass per FUSE-T)
            for (i, (ino, file_type, name)) in
                entries.iter().enumerate().skip(offset as usize)
            {
                // reply.add returns true if the buffer is full
                if reply.add(*ino, (i + 1) as i64, *file_type, &name) {
                    break;
                }
            }

            reply.ok();

            // Trigger background metadata refresh if stale (AFTER responding to FUSE)
            if let Some(stale_ipns) = ipns_stale {
                let api = self.api.clone();
                let rt = self.rt.clone();
                // Fire-and-forget background refresh
                rt.spawn(async move {
                    if let Err(e) =
                        crate::api::ipns::resolve_ipns(&api, &stale_ipns).await
                    {
                        log::debug!(
                            "Background metadata refresh failed for {}: {}",
                            stale_ipns,
                            e
                        );
                    }
                    // Note: actual inode update on next readdir/lookup when metadata is re-fetched
                });
            }
        }

        /// Open a file for reading.
        ///
        /// READ-ONLY in this plan. Write support (O_WRONLY, O_RDWR) added in plan 09-06.
        fn open(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            flags: i32,
            reply: ReplyOpen,
        ) {
            // Check if inode exists and is a file
            match self.inodes.get(ino) {
                Some(inode) => match &inode.kind {
                    InodeKind::File { .. } => {}
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

            // Check for write flags -- read-only in this plan
            let access_mode = flags & libc::O_ACCMODE;
            if access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR {
                reply.error(libc::EACCES);
                return;
            }

            // Allocate file handle (read-only)
            let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
            self.open_files.insert(fh, OpenFileHandle::new_read(ino, flags));

            reply.opened(fh, 0);
        }

        /// Read file content.
        ///
        /// Checks content cache first. On miss, fetches encrypted bytes from IPFS,
        /// unwraps the file key (ECIES), decrypts (AES-256-GCM), caches, and returns slice.
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
            // Get file metadata
            let (cid, encrypted_file_key_hex, iv_hex) = {
                match self.inodes.get(ino) {
                    Some(inode) => match &inode.kind {
                        InodeKind::File {
                            cid,
                            encrypted_file_key,
                            iv,
                            ..
                        } => (cid.clone(), encrypted_file_key.clone(), iv.clone()),
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

            // Cache miss: fetch, decrypt, cache, return
            let api = self.api.clone();
            let private_key = self.private_key.clone();
            let rt = self.rt.clone();

            // Block on the fetch+decrypt (FUSE requires a response)
            let result: Result<Vec<u8>, String> = rt.block_on(async {
                // Fetch encrypted bytes from IPFS
                let encrypted_bytes =
                    crate::api::ipfs::fetch_content(&api, &cid).await?;

                // Decode encrypted file key
                let encrypted_file_key = hex::decode(&encrypted_file_key_hex)
                    .map_err(|_| "Invalid file key hex".to_string())?;

                // Unwrap file key using ECIES
                let mut file_key =
                    crate::crypto::ecies::unwrap_key(&encrypted_file_key, &private_key)
                        .map_err(|e| format!("File key unwrap failed: {}", e))?;

                // Decode IV
                let iv = hex::decode(&iv_hex)
                    .map_err(|_| "Invalid file IV hex".to_string())?;
                let iv_arr: [u8; 12] = iv
                    .try_into()
                    .map_err(|_| "Invalid IV length".to_string())?;

                // Decrypt file content
                let file_key_arr: [u8; 32] = file_key
                    .clone()
                    .try_into()
                    .map_err(|_| "Invalid file key length".to_string())?;
                let plaintext = crate::crypto::aes::decrypt_aes_gcm(
                    &encrypted_bytes,
                    &file_key_arr,
                    &iv_arr,
                )
                .map_err(|e| format!("File decryption failed: {}", e))?;

                // Zero the file key from memory
                crate::crypto::utils::clear_bytes(&mut file_key);

                Ok(plaintext)
            });

            match result {
                Ok(plaintext) => {
                    // Cache the decrypted content
                    self.content_cache.set(&cid, plaintext.clone());

                    // Store in open file handle
                    if let Some(handle) = self.open_files.get_mut(&fh) {
                        handle.cached_content = Some(plaintext.clone());
                    }

                    // Return requested slice
                    let start = offset as usize;
                    if start >= plaintext.len() {
                        reply.data(&[]);
                    } else {
                        let end =
                            std::cmp::min(start + size as usize, plaintext.len());
                        reply.data(&plaintext[start..end]);
                    }
                }
                Err(e) => {
                    log::error!("File read failed for ino {}: {}", ino, e);
                    reply.error(libc::EIO);
                }
            }
        }

        /// Release (close) a file handle.
        fn release(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            fh: u64,
            _flags: i32,
            _lock_owner: Option<u64>,
            _flush: bool,
            reply: ReplyEmpty,
        ) {
            // Remove file handle (write/dirty handling deferred to plan 09-06)
            self.open_files.remove(&fh);
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
        fn access(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _mask: i32,
            reply: ReplyEmpty,
        ) {
            if self.inodes.get(ino).is_some() {
                reply.ok();
            } else {
                reply.error(libc::ENOENT);
            }
        }
    }
}

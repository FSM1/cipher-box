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
        ReplyEntry, ReplyEmpty, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    };
    use std::ffi::OsStr;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, SystemTime};

    use crate::fuse::CipherBoxFS;
    use crate::fuse::file_handle::OpenFileHandle;
    use crate::fuse::inode::{InodeData, InodeKind, ROOT_INO, BLOCK_SIZE};

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
        fs: &mut CipherBoxFS,
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

    /// Helper: Fetch and decrypt existing file content for editing.
    ///
    /// Used when opening an existing file for writing -- need to pre-populate
    /// the temp file with the current decrypted content.
    fn fetch_and_decrypt_file_content(
        fs: &CipherBoxFS,
        cid: &str,
        encrypted_file_key_hex: &str,
        iv_hex: &str,
    ) -> Result<Vec<u8>, String> {
        let api = fs.api.clone();
        let private_key = fs.private_key.clone();
        let cid_owned = cid.to_string();
        let key_hex = encrypted_file_key_hex.to_string();
        let iv_hex_owned = iv_hex.to_string();
        let rt = fs.rt.clone();

        rt.block_on(async {
            // Fetch encrypted bytes from IPFS
            let encrypted_bytes =
                crate::api::ipfs::fetch_content(&api, &cid_owned).await?;

            // Decode and unwrap file key
            let encrypted_file_key = hex::decode(&key_hex)
                .map_err(|_| "Invalid file key hex".to_string())?;
            let mut file_key =
                crate::crypto::ecies::unwrap_key(&encrypted_file_key, &private_key)
                    .map_err(|e| format!("File key unwrap failed: {}", e))?;

            // Decode IV and decrypt
            let iv = hex::decode(&iv_hex_owned)
                .map_err(|_| "Invalid file IV hex".to_string())?;
            let iv_arr: [u8; 12] = iv.try_into()
                .map_err(|_| "Invalid IV length".to_string())?;
            let file_key_arr: [u8; 32] = file_key.clone().try_into()
                .map_err(|_| "Invalid file key length".to_string())?;

            let plaintext = crate::crypto::aes::decrypt_aes_gcm(
                &encrypted_bytes, &file_key_arr, &iv_arr,
            )
            .map_err(|e| format!("File decryption failed: {}", e))?;

            // Zero file key from memory
            crate::crypto::utils::clear_bytes(&mut file_key);

            Ok(plaintext)
        })
    }

    impl Filesystem for CipherBoxFS {
        /// Initialize the filesystem: populate root folder from IPNS.
        fn init(
            &mut self,
            _req: &Request<'_>,
            _config: &mut fuser::KernelConfig,
        ) -> Result<(), libc::c_int> {
            log::info!("CipherBoxFS::init - populating root folder");

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

                    reply.attr(&FUSE_TTL, &inode.attr);
                    return;
                }
            }

            // For other setattr calls, just return current attributes
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
                },
                attr,
                children: None,
            };

            self.inodes.insert(inode);

            // Add to parent's children list
            if let Some(parent_inode) = self.inodes.get_mut(parent) {
                if let Some(ref mut children) = parent_inode.children {
                    children.push(ino);
                }
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

            log::debug!("create: {} in parent {} -> ino {} fh {}", name_str, parent, ino, fh);
            reply.created(&FUSE_TTL, &attr, 0, fh, 0);
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
                    InodeKind::File { cid, encrypted_file_key, iv, .. } => {
                        Some((cid.clone(), encrypted_file_key.clone(), iv.clone()))
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

            let (cid, encrypted_file_key, iv) = file_info.unwrap();
            let access_mode = flags & libc::O_ACCMODE;

            if access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR {
                // Writable open: create temp file
                // If existing file (has CID), pre-populate with decrypted content
                let existing_content = if !cid.is_empty() {
                    match fetch_and_decrypt_file_content(self, &cid, &encrypted_file_key, &iv) {
                        Ok(content) => Some(content),
                        Err(e) => {
                            log::error!("Failed to fetch content for write-open: {}", e);
                            reply.error(libc::EIO);
                            return;
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
                // Read-only open
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

            // Empty CID means newly created file with no content yet
            if cid.is_empty() {
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
        ///
        /// If the handle is dirty (has been written to), encrypts the temp file
        /// content, uploads to IPFS, updates inode metadata, and publishes
        /// updated folder metadata via IPNS.
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
            let handle = self.open_files.remove(&fh);

            if let Some(handle) = handle {
                if handle.dirty && handle.temp_path.is_some() {
                    // Dirty file: encrypt + upload
                    log::debug!("release: dirty file ino {}, encrypting and uploading", ino);

                    let upload_result = (|| -> Result<(), String> {
                        // Read complete temp file content
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

                        // Get the old CID for unpinning
                        let old_cid = self.inodes.get(ino).and_then(|inode| {
                            match &inode.kind {
                                InodeKind::File { cid, .. } if !cid.is_empty() => {
                                    Some(cid.clone())
                                }
                                _ => None,
                            }
                        });

                        // Upload encrypted content to IPFS
                        let api = self.api.clone();
                        let rt = self.rt.clone();
                        let new_cid = rt.block_on(async {
                            crate::api::ipfs::upload_content(&api, &ciphertext).await
                        })?;

                        // Update inode with new CID, key, IV, and size
                        let encrypted_file_key_hex = hex::encode(&wrapped_key);
                        let iv_hex = hex::encode(&iv);
                        let file_size = plaintext.len() as u64;

                        if let Some(inode) = self.inodes.get_mut(ino) {
                            inode.kind = InodeKind::File {
                                cid: new_cid.clone(),
                                encrypted_file_key: encrypted_file_key_hex,
                                iv: iv_hex,
                                size: file_size,
                                encryption_mode: "GCM".to_string(),
                            };
                            inode.attr.size = file_size;
                            inode.attr.blocks = (file_size + 511) / 512;
                            inode.attr.mtime = SystemTime::now();
                        }

                        // Cache decrypted content for immediate re-reads
                        self.content_cache.set(&new_cid, plaintext);

                        // Get parent inode for metadata update
                        let parent_ino = self.inodes.get(ino)
                            .map(|i| i.parent_ino)
                            .unwrap_or(ROOT_INO);

                        // Update parent folder metadata (re-encrypt + IPNS publish)
                        self.update_folder_metadata(parent_ino)?;

                        // Fire-and-forget unpin of old CID
                        if let Some(old_cid) = old_cid {
                            let api = self.api.clone();
                            self.rt.spawn(async move {
                                if let Err(e) = crate::api::ipfs::unpin_content(&api, &old_cid).await {
                                    log::debug!("Background unpin failed for {}: {}", old_cid, e);
                                }
                            });
                        }

                        Ok(())
                    })();

                    if let Err(e) = upload_result {
                        log::error!("File upload failed for ino {}: {}", ino, e);
                        // Don't return EIO -- reply.ok() to avoid confusing apps
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

            // Invalidate content cache for this CID
            if let Some(ref cid) = cid_to_unpin {
                // Content cache entry will be evicted naturally (LRU)
                // No explicit invalidate method needed
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

                // Create initial empty folder metadata
                let metadata = crate::crypto::folder::FolderMetadata {
                    version: "v1".to_string(),
                    children: vec![],
                };

                // Encrypt metadata
                let folder_key_arr: [u8; 32] = folder_key;
                let sealed = crate::crypto::folder::encrypt_folder_metadata(
                    &metadata, &folder_key_arr,
                )
                .map_err(|e| format!("Metadata encryption failed: {}", e))?;

                // Format as JSON `{ "iv": "<hex>", "data": "<base64>" }`
                let iv_hex = hex::encode(&sealed[..12]);
                use base64::Engine;
                let data_base64 = base64::engine::general_purpose::STANDARD
                    .encode(&sealed[12..]);
                let json_metadata = serde_json::json!({
                    "iv": iv_hex,
                    "data": data_base64,
                });
                let json_bytes = serde_json::to_vec(&json_metadata)
                    .map_err(|e| format!("JSON serialization failed: {}", e))?;

                // Upload encrypted metadata to IPFS
                let api = self.api.clone();
                let rt = self.rt.clone();
                let initial_cid = rt.block_on(async {
                    crate::api::ipfs::upload_content(&api, &json_bytes).await
                })?;

                // Create and sign initial IPNS record
                let ipns_key_arr: [u8; 32] = ipns_private_key.clone().try_into()
                    .map_err(|_| "Invalid IPNS private key length".to_string())?;
                let value = format!("/ipfs/{}", initial_cid);
                let record = crate::crypto::ipns::create_ipns_record(
                    &ipns_key_arr, &value, 0, 86_400_000,
                )
                .map_err(|e| format!("IPNS record creation failed: {}", e))?;

                let marshaled = crate::crypto::ipns::marshal_ipns_record(&record)
                    .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;
                let record_base64 = base64::engine::general_purpose::STANDARD
                    .encode(&marshaled);

                // Wrap folder key with user's public key (ECIES) for parent metadata
                let wrapped_folder_key = crate::crypto::ecies::wrap_key(
                    &folder_key, &self.public_key,
                )
                .map_err(|e| format!("Folder key wrapping failed: {}", e))?;
                let encrypted_folder_key_hex = hex::encode(&wrapped_folder_key);

                // Encrypt IPNS private key with TEE public key for republishing enrollment
                let encrypted_ipns_for_tee = if let Some(ref tee_key) = self.tee_public_key {
                    let wrapped = crate::crypto::ecies::wrap_key(&ipns_private_key, tee_key)
                        .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
                    Some(hex::encode(&wrapped))
                } else {
                    None
                };

                // Publish IPNS record
                let publish_request = crate::api::ipns::IpnsPublishRequest {
                    ipns_name: ipns_name.clone(),
                    record: record_base64,
                    metadata_cid: initial_cid.clone(),
                    encrypted_ipns_private_key: encrypted_ipns_for_tee,
                    key_epoch: self.tee_key_epoch,
                };

                let api = self.api.clone();
                rt.block_on(async {
                    crate::api::ipns::publish_ipns(&api, &publish_request).await
                })?;

                // Cache metadata for this new folder
                self.metadata_cache.set(&ipns_name, metadata, initial_cid);

                // Allocate inode and create InodeData
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
                        folder_key: folder_key.to_vec(),
                        ipns_private_key: Some(ipns_private_key),
                        children_loaded: true, // empty folder, so "loaded"
                    },
                    attr,
                    children: Some(vec![]),
                };

                self.inodes.insert(inode);

                // Add to parent's children
                if let Some(parent_inode) = self.inodes.get_mut(parent) {
                    if let Some(ref mut children) = parent_inode.children {
                        children.push(ino);
                    }
                }

                // Update parent folder metadata
                self.update_folder_metadata(parent)?;

                Ok(attr)
            })();

            match result {
                Ok(attr) => {
                    reply.entry(&FUSE_TTL, &attr, 0);
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

            // Find source inode
            let source_ino = match self.inodes.find_child(parent, name_str) {
                Some(ino) => ino,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

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

            // Remove source from old parent's name index
            self.inodes.name_to_ino.remove(&(parent, name_str.to_string()));

            // Update the source inode's name and parent
            if let Some(inode) = self.inodes.get_mut(source_ino) {
                inode.name = newname_str.to_string();
                inode.parent_ino = newparent;
                inode.attr.ctime = SystemTime::now();
            }

            // Update the name lookup index for the new location
            self.inodes.name_to_ino.insert(
                (newparent, newname_str.to_string()),
                source_ino,
            );

            if parent != newparent {
                // Cross-folder move: update both parent children lists
                // Remove from old parent
                if let Some(old_parent) = self.inodes.get_mut(parent) {
                    if let Some(ref mut children) = old_parent.children {
                        children.retain(|&c| c != source_ino);
                    }
                }
                // Add to new parent
                if let Some(new_parent) = self.inodes.get_mut(newparent) {
                    if let Some(ref mut children) = new_parent.children {
                        children.push(source_ino);
                    }
                }

                // Update both folders' metadata
                if let Err(e) = self.update_folder_metadata(parent) {
                    log::error!("Failed to update old parent metadata after rename: {}", e);
                }
                if let Err(e) = self.update_folder_metadata(newparent) {
                    log::error!("Failed to update new parent metadata after rename: {}", e);
                }
            } else {
                // Same-folder rename: just update parent metadata
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

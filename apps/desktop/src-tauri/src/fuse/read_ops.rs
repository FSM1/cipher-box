//! Read operations for macOS FUSE filesystem.
//!
//! Contains handler logic for: init, destroy, lookup, getattr, open, read,
//! release, flush, access, getxattr, listxattr.

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    use fuser::{
        ReplyAttr, ReplyData, ReplyEmpty, ReplyEntry,
        ReplyOpen, ReplyXattr,
        consts::FOPEN_DIRECT_IO,
    };
    use std::ffi::OsStr;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, SystemTime};

    use crate::fuse::CipherBoxFS;
    use crate::fuse::constants::{
        CONTENT_DOWNLOAD_TIMEOUT, MAX_VERSIONS_PER_FILE, VERSION_COOLDOWN_MS,
    };
    use crate::fuse::file_handle::OpenFileHandle;
    use crate::fuse::helpers::{is_platform_special, mime_from_extension};
    use crate::fuse::inode::{InodeKind, ROOT_INO};
    use crate::fuse::operations::implementation::{
        ttl_for_is_dir, current_uid, current_gid,
        fetch_and_decrypt_file_content, fetch_and_decrypt_content_async,
        publish_file_metadata,
    };

    /// Initialize the filesystem.
    pub fn handle_init(
        fs: &mut CipherBoxFS,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        log::info!("CipherBoxFS::init (root pre-populated, no network I/O)");
        log::info!("Root IPNS name: {}", fs.root_ipns_name);
        log::info!("Inode count: {}", fs.inodes.inodes.len());
        Ok(())
    }

    /// Clean up all caches and zeroize sensitive data on unmount.
    pub fn handle_destroy(fs: &mut CipherBoxFS) {
        use zeroize::Zeroize;

        fs.content_cache.clear();
        fs.metadata_cache.clear();

        for (_, content) in fs.pending_content.iter_mut() {
            content.zeroize();
        }
        fs.pending_content.clear();

        for (_, handle) in fs.open_files.iter_mut() {
            if let Some(ref mut c) = handle.cached_content {
                c.zeroize();
            }
        }
        fs.open_files.clear();

        log::info!("CipherBoxFS destroyed: all caches zeroized");
    }

    /// Look up a child by name within a parent directory.
    pub fn handle_lookup(
        fs: &mut CipherBoxFS,
        parent: u64,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
        fs.drain_upload_completions();
        fs.drain_refresh_completions();

        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Handle "." and ".." -- NFS clients rely on these working.
        if name_str == "." {
            if let Some(inode) = fs.inodes.get(parent) {
                reply.entry(&ttl_for_is_dir(inode.attr.is_dir), &inode.attr.to_fuse_attr(current_uid(), current_gid()), 0);
                return;
            }
        }
        if name_str == ".." {
            let parent_ino = fs.inodes.get(parent)
                .map(|i| i.parent_ino)
                .unwrap_or(1);
            if let Some(inode) = fs.inodes.get(parent_ino) {
                reply.entry(&ttl_for_is_dir(inode.attr.is_dir), &inode.attr.to_fuse_attr(current_uid(), current_gid()), 0);
                return;
            }
        }

        if is_platform_special(name_str) {
            reply.error(libc::ENOENT);
            return;
        }

        // Check if parent is a folder with unloaded children (lazy loading)
        let needs_load = {
            if let Some(parent_inode) = fs.inodes.get(parent) {
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

        // Non-blocking lazy load: fire background fetch
        if let Some((ipns_name, folder_key)) = needs_load {
            let api = fs.api.clone();
            let rt = fs.rt.clone();
            let tx = fs.refresh_tx.clone();
            let refresh_ino = parent;
            rt.spawn(async move {
                match cipherbox_api_client::ipns::resolve_ipns(&api, &ipns_name).await {
                    Ok(resolve_resp) => {
                        match cipherbox_api_client::ipfs::fetch_content(&api, &resolve_resp.cid).await {
                            Ok(encrypted_bytes) => {
                                match cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public(
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

        if let Some(child_ino) = fs.inodes.find_child(parent, name_str) {
            if let Some(inode) = fs.inodes.get(child_ino) {
                reply.entry(&ttl_for_is_dir(inode.attr.is_dir), &inode.attr.to_fuse_attr(current_uid(), current_gid()), 0);
                return;
            }
        }

        reply.error(libc::ENOENT);
    }

    /// Return file attributes for an inode.
    pub fn handle_getattr(
        fs: &mut CipherBoxFS,
        ino: u64,
        reply: ReplyAttr,
    ) {
        fs.drain_upload_completions();

        if let Some(inode) = fs.inodes.get(ino) {
            reply.attr(&ttl_for_is_dir(inode.attr.is_dir), &inode.attr.to_fuse_attr(current_uid(), current_gid()));
        } else {
            reply.error(libc::ENOENT);
        }
    }

    /// Open a file for reading or writing.
    pub fn handle_open(
        fs: &mut CipherBoxFS,
        ino: u64,
        flags: i32,
        reply: ReplyOpen,
    ) {
        let file_info = match fs.inodes.get(ino) {
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

        log::debug!(
            "open: ino={} flags=0x{:x} access_mode=0x{:x} O_TRUNC={} cid={}",
            ino, flags, access_mode, (flags & libc::O_TRUNC) != 0, &cid
        );

        if access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR {
            let is_trunc = (flags & libc::O_TRUNC) != 0;

            let inode_size = fs.inodes.get(ino)
                .map(|i| i.attr.size)
                .unwrap_or(0);

            let existing_content = if is_trunc || inode_size == 0 {
                if let Some(inode) = fs.inodes.get_mut(ino) {
                    inode.attr.size = 0;
                    inode.attr.blocks = 0;
                    inode.attr.mtime = SystemTime::now();
                    inode.write_generation += 1;
                    if let InodeKind::File { size: ref mut s, cid: ref mut c, .. } = inode.kind {
                        *s = 0;
                        *c = String::new();
                    }
                }
                None
            } else if !cid.is_empty() {
                fs.drain_content_prefetches();
                if let Some(cached) = fs.content_cache.get(&cid) {
                    Some(cached.to_vec())
                } else {
                    match fetch_and_decrypt_file_content(fs, &cid, &encrypted_file_key, &iv, &encryption_mode) {
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

            let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
            match OpenFileHandle::new_write(ino, &fs.temp_dir, existing_content.as_deref()) {
                Ok(handle) => {
                    fs.open_files.insert(fh, handle);
                    reply.opened(fh, FOPEN_DIRECT_IO);
                }
                Err(e) => {
                    log::error!("Failed to create write handle: {}", e);
                    reply.error(libc::EIO);
                }
            }
        } else {
            // Read-only open
            fs.drain_content_prefetches();

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

            let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
            fs.open_files.insert(fh, OpenFileHandle::new_read(ino));
            reply.opened(fh, FOPEN_DIRECT_IO);
        }
    }

    /// Read file content.
    pub fn handle_read(
        fs: &mut CipherBoxFS,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        reply: ReplyData,
    ) {
        fs.drain_content_prefetches();

        let has_temp = fs.open_files.get(&fh)
            .map(|h| h.temp_path.is_some())
            .unwrap_or(false);

        log::debug!(
            "read: ino={} fh={} offset={} size={} has_temp={}",
            ino, fh, offset, size, has_temp
        );

        if has_temp {
            match fs.open_files.get(&fh) {
                Some(handle) => {
                    match handle.read_at(offset, size) {
                        Ok(data) => {
                            log::debug!("read: temp file returned {} bytes", data.len());
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

        let (cid, encrypted_file_key_hex, iv_hex, encryption_mode) = {
            match fs.inodes.get(ino) {
                Some(inode) => match &inode.kind {
                    InodeKind::File {
                        cid, encrypted_file_key, iv, encryption_mode, ..
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

        if cid.is_empty() {
            if let Some(content) = fs.pending_content.get(&ino) {
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

        if let Some(handle) = fs.open_files.get(&fh) {
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

        if let Some(cached) = fs.content_cache.get(&cid) {
            let start = offset as usize;
            if start >= cached.len() {
                reply.data(&[]);
                return;
            }
            let end = std::cmp::min(start + size as usize, cached.len());
            let data_slice = cached[start..end].to_vec();
            if let Some(handle) = fs.open_files.get_mut(&fh) {
                handle.cached_content = Some(cached.to_vec());
            }
            reply.data(&data_slice);
            return;
        }

        // Content not in cache -- start prefetch and poll
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

        let poll_start = std::time::Instant::now();
        let max_wait = Duration::from_secs(3);
        loop {
            std::thread::sleep(Duration::from_millis(100));
            fs.drain_content_prefetches();
            if let Some(cached) = fs.content_cache.get(&cid) {
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

        reply.error(libc::EIO);
    }

    /// Release (close) a file handle.
    pub fn handle_release(
        fs: &mut CipherBoxFS,
        ino: u64,
        fh: u64,
        reply: ReplyEmpty,
    ) {
        fs.drain_upload_completions();

        let handle = fs.open_files.remove(&fh);

        if let Some(handle) = handle {
            let is_new_file = handle.temp_path.is_some() && {
                fs.inodes.get(ino).map(|i| match &i.kind {
                    InodeKind::File { cid, .. } => cid.is_empty(),
                    _ => false,
                }).unwrap_or(false)
            };
            let needs_upload = handle.temp_path.is_some() && (handle.dirty || is_new_file);
            if needs_upload {
                log::debug!("release: uploading ino {} (dirty={}, new={})", ino, handle.dirty, is_new_file);

                let prepare_result = (|| -> Result<(), String> {
                    let plaintext = handle.read_all()?;

                    let mut file_key = cipherbox_crypto::utils::generate_file_key();
                    let iv = cipherbox_crypto::utils::generate_iv();

                    let ciphertext = cipherbox_crypto::aes::encrypt_aes_gcm(
                        &plaintext, &file_key, &iv,
                    )
                    .map_err(|e| format!("File encryption failed: {}", e))?;

                    let wrapped_key = cipherbox_crypto::ecies::wrap_key(
                        &file_key, &fs.public_key,
                    )
                    .map_err(|e| format!("Key wrapping failed: {}", e))?;

                    cipherbox_crypto::utils::clear_bytes(&mut file_key);

                    let (old_file_cid, old_encrypted_key, old_iv, old_size, old_mode,
                         existing_versions, file_ipns_private_key, file_meta_ipns_name) =
                        fs.inodes.get(ino).map(|inode| {
                            match &inode.kind {
                                InodeKind::File {
                                    cid, encrypted_file_key, iv, size, encryption_mode,
                                    versions, file_ipns_private_key, file_meta_ipns_name, ..
                                } => (
                                    if cid.is_empty() { None } else { Some(cid.clone()) },
                                    encrypted_file_key.clone(), iv.clone(), *size,
                                    encryption_mode.clone(), versions.clone(),
                                    file_ipns_private_key.clone(), file_meta_ipns_name.clone(),
                                ),
                                _ => (None, String::new(), String::new(), 0, "GCM".to_string(), None, None, None),
                            }
                        }).unwrap_or((None, String::new(), String::new(), 0, "GCM".to_string(), None, None, None));

                    let encrypted_file_key_hex = hex::encode(&wrapped_key);
                    let iv_hex = hex::encode(&iv);
                    let file_size = plaintext.len() as u64;

                    let file_name = fs.inodes.get(ino).map(|i| i.name.clone()).unwrap_or_default();
                    let mime_type = mime_from_extension(&file_name);

                    let now_ms = SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    let should_version = if let Some(ref versions) = existing_versions {
                        if let Some(newest) = versions.first() {
                            now_ms.saturating_sub(newest.timestamp) >= VERSION_COOLDOWN_MS
                        } else {
                            old_file_cid.as_ref().is_some_and(|c| !c.is_empty())
                        }
                    } else {
                        old_file_cid.as_ref().is_some_and(|c| !c.is_empty())
                    };

                    let (new_versions, pruned_cids) = if should_version {
                        if let Some(ref old_c) = old_file_cid {
                            if !old_c.is_empty() {
                                let version_entry = cipherbox_core::folder::VersionEntry {
                                    cid: old_c.clone(),
                                    file_key_encrypted: old_encrypted_key.clone(),
                                    file_iv: old_iv.clone(),
                                    size: old_size,
                                    timestamp: now_ms,
                                    encryption_mode: old_mode.clone(),
                                };
                                let mut versions = vec![version_entry];
                                versions.extend(existing_versions.unwrap_or_default());
                                let pruned: Vec<String> = if versions.len() > MAX_VERSIONS_PER_FILE {
                                    versions.split_off(MAX_VERSIONS_PER_FILE).into_iter().map(|v| v.cid).collect()
                                } else {
                                    vec![]
                                };
                                if !pruned.is_empty() {
                                    log::info!("Pruned {} version(s) for ino {} (exceeded max {})", pruned.len(), ino, MAX_VERSIONS_PER_FILE);
                                }
                                log::debug!("Created version entry for ino {} (total versions: {})", ino, versions.len());
                                (Some(versions), pruned)
                            } else {
                                (existing_versions, vec![])
                            }
                        } else {
                            (existing_versions, vec![])
                        }
                    } else {
                        if existing_versions.is_some() {
                            log::debug!("Version cooldown active for ino {} -- skipping version creation", ino);
                        }
                        (existing_versions, vec![])
                    };

                    let versions_for_meta = new_versions.as_ref()
                        .filter(|v| !v.is_empty())
                        .cloned();

                    if let Some(inode) = fs.inodes.get_mut(ino) {
                        let cached_hex = match &inode.kind {
                            InodeKind::File { file_ipns_key_encrypted_hex, .. } => file_ipns_key_encrypted_hex.clone(),
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
                            file_ipns_private_key: file_ipns_private_key.clone(),
                            file_ipns_key_encrypted_hex: cached_hex,
                            versions: versions_for_meta.clone(),
                        };
                        inode.attr.size = file_size;
                        inode.attr.blocks = (file_size + 511) / 512;
                        inode.attr.mtime = SystemTime::now();
                    }

                    fs.pending_content.insert(ino, plaintext);

                    let write_gen = fs.inodes.get(ino)
                        .map(|i| i.write_generation)
                        .unwrap_or(0);

                    let parent_ino = fs.inodes.get(ino)
                        .map(|i| i.parent_ino)
                        .unwrap_or(ROOT_INO);

                    let folder_key_for_file_meta = fs.get_folder_key(parent_ino);

                    fs.queue_publish(parent_ino, true);

                    let api = fs.api.clone();
                    let rt = fs.rt.clone();
                    let upload_tx = fs.upload_tx.clone();
                    let coordinator = fs.publish_coordinator.clone();

                    let file_meta = cipherbox_core::folder::FileMetadata {
                        version: "v1".to_string(),
                        cid: String::new(),
                        file_key_encrypted: encrypted_file_key_hex.clone(),
                        file_iv: iv_hex.clone(),
                        size: file_size,
                        mime_type,
                        encryption_mode: "GCM".to_string(),
                        created_at: now_ms,
                        modified_at: now_ms,
                        versions: versions_for_meta,
                    };

                    std::thread::spawn(move || {
                        let result = rt.block_on(async {
                            let file_cid = cipherbox_api_client::ipfs::upload_content(
                                &api, &ciphertext,
                            ).await.map_err(|e| e.to_string())?;

                            log::info!("File uploaded: ino {} -> CID {}", ino, file_cid);

                            let _ = upload_tx.send(crate::fuse::UploadComplete {
                                ino,
                                new_cid: file_cid.clone(),
                                parent_ino,
                                old_file_cid,
                                pruned_cids,
                                write_generation: write_gen,
                            });

                            if let (Some(ipns_key), Some(ipns_name), Some(folder_key)) =
                                (&file_ipns_private_key, &file_meta_ipns_name, &folder_key_for_file_meta)
                            {
                                let mut file_meta_with_cid = file_meta;
                                file_meta_with_cid.cid = file_cid;

                                if let Err(e) = publish_file_metadata(
                                    &api, &file_meta_with_cid, folder_key, ipns_key, ipns_name, &coordinator,
                                ).await {
                                    log::warn!("Per-file IPNS publish failed for ino {}: {}", ino, e);
                                }
                            } else {
                                log::warn!(
                                    "release: skipping per-file IPNS publish for ino {} (missing key/name/folder_key)",
                                    ino
                                );
                            }

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

                handle.cleanup();
            }
        }

        reply.ok();
    }

    /// Flush file data (no-op).
    pub fn handle_flush(reply: ReplyEmpty) {
        reply.ok();
    }

    /// Check file access permissions.
    pub fn handle_access(
        fs: &CipherBoxFS,
        ino: u64,
        mask: i32,
        reply: ReplyEmpty,
    ) {
        if fs.inodes.get(ino).is_none() {
            reply.error(libc::ENOENT);
            return;
        }
        log::trace!("access: ino={} mask={:#o} -> OK", ino, mask);
        reply.ok();
    }

    /// Get extended attribute value.
    pub fn handle_getxattr(reply: ReplyXattr) {
        #[cfg(target_os = "macos")]
        { reply.error(libc::ENOATTR); }
        #[cfg(not(target_os = "macos"))]
        { reply.error(libc::ENODATA); }
    }

    /// List extended attribute names.
    pub fn handle_listxattr(size: u32, reply: ReplyXattr) {
        if size == 0 {
            reply.size(0);
        } else {
            reply.data(&[]);
        }
    }
}

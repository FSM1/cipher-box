//! Read operations for macOS FUSE filesystem.
//!
//! Contains handler logic for: init, destroy, lookup, getattr, open, read,
//! release, flush, access, getxattr, listxattr.

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    use fuser::{
        consts::FOPEN_DIRECT_IO, ReplyAttr, ReplyData, ReplyEmpty, ReplyEntry, ReplyOpen,
        ReplyXattr,
    };
    use std::ffi::OsStr;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, SystemTime};

    use crate::constants::CONTENT_DOWNLOAD_TIMEOUT;
    use crate::CipherBoxFS;

    const FILEPOINTER_POLL_TIMEOUT: Duration = Duration::from_secs(5);
    const FILEPOINTER_POLL_INTERVAL: Duration = Duration::from_millis(100);

    /// Poll for an in-flight async FilePointer resolution to complete.
    /// Poll result: why did we stop waiting?
    enum PollResult {
        Resolved,
        TimedOut,
        NotInFlight,
    }

    /// Poll for an in-flight async FilePointer resolution to complete.
    /// Only blocks if an async resolution task is actually in-flight for this inode.
    fn poll_filepointer_resolution(fs: &mut CipherBoxFS, ino: u64) -> PollResult {
        if !fs.resolving_file_pointers.contains(&ino) {
            log::debug!(
                "poll_filepointer_resolution: ino={} has no in-flight resolution",
                ino
            );
            return PollResult::NotInFlight;
        }
        let deadline = std::time::Instant::now() + FILEPOINTER_POLL_TIMEOUT;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(FILEPOINTER_POLL_INTERVAL);
            fs.drain_filepointer_completions();
            // Break early if async task completed with Failure (ino removed from set)
            if !fs.resolving_file_pointers.contains(&ino) {
                if let Some(inode) = fs.inodes.get(ino) {
                    if let crate::inode::InodeKind::File {
                        file_meta_resolved: true,
                        cid,
                        ..
                    } = &inode.kind
                    {
                        if !cid.is_empty() {
                            return PollResult::Resolved;
                        }
                    }
                }
                log::debug!(
                    "poll_filepointer_resolution: ino={} async task finished but resolution failed",
                    ino
                );
                return PollResult::NotInFlight;
            }
            // Still in-flight — check if resolved yet
            if let Some(inode) = fs.inodes.get(ino) {
                if let crate::inode::InodeKind::File {
                    cid,
                    file_meta_resolved: true,
                    ..
                } = &inode.kind
                {
                    if !cid.is_empty() {
                        return PollResult::Resolved;
                    }
                }
            }
        }
        PollResult::TimedOut
    }
    use crate::file_handle::OpenFileHandle;
    use crate::helpers::is_platform_special;
    use crate::inode::InodeKind;
    use crate::operations::implementation::{
        current_gid, current_uid, fetch_and_decrypt_content_async, fetch_and_decrypt_file_content,
        publish_file_metadata, ttl_for_is_dir,
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
    pub fn handle_lookup(fs: &mut CipherBoxFS, parent: u64, name: &OsStr, reply: ReplyEntry) {
        fs.drain_upload_completions();
        fs.drain_refresh_completions();
        fs.drain_filepointer_completions();

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
                reply.entry(
                    &ttl_for_is_dir(inode.attr.is_dir),
                    &inode.attr.to_fuse_attr(current_uid(), current_gid()),
                    0,
                );
                return;
            }
        }
        if name_str == ".." {
            let parent_ino = fs.inodes.get(parent).map(|i| i.parent_ino).unwrap_or(1);
            if let Some(inode) = fs.inodes.get(parent_ino) {
                reply.entry(
                    &ttl_for_is_dir(inode.attr.is_dir),
                    &inode.attr.to_fuse_attr(current_uid(), current_gid()),
                    0,
                );
                return;
            }
        }

        if is_platform_special(name_str) {
            reply.error(libc::ENOENT);
            return;
        }

        // Check if parent is a folder with unloaded children (lazy loading)
        // OR if the parent folder metadata is stale and needs a background refresh.
        // This mirrors readdir's staleness check so that file access (stat, open)
        // also triggers metadata refresh, not only directory listings.
        let (needs_load, needs_refresh) = {
            if let Some(parent_inode) = fs.inodes.get(parent) {
                match &parent_inode.kind {
                    InodeKind::Folder {
                        children_loaded,
                        ipns_name,
                        folder_key,
                        ..
                    } => {
                        if !children_loaded {
                            (Some((ipns_name.clone(), folder_key.clone())), None)
                        } else if fs.metadata_cache.get(ipns_name).is_none() {
                            (None, Some((ipns_name.clone(), folder_key.clone())))
                        } else {
                            (None, None)
                        }
                    }
                    InodeKind::Root { ipns_name, .. } => {
                        let stale = ipns_name.as_ref().and_then(|name| {
                            if fs.metadata_cache.get(name).is_none() {
                                Some((name.clone(), fs.root_folder_key.clone()))
                            } else {
                                None
                            }
                        });
                        (None, stale)
                    }
                    _ => (None, None),
                }
            } else {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Non-blocking stale metadata refresh (same as readdir's staleness check)
        if let Some((ipns_name, folder_key)) =
            needs_refresh.filter(|(n, _)| !fs.refreshing_metadata.contains(n))
        {
            fs.refreshing_metadata.insert(ipns_name.clone());
            crate::spawn_metadata_refresh(
                &fs.rt,
                fs.api.clone(),
                fs.refresh_tx.clone(),
                parent,
                ipns_name,
                folder_key,
            );
        }

        // Non-blocking lazy load: fire background fetch
        if let Some((ipns_name, folder_key)) =
            needs_load.filter(|(n, _)| !fs.refreshing_metadata.contains(n))
        {
            fs.refreshing_metadata.insert(ipns_name.clone());
            crate::spawn_metadata_refresh(
                &fs.rt,
                fs.api.clone(),
                fs.refresh_tx.clone(),
                parent,
                ipns_name,
                folder_key,
            );
            reply.error(libc::ENOENT);
            return;
        }

        if let Some(child_ino) = fs.inodes.find_child(parent, name_str) {
            if let Some(inode) = fs.inodes.get(child_ino) {
                reply.entry(
                    &ttl_for_is_dir(inode.attr.is_dir),
                    &inode.attr.to_fuse_attr(current_uid(), current_gid()),
                    0,
                );
                return;
            }
        }

        reply.error(libc::ENOENT);
    }

    /// Return file attributes for an inode.
    pub fn handle_getattr(fs: &mut CipherBoxFS, ino: u64, reply: ReplyAttr) {
        fs.drain_upload_completions();
        fs.drain_filepointer_completions();

        if let Some(inode) = fs.inodes.get(ino) {
            reply.attr(
                &ttl_for_is_dir(inode.attr.is_dir),
                &inode.attr.to_fuse_attr(current_uid(), current_gid()),
            );
        } else {
            reply.error(libc::ENOENT);
        }
    }

    /// Open a file for reading or writing.
    pub fn handle_open(fs: &mut CipherBoxFS, ino: u64, flags: i32, reply: ReplyOpen) {
        let file_info = match fs.inodes.get(ino) {
            Some(inode) => match &inode.kind {
                InodeKind::File {
                    cid,
                    encrypted_file_key,
                    iv,
                    encryption_mode,
                    ..
                } => Some((
                    cid.clone(),
                    encrypted_file_key.clone(),
                    iv.clone(),
                    encryption_mode.clone(),
                )),
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

        let (cid, encrypted_file_key, iv, encryption_mode) = {
            let mut info = file_info.unwrap();
            if info.0.is_empty() {
                let is_unresolved = fs
                    .inodes
                    .get(ino)
                    .map(|i| {
                        matches!(
                            &i.kind,
                            InodeKind::File {
                                file_meta_resolved: false,
                                ..
                            }
                        )
                    })
                    .unwrap_or(false);

                if is_unresolved {
                    log::debug!("open: ino={} is unresolved FilePointer, polling...", ino);
                    match poll_filepointer_resolution(fs, ino) {
                        PollResult::Resolved => {
                            if let Some(inode) = fs.inodes.get(ino) {
                                if let InodeKind::File {
                                    cid,
                                    encrypted_file_key,
                                    iv,
                                    encryption_mode,
                                    ..
                                } = &inode.kind
                                {
                                    info = (
                                        cid.clone(),
                                        encrypted_file_key.clone(),
                                        iv.clone(),
                                        encryption_mode.clone(),
                                    );
                                }
                            }
                        }
                        PollResult::TimedOut => {
                            log::warn!(
                                "open: ino={} timed out after {}s poll-wait, returning EIO",
                                ino,
                                FILEPOINTER_POLL_TIMEOUT.as_secs()
                            );
                        }
                        PollResult::NotInFlight => {
                            log::warn!("open: ino={} no in-flight resolution (previously failed?), returning EIO", ino);
                        }
                    }
                    if info.0.is_empty() {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
            info
        };
        let access_mode = flags & libc::O_ACCMODE;

        log::debug!(
            "open: ino={} flags=0x{:x} access_mode=0x{:x} O_TRUNC={} cid={}",
            ino,
            flags,
            access_mode,
            (flags & libc::O_TRUNC) != 0,
            &cid
        );

        if access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR {
            let is_trunc = (flags & libc::O_TRUNC) != 0;

            let inode_size = fs.inodes.get(ino).map(|i| i.attr.size).unwrap_or(0);

            let existing_content = if is_trunc || inode_size == 0 {
                if let Some(inode) = fs.inodes.get_mut(ino) {
                    inode.attr.size = 0;
                    inode.attr.blocks = 0;
                    inode.attr.mtime = SystemTime::now();
                    inode.write_generation += 1;
                    if let InodeKind::File {
                        size: ref mut s,
                        cid: ref mut c,
                        ..
                    } = inode.kind
                    {
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
                    match fetch_and_decrypt_file_content(
                        fs,
                        &cid,
                        &encrypted_file_key,
                        &iv,
                        &encryption_mode,
                    ) {
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
                            let _ = tx.send(crate::PendingContent::Success {
                                cid: cid_clone,
                                data: plaintext,
                            });
                        }
                        Ok(Err(e)) => {
                            log::error!("Prefetch failed for CID {}: {}", cid_clone, e);
                            let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
                        }
                        Err(_) => {
                            log::error!(
                                "Prefetch timed out for CID {} ({}s)",
                                cid_clone,
                                CONTENT_DOWNLOAD_TIMEOUT.as_secs()
                            );
                            let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
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

        let has_temp = fs
            .open_files
            .get(&fh)
            .map(|h| h.temp_path.is_some())
            .unwrap_or(false);

        log::debug!(
            "read: ino={} fh={} offset={} size={} has_temp={}",
            ino,
            fh,
            offset,
            size,
            has_temp
        );

        if has_temp {
            if let Some(handle) = fs.open_files.get(&fh) {
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
            } else {
                reply.error(libc::EBADF);
                return;
            }
        }

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
            let is_unresolved = fs
                .inodes
                .get(ino)
                .map(|i| {
                    matches!(
                        &i.kind,
                        InodeKind::File {
                            file_meta_resolved: false,
                            ..
                        }
                    )
                })
                .unwrap_or(false);

            if is_unresolved {
                log::debug!("read: ino={} is unresolved FilePointer, polling...", ino);
                let poll_result = poll_filepointer_resolution(fs, ino);
                if matches!(poll_result, PollResult::Resolved) {
                    if let Some(inode) = fs.inodes.get(ino) {
                        if let InodeKind::File {
                            cid,
                            encrypted_file_key,
                            iv,
                            encryption_mode,
                            file_meta_resolved: true,
                            ..
                        } = &inode.kind
                        {
                            if !cid.is_empty() {
                                // Re-extract file info for the normal read path
                                let new_cid = cid.clone();
                                let new_efk = encrypted_file_key.clone();
                                let new_iv = iv.clone();
                                let new_em = encryption_mode.clone();
                                // Check cache first
                                if let Some(cached) = fs.content_cache.get(&new_cid) {
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
                                // Not cached yet -- trigger prefetch, NFS/SMB will retry
                                if !fs.prefetching.contains(&new_cid) {
                                    let api = fs.api.clone();
                                    let rt = fs.rt.clone();
                                    let tx = fs.content_tx.clone();
                                    let cid_clone = new_cid.clone();
                                    let efk = new_efk;
                                    let iv_clone = new_iv;
                                    let enc_mode = new_em;
                                    let pk = fs.private_key.clone();
                                    fs.prefetching.insert(new_cid);

                                    rt.spawn(async move {
                                        let result = tokio::time::timeout(
                                            CONTENT_DOWNLOAD_TIMEOUT,
                                            fetch_and_decrypt_content_async(
                                                &api, &cid_clone, &efk, &iv_clone, &enc_mode, &pk,
                                            ),
                                        ).await;
                                        match result {
                                            Ok(Ok(plaintext)) => {
                                                let _ = tx.send(crate::PendingContent::Success { cid: cid_clone, data: plaintext });
                                            }
                                            Ok(Err(e)) => {
                                                log::error!("Read prefetch (post-FP-resolve) failed for CID {}: {}", cid_clone, e);
                                                let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
                                            }
                                            Err(_) => {
                                                log::error!("Read prefetch (post-FP-resolve) timed out for CID {}", cid_clone);
                                                let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
                                            }
                                        }
                                    });
                                }
                                reply.error(libc::EIO); // NFS/SMB will retry, prefetch will populate cache
                                return;
                            }
                        }
                    }
                }
                match poll_result {
                    PollResult::TimedOut => log::warn!(
                        "read: ino={} timed out after {}s poll-wait, returning EIO",
                        ino,
                        FILEPOINTER_POLL_TIMEOUT.as_secs()
                    ),
                    PollResult::NotInFlight => log::warn!(
                        "read: ino={} no in-flight resolution (previously failed?), returning EIO",
                        ino
                    ),
                    PollResult::Resolved => {} // handled above
                }
                reply.error(libc::EIO);
                return;
            }

            // Not an unresolved FilePointer -- fall through to existing empty-CID handling
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
                        let _ = tx.send(crate::PendingContent::Success {
                            cid: cid_clone,
                            data: plaintext,
                        });
                    }
                    Ok(Err(e)) => {
                        log::error!("Read prefetch failed for CID {}: {}", cid_clone, e);
                        let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
                    }
                    Err(_) => {
                        log::error!("Read prefetch timed out for CID {}", cid_clone);
                        let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
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
    pub fn handle_release(fs: &mut CipherBoxFS, ino: u64, fh: u64, reply: ReplyEmpty) {
        fs.drain_upload_completions();

        let handle = fs.open_files.remove(&fh);

        if let Some(handle) = handle {
            let is_new_file = handle.temp_path.is_some() && {
                fs.inodes
                    .get(ino)
                    .map(|i| match &i.kind {
                        InodeKind::File { cid, .. } => cid.is_empty(),
                        _ => false,
                    })
                    .unwrap_or(false)
            };
            let needs_upload = handle.temp_path.is_some() && (handle.dirty || is_new_file);
            if needs_upload {
                log::debug!(
                    "release: uploading ino {} (dirty={}, new={})",
                    ino,
                    handle.dirty,
                    is_new_file
                );

                // Build the journal entry via the shared helper (journal_helpers.rs),
                // then write the ciphertext sidecar + entry OFF the FUSE callback thread,
                // blocking on a bounded durable-ack before applying in-memory mutations.
                //
                // D-01 (WR-06): the heavy sidecar write + F_FULLFSYNC no longer runs on the
                // single FS callback thread — it runs on a background tokio task. The callback
                // thread blocks on a BOUNDED oneshot (NETWORK_TIMEOUT * 18 ≈ 180s) so a wedged
                // writer cannot hang the whole filesystem forever.
                //
                // CR-04: all in-memory mutations (inode kind/attr, pending_content, queued
                // publish) are still deferred until AFTER the journal entry is durable. If the
                // build, the size cap, or the durable write fails/times out, the Err arm replies
                // EIO having mutated nothing — no false durability ack (Pitfall 1).
                let build_result =
                    (|| -> Result<crate::journal_helpers::UploadJournalResult, String> {
                        // Steps 1-7: size cap, encrypt, wrap, encrypt name, sidecar fields.
                        // build_upload_journal_entry returns Err for oversized files (EIO).
                        fs.build_upload_journal_entry(ino, &handle, is_new_file)
                    })();

                // Off-thread durable write + bounded durable-ack (D-01).
                let build_result = match build_result {
                    Ok(mut result) => {
                        // Stream the ciphertext sidecar + fsync the entry on a separate OS
                        // thread (NOT a tokio task — put_with_sidecar is synchronous, and a
                        // plain std::sync::mpsc recv_timeout works whether or not the caller
                        // is inside a tokio runtime, avoiding a nested-runtime panic on the
                        // single FS callback thread).
                        //
                        // The ciphertext (up to the 2 GiB cap) is MOVED into the writer thread
                        // rather than cloned, then handed back through the channel so the later
                        // upload thread can reuse it without a second multi-GB allocation.
                        let (tx, rx) =
                            std::sync::mpsc::channel::<(Result<(), String>, Vec<u8>)>();
                        let put_journal = fs.journal.clone();
                        let put_entry = result.entry.clone();
                        let put_ciphertext = std::mem::take(&mut result.ciphertext);
                        std::thread::spawn(move || {
                            let r = put_journal.put_with_sidecar(&put_entry, &put_ciphertext);
                            let _ = tx.send((r, put_ciphertext));
                        });

                        // Block the callback thread on a BOUNDED recv. A sidecar fsync that
                        // genuinely needs >3 minutes means a wedged/failing disk; acking
                        // success then would violate the durable-ack contract, and blocking
                        // forever would hang the whole FS — the DoS this phase removes.
                        match rx.recv_timeout(crate::runtime::NETWORK_TIMEOUT * 18) {
                            Ok((Ok(()), ciphertext)) => {
                                result.ciphertext = ciphertext;
                                Ok(result)
                            }
                            Ok((Err(e), _)) => {
                                Err(format!("journal sidecar write failed: {}", e))
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(format!(
                                "journal sidecar write timed out after {}s",
                                (crate::runtime::NETWORK_TIMEOUT * 18).as_secs()
                            )),
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                Err("journal sidecar writer dropped before durability".to_string())
                            }
                        }
                    }
                    Err(e) => Err(e),
                };

                // CR-04: journal is durably committed — now apply the in-memory write.
                let build_result = match build_result {
                    Ok(result) => {
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
                                encrypted_file_key: result.encrypted_file_key_hex.clone(),
                                iv: result.iv_hex.clone(),
                                size: result.file_size,
                                encryption_mode: "GCM".to_string(),
                                file_meta_ipns_name: result.file_meta_ipns_name.clone(),
                                file_meta_resolved: true,
                                file_ipns_private_key: result.file_ipns_private_key.clone(),
                                file_ipns_key_encrypted_hex: cached_hex,
                                versions: result.versions_for_meta.clone(),
                            };
                            inode.attr.size = result.file_size;
                            inode.attr.blocks = (result.file_size + 511) / 512;
                            inode.attr.mtime = SystemTime::now();
                        }

                        fs.pending_content.insert(ino, result.plaintext.clone());

                        fs.queue_publish(result.parent_ino, true);

                        Ok(result)
                    }
                    Err(e) => Err(e),
                };

                match build_result {
                    Ok(result) => {
                        // CR-07: snapshot the entry (already put to disk) for record_failure.
                        let journal_entry_snapshot = result.entry.clone();

                        let crate::journal_helpers::UploadJournalResult {
                            ciphertext,
                            file_meta,
                            file_ipns_private_key,
                            file_meta_ipns_name,
                            folder_key_for_file_meta,
                            parent_ino,
                            old_file_cid,
                            pruned_cids,
                            write_gen,
                            ..
                        } = result;
                        let spawn_ino = ino;

                        let api = fs.api.clone();
                        let rt = fs.rt.clone();
                        let upload_tx = fs.upload_tx.clone();
                        let coordinator = fs.publish_coordinator.clone();
                        let tee_public_key = fs.tee_public_key.clone();
                        let tee_key_epoch = fs.tee_key_epoch;
                        let spawn_journal = fs.journal.clone();

                        // D-05: zeroize and delete plaintext temp file BEFORE acking OS.
                        handle.cleanup();
                        // D-04: ack OS only after local journal fsync is confirmed above.
                        reply.ok();

                        // Spawn background upload AFTER ack; entry stays in journal until
                        // success, preserving the write_generation stale-drain guard.
                        std::thread::spawn(move || {
                            let result = rt.block_on(async {
                                let file_cid = cipherbox_api_client::ipfs::upload_content(
                                    &api, &ciphertext,
                                ).await.map_err(|e| format!("{}", e))?;

                                log::info!("File uploaded: ino {} -> CID {}", spawn_ino, file_cid);

                                let _ = upload_tx.send(crate::FsEvent::UploadComplete(crate::UploadComplete {
                                    ino: spawn_ino,
                                    new_cid: file_cid.clone(),
                                    parent_ino,
                                    old_file_cid,
                                    pruned_cids,
                                    write_generation: write_gen,
                                }));

                                if let (Some(ipns_key), Some(ipns_name), Some(folder_key)) =
                                    (&file_ipns_private_key, &file_meta_ipns_name, &folder_key_for_file_meta)
                                {
                                    let mut file_meta_with_cid = file_meta;
                                    file_meta_with_cid.cid = file_cid;

                                    if let Err(e) = publish_file_metadata(
                                        &api, &file_meta_with_cid, folder_key, ipns_key, ipns_name, &coordinator,
                                        tee_public_key.as_deref(),
                                        tee_key_epoch,
                                        is_new_file,
                                    ).await {
                                        log::warn!("Per-file IPNS publish failed for ino {}: {}", spawn_ino, e);
                                    }
                                } else {
                                    log::warn!(
                                        "release: skipping per-file IPNS publish for ino {} (missing key/name/folder_key)",
                                        spawn_ino
                                    );
                                }

                                // CR-08 (mechanism b): do NOT remove the journal entry here.
                                // The parent folder pointer is published by the debounced
                                // publisher AFTER this thread exits. Removing the entry before
                                // that publish is confirmed creates an irrecoverable orphan
                                // window on crash. Replay is the authoritative cleanup path:
                                // replay's already_present check returns Ok and the caller
                                // removes the entry once the child is confirmed in the parent
                                // metadata on the next mount.

                                Ok::<(), String>(())
                            });

                            if let Err(e) = result {
                                // CR-07: call record_failure so retries increment and the entry
                                // parks as Failed after max_retries (D-09). Never silently drop.
                                if let Err(re) =
                                    spawn_journal.record_failure(&journal_entry_snapshot, &e)
                                {
                                    log::warn!(
                                        "record_failure failed for ino {}: {}",
                                        spawn_ino,
                                        re
                                    );
                                }
                                log::error!(
                                    "Background upload failed for ino {}: {}",
                                    spawn_ino,
                                    e
                                );
                            }
                        });
                        return; // reply already sent
                    }
                    Err(e) => {
                        // CR-04: reply EIO and return — do NOT fall through to reply.ok().
                        // All in-memory mutations (inode kind/attr, pending_content, queued
                        // publish) are deferred until after the journal fsync, so a failure
                        // here has mutated nothing: no rollback needed, and no journal entry
                        // was fsynced, so there is nothing to remove.
                        log::error!("File upload preparation failed for ino {}: {}", ino, e);
                        handle.cleanup();
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
        }

        reply.ok();
    }

    /// Flush file data (no-op).
    pub fn handle_flush(reply: ReplyEmpty) {
        reply.ok();
    }

    /// Check file access permissions.
    pub fn handle_access(fs: &CipherBoxFS, ino: u64, mask: i32, reply: ReplyEmpty) {
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
        {
            reply.error(libc::ENOATTR);
        }
        #[cfg(not(target_os = "macos"))]
        {
            reply.error(libc::ENODATA);
        }
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

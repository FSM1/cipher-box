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

    // PollResult and poll_filepointer_resolution are now in crate::poll (Tier-2
    // dedup, Plan 55-03). Import them here for use by handle_open and handle_read.
    use crate::poll::{poll_filepointer_resolution, PollResult};

    use crate::file_handle::OpenFileHandle;
    use crate::helpers::is_platform_special;
    use crate::inode::InodeKind;
    use crate::operations::implementation::{
        current_gid, current_uid, fetch_and_decrypt_file_content, fetch_node_and_decrypt_content,
        publish_file_node, ttl_for_is_dir,
    };

    /// Spawn a background content-prefetch task for a file CID.
    ///
    /// Dedupes the three identical prefetch-spawn blocks that appear in
    /// handle_open (read path) and handle_read (two sites). The `label` parameter
    /// is used in error log messages so callers retain their distinct context.
    ///
    /// node/v3 (69-09 Slice 5b): prefetch resolves the file's OWN gated node
    /// (SC#6) via `ipns_name` and unseals the content under `read_key` — the
    /// former `(encrypted_file_key, iv, encryption_mode)` params are gone (those
    /// descriptors now live inside the sealed node). The spawned task takes an
    /// OWNED `high_water` clone (5b(a)). The result is cached under `cid`.
    fn spawn_content_prefetch_fuse(
        fs: &mut CipherBoxFS,
        cid: String,
        ipns_name: String,
        read_key: [u8; 32],
        label: &'static str,
    ) {
        let api = fs.api.clone();
        let rt = fs.rt.clone();
        let tx = fs.content_tx.clone();
        let cid_clone = cid.clone();
        let ipns_clone = ipns_name;
        let read_key_owned = read_key;
        let high_water = fs.high_water.clone();
        fs.prefetching.insert(cid);

        rt.spawn(async move {
            let result = tokio::time::timeout(
                CONTENT_DOWNLOAD_TIMEOUT,
                fetch_node_and_decrypt_content(&api, &high_water, &ipns_clone, &read_key_owned),
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
                    log::error!("{} for CID {}: {}", label, cid_clone, e);
                    let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
                }
                Err(_) => {
                    log::error!(
                        "{} timed out for CID {} ({}s)",
                        label,
                        cid_clone,
                        CONTENT_DOWNLOAD_TIMEOUT.as_secs()
                    );
                    let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
                }
            }
        });
    }

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
        // node/v3 (69-09 Slice 5b(d)): refresh needs the folder's symmetric
        // read_key + write_key for list_folder_owned (not a legacy folder_key).
        type RefreshTarget = (String, [u8; 32], [u8; 32]);
        let (needs_load, needs_refresh): (Option<RefreshTarget>, Option<RefreshTarget>) = {
            if let Some(parent_inode) = fs.inodes.get(parent) {
                match &parent_inode.kind {
                    InodeKind::Folder {
                        children_loaded,
                        ipns_name,
                        read_key,
                        write_key,
                        ..
                    } => {
                        if !children_loaded {
                            (Some((ipns_name.clone(), **read_key, **write_key)), None)
                        } else if fs.metadata_cache.get(ipns_name).is_none() {
                            (None, Some((ipns_name.clone(), **read_key, **write_key)))
                        } else {
                            (None, None)
                        }
                    }
                    InodeKind::Root {
                        ipns_name,
                        read_key,
                        write_key,
                        ..
                    } => {
                        let name = if ipns_name.is_empty() {
                            fs.root_ipns_name.clone()
                        } else {
                            ipns_name.clone()
                        };
                        let stale = if !name.is_empty() && fs.metadata_cache.get(&name).is_none() {
                            Some((name, **read_key, **write_key))
                        } else {
                            None
                        };
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
        if let Some((ipns_name, read_key, write_key)) =
            needs_refresh.filter(|(n, _, _)| !fs.refreshing_metadata.contains(n))
        {
            fs.refreshing_metadata.insert(ipns_name.clone());
            crate::spawn_metadata_refresh(
                &fs.rt,
                fs.api.clone(),
                fs.refresh_tx.clone(),
                parent,
                ipns_name,
                read_key,
                write_key,
                fs.high_water.clone(),
            );
        }

        // Non-blocking lazy load: fire background fetch
        if let Some((ipns_name, read_key, write_key)) =
            needs_load.filter(|(n, _, _)| !fs.refreshing_metadata.contains(n))
        {
            fs.refreshing_metadata.insert(ipns_name.clone());
            crate::spawn_metadata_refresh(
                &fs.rt,
                fs.api.clone(),
                fs.refresh_tx.clone(),
                parent,
                ipns_name,
                read_key,
                write_key,
                fs.high_water.clone(),
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
        // node/v3 (69-09 Slice 5b): the open path carries the file's stable
        // identity `(cid, ipns_name, read_key)` — the content descriptors
        // (encrypted_file_key/iv/encryption_mode) now live inside the sealed node
        // and are recovered lazily by the gated fetch. "unresolved" == empty CID.
        let file_info = match fs.inodes.get(ino) {
            Some(inode) => match &inode.kind {
                InodeKind::File {
                    cid,
                    ipns_name,
                    read_key,
                    ..
                } => Some((cid.clone(), ipns_name.clone(), **read_key)),
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

        let (cid, ipns_name, read_key): (String, String, [u8; 32]) = {
            let mut info = file_info.unwrap();
            if info.0.is_empty() {
                // A file with content buffered locally (pending background
                // upload) is not an unresolved remote FilePointer — let the
                // open succeed so the subsequent read serves `pending_content`,
                // instead of polling → NotInFlight → EIO.
                let is_unresolved = !fs.pending_content.contains_key(&ino)
                    && fs
                        .inodes
                        .get(ino)
                        .map(|i| {
                            matches!(
                                &i.kind,
                                InodeKind::File { cid, .. } if cid.is_empty()
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
                                    ipns_name,
                                    read_key,
                                    ..
                                } = &inode.kind
                                {
                                    info = (cid.clone(), ipns_name.clone(), **read_key);
                                }
                            }
                        }
                        PollResult::TimedOut => {
                            log::warn!(
                                "open: ino={} timed out after {}s poll-wait, returning EIO",
                                ino,
                                crate::poll::FILEPOINTER_POLL_TIMEOUT.as_secs()
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
                    match fetch_and_decrypt_file_content(fs, &ipns_name, &read_key) {
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
                spawn_content_prefetch_fuse(
                    fs,
                    cid.clone(),
                    ipns_name.clone(),
                    read_key,
                    "Prefetch failed",
                );
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

        let (cid, ipns_name, read_key): (String, String, [u8; 32]) = {
            match fs.inodes.get(ino) {
                Some(inode) => match &inode.kind {
                    InodeKind::File {
                        cid,
                        ipns_name,
                        read_key,
                        ..
                    } => (cid.clone(), ipns_name.clone(), **read_key),
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
            // Read-after-write / empty-file fast path: if this inode has content
            // buffered locally (awaiting the background upload's UploadComplete),
            // serve it directly. Without this, the unresolved-FilePointer poll
            // below — which matches on the SAME empty-cid predicate and so is
            // always taken — returns NotInFlight → EIO before the buffered
            // content (and the empty-file fallback further down) is ever
            // reachable, so a read immediately after a write spuriously fails.
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

            let is_unresolved = fs
                .inodes
                .get(ino)
                .map(|i| {
                    matches!(
                        &i.kind,
                        InodeKind::File { cid, .. } if cid.is_empty()
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
                            ipns_name,
                            read_key,
                            ..
                        } = &inode.kind
                        {
                            if !cid.is_empty() {
                                // Re-extract file info for the normal read path
                                let new_cid = cid.clone();
                                let new_ipns = ipns_name.clone();
                                let new_read_key: [u8; 32] = **read_key;
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
                                    spawn_content_prefetch_fuse(
                                        fs,
                                        new_cid,
                                        new_ipns,
                                        new_read_key,
                                        "Read prefetch (post-FP-resolve) failed",
                                    );
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
                        crate::poll::FILEPOINTER_POLL_TIMEOUT.as_secs()
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
            spawn_content_prefetch_fuse(
                fs,
                cid.clone(),
                ipns_name.clone(),
                read_key,
                "Read prefetch failed",
            );
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
                        let (tx, rx) = std::sync::mpsc::channel::<(Result<(), String>, Vec<u8>)>();
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
                            Ok((Err(e), _)) => Err(format!("journal sidecar write failed: {}", e)),
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
                            // node/v3 (69-09 Slice 5b): the file inode already owns
                            // its node identity (ipns_name + read/write keys +
                            // signing seed) from handle_create / populate_folder.
                            // Update ONLY the content descriptors in place, clearing
                            // the CID (filled by the live publish's UploadComplete),
                            // and PRESERVE the moved-in keys (D-09).
                            if let InodeKind::File {
                                cid,
                                iv,
                                size,
                                encryption_mode,
                                ..
                            } = &mut inode.kind
                            {
                                cid.clear();
                                *iv = result.iv_hex.clone();
                                *size = result.file_size;
                                *encryption_mode = result.encryption_mode.clone();
                            }
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

                        // node/v3 (69-09 Slice 5b(c)): destructure the file node's
                        // OWN identity + content descriptors for the live per-file
                        // node publish (`publish_file_node`).
                        let crate::journal_helpers::UploadJournalResult {
                            ciphertext,
                            file_read_key,
                            file_write_key,
                            file_ipns_private_key,
                            file_ipns_name,
                            file_key,
                            iv_hex,
                            mime_type,
                            encryption_mode,
                            encrypted_ipns_for_tee,
                            tee_key_epoch,
                            file_size,
                            parent_ino,
                            old_file_cid,
                            pruned_cids,
                            write_gen,
                            is_first_publish,
                            ..
                        } = result;
                        let spawn_ino = ino;
                        // The file node's canonical id (D-07): matches the parent's
                        // WriteChildRef.child_id + the read-body AAD. Sourced from the
                        // inode's STORED node_id (its real published.id) — NOT
                        // uuid_from_ino(spawn_ino): a file materialized from a remote
                        // listing then written via the mount keeps the id its creator
                        // published under, so this per-file re-publish preserves the
                        // identity the parent's write plane pairs on. Falls back to
                        // uuid_from_ino only if the inode vanished (never expected).
                        let child_id = fs
                            .inodes
                            .get(spawn_ino)
                            .map(|i| i.node_id.clone())
                            .unwrap_or_else(|| crate::fs::uuid_from_ino(spawn_ino));
                        // D-03 (Plan 80): source the file's CACHED owner-sealed
                        // recipient pins from the inode so a routine overwrite
                        // re-publish PRESERVES them (a shared file republished
                        // pin-less would hard-fail a later re-mint, D-03e). Pins
                        // are public ECIES keys — copied verbatim, never rotated.
                        let file_recipient_pins = fs
                            .inodes
                            .get(spawn_ino)
                            .map(|i| match &i.kind {
                                crate::inode::InodeKind::File { recipient_pins, .. } => {
                                    recipient_pins.clone()
                                }
                                _ => Vec::new(),
                            })
                            .unwrap_or_default();

                        let api = fs.api.clone();
                        let rt = fs.rt.clone();
                        let upload_tx = fs.upload_tx.clone();
                        let coordinator = fs.publish_coordinator.clone();
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

                                if !file_ipns_name.is_empty() {
                                    // Live per-file node/v3 publish: re-seal the file
                                    // node with the real content CID and publish its
                                    // per-file IPNS record (first-publish or CAS update).
                                    if let Err(e) = publish_file_node(
                                        &api,
                                        &file_ipns_name,
                                        &child_id,
                                        &file_cid,
                                        &file_key,
                                        &iv_hex,
                                        file_size,
                                        &mime_type,
                                        &encryption_mode,
                                        &file_read_key,
                                        &file_write_key,
                                        &file_ipns_private_key,
                                        &file_recipient_pins,
                                        &coordinator,
                                        encrypted_ipns_for_tee.as_deref(),
                                        tee_key_epoch,
                                        is_first_publish,
                                    ).await {
                                        log::warn!("Per-file node publish failed for ino {}: {}", spawn_ino, e);
                                    }
                                } else {
                                    log::warn!(
                                        "release: skipping per-file node publish for ino {} (missing file ipns_name)",
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

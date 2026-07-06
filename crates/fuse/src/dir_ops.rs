//! Directory operations for macOS FUSE filesystem.
//!
//! Contains handler logic for: readdir, opendir, releasedir, statfs.

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    use fuser::{FileType, ReplyDirectory, ReplyEmpty, ReplyOpen, ReplyStatfs};
    use std::sync::atomic::Ordering;

    use crate::constants::{CONTENT_DOWNLOAD_TIMEOUT, QUOTA_BYTES};
    use crate::helpers::is_platform_special;
    use crate::inode::{InodeKind, BLOCK_SIZE};
    use crate::operations::implementation::fetch_node_and_decrypt_content;
    use crate::CipherBoxFS;

    /// List directory entries.
    ///
    /// Returns ALL entries in a single pass (FUSE-T requirement).
    pub fn handle_readdir(fs: &mut CipherBoxFS, ino: u64, offset: i64, mut reply: ReplyDirectory) {
        // 1. Drain any pending background results (non-blocking)
        fs.drain_upload_completions();
        fs.drain_refresh_completions();
        fs.drain_filepointer_completions();

        // 2. Check if metadata is stale -- fire background refresh if so
        let stale_info: Option<(String, zeroize::Zeroizing<Vec<u8>>)> = {
            let inode = match fs.inodes.get(ino) {
                Some(i) => i,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            match &inode.kind {
                InodeKind::Root { ipns_name, .. } => ipns_name.as_ref().and_then(|name| {
                    if fs.metadata_cache.get(name).is_none() {
                        Some((name.clone(), fs.root_folder_key.clone()))
                    } else {
                        None
                    }
                }),
                InodeKind::Folder {
                    ipns_name,
                    folder_key,
                    ..
                } => {
                    if fs.metadata_cache.get(ipns_name).is_none() {
                        Some((ipns_name.clone(), folder_key.clone()))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };

        // Fire background refresh (non-blocking, results applied on next readdir)
        if let Some((ipns_name, folder_key)) =
            stale_info.filter(|(n, _)| offset == 0 && !fs.refreshing_metadata.contains(n))
        {
            fs.refreshing_metadata.insert(ipns_name.clone());
            crate::spawn_metadata_refresh(
                &fs.rt,
                fs.api.clone(),
                fs.refresh_tx.clone(),
                ino,
                ipns_name,
                folder_key,
            );
        }

        // 3. Return current (possibly stale) entries immediately
        let (parent_ino, children) = {
            let inode = match fs.inodes.get(ino) {
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
            if let Some(child) = fs.inodes.get(child_ino) {
                if is_platform_special(&child.name) {
                    continue;
                }
                let file_type = match &child.kind {
                    InodeKind::Root { .. } | InodeKind::Folder { .. } => FileType::Directory,
                    InodeKind::File { .. } => FileType::RegularFile,
                };
                entries.push((child_ino, file_type, child.name.clone()));
            }
        }

        for (i, (ino, file_type, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *file_type, &name) {
                break;
            }
        }

        reply.ok();

        // Proactive content prefetch for child files
        if offset == 0 {
            fs.drain_content_prefetches();
            for &child_ino in &children {
                if let Some(child) = fs.inodes.get(child_ino) {
                    // node/v3: prefetch a resolved file by fetching its own gated
                    // node (SC#6) and unsealing the content under its read_key.
                    if let InodeKind::File {
                        cid,
                        ipns_name,
                        read_key,
                        ..
                    } = &child.kind
                    {
                        if !cid.is_empty()
                            && !ipns_name.is_empty()
                            && fs.content_cache.get(cid).is_none()
                            && !fs.prefetching.contains(cid)
                        {
                            let api = fs.api.clone();
                            let rt = fs.rt.clone();
                            let tx = fs.content_tx.clone();
                            let cid_clone = cid.clone();
                            let ipns_clone = ipns_name.clone();
                            let read_key_owned: [u8; 32] = **read_key;
                            // Owned high-water clone for the spawned prefetch task
                            // (shares the same durable PathBuf-backed floor, 5b(a)).
                            let high_water = fs.high_water.clone();
                            fs.prefetching.insert(cid.clone());

                            rt.spawn(async move {
                                let result = tokio::time::timeout(
                                    CONTENT_DOWNLOAD_TIMEOUT,
                                    fetch_node_and_decrypt_content(
                                        &api,
                                        &high_water,
                                        &ipns_clone,
                                        &read_key_owned,
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
                                        let _ = tx.send(crate::PendingContent::Success {
                                            cid: cid_clone,
                                            data: plaintext,
                                        });
                                    }
                                    Ok(Err(e)) => {
                                        log::error!(
                                            "Prefetch(readdir) failed for CID {}: {}",
                                            cid_clone,
                                            e
                                        );
                                        let _ = tx.send(crate::PendingContent::Failure {
                                            cid: cid_clone,
                                        });
                                    }
                                    Err(_) => {
                                        log::error!(
                                            "Prefetch(readdir) timed out for CID {}",
                                            cid_clone
                                        );
                                        let _ = tx.send(crate::PendingContent::Failure {
                                            cid: cid_clone,
                                        });
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    }

    /// Open a directory handle.
    pub fn handle_opendir(fs: &mut CipherBoxFS, ino: u64, reply: ReplyOpen) {
        if fs.inodes.get(ino).is_some() {
            let fh = fs.next_fh.fetch_add(1, Ordering::SeqCst);
            reply.opened(fh, 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    /// Release (close) a directory handle.
    pub fn handle_releasedir(reply: ReplyEmpty) {
        reply.ok();
    }

    /// Return filesystem statistics.
    pub fn handle_statfs(fs: &CipherBoxFS, reply: ReplyStatfs) {
        let block_size = BLOCK_SIZE as u64;
        let total_blocks = QUOTA_BYTES / block_size;

        let used_bytes: u64 = fs
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

        let total_files: u64 = fs.inodes.inodes.len() as u64;

        reply.statfs(
            total_blocks,
            free_blocks,
            free_blocks,
            total_files,
            total_files,
            block_size as u32,
            255,
            block_size as u32,
        );
    }
}

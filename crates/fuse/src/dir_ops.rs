//! Directory operations for macOS FUSE filesystem.
//!
//! Contains handler logic for: readdir, opendir, releasedir, statfs.

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    use fuser::{
        FileType, ReplyDirectory, ReplyEmpty, ReplyOpen, ReplyStatfs,
    };
    use std::sync::atomic::Ordering;

    use crate::CipherBoxFS;
    use crate::constants::{CONTENT_DOWNLOAD_TIMEOUT, QUOTA_BYTES};
    use crate::helpers::is_platform_special;
    use crate::inode::{InodeKind, BLOCK_SIZE};
    use crate::operations::implementation::fetch_and_decrypt_content_async;

    /// List directory entries.
    ///
    /// Returns ALL entries in a single pass (FUSE-T requirement).
    pub fn handle_readdir(
        fs: &mut CipherBoxFS,
        ino: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
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
                InodeKind::Root { ipns_name, .. } => {
                    ipns_name.as_ref().and_then(|name| {
                        if fs.metadata_cache.get(name).is_none() {
                            Some((name.clone(), fs.root_folder_key.clone()))
                        } else {
                            None
                        }
                    })
                }
                InodeKind::Folder { ipns_name, folder_key, .. } => {
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
        if let Some((ipns_name, folder_key)) = stale_info.filter(|_| offset == 0) {
            let api = fs.api.clone();
            let rt = fs.rt.clone();
            let tx = fs.refresh_tx.clone();
            let refresh_ino = ino;
            rt.spawn(async move {
                match cipherbox_api_client::ipns::resolve_ipns(&api, &ipns_name).await {
                    Ok(resolve_resp) => {
                        match cipherbox_api_client::ipfs::fetch_content(&api, &resolve_resp.cid).await {
                            Ok(encrypted_bytes) => {
                                match cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public(
                                    &encrypted_bytes, &folder_key,
                                ) {
                                    Ok(metadata) => {
                                        let _ = tx.send(crate::PendingRefresh {
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

        // Proactive content prefetch for child files
        if offset == 0 {
            fs.drain_content_prefetches();
            for &child_ino in &children {
                if let Some(child) = fs.inodes.get(child_ino) {
                    if let InodeKind::File { cid, encrypted_file_key, iv, encryption_mode, .. } = &child.kind {
                        if !cid.is_empty()
                            && fs.content_cache.get(cid).is_none()
                            && !fs.prefetching.contains(cid)
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
                                        log::error!("Prefetch(readdir) failed for CID {}: {}", cid_clone, e);
                                        let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
                                    }
                                    Err(_) => {
                                        log::error!("Prefetch(readdir) timed out for CID {}", cid_clone);
                                        let _ = tx.send(crate::PendingContent::Failure { cid: cid_clone });
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
    pub fn handle_opendir(
        fs: &mut CipherBoxFS,
        ino: u64,
        reply: ReplyOpen,
    ) {
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

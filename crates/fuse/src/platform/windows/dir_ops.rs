//! Directory operations for Windows WinFsp filesystem.
//!
//! Contains handler logic for: read_directory.

#[cfg(feature = "winfsp")]
pub(crate) mod implementation {
    use winfsp::filesystem::{DirInfo, DirMarker, FileInfo, WideNameInfo};
    use widestring::U16CString;
    use winfsp::FspError;

    use crate::constants::CONTENT_DOWNLOAD_TIMEOUT;
    use crate::inode::InodeKind;
    use super::operations::implementation::{
        WinFspContext, WinFspFileContext,
        status_object_name_not_found,
        fill_file_info, fetch_and_decrypt_content_async,
        is_windows_special,
    };

    /// read_directory handler
    pub fn handle_read_directory(
        ctx: &WinFspContext,
        context: &WinFspFileContext,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32, FspError> {
        let mut fs = ctx.inner.lock().unwrap();
        let ino = context.ino;

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
                InodeKind::Folder { ipns_name, folder_key, .. } => {
                    if fs.metadata_cache.get(&ipns_name).is_none() {
                        Some((ipns_name.clone(), folder_key.clone()))
                    } else {
                        None
                    }
                }
                _ => None,
            };

        if let Some((ipns_name, folder_key)) = stale_info {
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

        let parent_ino = inode.parent_ino;
        let children = inode.children.clone().unwrap_or_default();

        let mut entries: Vec<(U16CString, FileInfo)> = Vec::new();

        if let Ok(name) = U16CString::from_str(".") {
            entries.push((name, fill_file_info(&inode.attr)));
        }

        if let Some(parent) = fs.inodes.get(parent_ino) {
            if let Ok(name) = U16CString::from_str("..") {
                entries.push((name, fill_file_info(&parent.attr)));
            }
        }

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

        let mut past_marker = marker.is_none();
        let mut bytes_written: u32 = 0;

        for (entry_name, entry_info) in &entries {
            if !past_marker {
                let entry_str = entry_name.to_string_lossy();
                let is_match = if marker.is_current() {
                    entry_str == "."
                } else if marker.is_parent() {
                    entry_str == ".."
                } else if let Some(marker_cstr) = marker.inner_as_cstr() {
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
                break;
            }
        }

        // Proactive content prefetch for child files
        fs.drain_content_prefetches();
        for &child_ino in &children {
            let file_info = fs.inodes.get(child_ino).and_then(|child| {
                if let InodeKind::File { cid, encrypted_file_key, iv, encryption_mode, .. } = &child.kind {
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
                                &api, &cid_clone, &efk, &iv_clone, &enc_mode, &pk,
                            ),
                        )
                        .await;

                        match result {
                            Ok(Ok(plaintext)) => {
                                let _ = tx.send(crate::PendingContent::Success {
                                    cid: cid_clone,
                                    data: plaintext,
                                });
                            }
                            Ok(Err(_e)) => {
                                let _ = tx.send(crate::PendingContent::Failure {
                                    cid: cid_clone,
                                });
                            }
                            Err(_) => {
                                let _ = tx.send(crate::PendingContent::Failure {
                                    cid: cid_clone,
                                });
                            }
                        }
                    });
                }
            }
        }

        Ok(bytes_written)
    }
}

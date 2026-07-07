//! Directory operations for Windows WinFsp filesystem.
//!
//! Contains handler logic for: read_directory.

#[cfg(feature = "winfsp")]
pub mod implementation {
    use winfsp::filesystem::{DirInfo, DirMarker, FileInfo, WideNameInfo};
    use widestring::U16CString;
    use winfsp::FspError;

    use crate::constants::CONTENT_DOWNLOAD_TIMEOUT;
    use crate::inode::InodeKind;
    use super::super::operations::implementation::{
        WinFspContext, WinFspFileContext,
        status_object_name_not_found,
        fill_file_info, fetch_node_and_decrypt_content,
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
        fs.drain_filepointer_completions();
        fs.drain_upload_completions();

        let inode = fs
            .inodes
            .get(ino)
            .ok_or(status_object_name_not_found())?;

        // Extract values from inode before mutable borrow of fs below
        let parent_ino = inode.parent_ino;
        let children = inode.children.clone().unwrap_or_default();
        let inode_attr = inode.attr.clone();

        // Check if metadata is stale and fire background refresh.
        // node/v3 (69-14, mirrors 69-09 Slice 5b(d)): the refresh needs the
        // folder's symmetric read_key + write_key (for list_folder_owned), not
        // a legacy folder_key, and `ipns_name` is a plain `String` (empty ==
        // unset), not `Option<String>`.
        let stale_info: Option<(String, [u8; 32], [u8; 32])> = match &inode.kind {
            InodeKind::Root { ipns_name, read_key, write_key, .. } => {
                let name = if ipns_name.is_empty() {
                    fs.root_ipns_name.clone()
                } else {
                    ipns_name.clone()
                };
                if !name.is_empty() && fs.metadata_cache.get(&name).is_none() {
                    Some((name, **read_key, **write_key))
                } else {
                    None
                }
            }
            InodeKind::Folder { ipns_name, read_key, write_key, .. } => {
                if fs.metadata_cache.get(ipns_name).is_none() {
                    Some((ipns_name.clone(), **read_key, **write_key))
                } else {
                    None
                }
            }
            _ => None,
        };

        // `inode` (a `&InodeData` borrow of `fs.inodes`) is no longer used past
        // this point; NLL ends its borrow here so `fs` can be mutably borrowed
        // below.
        let _ = inode;

        if let Some((ipns_name, read_key, write_key)) =
            stale_info.filter(|(n, _, _)| !fs.refreshing_metadata.contains(n))
        {
            fs.refreshing_metadata.insert(ipns_name.clone());
            crate::spawn_metadata_refresh(
                &fs.rt,
                fs.api.clone(),
                fs.refresh_tx.clone(),
                ino,
                ipns_name,
                read_key,
                write_key,
                fs.high_water.clone(),
            );
        }

        let mut entries: Vec<(U16CString, FileInfo)> = Vec::new();

        if let Ok(name) = U16CString::from_str(".") {
            entries.push((name, fill_file_info(&inode_attr)));
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

        // Proactive content prefetch for child files.
        // node/v3 (69-14, mirrors the macOS dir_ops.rs prefetch): a resolved
        // file's content-key is recovered by fetching its own gated node (SC#6)
        // and unsealing the content under its `read_key` — the former
        // `(encrypted_file_key, iv, encryption_mode)` triple is gone.
        fs.drain_content_prefetches();
        for &child_ino in &children {
            let file_info = fs.inodes.get(child_ino).and_then(|child| {
                if let InodeKind::File { cid, ipns_name, read_key, .. } = &child.kind {
                    if !cid.is_empty() && !ipns_name.is_empty() {
                        Some((cid.clone(), ipns_name.clone(), **read_key))
                    } else {
                        None
                    }
                } else {
                    None
                }
            });
            if let Some((cid_clone, ipns_clone, read_key_owned)) = file_info {
                if fs.content_cache.get(&cid_clone).is_none()
                    && !fs.prefetching.contains(&cid_clone)
                {
                    let api = fs.api.clone();
                    let rt = fs.rt.clone();
                    let tx = fs.content_tx.clone();
                    // Owned high-water clone for the spawned prefetch task
                    // (shares the same durable PathBuf-backed floor).
                    let high_water = fs.high_water.clone();
                    fs.prefetching.insert(cid_clone.clone());

                    rt.spawn(async move {
                        let result = tokio::time::timeout(
                            CONTENT_DOWNLOAD_TIMEOUT,
                            fetch_node_and_decrypt_content(
                                &api, &high_water, &ipns_clone, &read_key_owned,
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

use fuser::ReplyEmpty;
use std::ffi::OsStr;
use std::time::SystemTime;

use crate::helpers::is_platform_special;
use crate::inode::InodeKind;
use crate::CipherBoxFS;

/// Rename or move a file/folder.
pub fn handle_rename(
    fs: &mut CipherBoxFS,
    parent: u64,
    name: &OsStr,
    newparent: u64,
    newname: &OsStr,
    reply: ReplyEmpty,
) {
    log::debug!(
        "rename: {:?} (parent {}) -> {:?} (parent {})",
        name,
        parent,
        newname,
        newparent,
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

    // Find source inode (with FUSE-T truncated name fallback)
    let (source_ino, actual_name) = match fs.inodes.find_child(parent, name_str) {
        Some(ino) => (ino, name_str.to_string()),
        None => {
            let parent_inode = match fs.inodes.get(parent) {
                Some(i) => i,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };
            let children = parent_inode.children.clone().unwrap_or_default();
            let mut matches: Vec<(u64, String)> = Vec::new();
            for &child_ino in &children {
                if let Some(child) = fs.inodes.get(child_ino) {
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
                    name_str,
                    matches[0].1
                );
                (matches[0].0, matches[0].1.clone())
            } else {
                log::debug!(
                    "rename failed: {:?} not found (suffix matches: {})",
                    name_str,
                    matches.len()
                );
                reply.error(libc::ENOENT);
                return;
            }
        }
    };

    let name_str = &actual_name;

    log::debug!(
        "rename: {} (ino {}) in parent {} -> {} in parent {}",
        name_str,
        source_ino,
        parent,
        newname_str,
        newparent,
    );

    // SC#3 grant-scope gate for a cross-folder move (a scope-exit for the source
    // subtree). A same-folder rename is NOT a scope exit — the node stays in
    // place, so no rotation. Computed on the SOURCE ancestry BEFORE any inode
    // mutation so a fail-closed rotation aborts the move cleanly (item stays
    // put). Private move → pure `SealedChildRef` relink of both parents (ZERO
    // rotation, D-08 unlink+bin-equivalent with no cross-principal revoke);
    // shared-scope exit → rotate the read key from the matched grant-root
    // ancestor EXACTLY ONCE. D-07 dual-keying is threaded inside the driver.
    if parent != newparent
        && crate::write_ops::grant_scope::run_scope_exit_gate(fs, source_ino).is_err()
    {
        reply.error(libc::EIO);
        return;
    }

    // Cross-folder FILE moves must re-encrypt the per-file FileMetadata to the
    // destination folderKey (it is sealed with the parent folderKey). Capture
    // the inputs now, before any inode mutation. Folder moves need nothing — a
    // folder keeps its own key, as do the files inside it.
    let reencrypt_inputs: Option<(
        String,
        zeroize::Zeroizing<Vec<u8>>,
        zeroize::Zeroizing<Vec<u8>>,
        zeroize::Zeroizing<Vec<u8>>,
    )> = if parent != newparent {
        match fs.inodes.get(source_ino).map(|i| &i.kind) {
            // node/v3: the file carries a plain `ipns_name` + raw signing seed
            // (69-13 owns the cross-folder re-encrypt semantics — this only
            // repoints the capture onto the reshaped InodeKind fields).
            Some(InodeKind::File {
                ipns_name,
                ipns_private_key,
                ..
            }) if !ipns_name.is_empty() => {
                match (fs.get_folder_key(parent), fs.get_folder_key(newparent)) {
                    (Some(src_key), Some(dst_key)) => Some((
                        ipns_name.clone(),
                        ipns_private_key.clone(),
                        src_key,
                        dst_key,
                    )),
                    _ => {
                        log::warn!(
                                "rename: cross-folder move missing folder key(s) for ino {}; skipping metadata re-encrypt",
                                source_ino
                            );
                        None
                    }
                }
            }
            Some(InodeKind::File { .. }) => {
                log::warn!(
                        "rename: cross-folder file move for ino {} missing IPNS name/key; skipping metadata re-encrypt",
                        source_ino
                    );
                None
            }
            _ => None,
        }
    } else {
        None
    };

    // If destination exists, handle replacement
    if let Some(dest_ino) = fs.inodes.find_child(newparent, newname_str) {
        // Self-replace (rename "a" to "a" in same dir): no-op
        if dest_ino == source_ino {
            reply.ok();
            return;
        }

        if let Some(dest_inode) = fs.inodes.get(dest_ino) {
            // Validate kind compatibility (POSIX: can't replace file with dir or vice versa)
            let source_is_dir = fs
                .inodes
                .get(source_ino)
                .map(|i| matches!(i.kind, InodeKind::Root { .. } | InodeKind::Folder { .. }))
                .unwrap_or(false);
            let dest_is_dir = matches!(
                dest_inode.kind,
                InodeKind::Root { .. } | InodeKind::Folder { .. }
            );
            if source_is_dir && !dest_is_dir {
                reply.error(libc::ENOTDIR);
                return;
            }
            if !source_is_dir && dest_is_dir {
                reply.error(libc::EISDIR);
                return;
            }

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
                    if !cid.is_empty() {
                        let cid_clone = cid.clone();
                        let api = fs.api.clone();
                        fs.rt.spawn(async move {
                            let _ =
                                cipherbox_api_client::ipfs::unpin_content(&api, &cid_clone).await;
                        });
                    }
                }
                _ => {}
            }
        }
        fs.publish_queue.remove(&dest_ino);
        fs.inodes.remove(dest_ino);
    }

    // Remove source from old parent's name index (NFC-normalized)
    {
        use unicode_normalization::UnicodeNormalization;
        let nfc_key: String = name_str.nfc().collect();
        fs.inodes.name_to_ino.remove(&(parent, nfc_key));
    }

    // Update the source inode's name and parent
    if let Some(inode) = fs.inodes.get_mut(source_ino) {
        inode.name = newname_str.to_string();
        inode.parent_ino = newparent;
        inode.attr.ctime = SystemTime::now();
    }

    // Update the name lookup index for the new location (NFC-normalized)
    {
        use unicode_normalization::UnicodeNormalization;
        let nfc_key: String = newname_str.nfc().collect();
        fs.inodes
            .name_to_ino
            .insert((newparent, nfc_key), source_ino);
    }

    if parent != newparent {
        if let Some(old_parent) = fs.inodes.get_mut(parent) {
            if let Some(ref mut children) = old_parent.children {
                children.retain(|&c| c != source_ino);
            }
            old_parent.attr.mtime = SystemTime::now();
            old_parent.attr.ctime = SystemTime::now();
        }
        if let Some(new_parent) = fs.inodes.get_mut(newparent) {
            if let Some(ref mut children) = new_parent.children {
                children.push(source_ino);
            }
            new_parent.attr.mtime = SystemTime::now();
            new_parent.attr.ctime = SystemTime::now();
        }

        if let Err(e) = fs.update_folder_metadata(parent) {
            log::error!("Failed to update old parent metadata after rename: {}", e);
        }
        if let Err(e) = fs.update_folder_metadata(newparent) {
            log::error!("Failed to update new parent metadata after rename: {}", e);
        }
    } else {
        if let Some(parent_inode) = fs.inodes.get_mut(parent) {
            parent_inode.attr.mtime = SystemTime::now();
            parent_inode.attr.ctime = SystemTime::now();
        }
        if let Err(e) = fs.update_folder_metadata(parent) {
            log::error!("Failed to update parent metadata after rename: {}", e);
        }
    }

    // Re-encrypt the moved file's metadata to the destination folderKey
    // (fire-and-forget). Without this, every fresh resolve under the new
    // folder's key fails to decrypt.
    if let Some((meta_ipns, file_ipns_key, src_key, dst_key)) = reencrypt_inputs {
        crate::spawn_file_meta_reencrypt(
            fs.api.clone(),
            fs.rt.clone(),
            meta_ipns,
            file_ipns_key,
            src_key,
            dst_key,
            fs.publish_coordinator.clone(),
            fs.tee_public_key.clone(),
            fs.tee_key_epoch,
        );
    }

    reply.ok();
}

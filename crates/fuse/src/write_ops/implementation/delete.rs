use fuser::ReplyEmpty;
use std::ffi::OsStr;
use std::time::SystemTime;

use crate::inode::InodeKind;
use crate::CipherBoxFS;

/// Shared bin-publish tail for delete operations (unlink + rmdir).
///
/// Resolves the parent IPNS name from the inode table and, if present, builds
/// the folder path and fires a fire-and-forget bin-entry publish.
///
/// The caller supplies a closure that receives `(parent_ipns_name, parent_path)`
/// and returns the fully-populated `BinEntry`.  The closure is only called when
/// the parent IPNS name is non-empty (i.e. the publish is not skipped).
fn publish_bin_entry_on_delete<F>(
    fs: &mut CipherBoxFS,
    parent: u64,
    op: &str,
    make_entry: F,
)
where
    F: FnOnce(String, String) -> cipherbox_core::bin::BinEntry,
{
    let parent_ipns_name = fs
        .inodes
        .get(parent)
        .map(|p| match &p.kind {
            InodeKind::Root { ipns_name, .. } => ipns_name.clone().unwrap_or_default(),
            InodeKind::Folder { ipns_name, .. } => ipns_name.clone(),
            _ => String::new(),
        })
        .unwrap_or_default();

    if parent_ipns_name.is_empty() {
        log::warn!(
            "{}: missing parent IPNS name for parent ino {}, skipping bin publish",
            op,
            parent
        );
        return;
    }

    let parent_path = crate::helpers::build_folder_path(fs, parent);
    let bin_entry = make_entry(parent_ipns_name, parent_path);

    crate::spawn_bin_entry_publish(
        fs.api.clone(),
        fs.rt.clone(),
        bin_entry,
        fs.private_key.clone(),
        fs.public_key.to_vec(),
        fs.publish_coordinator.clone(),
    );
}

/// Delete a file from a directory.
pub fn handle_unlink(fs: &mut CipherBoxFS, parent: u64, name: &OsStr, reply: ReplyEmpty) {
    let name_str = match name.to_str() {
        Some(n) => n,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    let child_ino = match fs.inodes.find_child(parent, name_str) {
        Some(ino) => ino,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    // Capture data for bin entry before inode removal
    let bin_entry_data = match fs.inodes.get(child_ino) {
        Some(inode) => match &inode.kind {
            InodeKind::File {
                file_meta_ipns_name,
                file_ipns_key_encrypted_hex,
                size,
                cid,
                versions,
                ..
            } => {
                let now_ms = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let created_ms = inode
                    .attr
                    .crtime
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let meta_ipns = match file_meta_ipns_name {
                    Some(name) if !name.is_empty() => Some(name.clone()),
                    _ => {
                        // file_meta_ipns_name is optional for files loaded from
                        // remote metadata before IPNS resolve. Since bin publishing
                        // is best-effort, skip creating a bin entry when it's missing
                        // instead of failing the unlink.
                        log::warn!(
                            "unlink: missing file_meta_ipns_name for ino {}, skipping bin entry",
                            child_ino
                        );
                        None
                    }
                };

                if let Some(meta_ipns) = meta_ipns {
                    let file_pointer = cipherbox_core::folder::FilePointer {
                        id: cipherbox_crypto::utils::generate_uuid_v4(),
                        name: inode.name.clone(),
                        file_meta_ipns_name: meta_ipns,
                        ipns_private_key_encrypted: file_ipns_key_encrypted_hex.clone(),
                        created_at: if created_ms > 0 { created_ms } else { now_ms },
                        modified_at: now_ms,
                    };

                    let ver_cids = crate::helpers::versions_to_bin_entries(versions);
                    Some((
                        inode.name.clone(),
                        *size,
                        file_pointer,
                        cid.clone(),
                        ver_cids,
                    ))
                } else {
                    None
                }
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

    let now = SystemTime::now();

    fs.inodes.remove(child_ino);

    if let Some(parent_inode) = fs.inodes.get_mut(parent) {
        parent_inode.attr.mtime = now;
        parent_inode.attr.ctime = now;
    }

    if let Err(e) = fs.update_folder_metadata(parent) {
        log::error!("Failed to update folder metadata after unlink: {}", e);
    }

    // Create bin entry and publish to bin IPNS (fire-and-forget)
    if let Some((item_name, file_size, file_pointer, content_cid, ver_cids)) = bin_entry_data {
        // Capture the file's parent folderKey (ECIES-wrapped to the user)
        // so a later restore can re-encrypt the FileMetadata to a different
        // destination folder — including when the original parent folder no
        // longer exists. Mirrors the SDK `addToBin` capture.
        let original_folder_key_encrypted = fs
            .get_folder_key(parent)
            .and_then(|fk| {
                cipherbox_crypto::ecies::wrap_key(&fk, fs.public_key.as_slice()).ok()
            })
            .map(hex::encode);

        let deleted_at = now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mime = cipherbox_crypto::utils::mime_from_extension(&item_name).to_string();
        let content_cid_opt = if content_cid.is_empty() {
            None
        } else {
            Some(content_cid)
        };

        publish_bin_entry_on_delete(fs, parent, "unlink", |parent_ipns_name, parent_path| {
            cipherbox_core::bin::BinEntry {
                id: cipherbox_crypto::utils::generate_uuid_v4(),
                item_type: cipherbox_core::bin::BinItemType::File,
                name: item_name.clone(),
                original_parent_ipns_name: parent_ipns_name,
                original_path: parent_path,
                original_folder_key_encrypted,
                deleted_at,
                size: file_size,
                mime_type: mime,
                content_cid: content_cid_opt,
                content_size: Some(file_size),
                version_cids: ver_cids,
                file_pointer: Some(file_pointer),
                folder_entry: None,
            }
        });
    }

    reply.ok();
}

/// Remove an empty directory.
pub fn handle_rmdir(fs: &mut CipherBoxFS, parent: u64, name: &OsStr, reply: ReplyEmpty) {
    let name_str = match name.to_str() {
        Some(n) => n,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    let child_ino = match fs.inodes.find_child(parent, name_str) {
        Some(ino) => ino,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    // Capture folder data for bin entry before inode removal
    let bin_entry_data = match fs.inodes.get(child_ino) {
        Some(inode) => {
            match &inode.kind {
                InodeKind::Folder {
                    ipns_name,
                    encrypted_folder_key,
                    ipns_private_key,
                    ..
                } => {
                    // Check for non-empty folder (POSIX requirement)
                    if let Some(ref children) = inode.children {
                        if !children.is_empty() {
                            reply.error(libc::ENOTEMPTY);
                            return;
                        }
                    }

                    let now_ms = SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let created_ms = inode
                        .attr
                        .crtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    // Build the ECIES-wrapped IPNS private key for the FolderEntry
                    let ipns_key_encrypted = match ipns_private_key {
                        Some(key) => match cipherbox_crypto::wrap_key(key, &fs.public_key) {
                            Ok(wrapped) => hex::encode(&wrapped),
                            Err(e) => {
                                log::error!(
                                    "rmdir: failed to wrap IPNS key for bin entry: {}",
                                    e
                                );
                                reply.error(libc::EIO);
                                return;
                            }
                        },
                        None => {
                            log::error!(
                                "rmdir: missing folder IPNS private key for ino {}",
                                child_ino
                            );
                            reply.error(libc::EIO);
                            return;
                        }
                    };

                    let folder_entry = cipherbox_core::folder::FolderEntry {
                        id: cipherbox_crypto::utils::generate_uuid_v4(),
                        name: inode.name.clone(),
                        ipns_name: ipns_name.clone(),
                        folder_key_encrypted: encrypted_folder_key.clone(),
                        ipns_private_key_encrypted: ipns_key_encrypted,
                        created_at: if created_ms > 0 { created_ms } else { now_ms },
                        modified_at: now_ms,
                    };

                    Some((inode.name.clone(), folder_entry))
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

    let now = SystemTime::now();

    // Remove from publish queue before removing inode — a queued folder
    // that no longer exists would cause "Folder inode not found" on flush.
    fs.publish_queue.remove(&child_ino);
    fs.inodes.remove(child_ino);

    if let Some(parent_inode) = fs.inodes.get_mut(parent) {
        parent_inode.attr.mtime = now;
        parent_inode.attr.ctime = now;
    }

    if let Err(e) = fs.update_folder_metadata(parent) {
        log::error!("Failed to update folder metadata after rmdir: {}", e);
    }

    // Create bin entry and publish to bin IPNS (fire-and-forget)
    if let Some((item_name, folder_entry)) = bin_entry_data {
        let deleted_at = now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        publish_bin_entry_on_delete(fs, parent, "rmdir", |parent_ipns_name, parent_path| {
            cipherbox_core::bin::BinEntry {
                id: cipherbox_crypto::utils::generate_uuid_v4(),
                item_type: cipherbox_core::bin::BinItemType::Folder,
                name: item_name,
                original_parent_ipns_name: parent_ipns_name,
                original_path: parent_path,
                // Folders keep their own key on restore; nothing to capture.
                original_folder_key_encrypted: None,
                deleted_at,
                size: 0,
                mime_type: String::new(),
                content_cid: None,
                content_size: None,
                version_cids: None,
                file_pointer: None,
                folder_entry: Some(folder_entry),
            }
        });
    }

    reply.ok();
}

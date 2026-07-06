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
fn publish_bin_entry_on_delete<F>(fs: &mut CipherBoxFS, parent: u64, op: &str, make_entry: F)
where
    F: FnOnce(String, String) -> cipherbox_core::bin::BinEntry,
{
    let parent_ipns_name = fs
        .inodes
        .get(parent)
        .map(|p| match &p.kind {
            InodeKind::Root { ipns_name, .. } => ipns_name.clone(),
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

    // Capture the file's own metadata IPNS name (for fail-closed share
    // revocation ahead of the destructive removal) and the bin-entry data in a
    // single inode lookup. The revoke name is empty when the file was loaded
    // from remote metadata before its IPNS resolve — in that case nothing was
    // ever shared under a name, so there is nothing to revoke (and we skip the
    // bin entry too, matching the existing behaviour). Mirrors the rmdir
    // pattern of carrying the revoke name out of the same match.
    let (file_meta_ipns_name, bin_entry_data) = match fs.inodes.get(child_ino) {
        Some(inode) => match &inode.kind {
            // node/v3: the file carries a plain `ipns_name` + raw signing seed.
            InodeKind::File {
                ipns_name,
                ipns_private_key,
                size,
                cid,
                ..
            } => {
                let revoke_ipns_name = ipns_name.clone();
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

                let meta_ipns = if ipns_name.is_empty() {
                    // A never-published file (no IPNS identity yet). Bin publishing
                    // is best-effort — skip the bin entry rather than fail the unlink.
                    log::warn!(
                        "unlink: missing ipns_name for ino {}, skipping bin entry",
                        child_ino
                    );
                    None
                } else {
                    Some(ipns_name.clone())
                };

                let bin_data = if let Some(meta_ipns) = meta_ipns {
                    // Restore-blob keeper: user-ECIES-wrap the file's signing seed so
                    // a later restore can re-publish the file IPNS record. This is a
                    // user-key wrap (like vault export), NOT a node-to-node key hop.
                    let ipns_private_key_encrypted =
                        cipherbox_crypto::wrap_key(ipns_private_key.as_slice(), &fs.public_key)
                            .ok()
                            .map(|w| hex::encode(&w));
                    let file_pointer = cipherbox_core::folder::FilePointer {
                        id: cipherbox_crypto::utils::generate_uuid_v4(),
                        name: inode.name.clone(),
                        file_meta_ipns_name: meta_ipns,
                        ipns_private_key_encrypted,
                        created_at: if created_ms > 0 { created_ms } else { now_ms },
                        modified_at: now_ms,
                    };

                    // Version history now lives in the sealed NodeContent, not the
                    // inode (Slice 1) — version CIDs are not captured in the bin
                    // entry here (file-versioning restore E2E flag).
                    let ver_cids: Option<Vec<cipherbox_core::bin::VersionCidEntry>> = None;
                    Some((
                        inode.name.clone(),
                        *size,
                        file_pointer,
                        cid.clone(),
                        ver_cids,
                    ))
                } else {
                    None
                };

                (revoke_ipns_name, bin_data)
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

    // Fail-closed share cutoff: revoke any shares/invites for this file BEFORE
    // the destructive removal so a deleted-then-unpinned file can't leave a
    // sharee with read access. Aborts the unlink (item stays put) on failure.
    if crate::metadata::revoke_shares_blocking(&fs.api, &fs.rt, &file_meta_ipns_name).is_err() {
        reply.error(libc::EIO);
        return;
    }

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
            .and_then(|fk| cipherbox_crypto::ecies::wrap_key(&fk, fs.public_key.as_slice()).ok())
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
                // node/v3: the folder carries symmetric read/write keys + a raw
                // signing seed (non-Option).
                InodeKind::Folder {
                    ipns_name,
                    read_key,
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

                    // Restore-blob keeper: user-ECIES-wrap the folder's signing seed
                    // so a later restore can re-publish the folder IPNS record. A
                    // user-key wrap (like vault export), NOT a node-to-node key hop.
                    let ipns_key_encrypted = match cipherbox_crypto::wrap_key(
                        ipns_private_key.as_slice(),
                        &fs.public_key,
                    ) {
                        Ok(wrapped) => hex::encode(&wrapped),
                        Err(e) => {
                            log::error!("rmdir: failed to wrap IPNS key for bin entry: {}", e);
                            reply.error(libc::EIO);
                            return;
                        }
                    };
                    // Restore-blob keeper: user-ECIES-wrap the folder's symmetric
                    // readKey so restore can re-derive the folder's node key.
                    let folder_key_encrypted =
                        match cipherbox_crypto::wrap_key(read_key.as_slice(), &fs.public_key) {
                            Ok(wrapped) => hex::encode(&wrapped),
                            Err(e) => {
                                log::error!(
                                    "rmdir: failed to wrap folder readKey for bin entry: {}",
                                    e
                                );
                                reply.error(libc::EIO);
                                return;
                            }
                        };

                    let folder_entry = cipherbox_core::folder::FolderEntry {
                        id: cipherbox_crypto::utils::generate_uuid_v4(),
                        name: inode.name.clone(),
                        ipns_name: ipns_name.clone(),
                        folder_key_encrypted,
                        ipns_private_key_encrypted: ipns_key_encrypted,
                        created_at: if created_ms > 0 { created_ms } else { now_ms },
                        modified_at: now_ms,
                    };

                    Some((inode.name.clone(), folder_entry, ipns_name.clone()))
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

    // Fail-closed share cutoff: revoke any shares/invites for this folder BEFORE
    // the destructive removal. The directory is guaranteed empty here (ENOTEMPTY
    // returned above otherwise), so revoking the folder's own ipns_name is
    // complete coverage — there are no descendant nodes to revoke. Aborts the
    // rmdir (folder stays put) on failure.
    let folder_ipns_name = bin_entry_data
        .as_ref()
        .map(|(_, _, ipns_name)| ipns_name.clone())
        .unwrap_or_default();
    if crate::metadata::revoke_shares_blocking(&fs.api, &fs.rt, &folder_ipns_name).is_err() {
        reply.error(libc::EIO);
        return;
    }

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
    if let Some((item_name, folder_entry, _ipns_name)) = bin_entry_data {
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

#[cfg(all(test, feature = "fuse"))]
mod tests {
    use super::*;
    use crate::inode::{FileAttrs, InodeData, InodeKind, ROOT_INO};
    use crate::test_support::{make_test_fs_with_keypair, reply_error_code, CaptureSender};
    use fuser::Reply;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, UNIX_EPOCH};
    use zeroize::Zeroizing;

    /// Real secp256k1 keypair so `wrap_key` succeeds on the rmdir bin path.
    fn real_keypair() -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (
            Zeroizing::new(sk.serialize().to_vec()),
            Zeroizing::new(pk.serialize().to_vec()),
        )
    }

    /// Insert a `secret.txt` File child of root carrying a non-empty
    /// `file_meta_ipns_name` (so it has a shareable identity to revoke).
    fn insert_file_child(fs: &mut crate::CipherBoxFS, name: &str) -> u64 {
        let ino = fs.inodes.allocate_ino();
        let t = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
        fs.inodes.insert(InodeData {
            ino,
            parent_ino: ROOT_INO,
            name: name.to_string(),
            // node/v3: shareable identity is the plain `ipns_name`; descriptors
            // (cid/iv) filled, keys moved in.
            kind: InodeKind::File {
                ipns_name: "k51file-shared".to_string(),
                cid: "bafyContent".to_string(),
                size: 10,
                encryption_mode: "GCM".to_string(),
                iv: "aabbccdd".to_string(),
                read_key: Zeroizing::new([2u8; 32]),
                write_key: Zeroizing::new([4u8; 32]),
                ipns_private_key: Zeroizing::new(vec![3u8; 32]),
            },
            attr: FileAttrs {
                ino,
                size: 10,
                blocks: 1,
                atime: t,
                mtime: t,
                ctime: t,
                crtime: t,
                is_dir: false,
                perm: 0o644,
                nlink: 1,
            },
            children: None,
            write_generation: 0,
        });
        if let Some(root) = fs.inodes.get_mut(ROOT_INO) {
            root.children.get_or_insert_with(Vec::new).push(ino);
        }
        ino
    }

    /// Insert an EMPTY `subdir` Folder child of root with its own ipns_name.
    fn insert_empty_folder_child(fs: &mut crate::CipherBoxFS, name: &str) -> u64 {
        let ino = fs.inodes.allocate_ino();
        let t = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
        fs.inodes.insert(InodeData {
            ino,
            parent_ino: ROOT_INO,
            name: name.to_string(),
            kind: InodeKind::Folder {
                ipns_name: "k51folder-shared".to_string(),
                read_key: Zeroizing::new([1u8; 32]),
                write_key: Zeroizing::new([6u8; 32]),
                ipns_private_key: Zeroizing::new(vec![5u8; 32]),
                children_loaded: true,
            },
            attr: FileAttrs {
                ino,
                size: 0,
                blocks: 0,
                atime: t,
                mtime: t,
                ctime: t,
                crtime: t,
                is_dir: true,
                perm: 0o755,
                nlink: 2,
            },
            // Empty directory (Some, but no children) — rmdir is allowed.
            children: Some(Vec::new()),
            write_generation: 0,
        });
        if let Some(root) = fs.inodes.get_mut(ROOT_INO) {
            root.children.get_or_insert_with(Vec::new).push(ino);
        }
        ino
    }

    /// Build a multi-thread runtime, construct the fs inside its context (so the
    /// `Handle::current()` in `make_test_fs_with_keypair` resolves), and return
    /// both. The caller invokes the handler on the TEST thread — which is NOT a
    /// runtime worker — so `revoke_shares_blocking`'s `rt.block_on` is valid,
    /// faithfully reproducing the production mount thread (the fuser callback
    /// thread is likewise not a tokio worker). A `#[tokio::test]` would instead
    /// run the body ON a worker thread and panic ("Cannot start a runtime from
    /// within a runtime") — an artifact of the test driver, not the code.
    fn fs_on_runtime() -> (tokio::runtime::Runtime, crate::CipherBoxFS) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let (private_key, public_key) = real_keypair();
        let fs = make_test_fs_with_keypair(private_key, public_key);
        (rt, fs)
    }

    /// FAIL-CLOSED: when share revocation fails (backend unreachable — the test
    /// harness points the API client at an unroutable host), handle_unlink must
    /// return EIO and leave the file inode in place. No share is left stranded
    /// active because the destructive removal never happens.
    #[test]
    fn unlink_aborts_with_eio_when_revoke_fails() {
        let (_rt, mut fs) = fs_on_runtime();
        let child = insert_file_child(&mut fs, "secret.txt");

        let buf = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(buf.clone()));
        handle_unlink(&mut fs, ROOT_INO, OsStr::new("secret.txt"), reply);

        assert_eq!(
            reply_error_code(&buf),
            -libc::EIO,
            "unlink must abort with EIO when share revocation fails"
        );
        assert!(
            fs.inodes.get(child).is_some(),
            "file inode must remain (delete aborted) so its shares are not stranded"
        );
    }

    /// FAIL-CLOSED: handle_rmdir on an empty, shareable folder must return EIO
    /// and keep the folder inode when revocation fails.
    #[test]
    fn rmdir_aborts_with_eio_when_revoke_fails() {
        let (_rt, mut fs) = fs_on_runtime();
        let child = insert_empty_folder_child(&mut fs, "subdir");

        let buf = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(buf.clone()));
        handle_rmdir(&mut fs, ROOT_INO, OsStr::new("subdir"), reply);

        assert_eq!(
            reply_error_code(&buf),
            -libc::EIO,
            "rmdir must abort with EIO when share revocation fails"
        );
        assert!(
            fs.inodes.get(child).is_some(),
            "folder inode must remain (delete aborted) so its shares are not stranded"
        );
    }

    /// The non-empty rmdir guard (ENOTEMPTY) still fires BEFORE the revoke, so a
    /// populated directory is rejected without a wasted revoke round-trip.
    #[test]
    fn rmdir_non_empty_returns_enotempty_before_revoke() {
        let (_rt, mut fs) = fs_on_runtime();
        let dir = insert_empty_folder_child(&mut fs, "subdir");
        // Make it non-empty.
        if let Some(d) = fs.inodes.get_mut(dir) {
            d.children = Some(vec![999]);
        }

        let buf = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(buf.clone()));
        handle_rmdir(&mut fs, ROOT_INO, OsStr::new("subdir"), reply);

        assert_eq!(
            reply_error_code(&buf),
            -libc::ENOTEMPTY,
            "non-empty rmdir must return ENOTEMPTY before attempting revocation"
        );
        assert!(fs.inodes.get(dir).is_some(), "non-empty folder must remain");
    }
}

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

    // Capture the PARENT read/write keys (borrow → copy into owned arrays) so
    // the D-07 dual child-ref can be sealed under the parent planes. Terminal-
    // owner (D-09): the parent inode owns these buffers; we copy the 32 bytes
    // and NEVER zero the inode-owned originals.
    let parent_keys: Option<([u8; 32], [u8; 32])> =
        fs.inodes.get(parent).and_then(|p| match &p.kind {
            InodeKind::Root {
                read_key,
                write_key,
                ..
            }
            | InodeKind::Folder {
                read_key,
                write_key,
                ..
            } => Some((**read_key, **write_key)),
            _ => None,
        });

    // Capture the bin-entry data in a single inode lookup. The child's node/v3
    // read/write keys are re-sealed under the PARENT keys into the D-07 dual
    // ref here — the SC#3 grant-scope gate below reads the mutated node's
    // ancestry directly from the inode table, not from a name carried out of
    // this match.
    let bin_entry_data = match fs.inodes.get(child_ino) {
        Some(inode) => match &inode.kind {
            // node/v3: the file carries a plain `ipns_name` + symmetric
            // read/write keys (the D-07 dual-plane material).
            InodeKind::File {
                ipns_name,
                read_key,
                write_key,
                size,
                cid,
                ..
            } => {
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

                let bin_data = if let (Some(meta_ipns), Some((parent_read_key, parent_write_key))) =
                    (meta_ipns, parent_keys)
                {
                    // D-07 dual ref captured from the inode's OWN node/v3 keys:
                    // SealedChildRef.ipns_name = the child ipns_name (READ plane,
                    // a k51) and WriteChildRef.child_id = uuid_from_ino(child_ino)
                    // (WRITE plane, a UUID) — the two key spaces are NEVER
                    // conflated.
                    // SECURITY-REVIEW: D-07 dual-keying — childId(UUID) vs ipnsName
                    // must not be conflated. childId is the inode's STORED node_id
                    // (its real published.id), NOT uuid_from_ino(child_ino): a
                    // materialized-then-deleted file keeps its creator's id, so the
                    // bin entry's WriteChildRef pairs correctly on restore.
                    let child_id = inode.node_id.clone();
                    let refs = cipherbox_sdk::build_child_refs(
                        &**read_key,
                        &**write_key,
                        &parent_read_key,
                        &parent_write_key,
                        &child_id,
                        &meta_ipns,
                        &inode.name,
                        cipherbox_core::node::NodeKind::File,
                        0,
                        0,
                    );

                    match refs {
                        Ok((child_ref, write_child_ref)) => {
                            // Best-effort published-node keeper: the single-thread
                            // FUSE callback forbids blocking I/O, so we cannot
                            // re-seal the child envelope here → empty-string keeper
                            // (restore re-derives it from the live record).
                            let child_published_node = String::new();
                            // Version history now lives in the sealed NodeContent,
                            // not the inode (Slice 1) — version CIDs are not
                            // captured here (file-versioning restore E2E flag).
                            let ver_cids: Option<Vec<cipherbox_core::bin::VersionCidEntry>> = None;
                            Some((
                                inode.name.clone(),
                                *size,
                                child_ref,
                                write_child_ref,
                                child_published_node,
                                cid.clone(),
                                ver_cids,
                            ))
                        }
                        Err(e) => {
                            log::warn!(
                                "unlink: build_child_refs failed for ino {}, skipping bin entry: {}",
                                child_ino,
                                e
                            );
                            None
                        }
                    }
                } else {
                    None
                };

                bin_data
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

    // SC#3 grant-scope gate (research landmine 9): the unconditional
    // `revoke_shares_blocking` is REPLACED, not augmented. A private delete (no
    // covering grant) is a pure relink with ZERO rotation — the
    // `update_folder_metadata(parent)` below is the only durable effect. A
    // shared-scope exit rotates the read key from the matched grant-root
    // ancestor EXACTLY ONCE. Fail-closed: rotation failure aborts the unlink.
    if crate::write_ops::grant_scope::run_scope_exit_gate(fs, child_ino).is_err() {
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
    if let Some((
        item_name,
        file_size,
        child_ref,
        write_child_ref,
        child_published_node,
        content_cid,
        ver_cids,
    )) = bin_entry_data
    {
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
                deleted_at,
                size: file_size,
                mime_type: mime,
                content_cid: content_cid_opt,
                content_size: Some(file_size),
                version_cids: ver_cids,
                child_published_node,
                child_ref,
                write_child_ref,
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

    // Capture the PARENT read/write keys (borrow → copy) for the D-07 dual
    // child-ref seal. Terminal-owner (D-09): copy the bytes, never zero the
    // inode-owned buffers.
    let parent_keys: Option<([u8; 32], [u8; 32])> =
        fs.inodes.get(parent).and_then(|p| match &p.kind {
            InodeKind::Root {
                read_key,
                write_key,
                ..
            }
            | InodeKind::Folder {
                read_key,
                write_key,
                ..
            } => Some((**read_key, **write_key)),
            _ => None,
        });

    // Capture folder data for bin entry before inode removal
    let bin_entry_data = match fs.inodes.get(child_ino) {
        Some(inode) => {
            match &inode.kind {
                // node/v3: the folder carries symmetric read/write keys + a raw
                // signing seed (non-Option).
                InodeKind::Folder {
                    ipns_name,
                    read_key,
                    write_key,
                    ..
                } => {
                    // Check for non-empty folder (POSIX requirement)
                    if let Some(ref children) = inode.children {
                        if !children.is_empty() {
                            reply.error(libc::ENOTEMPTY);
                            return;
                        }
                    }

                    if ipns_name.is_empty() {
                        log::warn!(
                            "rmdir: missing ipns_name for ino {}, skipping bin entry",
                            child_ino
                        );
                        None
                    } else if let Some((parent_read_key, parent_write_key)) = parent_keys {
                        // D-07 dual ref from the folder's OWN node/v3 keys:
                        // SealedChildRef.ipns_name = the folder ipns_name (READ
                        // plane, a k51), WriteChildRef.child_id =
                        // uuid_from_ino(child_ino) (WRITE plane, a UUID) — never
                        // conflated.
                        // SECURITY-REVIEW: D-07 dual-keying — childId(UUID) vs
                        // ipnsName must not be conflated. childId is the inode's
                        // STORED node_id (its real published.id), NOT
                        // uuid_from_ino(child_ino), so a materialized-then-removed
                        // folder's bin entry pairs correctly on restore.
                        let child_id = inode.node_id.clone();
                        match cipherbox_sdk::build_child_refs(
                            &**read_key,
                            &**write_key,
                            &parent_read_key,
                            &parent_write_key,
                            &child_id,
                            ipns_name,
                            &inode.name,
                            cipherbox_core::node::NodeKind::Folder,
                            0,
                            0,
                        ) {
                            Ok((child_ref, write_child_ref)) => {
                                // Best-effort published-node keeper: no blocking
                                // I/O in the FUSE callback → empty-string keeper.
                                let child_published_node = String::new();
                                Some((
                                    inode.name.clone(),
                                    child_ref,
                                    write_child_ref,
                                    child_published_node,
                                ))
                            }
                            Err(e) => {
                                log::warn!(
                                    "rmdir: build_child_refs failed for ino {}, skipping bin entry: {}",
                                    child_ino,
                                    e
                                );
                                None
                            }
                        }
                    } else {
                        log::warn!(
                            "rmdir: missing parent keys for ino {}, skipping bin entry",
                            child_ino
                        );
                        None
                    }
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

    // SC#3 grant-scope gate (research landmine 9): the unconditional
    // `revoke_shares_blocking` is REPLACED. The directory is guaranteed empty
    // here (ENOTEMPTY returned above otherwise), so its own ancestry is the
    // complete coverage set — there are no descendant nodes. A private rmdir is
    // a pure relink with ZERO rotation (the `update_folder_metadata(parent)`
    // below is the only durable effect); a shared-scope exit rotates the read
    // key from the matched grant-root ancestor EXACTLY ONCE. Fail-closed:
    // rotation failure aborts the rmdir (folder stays put).
    if crate::write_ops::grant_scope::run_scope_exit_gate(fs, child_ino).is_err() {
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
    if let Some((item_name, child_ref, write_child_ref, child_published_node)) = bin_entry_data {
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
                deleted_at,
                size: 0,
                mime_type: String::new(),
                content_cid: None,
                content_size: None,
                version_cids: None,
                child_published_node,
                child_ref,
                write_child_ref,
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

    /// Seed the local sent-shares cache with a single grant rooted at
    /// `root_ipns_name` so a delete whose ancestry contains that name is a
    /// SHARED-scope exit (covering grant present).
    fn seed_sent_share(fs: &crate::CipherBoxFS, root_ipns_name: &str) {
        use cipherbox_api_client::shares::SentShareResponse;
        let share = SentShareResponse {
            share_id: "s1".to_string(),
            recipient_public_key: "0x04".to_string(),
            read_descriptor_ref: "ref".to_string(),
            write_descriptor_ref: None,
            root_node_id: "n1".to_string(),
            root_ipns_name: root_ipns_name.to_string(),
            root_generation: "1".to_string(),
            item_name_encrypted: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };
        *fs.sent_shares.write().expect("sent_shares lock poisoned") =
            crate::write_ops::grant_scope::SentSharesCache::from_sent_shares(&[share]);
    }

    /// Insert a `secret.txt` File child of root carrying a non-empty
    /// `ipns_name` (so it has an IPNS identity in its ancestry chain).
    fn insert_file_child(fs: &mut crate::CipherBoxFS, name: &str) -> u64 {
        let ino = fs.inodes.allocate_ino();
        let t = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
        fs.inodes.insert(InodeData {
            ino,
            node_id: crate::fs::uuid_from_ino(ino),
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
            node_id: crate::fs::uuid_from_ino(ino),
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
    /// runtime worker — so the grant-scope gate's `rt.block_on` is valid,
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

    /// SC#3 / ROT-02 zero-rotation invariant (PRIVATE delete): with an EMPTY
    /// sent-shares cache the file has NO covering grant, so `handle_unlink` is a
    /// pure relink — it succeeds (error code 0) and removes the inode WITHOUT
    /// any rotation. This is the behaviour the unconditional `revoke_shares_blocking`
    /// wrongly prevented (research landmine 9): a private delete must not abort.
    #[test]
    fn unlink_private_delete_succeeds_with_zero_rotation() {
        let (_rt, mut fs) = fs_on_runtime();
        let child = insert_file_child(&mut fs, "secret.txt");
        // No sent shares seeded → private delete (no covering grant).

        let buf = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(buf.clone()));
        handle_unlink(&mut fs, ROOT_INO, OsStr::new("secret.txt"), reply);

        assert_eq!(
            reply_error_code(&buf),
            0,
            "a private unlink (no covering grant) must succeed with zero rotation"
        );
        assert!(
            fs.inodes.get(child).is_none(),
            "the file inode must be removed on a successful private unlink"
        );
    }

    /// PRIVATE rmdir on an empty folder with no covering grant succeeds (error
    /// code 0) and removes the inode — zero rotation.
    #[test]
    fn rmdir_private_delete_succeeds_with_zero_rotation() {
        let (_rt, mut fs) = fs_on_runtime();
        let child = insert_empty_folder_child(&mut fs, "subdir");

        let buf = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(buf.clone()));
        handle_rmdir(&mut fs, ROOT_INO, OsStr::new("subdir"), reply);

        assert_eq!(
            reply_error_code(&buf),
            0,
            "a private rmdir (no covering grant) must succeed with zero rotation"
        );
        assert!(
            fs.inodes.get(child).is_none(),
            "the folder inode must be removed on a successful private rmdir"
        );
    }

    /// SHARED-scope exit routes through read-key rotation. With a covering grant
    /// seeded on the file's ancestry (the vault root is a grant root), the gate
    /// invokes the rotation seam. That seam is not yet live-wired (no production
    /// `RotationDeps`), so it fails CLOSED: `handle_unlink` returns EIO and the
    /// inode remains — a removed reader is never silently left with access. This
    /// documents the deferred live-wiring residual (flagged in the SUMMARY).
    #[test]
    fn unlink_shared_scope_exit_fails_closed_until_rotation_wired() {
        let (_rt, mut fs) = fs_on_runtime();
        let child = insert_file_child(&mut fs, "secret.txt");
        // The vault root ("k51test-root") is a grant root → covering grant on
        // the file's ancestry → shared-scope exit → rotation seam invoked.
        seed_sent_share(&fs, "k51test-root");

        let buf = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(buf.clone()));
        handle_unlink(&mut fs, ROOT_INO, OsStr::new("secret.txt"), reply);

        assert_eq!(
            reply_error_code(&buf),
            -libc::EIO,
            "a shared-scope exit fails closed (EIO) until read-key rotation is live-wired"
        );
        assert!(
            fs.inodes.get(child).is_some(),
            "the file inode must remain when the shared-scope-exit rotation cannot complete"
        );
    }

    /// The non-empty rmdir guard (ENOTEMPTY) still fires BEFORE the grant-scope
    /// gate, so a populated directory is rejected without touching the gate.
    #[test]
    fn rmdir_non_empty_returns_enotempty_before_gate() {
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
            "non-empty rmdir must return ENOTEMPTY before the grant-scope gate"
        );
        assert!(fs.inodes.get(dir).is_some(), "non-empty folder must remain");
    }

    /// Restore-sufficiency + D-07 non-conflation: the bin-write captures the
    /// SAME D-07 dual ref the delete path builds (`build_child_refs`). This
    /// re-splices BOTH planes into a FRESH target parent node (the restore op —
    /// there is no live Rust restore command today, so this pure round-trip is
    /// the reachable proof) and asserts (a) the child's `ipns_name` reappears in
    /// the recovered parent children (read plane), (b) the parent write-body
    /// carries the child's `write_child_ref` keyed by the UUID (write plane),
    /// and (c) `write_child_ref.child_id` (a UUID) is never equal to
    /// `child_ref.ipns_name` (a k51).
    #[test]
    fn bin_dual_refs_are_restore_sufficient_and_d07_distinct() {
        use base64::Engine as _;
        use cipherbox_core::node::{
            decode_node, decode_write_body,
            seal::{seal_published_node, unseal_node},
            Node, NodeKind, NodeWriteBody,
        };

        let parent_read_key = [7u8; 32];
        let parent_write_key = [9u8; 32];
        let child_read_key = [2u8; 32];
        let child_write_key = [4u8; 32];
        let child_ipns_name = "k51childfolder";
        // The write plane is keyed by uuid_from_ino — the exact source the
        // delete path uses.
        let child_id = crate::fs::uuid_from_ino(42);

        let (child_ref, write_child_ref) = cipherbox_sdk::build_child_refs(
            &child_read_key,
            &child_write_key,
            &parent_read_key,
            &parent_write_key,
            &child_id,
            child_ipns_name,
            "restore-me",
            NodeKind::Folder,
            0,
            0,
        )
        .expect("build_child_refs must succeed");

        // (c) D-07: the two key spaces are structurally distinct.
        assert_ne!(
            write_child_ref.child_id, child_ref.ipns_name,
            "D-07: WriteChildRef.child_id (UUID) must never equal SealedChildRef.ipns_name (k51)"
        );
        assert_eq!(
            write_child_ref.child_id, child_id,
            "write plane keyed by UUID"
        );
        assert_eq!(
            child_ref.ipns_name, child_ipns_name,
            "read plane keyed by ipnsName"
        );

        // Re-splice BOTH captured refs into a FRESH target parent node.
        let parent_id = crate::fs::uuid_from_ino(1);
        let parent_node = Node::Folder {
            id: parent_id.clone(),
            generation: 0,
            created_at: 0,
            modified_at: 0,
            children: vec![child_ref.clone()],
        };
        let write_body = NodeWriteBody {
            ipns_private_key: vec![0u8; 32],
            write_children: vec![write_child_ref.clone()],
        };
        let published = seal_published_node(
            &parent_node,
            &parent_read_key,
            &parent_write_key,
            Some(&write_body),
        )
        .expect("seal_published_node must succeed");

        // (a) Read plane: unseal the parent read-body → child ipns_name present.
        let read_sealed = base64::engine::general_purpose::STANDARD
            .decode(&published.read_sealed)
            .expect("valid base64");
        let read_body = unseal_node(
            &read_sealed,
            &parent_read_key,
            &parent_id,
            NodeKind::Folder,
            0,
        )
        .expect("unseal parent read-body");
        let recovered = decode_node(&read_body).expect("decode parent node");
        match recovered {
            Node::Folder { children, .. } => {
                assert!(
                    children.iter().any(|c| c.ipns_name == child_ipns_name),
                    "the re-spliced child must be recovered in the parent read plane"
                );
            }
            other => panic!("expected a recovered Folder node, got {:?}", other.kind()),
        }

        // (b) Write plane: unseal the parent write-body → child_id present.
        let write_sealed_b64 = published.write_sealed.expect("write_sealed present");
        let write_sealed = base64::engine::general_purpose::STANDARD
            .decode(write_sealed_b64)
            .expect("valid base64");
        let wb_bytes = unseal_node(
            &write_sealed,
            &parent_write_key,
            &parent_id,
            NodeKind::Folder,
            0,
        )
        .expect("unseal parent write-body");
        let recovered_wb = decode_write_body(&wb_bytes).expect("decode write body");
        assert!(
            recovered_wb
                .write_children
                .iter()
                .any(|w| w.child_id == child_id),
            "the re-spliced child must be recovered in the parent write plane (keyed by UUID)"
        );
    }
}

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

    // Pre-gate POSIX validation (D-15d): unlink only ever targets a File —
    // reject a directory (EISDIR) BEFORE the scope-exit gate runs, so a
    // doomed-to-fail unlink never triggers a rotation attempt.
    match fs.inodes.get(child_ino).map(|i| &i.kind) {
        Some(InodeKind::File { .. }) => {}
        Some(_) => {
            reply.error(libc::EISDIR);
            return;
        }
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    }

    log::debug!("unlink: {} from parent {}", name_str, parent);

    // SC#3 grant-scope gate (research landmine 9): the unconditional
    // `revoke_shares_blocking` is REPLACED, not augmented. A private delete (no
    // covering grant) is a pure relink with ZERO rotation — the
    // `update_folder_metadata(parent)` below is the only durable effect. A
    // shared-scope exit rotates the read key from the matched grant-root
    // ancestor EXACTLY ONCE. Fail-closed: rotation failure aborts the unlink.
    //
    // D-15d: this gate runs BEFORE the D-07 bin-ref capture below — a shared-
    // scope-exit rotation must never be raced by a bin ref sealed under stale
    // pre-rotation parent state.
    if crate::write_ops::grant_scope::run_scope_exit_gate(fs, child_ino).is_err() {
        reply.error(libc::EIO);
        return;
    }

    // D-15d: capture the PARENT read/write keys (borrow → copy into owned
    // arrays) AFTER the gate has run, so the D-07 dual child-ref below seals
    // under post-rotation parent state, never a stale pre-rotation key.
    // Terminal-owner (D-09): the parent inode owns these buffers; we copy the
    // 32 bytes and NEVER zero the inode-owned originals.
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

    // Capture the bin-entry data in a single inode lookup, now that the gate
    // has run. The child's node/v3 read/write keys are re-sealed under the
    // PARENT keys into the D-07 dual ref here. The kind was already validated
    // File above, so the non-File arm below is unreachable in practice (no
    // concurrent mutator exists in the single-threaded FUSE callback) — kept
    // exhaustive and fail-soft (skip the bin entry) rather than re-erroring
    // after the destructive gate has already run.
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
            _ => None,
        },
        None => None,
    };

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

    // Pre-gate POSIX validation (unchanged position, D-15d): ENOTDIR (not a
    // folder) / ENOTEMPTY (non-empty folder) must reject BEFORE the
    // scope-exit gate runs, so a doomed-to-fail rmdir never triggers a
    // rotation attempt.
    match fs.inodes.get(child_ino) {
        Some(inode) => match &inode.kind {
            InodeKind::Folder { .. } => {
                if let Some(ref children) = inode.children {
                    if !children.is_empty() {
                        reply.error(libc::ENOTEMPTY);
                        return;
                    }
                }
            }
            _ => {
                reply.error(libc::ENOTDIR);
                return;
            }
        },
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    }

    log::debug!("rmdir: {} from parent {}", name_str, parent);

    // SC#3 grant-scope gate (research landmine 9): the unconditional
    // `revoke_shares_blocking` is REPLACED. The directory is guaranteed empty
    // here (ENOTEMPTY returned above otherwise), so its own ancestry is the
    // complete coverage set — there are no descendant nodes. A private rmdir is
    // a pure relink with ZERO rotation (the `update_folder_metadata(parent)`
    // below is the only durable effect); a shared-scope exit rotates the read
    // key from the matched grant-root ancestor EXACTLY ONCE. Fail-closed:
    // rotation failure aborts the rmdir (folder stays put).
    //
    // D-15d: this gate runs BEFORE the D-07 bin-ref capture below — see
    // handle_unlink's identical rationale.
    if crate::write_ops::grant_scope::run_scope_exit_gate(fs, child_ino).is_err() {
        reply.error(libc::EIO);
        return;
    }

    // D-15d: capture the PARENT read/write keys (borrow → copy) AFTER the
    // gate has run, so the D-07 dual child-ref below seals under
    // post-rotation parent state. Terminal-owner (D-09): copy the bytes,
    // never zero the inode-owned buffers.
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

    // Capture folder data for the bin entry, now that the gate has run. The
    // POSIX shape was already validated above, so the non-Folder arm below is
    // unreachable in practice (single-threaded FUSE callback) — kept
    // exhaustive and fail-soft rather than re-erroring post-gate.
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
                _ => None,
            }
        }
        None => None,
    };

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

    /// Seed an AUTHORITATIVE-but-EMPTY sent-shares cache (D-15a / Pitfall 8,
    /// Plan 70.1-11): a refreshed cache with genuinely zero shares, distinct
    /// from the NON-authoritative `SentSharesCache::empty()` default the test
    /// harness starts with (`test_support::make_test_fs_with_keypair`). Since
    /// Plan 70.1-11 made `gate_scope_exit` fail closed on a non-authoritative
    /// cache, a private-delete test must seed THIS (authoritative-empty)
    /// state to exercise the "legitimately nothing shared" success path
    /// rather than the fail-closed path — mirrors the pattern established by
    /// `grant_scope.rs`'s own
    /// `gate_scope_exit_authoritative_empty_cache_allows_private_delete`.
    fn seed_authoritative_empty_cache(fs: &crate::CipherBoxFS) {
        *fs.sent_shares.write().expect("sent_shares lock poisoned") =
            crate::write_ops::grant_scope::SentSharesCache::from_sent_shares(&[]);
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

    /// SC#3 / ROT-02 zero-rotation invariant (PRIVATE delete): with an
    /// AUTHORITATIVE-but-EMPTY sent-shares cache the file has NO covering
    /// grant, so `handle_unlink` is a pure relink — it succeeds (error code
    /// 0) and removes the inode WITHOUT any rotation. This is the behaviour
    /// the unconditional `revoke_shares_blocking` wrongly prevented (research
    /// landmine 9): a private delete must not abort. Seeds
    /// `seed_authoritative_empty_cache` (D-15a / Pitfall 8, Plan 70.1-11) —
    /// NOT the harness's non-authoritative default — so this exercises the
    /// "legitimately nothing shared" success path, not the fail-closed path.
    #[test]
    fn unlink_private_delete_succeeds_with_zero_rotation() {
        let (_rt, mut fs) = fs_on_runtime();
        let child = insert_file_child(&mut fs, "secret.txt");
        // Authoritative-but-empty (refreshed, zero shares) → private delete
        // (no covering grant), NOT the fail-closed non-authoritative path.
        seed_authoritative_empty_cache(&fs);

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
    /// code 0) and removes the inode — zero rotation. Seeds
    /// `seed_authoritative_empty_cache` (D-15a / Pitfall 8, Plan 70.1-11) for
    /// the same reason as `unlink_private_delete_succeeds_with_zero_rotation`.
    #[test]
    fn rmdir_private_delete_succeeds_with_zero_rotation() {
        let (_rt, mut fs) = fs_on_runtime();
        let child = insert_empty_folder_child(&mut fs, "subdir");
        seed_authoritative_empty_cache(&fs);

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

    // -----------------------------------------------------------------
    // Minimal in-process HTTP/1.1 mock rotation server (D-14/D-15d
    // inversion test below) — no live network egress, no new crate
    // dependency. Just enough of resolve/fetch/upload/publish for a
    // ROOT-only (zero children) `rotate_read_from_node` round trip to
    // complete through the REAL `ApiClientTransport`/`FuseRotationDeps`
    // production adapter (Plan 70.1-09), so the inversion below exercises
    // the actual production code path rather than a spy/fake transport.
    // -----------------------------------------------------------------

    /// Spawn a dedicated OS thread (deliberately NOT a tokio task — it
    /// blocks on `std::net::TcpListener`) serving a bounded number of
    /// requests against 127.0.0.1. `resolve_body` answers every
    /// `GET /ipns/resolve*`; `node_body` answers every `GET /ipfs/*`
    /// (fetch); `POST /ipfs/upload` and `POST /ipns/publish` always
    /// succeed. A single root-only rotation needs resolve×2 + fetch×2 +
    /// upload×1 + publish×1 = 6 requests; the cap below is generous.
    fn spawn_mock_rotation_server(
        resolve_body: Vec<u8>,
        node_body: Vec<u8>,
    ) -> std::net::SocketAddr {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock rotation server");
        let addr = listener.local_addr().expect("mock server local_addr");
        std::thread::spawn(move || {
            for stream in listener.incoming().take(16) {
                let Ok(mut stream) = stream else { continue };
                handle_mock_rotation_request(&mut stream, &resolve_body, &node_body);
            }
        });
        addr
    }

    /// Handle one HTTP/1.1 request, dispatching purely on method + path
    /// prefix (query strings/headers otherwise ignored — no auth is
    /// required since the test's `ApiClient` never calls
    /// `set_access_token`).
    fn handle_mock_rotation_request(
        stream: &mut std::net::TcpStream,
        resolve_body: &[u8],
        node_body: &[u8],
    ) {
        use std::io::{Read, Write};

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let headers_end = loop {
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                return; // peer closed before a full request arrived
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > 1_000_000 {
                return; // safety cap against a malformed/oversized request
            }
        };

        let content_length = {
            let headers = String::from_utf8_lossy(&buf[..headers_end]);
            headers
                .split("\r\n")
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().to_string())
                })
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0)
        };
        let have = buf.len() - headers_end;
        if have < content_length {
            let mut remaining = vec![0u8; content_length - have];
            if stream.read_exact(&mut remaining).is_err() {
                return;
            }
            buf.extend_from_slice(&remaining);
        }

        let request_line = buf
            .split(|&b| b == b'\n')
            .next()
            .map(|l| String::from_utf8_lossy(l).trim().to_string())
            .unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        let (status, content_type, body): (&str, &str, Vec<u8>) =
            if method == "GET" && path.starts_with("/ipns/resolve") {
                ("200 OK", "application/json", resolve_body.to_vec())
            } else if method == "POST" && path.starts_with("/ipfs/upload") {
                (
                    "200 OK",
                    "application/json",
                    br#"{"cid":"mock-rotated-cid"}"#.to_vec(),
                )
            } else if method == "GET" && path.starts_with("/ipfs/") {
                ("200 OK", "application/octet-stream", node_body.to_vec())
            } else if method == "POST" && path.starts_with("/ipns/publish") {
                ("200 OK", "application/json", b"{}".to_vec())
            } else {
                ("404 Not Found", "text/plain", b"not found".to_vec())
            };

        let header = format!(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            content_type,
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
    }

    /// D-14/D-15d inversion (post-wiring, Plan 70.1-09/11/12): with
    /// production rotation live-wired (`FuseRotationDeps`/
    /// `ApiClientTransport`, Plan 09) and the gate-correctness fixes landed
    /// (Plan 11), a shared-scope-exit unlink now SUCCEEDS and publishes
    /// exactly ONE rotation for the grant-root, instead of the pre-wiring
    /// EIO this test used to assert (the historical name is kept for
    /// traceability with the plan's own `must_haves`). The mock server
    /// above stands in for the live IPNS/IPFS relay so this exercises the
    /// REAL `ApiClientTransport` code path end to end while staying a fast,
    /// deterministic, offline unit test (no docker/live-API dependency) —
    /// the desktop-e2e real-mount smoke is Plan 70.1-13's job.
    #[test]
    fn unlink_shared_scope_exit_fails_closed_until_rotation_wired() {
        use base64::Engine as _;

        let (_rt, mut fs) = fs_on_runtime();

        // A real Ed25519 identity for the vault root: `resolve_ipns_verified`
        // cross-checks `derive_ipns_name(pubKey) == ipns_name`, so the
        // fixture's placeholder "k51test-root" string cannot stand in for
        // the grant root once a REAL transport is exercised.
        let (root_pub, root_priv) = cipherbox_crypto::generate_ed25519_keypair();
        let root_pub_arr: [u8; 32] = root_pub.clone().try_into().expect("32-byte pubkey");
        let root_ipns_name =
            cipherbox_crypto::derive_ipns_name(&root_pub_arr).expect("derive root ipns name");
        let root_read_key = [11u8; 32];

        if let Some(root) = fs.inodes.get_mut(ROOT_INO) {
            root.kind = InodeKind::Root {
                ipns_name: root_ipns_name.clone(),
                read_key: Zeroizing::new(root_read_key),
                write_key: Zeroizing::new([0u8; 32]),
                ipns_private_key: root_priv.clone(),
            };
        }

        let child = insert_file_child(&mut fs, "secret.txt");
        // The (now real) vault root is a grant root → covering grant on the
        // file's ancestry → shared-scope exit → rotation seam invoked.
        seed_sent_share(&fs, &root_ipns_name);

        // Seed the CURRENTLY-published root (generation 0, zero children,
        // sealed under root_read_key) — what verify_subtree_clean/rotate_one
        // resolve+fetch before rotating.
        let root_node_id = crate::fs::uuid_from_ino(ROOT_INO);
        let root_node = cipherbox_core::node::Node::Root {
            id: root_node_id.clone(),
            generation: 0,
            created_at: 0,
            modified_at: 0,
            children: vec![],
        };
        let body = cipherbox_core::node::encode_node(&root_node).expect("encode root node");
        let sealed = cipherbox_core::node::seal::seal_node(
            &body,
            &root_read_key,
            root_node.id(),
            root_node.kind(),
            root_node.generation(),
        )
        .expect("seal root node");
        let published = cipherbox_core::node::PublishedNode {
            schema: "node/v3".to_string(),
            kind: root_node.kind().as_str().to_string(),
            id: root_node.id().to_string(),
            generation: root_node.generation(),
            aead_version: 1,
            read_sealed: base64::engine::general_purpose::STANDARD.encode(sealed),
            write_sealed: None,
        };
        let published_bytes =
            cipherbox_core::node::encode_published_node(&published).expect("encode published node");

        // Craft the signed resolve envelope the same way `ApiClientTransport`
        // itself constructs one on a real publish (`create_ipns_record`), so
        // `resolve_ipns_verified`'s real signature/CBOR-binding check passes.
        let seed_arr: [u8; 32] = root_priv.as_slice().try_into().expect("32-byte seed");
        let cid = "root-cid-v1";
        let seq = 1u64;
        let record =
            cipherbox_core::create_ipns_record(&seed_arr, &format!("/ipfs/{cid}"), seq, 86_400_000)
                .expect("create resolve-fixture ipns record");
        let resolve_json = serde_json::json!({
            "success": true,
            "cid": cid,
            "sequenceNumber": seq.to_string(),
            "signatureV2": base64::engine::general_purpose::STANDARD.encode(&record.signature_v2),
            "data": base64::engine::general_purpose::STANDARD.encode(&record.data),
            "pubKey": base64::engine::general_purpose::STANDARD.encode(&record.public_key),
        })
        .to_string()
        .into_bytes();

        let addr = spawn_mock_rotation_server(resolve_json, published_bytes);
        fs.api = Arc::new(cipherbox_api_client::ApiClient::new(&format!(
            "http://{}",
            addr
        )));

        let buf = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(buf.clone()));
        handle_unlink(&mut fs, ROOT_INO, OsStr::new("secret.txt"), reply);

        assert_eq!(
            reply_error_code(&buf),
            0,
            "a shared-scope exit now SUCCEEDS once read-key rotation is live-wired \
             (D-14/D-15d inversion, Plan 70.1-09/11/12) — was EIO pre-wiring"
        );
        assert!(
            fs.inodes.get(child).is_none(),
            "the file inode is removed once the shared-scope-exit rotation completes"
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

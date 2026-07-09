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

    // D-15d: destination-REPLACEMENT POSIX validation runs BEFORE any
    // scope-exit gate. A rename that will fail ENOTDIR/EISDIR/ENOTEMPTY must
    // never trigger a rotation — validate first, gate second, mutate third.
    let dest_ino = fs.inodes.find_child(newparent, newname_str);
    if let Some(dest_ino) = dest_ino {
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

            if let InodeKind::Folder { .. } = &dest_inode.kind {
                if let Some(ref children) = dest_inode.children {
                    if !children.is_empty() {
                        reply.error(libc::ENOTEMPTY);
                        return;
                    }
                }
            }
        }
    }

    // SC#3 grant-scope gate for a cross-folder move (a scope-exit for the source
    // subtree). A same-folder rename is NOT a scope exit — the node stays in
    // place, so no rotation. Computed on the SOURCE ancestry AFTER the
    // destination-replacement POSIX validation above (D-15d) but BEFORE any
    // inode mutation, so a fail-closed rotation aborts the move cleanly (item
    // stays put). Private move → pure `SealedChildRef` relink of both parents
    // (ZERO rotation, D-08 unlink+bin-equivalent with no cross-principal
    // revoke); shared-scope exit → rotate the read key from the matched
    // grant-root ancestor EXACTLY ONCE. D-07 dual-keying is threaded inside
    // the driver.
    if parent != newparent
        && crate::write_ops::grant_scope::run_scope_exit_gate(fs, source_ino).is_err()
    {
        reply.error(libc::EIO);
        return;
    }

    // D-15d: gate the OVERWRITTEN destination's OWN scope-exit too. Replacing
    // a destination removes dest_ino outright — that is itself a scope-exit
    // for dest_ino's subtree whenever dest_ino is (or roots) a shared node,
    // regardless of whether the move is same-folder or cross-folder. Runs
    // AFTER the POSIX validation above (a doomed rename never reaches here)
    // and independently of the source gate (two independent scope-exits).
    if let Some(dest_ino) = dest_ino {
        if crate::write_ops::grant_scope::run_scope_exit_gate(fs, dest_ino).is_err() {
            reply.error(libc::EIO);
            return;
        }
    }

    // SC#2: a cross-folder move is now a PURE `SealedChildRef` relink — each
    // node self-seals under its OWN readKey, so there is no per-file metadata to
    // re-encrypt on move (the legacy re-encrypt-on-move path is dead by
    // construction and deleted). The read-scope cut for a shared move is handled
    // by the grant-scope gate above (rotation), not by re-keying the moved file.

    // Destination replacement mutation (validated + gated above): unpin the
    // replaced file's content (fire-and-forget) and remove its inode.
    if let Some(dest_ino) = dest_ino {
        if let Some(dest_inode) = fs.inodes.get(dest_ino) {
            if let InodeKind::File { cid, .. } = &dest_inode.kind {
                if !cid.is_empty() {
                    let cid_clone = cid.clone();
                    let api = fs.api.clone();
                    fs.rt.spawn(async move {
                        let _ = cipherbox_api_client::ipfs::unpin_content(&api, &cid_clone).await;
                    });
                }
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

    /// Real secp256k1 keypair — mirrors `delete.rs`'s own test harness.
    fn real_keypair() -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (
            Zeroizing::new(sk.serialize().to_vec()),
            Zeroizing::new(pk.serialize().to_vec()),
        )
    }

    /// Build a multi-thread runtime + `CipherBoxFS` inside its context so the
    /// grant-scope gate's `rt.block_on` is valid when invoked from the TEST
    /// thread (not a runtime worker) — mirrors `delete.rs`'s `fs_on_runtime`.
    /// The harness's `ApiClient` points at an unroutable host (127.0.0.1:1,
    /// `test_support::make_test_fs_with_keypair`), so any GATED rotation
    /// attempt surfaces `EIO` — the tests below use that as a positive proof
    /// that the gate fired, not a live rotation success (that proof lives in
    /// `delete.rs`'s mock-server inversion test).
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

    /// Seed the local sent-shares cache with a single AUTHORITATIVE grant
    /// rooted at `root_ipns_name` so a mutation whose ancestry contains that
    /// name is a SHARED-scope exit (covering grant present).
    fn seed_sent_share(fs: &crate::CipherBoxFS, root_ipns_name: &str) {
        use cipherbox_api_client::shares::SentShareResponse;
        let share = SentShareResponse {
            share_id: "s1".to_string(),
            recipient_public_key: "0x04".to_string(),
            encrypted_read_key: "ref".to_string(),
            encrypted_write_key: None,
            root_node_id: "n1".to_string(),
            share_root_ipns_name: root_ipns_name.to_string(),
            root_generation: "1".to_string(),
            item_name_encrypted: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };
        *fs.sent_shares.write().expect("sent_shares lock poisoned") =
            crate::write_ops::grant_scope::SentSharesCache::from_sent_shares(&[share]);
    }

    /// Insert an EMPTY Folder child of `parent`.
    fn insert_empty_folder(
        fs: &mut crate::CipherBoxFS,
        parent: u64,
        name: &str,
        ipns_name: &str,
    ) -> u64 {
        let ino = fs.inodes.allocate_ino();
        let t = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
        fs.inodes.insert(InodeData {
            ino,
            node_id: crate::fs::uuid_from_ino(ino),
            parent_ino: parent,
            name: name.to_string(),
            kind: InodeKind::Folder {
                ipns_name: ipns_name.to_string(),
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
            children: Some(Vec::new()),
            write_generation: 0,
        });
        if let Some(p) = fs.inodes.get_mut(parent) {
            p.children.get_or_insert_with(Vec::new).push(ino);
        }
        ino
    }

    /// Insert a NON-empty Folder child (carries one dangling child ino so
    /// the ENOTEMPTY-on-replace check fires; the dangling ino is never
    /// dereferenced by that check).
    fn insert_non_empty_folder(
        fs: &mut crate::CipherBoxFS,
        parent: u64,
        name: &str,
        ipns_name: &str,
    ) -> u64 {
        let ino = insert_empty_folder(fs, parent, name, ipns_name);
        if let Some(f) = fs.inodes.get_mut(ino) {
            f.children = Some(vec![999_999]);
        }
        ino
    }

    /// Insert a File child of `parent`.
    fn insert_file(fs: &mut crate::CipherBoxFS, parent: u64, name: &str, ipns_name: &str) -> u64 {
        let ino = fs.inodes.allocate_ino();
        let t = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
        fs.inodes.insert(InodeData {
            ino,
            node_id: crate::fs::uuid_from_ino(ino),
            parent_ino: parent,
            name: name.to_string(),
            kind: InodeKind::File {
                ipns_name: ipns_name.to_string(),
                cid: String::new(),
                size: 0,
                encryption_mode: "GCM".to_string(),
                iv: String::new(),
                read_key: Zeroizing::new([2u8; 32]),
                write_key: Zeroizing::new([4u8; 32]),
                ipns_private_key: Zeroizing::new(vec![3u8; 32]),
            },
            attr: FileAttrs {
                ino,
                size: 0,
                blocks: 0,
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
        if let Some(p) = fs.inodes.get_mut(parent) {
            p.children.get_or_insert_with(Vec::new).push(ino);
        }
        ino
    }

    /// D-15d: a cross-folder rename whose SOURCE has an active covering
    /// grant (would trigger a rotation attempt if the gate ran) but whose
    /// destination replacement is POSIX-invalid (a non-empty folder,
    /// ENOTEMPTY) must reject with ENOTEMPTY WITHOUT ever invoking the
    /// scope-exit gate. Pre-fix, the gate ran BEFORE this validation, so a
    /// covered source surfaced `-EIO` (the rotation attempt failing against
    /// the harness's unroutable API) instead of the correct `-ENOTEMPTY` — a
    /// doomed rename must never attempt a rotation.
    #[test]
    fn rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt() {
        let (_rt, mut fs) = fs_on_runtime();

        // Source folder under the vault root, which IS a grant root: a
        // cross-folder move of this source is a covered scope-exit if the
        // gate is ever reached.
        let source = insert_empty_folder(&mut fs, ROOT_INO, "shared-src", "k51shared-src");
        seed_sent_share(&fs, "k51test-root");

        // A second folder to move INTO, containing a non-empty destination
        // folder occupying the target name (ENOTEMPTY on replace).
        let other_parent = insert_empty_folder(&mut fs, ROOT_INO, "other", "k51other");
        insert_non_empty_folder(&mut fs, other_parent, "dest", "k51dest");

        let buf = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(buf.clone()));
        handle_rename(
            &mut fs,
            ROOT_INO,
            OsStr::new("shared-src"),
            other_parent,
            OsStr::new("dest"),
            reply,
        );

        assert_eq!(
            reply_error_code(&buf),
            -libc::ENOTEMPTY,
            "POSIX destination validation must run BEFORE the scope-exit gate (D-15d) — a \
             covered source must never attempt rotation on a doomed rename"
        );
        assert!(
            fs.inodes.get(source).is_some(),
            "the source must remain untouched when the rename is rejected pre-gate"
        );
    }

    /// D-15d: renaming a private (uncovered) source OVER an existing
    /// destination that IS itself covered by a grant must gate the
    /// destination's OWN scope-exit before removing it — an ungated removal
    /// would be a silent revocation bypass. The harness's API points at an
    /// unroutable host, so a GATED (attempted) rotation surfaces `EIO`,
    /// proving the gate fired for `dest_ino` rather than silently succeeding.
    #[test]
    fn rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit() {
        let (_rt, mut fs) = fs_on_runtime();

        // Source: a private file with no covering grant.
        let source_parent = insert_empty_folder(&mut fs, ROOT_INO, "srcdir", "k51srcdir");
        let source = insert_file(&mut fs, source_parent, "a.txt", "k51a");

        // Destination: an existing file under a DIFFERENT folder that IS a
        // grant root — replacing it is itself a covered scope-exit.
        let dest_parent = insert_empty_folder(&mut fs, ROOT_INO, "destdir", "k51destdir-shared");
        let dest = insert_file(&mut fs, dest_parent, "b.txt", "k51b");
        seed_sent_share(&fs, "k51destdir-shared");

        let buf = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(buf.clone()));
        handle_rename(
            &mut fs,
            source_parent,
            OsStr::new("a.txt"),
            dest_parent,
            OsStr::new("b.txt"),
            reply,
        );

        assert_eq!(
            reply_error_code(&buf),
            -libc::EIO,
            "overwriting a covered destination must gate dest_ino's own scope-exit (D-15d) — \
             the attempted rotation fails closed (EIO) against the unroutable test API, proving \
             the gate fired rather than silently dropping dest_ino ungated"
        );
        assert!(
            fs.inodes.get(dest).is_some(),
            "the covered destination must remain when its scope-exit rotation cannot complete"
        );
        assert!(
            fs.inodes.get(source).is_some(),
            "the source must remain untouched when the rename aborts on the dest gate"
        );
    }
}
